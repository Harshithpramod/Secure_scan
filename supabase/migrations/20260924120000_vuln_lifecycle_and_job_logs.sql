-- Vulnerability lifecycle (one row per real issue, tracked across scans) and
-- live sandbox activity (verify/fix job progress streamed to the UI).
--
-- Apply by hand in the Supabase SQL editor, like every migration in this repo.
-- Safe to re-run. The app keeps working before this is applied: it detects the
-- missing columns/tables and falls back to the old behaviour.

-- ---------------------------------------------------------------------------
-- 1. Lifecycle columns
-- ---------------------------------------------------------------------------
-- A scan used to INSERT every finding it reported, so the same issue piled up
-- once per scan and nothing ever closed. Scans now reconcile against existing
-- rows: a finding seen again updates its row, one that stops appearing is
-- eventually resolved, and one that comes back after being fixed is reopened.
ALTER TABLE public.vulnerabilities
  ADD COLUMN IF NOT EXISTS last_seen_scan_id UUID REFERENCES public.scans(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
  -- Consecutive scans that read this finding's file and did not report it.
  -- The AI scanner is not deterministic, so one miss is not proof of a fix.
  ADD COLUMN IF NOT EXISTS missed_scans INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS regression_count INTEGER NOT NULL DEFAULT 0,
  -- Set on rows that turned out to be the same issue as another row (e.g. the
  -- scanner reported one bug as CWE-312 in one scan and CWE-256 in the next).
  -- Kept rather than deleted so their verification/fix history survives.
  ADD COLUMN IF NOT EXISTS duplicate_of UUID REFERENCES public.vulnerabilities(id) ON DELETE SET NULL,
  -- Why the status last changed, when the system changed it. Read by the
  -- status trigger below; a manual change from the UI leaves it untouched.
  ADD COLUMN IF NOT EXISTS status_reason TEXT;

UPDATE public.vulnerabilities
   SET last_seen_scan_id = scan_id,
       last_seen_at = detected_at
 WHERE last_seen_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_vulns_repo_canonical
  ON public.vulnerabilities(repository_id)
  WHERE duplicate_of IS NULL;

-- ---------------------------------------------------------------------------
-- 2. Timeline events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.vulnerability_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vulnerability_id UUID NOT NULL REFERENCES public.vulnerabilities(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  repository_id UUID REFERENCES public.repositories(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES public.scans(id) ON DELETE SET NULL,
  -- detected | seen | not_seen | status_changed | duplicate_merged |
  -- verification | fix_requested | fix_pr_opened | fix_rejected
  kind TEXT NOT NULL,
  message TEXT,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  -- clock_timestamp(), not now(): several events are written in one statement
  -- and now() would give them identical timestamps, scrambling their order.
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_vuln_events_vuln_created
  ON public.vulnerability_events(vulnerability_id, created_at);
CREATE INDEX IF NOT EXISTS idx_vuln_events_scan
  ON public.vulnerability_events(scan_id) WHERE scan_id IS NOT NULL;

GRANT SELECT ON public.vulnerability_events TO authenticated;
GRANT ALL ON public.vulnerability_events TO service_role;
ALTER TABLE public.vulnerability_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users view their vulnerability events" ON public.vulnerability_events;
CREATE POLICY "Users view their vulnerability events"
  ON public.vulnerability_events FOR SELECT TO authenticated
  USING (auth.uid() = user_id);
-- No insert/update/delete policy: written only by the server and the trigger.

-- ---------------------------------------------------------------------------
-- 3. Every status change becomes a timeline event, whoever makes it
-- ---------------------------------------------------------------------------
-- One source of truth for status history: the triage dropdown in the UI and
-- the scan reconciler both go through this. A system change sets
-- status_reason in the same UPDATE; a manual change doesn't, so it's recorded
-- as "Changed manually" and any stale reason is cleared.
CREATE OR REPLACE FUNCTION public.log_vulnerability_status_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  reason TEXT;
BEGIN
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    RETURN NEW;
  END IF;

  IF NEW.status_reason IS NOT NULL AND NEW.status_reason IS DISTINCT FROM OLD.status_reason THEN
    reason := NEW.status_reason;
  ELSE
    reason := 'Changed manually';
    NEW.status_reason := NULL;
  END IF;

  INSERT INTO public.vulnerability_events
    (vulnerability_id, user_id, repository_id, scan_id, kind, message, data)
  VALUES (
    NEW.id, NEW.user_id, NEW.repository_id, NEW.last_seen_scan_id,
    'status_changed', reason,
    jsonb_build_object(
      'from', OLD.status,
      'to', NEW.status,
      'by', CASE WHEN auth.uid() IS NULL THEN 'system' ELSE 'user' END
    )
  );
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_vulnerability_status_event ON public.vulnerabilities;
CREATE TRIGGER trg_vulnerability_status_event
  BEFORE UPDATE OF status ON public.vulnerabilities
  FOR EACH ROW EXECUTE FUNCTION public.log_vulnerability_status_change();

-- ---------------------------------------------------------------------------
-- 4. Live sandbox activity
-- ---------------------------------------------------------------------------
-- Structured progress lines from verify/fix containers, forwarded by the
-- worker over the signed callback. Only lines the containers deliberately emit
-- land here (never raw tool output), and the worker redacts secret-shaped
-- values before sending.
CREATE TABLE IF NOT EXISTS public.job_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id TEXT NOT NULL,
  job_kind TEXT NOT NULL CHECK (job_kind IN ('verify', 'fix')),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  vulnerability_id UUID REFERENCES public.vulnerabilities(id) ON DELETE CASCADE,
  -- Monotonic per job, assigned by the worker: callbacks can arrive out of
  -- order, and this is what puts console lines back in sequence.
  seq INTEGER NOT NULL,
  stage TEXT,
  level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info', 'warn', 'error', 'success')),
  message TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (job_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_job_logs_vuln_created
  ON public.job_logs(vulnerability_id, created_at);

GRANT SELECT ON public.job_logs TO authenticated;
GRANT ALL ON public.job_logs TO service_role;
ALTER TABLE public.job_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users view their job logs" ON public.job_logs;
CREATE POLICY "Users view their job logs"
  ON public.job_logs FOR SELECT TO authenticated
  USING (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- 5. Realtime, so the UI updates without polling (it polls as a fallback)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
       WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'job_logs'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.job_logs;
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
       WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'vulnerability_events'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.vulnerability_events;
    END IF;
  END IF;
END;
$$;
