-- Weekly automated scanning + digest email.
--
-- scan_mode/schedule_day/schedule_hour/timezone on `repositories` and the
-- 'scheduled' value of scan_trigger already existed in the original schema
-- but were never wired up — this feature is what finally uses scan_mode.

-- Groups the scans one weekly sweep creates, so "is this user's digest ready
-- to send" can be checked per-run rather than per-scan. Nullable: manual
-- scans never set it.
ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS weekly_run_id UUID;

CREATE INDEX IF NOT EXISTS idx_scans_weekly_run_id
  ON public.scans(weekly_run_id)
  WHERE weekly_run_id IS NOT NULL;

-- Idempotency guard for the digest email. Both a scan-complete callback and a
-- verify-complete callback can independently notice "this run just finished"
-- at nearly the same moment; whichever inserts here first wins, the other
-- hits a PK conflict and skips. Same claim-before-act discipline already used
-- for sandbox_job_id / fix_job_id elsewhere in this schema.
CREATE TABLE public.weekly_digest_log (
  weekly_run_id UUID NOT NULL,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (weekly_run_id, user_id)
);

GRANT ALL ON public.weekly_digest_log TO service_role;
ALTER TABLE public.weekly_digest_log ENABLE ROW LEVEL SECURITY;
-- No authenticated policies: nothing in the UI reads this, only the server-side
-- digest check does (via the service-role client) — same pattern as
-- github_connections having no client-facing policy.
