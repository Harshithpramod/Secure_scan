-- The scan pipeline moved out of the app's request path and into the sandbox
-- worker as a queued job (see sandbox/worker/scan.js). Scans are now claimed
-- with a job id the app generates BEFORE submitting, so the sandbox callback
-- can bind to the exact row it is meant to update — the same discipline the
-- vulnerabilities table already uses for verification and fix jobs.

ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS sandbox_job_id TEXT;

CREATE INDEX IF NOT EXISTS idx_scans_sandbox_job_id
  ON public.scans(sandbox_job_id)
  WHERE sandbox_job_id IS NOT NULL;

-- Used by startScan to reject a second concurrent scan of the same repository.
CREATE INDEX IF NOT EXISTS idx_scans_active_by_repo
  ON public.scans(repository_id, status)
  WHERE status IN ('queued', 'running');
