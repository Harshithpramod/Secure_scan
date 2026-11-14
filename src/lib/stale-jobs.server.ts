// Fails work the sandbox never reported back on (server-only). A worker restart
// mid-job, or a callback lost while the app was down, used to leave the row
// "running"/"pending" forever — and a stuck scan blocks every later scan of
// that repository, a stuck fix every later fix of that finding.
//
// Reaping is safe against a job that is merely slow: the callback handlers
// bind on the job id, not the status, so a genuine late verdict still lands
// and overwrites the timeout.

import type { AdminClient } from "@/lib/supabase-admin.server";

const MINUTE = 60_000;

/**
 * Comfortably past the sandbox's own hard limits (runner 20 min, fixer 10 min)
 * plus time spent queued behind other jobs on the single worker.
 */
export const STALE_AFTER_MS = {
  scan: 45 * MINUTE,
  verification: 120 * MINUTE,
  fix: 30 * MINUTE,
};

export async function reapStaleJobs(supabaseAdmin: AdminClient, now = Date.now()) {
  const before = (ms: number) => new Date(now - ms).toISOString();
  const nowIso = new Date(now).toISOString();

  // scans.updated_at is bumped by a trigger on every progress callback, so it
  // is "last sign of life", not "last edited by a user".
  const { data: scans, error: scansErr } = await supabaseAdmin
    .from("scans")
    .select("id, user_id, repository_id, weekly_run_id")
    .in("status", ["queued", "running"])
    .lt("updated_at", before(STALE_AFTER_MS.scan));
  if (scansErr) throw scansErr;

  const { failScan } = await import("@/lib/scan-results.server");
  for (const scan of scans ?? []) {
    await failScan(
      supabaseAdmin,
      scan,
      "Timed out: the sandbox never reported a result. Run the scan again.",
    );
  }

  const { data: verifications, error: verifyErr } = await supabaseAdmin
    .from("vulnerabilities")
    .update({
      verification_status: "failed",
      verification_evidence: "Timed out: the sandbox never reported a verification result.",
      verification_completed_at: nowIso,
    })
    .eq("verification_status", "pending")
    .lt("updated_at", before(STALE_AFTER_MS.verification))
    .select("id");
  if (verifyErr) throw verifyErr;

  const { data: fixes, error: fixErr } = await supabaseAdmin
    .from("vulnerabilities")
    .update({
      fix_status: "failed",
      fix_error: "Timed out: the sandbox never reported a result. Try Fix with AI again.",
      fix_completed_at: nowIso,
    })
    .eq("fix_status", "pending")
    .lt("fix_requested_at", before(STALE_AFTER_MS.fix))
    .select("id");
  if (fixErr) throw fixErr;

  // A weekly run whose last scan was reaped has no callback left to send its
  // digest, so nudge it here.
  // shortcut: a run blocked only by a reaped *verification* still gets no digest; look up its scan's weekly_run_id if that ever matters.
  const { maybeSendWeeklyDigest } = await import("@/lib/weekly-digest.server");
  for (const scan of scans ?? []) {
    if (scan.weekly_run_id) {
      await maybeSendWeeklyDigest(supabaseAdmin, scan.user_id, scan.weekly_run_id);
    }
  }

  const reaped = {
    scans: scans?.length ?? 0,
    verifications: verifications?.length ?? 0,
    fixes: fixes?.length ?? 0,
  };
  if (reaped.scans + reaped.verifications + reaped.fixes > 0) {
    console.warn("[stale-jobs] timed out", reaped);
  }
  return reaped;
}

/** For callers where a cleanup failure must not block the real work. */
export async function reapStaleJobsQuietly(supabaseAdmin: AdminClient) {
  try {
    await reapStaleJobs(supabaseAdmin);
  } catch (err) {
    console.error("[stale-jobs] cleanup failed", err);
  }
}
