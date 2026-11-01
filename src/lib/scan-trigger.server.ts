// Starts a scan for a repository (server-only). The one piece of logic behind
// both entry points that create a scan: a user clicking "Scan" (startScan in
// scans.functions.ts, trigger="manual") and the weekly sweep triggering every
// repo in weekly mode (weekly-scan-sweep.server.ts, trigger="scheduled").
// Extracted so the two never drift out of sync with each other.

import type { AdminClient } from "@/lib/supabase-admin.server";
import { submitScanJob } from "@/lib/sandbox";

export type TriggerScanArgs = {
  repositoryId: string;
  userId: string;
  trigger: "manual" | "scheduled";
  weeklyRunId?: string;
};

export type TriggerScanResult =
  | { ok: true; scanId: string }
  | { ok: false; reason: "not_found" | "already_running" | "submit_failed"; message: string };

export async function triggerScan(
  supabaseAdmin: AdminClient,
  { repositoryId, userId, trigger, weeklyRunId }: TriggerScanArgs,
): Promise<TriggerScanResult> {
  const { data: repo, error: repoErr } = await supabaseAdmin
    .from("repositories")
    .select("*")
    .eq("id", repositoryId)
    .eq("user_id", userId)
    .maybeSingle();
  if (repoErr) throw repoErr;
  if (!repo) return { ok: false, reason: "not_found", message: "Repository not found" };

  // Reject a second scan while one is still in flight, rather than racing two
  // pipelines against the same repository row.
  const { data: active } = await supabaseAdmin
    .from("scans")
    .select("id")
    .eq("repository_id", repo.id)
    .eq("user_id", userId)
    .in("status", ["queued", "running"])
    .limit(1);
  if (active && active.length > 0) {
    return {
      ok: false,
      reason: "already_running",
      message: "A scan is already running for this repository.",
    };
  }

  const { getUserAccessToken } = await import("@/lib/github-token.server");
  const token = await getUserAccessToken(userId);

  // The job id is generated here and stored on the row before submission, so
  // a fast callback can never arrive before the row that receives it.
  const jobId = crypto.randomUUID();

  const { insertScanLog, failScan } = await import("@/lib/scan-results.server");

  const { data: scanRow, error: scanErr } = await supabaseAdmin
    .from("scans")
    .insert({
      repository_id: repo.id,
      user_id: userId,
      trigger,
      weekly_run_id: weeklyRunId ?? null,
      profile: repo.scan_depth ?? "standard",
      branch: repo.default_branch,
      status: "queued",
      current_stage: "queued",
      progress: 5,
      sandbox_job_id: jobId,
      started_at: new Date().toISOString(),
    })
    .select()
    .single();
  if (scanErr) throw scanErr;
  const scanId = scanRow.id as string;

  await supabaseAdmin.from("repositories").update({ status: "testing" }).eq("id", repo.id);
  await insertScanLog(
    supabaseAdmin,
    scanId,
    userId,
    "init",
    trigger === "scheduled"
      ? `Weekly auto-scan of ${repo.full_name}`
      : `Queued scan of ${repo.full_name}`,
  );

  try {
    await submitScanJob({
      job_id: jobId,
      scan_id: scanId,
      repository_id: repo.id,
      owner: repo.owner,
      repo: repo.name,
      full_name: repo.full_name,
      default_branch: repo.default_branch ?? "main",
      language: repo.language ?? null,
      repo_clone_url: `https://github.com/${repo.full_name}.git`,
      repo_token: token,
    });
  } catch (err) {
    const message = String((err as Error)?.message ?? err);
    await failScan(
      supabaseAdmin,
      { id: scanId, user_id: userId, repository_id: repo.id },
      `Could not reach the sandbox: ${message}`,
    );
    return { ok: false, reason: "submit_failed", message: `Could not start the scan: ${message}` };
  }

  return { ok: true, scanId };
}
