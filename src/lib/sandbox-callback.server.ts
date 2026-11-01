import { createHmac, timingSafeEqual } from "node:crypto";
import { getSupabaseAdmin } from "@/lib/supabase-admin.server";
import type { Database, Json } from "@/integrations/supabase/types";

type VerifyVerdict = {
  // "failed" means the probe itself errored (e.g. CodeQL/semgrep crashed) —
  // distinct from a clean scan that legitimately found nothing, so the UI
  // never has to guess whether "not_exploitable" was actually verified.
  status: "confirmed" | "not_exploitable" | "failed";
  evidence: string;
  details?: Record<string, unknown>;
};

type ScanVerdict = {
  status: "completed" | "failed";
  evidence?: string;
  details?: Record<string, unknown>;
};

type FixVerdict = {
  status: "pr_created" | "failed";
  evidence?: string;
  details?: Record<string, unknown>;
};

type CallbackPayload = {
  kind?: "verify" | "fix" | "scan" | "scan_progress" | "job_progress";
  job_id: string;
  scan_id: string | null;
  vulnerability_id: string;
  verdict: VerifyVerdict | FixVerdict | ScanVerdict;
  duration_ms: number;
  // scan_progress only
  stage?: string;
  progress?: number;
  message?: string;
  level?: "info" | "warn" | "error" | "success";
  // job_progress only
  job_kind?: "verify" | "fix";
  seq?: number;
  data?: Record<string, unknown>;
};

const VALID_VERIFY_STATUSES = new Set(["confirmed", "not_exploitable", "failed"]);
const VALID_FIX_STATUSES = new Set(["pr_created", "failed"]);

export async function handleSandboxCallback(request: Request): Promise<Response> {
  const secret = process.env.CALLBACK_HMAC_SECRET;
  if (!secret) {
    console.error("[sandbox-callback] CALLBACK_HMAC_SECRET not set");
    return new Response("misconfigured", { status: 500 });
  }

  const body = await request.text();

  const sig = request.headers.get("x-sandbox-signature") ?? "";
  const expected = createHmac("sha256", secret).update(body).digest("hex");
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    console.warn("[sandbox-callback] HMAC mismatch — rejected");
    return new Response("unauthorized", { status: 401 });
  }

  let payload: CallbackPayload;
  try {
    payload = JSON.parse(body) as CallbackPayload;
  } catch {
    return new Response("invalid json", { status: 400 });
  }

  const { vulnerability_id, job_id, verdict } = payload;
  const kind = payload.kind ?? "verify";

  if (!job_id) return new Response("missing fields", { status: 400 });

  try {
    if (kind === "scan_progress") return await applyScanProgress(payload);
    if (kind === "job_progress") return await applyJobProgress(payload);
    if (kind === "scan") {
      if (!verdict?.status) return new Response("missing fields", { status: 400 });
      return await applyScanVerdict(payload, verdict as ScanVerdict);
    }

    if (!vulnerability_id || !verdict?.status) {
      return new Response("missing fields", { status: 400 });
    }
    if (kind === "fix") return await applyFixVerdict(payload, verdict as FixVerdict);
    return await applyVerifyVerdict(payload, verdict as VerifyVerdict);
  } catch (err) {
    console.error("[sandbox-callback] unexpected error", err);
    return new Response("internal error", { status: 500 });
  }
}

/**
 * Looks up the scan this callback belongs to, bound to the job id we issued.
 * A stray or replayed callback with the wrong job id matches nothing.
 */
async function loadScanForJob(scanId: string | null, jobId: string) {
  if (!scanId) return null;
  const { data } = await getSupabaseAdmin()
    .from("scans")
    .select(
      "id, user_id, repository_id, started_at, status, weekly_run_id, repositories(id, full_name, default_branch)",
    )
    .eq("id", scanId)
    .eq("sandbox_job_id", jobId)
    .maybeSingle();
  return data;
}

async function applyScanProgress(payload: CallbackPayload): Promise<Response> {
  const scan = await loadScanForJob(payload.scan_id, payload.job_id);
  if (!scan) return new Response("not found", { status: 404 });

  // A late progress update must never reopen a scan that already finished.
  if (scan.status === "completed" || scan.status === "failed") {
    return new Response("ok", { status: 200 });
  }

  const supabase = getSupabaseAdmin();
  const progress =
    Number.isFinite(payload.progress) && payload.progress! >= 0 && payload.progress! <= 100
      ? payload.progress
      : undefined;

  await supabase
    .from("scans")
    .update({
      status: "running",
      current_stage: (payload.stage ?? "running").slice(0, 60),
      ...(progress !== undefined ? { progress } : {}),
    })
    .eq("id", scan.id);

  if (payload.message) {
    const { insertScanLog } = await import("@/lib/scan-results.server");
    await insertScanLog(
      supabase,
      scan.id,
      scan.user_id,
      (payload.stage ?? "scan").slice(0, 60),
      payload.message.slice(0, 1000),
      payload.level === "warn" || payload.level === "error" ? payload.level : "info",
    );
  }

  return new Response("ok", { status: 200 });
}

async function applyScanVerdict(payload: CallbackPayload, verdict: ScanVerdict): Promise<Response> {
  const scan = await loadScanForJob(payload.scan_id, payload.job_id);
  if (!scan) {
    console.warn(
      `[sandbox-callback] no matching scan for id=${payload.scan_id} job=${payload.job_id}`,
    );
    return new Response("not found", { status: 404 });
  }

  const supabase = getSupabaseAdmin();
  const { persistScanResults, failScan } = await import("@/lib/scan-results.server");

  if (scan.status === "completed" || scan.status === "failed") {
    return new Response("ok", { status: 200 });
  }

  if (verdict.status !== "completed") {
    await failScan(supabase, scan, verdict.evidence || "The scan failed in the sandbox.");
    return new Response("ok", { status: 200 });
  }

  const repo = scan.repositories;
  if (!repo) {
    await failScan(supabase, scan, "The repository for this scan no longer exists.");
    return new Response("ok", { status: 200 });
  }

  try {
    const { findings } = await persistScanResults(supabase, scan, repo, verdict.details ?? {});
    console.log(`[sandbox-callback] scan ${scan.id} -> completed (${findings} findings)`);
  } catch (err) {
    console.error("[sandbox-callback] failed to persist scan results", err);
    await failScan(
      supabase,
      scan,
      `Could not save results: ${String((err as Error)?.message ?? err)}`,
    );
  }

  return new Response("ok", { status: 200 });
}

const JOB_LEVELS = new Set(["info", "warn", "error", "success"]);
const MAX_JOB_DATA_BYTES = 24_000;
let warnedNoJobLogs = false;

/**
 * One console line from a verify/fix container, relayed by the worker. Bound
 * the same way as the job's verdict (the row must currently own this job id),
 * and the owner comes from that row, never from the payload.
 */
async function applyJobProgress(payload: CallbackPayload): Promise<Response> {
  const { job_id, vulnerability_id, job_kind } = payload;
  if (!vulnerability_id || (job_kind !== "verify" && job_kind !== "fix")) {
    return new Response("missing fields", { status: 400 });
  }
  if (!Number.isInteger(payload.seq) || typeof payload.message !== "string") {
    return new Response("missing fields", { status: 400 });
  }

  const supabase = getSupabaseAdmin();
  const { data: row } = await supabase
    .from("vulnerabilities")
    .select("id, user_id")
    .eq("id", vulnerability_id)
    .eq(job_kind === "fix" ? "fix_job_id" : "sandbox_job_id", job_id)
    .maybeSingle();
  if (!row) return new Response("not found", { status: 404 });

  let data = (payload.data ?? {}) as Json;
  if (JSON.stringify(data).length > MAX_JOB_DATA_BYTES) {
    data = { truncated: true };
  }

  const { error } = await supabase.from("job_logs").insert({
    job_id,
    job_kind,
    user_id: row.user_id,
    vulnerability_id,
    seq: payload.seq as number,
    stage: (payload.stage ?? "").slice(0, 40) || null,
    level: JOB_LEVELS.has(String(payload.level)) ? String(payload.level) : "info",
    message: payload.message.slice(0, 1000),
    data,
  });
  if (error) {
    const { isMissingSchemaError } = await import("@/lib/vuln-lifecycle.server");
    if (isMissingSchemaError(error)) {
      // Before the migration: accept and drop, so the worker doesn't log a
      // failure for every progress line of every job.
      if (!warnedNoJobLogs) {
        warnedNoJobLogs = true;
        console.warn(
          "[sandbox-callback] job_logs table missing; live sandbox logs are dropped until the lifecycle migration is applied",
        );
      }
      return new Response("ignored", { status: 202 });
    }
    // A retried line (same job, same seq) is already stored.
    if ((error as { code?: string }).code === "23505") return new Response("ok", { status: 200 });
    console.error("[sandbox-callback] job_logs insert failed", error);
    return new Response("db error", { status: 500 });
  }
  return new Response("ok", { status: 200 });
}

async function applyVerifyVerdict(
  payload: CallbackPayload,
  verdict: VerifyVerdict,
): Promise<Response> {
  const { vulnerability_id, job_id } = payload;
  if (!VALID_VERIFY_STATUSES.has(verdict.status)) {
    return new Response("invalid verdict status", { status: 400 });
  }

  const evidence = (verdict.evidence || "").slice(0, 10000);
  let details: Json = (verdict.details ?? null) as Json;
  if (details && JSON.stringify(details).length > 20000) {
    details = { truncated: true, note: "Details payload exceeded size limit and was dropped." };
  }

  const supabase = getSupabaseAdmin();
  const { data: updated, error } = await supabase
    .from("vulnerabilities")
    .update({
      verification_status: verdict.status,
      verification_evidence: evidence || null,
      verification_details: details,
      verification_duration_ms: Number.isFinite(payload.duration_ms) ? payload.duration_ms : null,
      verification_completed_at: new Date().toISOString(),
    })
    // Bound to the job we actually submitted. sandbox_job_id is a fresh random
    // UUID per submission and is overwritten by the next one, so a stray or
    // replayed callback for an older job matches nothing. scan_id used to be
    // part of this too, but a finding now spans scans (vuln-lifecycle.ts): a
    // re-scan updating the row must not orphan a verification still running.
    .eq("id", vulnerability_id)
    .eq("sandbox_job_id", job_id)
    .select("id, user_id, repository_id, last_seen_scan_id");

  if (error) {
    console.error("[sandbox-callback] DB update failed", error);
    return new Response("db error", { status: 500 });
  }
  if (!updated || updated.length === 0) {
    console.warn(
      `[sandbox-callback] no matching vulnerability for id=${vulnerability_id} job=${job_id}`,
    );
    return new Response("not found", { status: 404 });
  }

  console.log(`[sandbox-callback] verify ${vulnerability_id} -> ${verdict.status}`);
  const row = updated[0] as { user_id: string; repository_id: string; last_seen_scan_id?: string };
  const { recordEvents } = await import("@/lib/vuln-lifecycle.server");
  await recordEvents(supabase, [
    {
      vulnerability_id,
      user_id: row.user_id,
      repository_id: row.repository_id,
      scan_id: row.last_seen_scan_id ?? null,
      kind: "verification",
      message:
        verdict.status === "confirmed"
          ? "Sandbox verification: confirmed"
          : verdict.status === "not_exploitable"
            ? "Sandbox verification: not confirmed"
            : "Sandbox verification failed to run",
      data: {
        status: verdict.status,
        duration_ms: Number.isFinite(payload.duration_ms) ? payload.duration_ms : null,
        evidence: evidence.slice(0, 300),
        job_id,
      },
    },
  ]);

  // A verification finishing can be the last thing a weekly run was waiting on.
  // An email failure must never fail the verdict write, hence the try/catch.
  try {
    const { data: scanRow } = await supabase
      .from("scans")
      .select("user_id, weekly_run_id")
      .eq("id", payload.scan_id ?? row.last_seen_scan_id ?? "")
      .maybeSingle();
    if (scanRow?.weekly_run_id) {
      const { maybeSendWeeklyDigest } = await import("@/lib/weekly-digest.server");
      await maybeSendWeeklyDigest(supabase, scanRow.user_id, scanRow.weekly_run_id);
    }
  } catch (err) {
    console.error("[sandbox-callback] weekly digest check failed", err);
  }

  return new Response("ok", { status: 200 });
}

async function applyFixVerdict(payload: CallbackPayload, verdict: FixVerdict): Promise<Response> {
  const { vulnerability_id, job_id } = payload;
  if (!VALID_FIX_STATUSES.has(verdict.status)) {
    return new Response("invalid verdict status", { status: 400 });
  }

  const details = (verdict.details ?? {}) as Record<string, unknown>;
  const prUrl = typeof details.pr_url === "string" ? details.pr_url : null;
  const prNumber = Number.isFinite(details.pr_number) ? (details.pr_number as number) : null;
  const branch = typeof details.branch === "string" ? details.branch : null;

  // A "pr_created" verdict with no URL is not a success — the UI would show a
  // fix that leads nowhere, so it is recorded as a failure instead.
  const status = verdict.status === "pr_created" && !prUrl ? "failed" : verdict.status;
  const evidence = (verdict.evidence || "").slice(0, 5000);

  const update: Database["public"]["Tables"]["vulnerabilities"]["Update"] = {
    fix_status: status,
    fix_pr_url: prUrl,
    fix_pr_number: prNumber,
    fix_branch: branch,
    fix_error: status === "failed" ? evidence || "The fixer reported a failure." : null,
    fix_completed_at: new Date().toISOString(),
  };
  if (typeof details.explanation === "string" && details.explanation.trim()) {
    update.suggested_fix_diff = details.explanation.slice(0, 20000);
  }

  // Fix jobs are bound by (id, fix_job_id) only — a fix can be requested for a
  // vulnerability long after its scan, so scan_id is not part of the binding.
  const supabase = getSupabaseAdmin();
  const { data: updated, error } = await supabase
    .from("vulnerabilities")
    .update(update)
    .eq("id", vulnerability_id)
    .eq("fix_job_id", job_id)
    .select("id, user_id, repository_id, last_seen_scan_id");

  if (error) {
    console.error("[sandbox-callback] fix DB update failed", error);
    return new Response("db error", { status: 500 });
  }
  if (!updated || updated.length === 0) {
    console.warn(
      `[sandbox-callback] no matching vulnerability for fix id=${vulnerability_id} job=${job_id}`,
    );
    return new Response("not found", { status: 404 });
  }

  console.log(`[sandbox-callback] fix ${vulnerability_id} -> ${status}`);
  const row = updated[0] as { user_id: string; repository_id: string; last_seen_scan_id?: string };
  const rescan = (details.rescan ?? null) as {
    attempt?: number;
    max_attempts?: number;
    attempts?: unknown[];
  } | null;
  const { recordEvents } = await import("@/lib/vuln-lifecycle.server");
  await recordEvents(supabase, [
    {
      vulnerability_id,
      user_id: row.user_id,
      repository_id: row.repository_id,
      scan_id: row.last_seen_scan_id ?? null,
      kind: status === "pr_created" ? "fix_pr_opened" : "fix_rejected",
      message:
        status === "pr_created"
          ? `Verified fix opened as pull request${prNumber ? ` #${prNumber}` : ""}` +
            (rescan?.attempt
              ? ` (passed the re-scan on attempt ${rescan.attempt} of ${rescan.max_attempts ?? "?"})`
              : "")
          : evidence.slice(0, 500) || "The fixer reported a failure.",
      data: {
        pr_url: prUrl,
        pr_number: prNumber,
        attempts: Array.isArray(rescan?.attempts) ? rescan.attempts.length : null,
        job_id,
      },
    },
  ]);
  return new Response("ok", { status: 200 });
}
