// Persists a completed scan and chains verification jobs (server-only).
//
// This used to be the tail of `startScan`. Now that the pipeline runs in the
// sandbox, the sandbox owns analysis and the app owns the database — the
// sandbox never receives Supabase credentials, it just posts findings back
// over the signed callback and this module writes them.

import type { AdminClient } from "@/lib/supabase-admin.server";
import type { Tables, TablesInsert } from "@/integrations/supabase/types";
import { submitVerificationJob } from "@/lib/sandbox";
import { reconcileFindings } from "@/lib/vuln-lifecycle";
import {
  applyReconcilePlan,
  findMergedFixes,
  loadLifecycleRows,
  toExistingVuln,
} from "@/lib/vuln-lifecycle.server";

export type ScanFinding = {
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string | null;
  cwe_id: string | null;
  owasp_category: string | null;
  cvss_score: number | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  description: string | null;
  remediation_steps: string[];
  ai_analysis: string | null;
  detected_by_agents: string[];
};

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export async function insertScanLog(
  supabaseAdmin: AdminClient,
  scanId: string,
  userId: string,
  stage: string,
  message: string,
  level: "info" | "warn" | "error" = "info",
) {
  await supabaseAdmin.from("scan_logs").insert({
    scan_id: scanId,
    user_id: userId,
    stage,
    level,
    message,
  });
}

/** Marks a scan failed and logs why. Used by every error path. */
export async function failScan(
  supabaseAdmin: AdminClient,
  scan: { id: string; user_id: string; repository_id: string },
  message: string,
) {
  await supabaseAdmin
    .from("scans")
    .update({
      status: "failed",
      error_message: message.slice(0, 500),
      completed_at: new Date().toISOString(),
    })
    .eq("id", scan.id);
  await supabaseAdmin
    .from("repositories")
    .update({ status: "never_scanned" })
    .eq("id", scan.repository_id)
    .eq("status", "testing");
  await insertScanLog(
    supabaseAdmin,
    scan.id,
    scan.user_id,
    "error",
    `Scan failed: ${message}`,
    "error",
  );
}

/**
 * Reconciles findings against what the repository already has (see
 * vuln-lifecycle.ts), finalises the scan and repository rows, then submits
 * new and regressed high/critical findings for sandbox verification.
 */
export async function persistScanResults(
  supabaseAdmin: AdminClient,
  scan: {
    id: string;
    user_id: string;
    repository_id: string;
    started_at: string | null;
    weekly_run_id?: string | null;
  },
  repo: { id: string; full_name: string; default_branch: string },
  result: {
    commit_sha?: string;
    findings?: ScanFinding[];
    security_score?: number;
    summary?: string;
    files_reviewed?: number;
    /** Paths this scan read. Lets a missed finding count as a miss only when its file was read. */
    files_scanned?: string[];
    /** Every path at the scanned commit (omitted for huge or truncated trees). */
    tree_paths?: string[];
  },
) {
  const reported = Array.isArray(result.findings) ? result.findings : [];
  const counts: Record<(typeof SEVERITIES)[number], number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  let findings = reported;
  let toVerify: Tables<"vulnerabilities">[];
  const existingRows = await loadLifecycleRows(supabaseAdmin, repo.id, scan.user_id);
  if (existingRows) {
    const plan = reconcileFindings({
      existing: existingRows.map(toExistingVuln),
      found: reported,
      coverage: {
        scannedFiles: Array.isArray(result.files_scanned) ? result.files_scanned : null,
        treePaths: Array.isArray(result.tree_paths) ? result.tree_paths : null,
      },
      mergedFixIds: await findMergedFixes(existingRows, repo.full_name, scan.user_id),
    });
    findings = plan.scanFindings;
    const { inserted, regressed } = await applyReconcilePlan(
      supabaseAdmin,
      scan,
      repo,
      plan,
      new Map(existingRows.map((r) => [r.id, r])),
    );
    toVerify = [...inserted, ...regressed];
    console.log(
      `[scan-results] ${repo.full_name}: ${plan.inserts.length} new, ${plan.seen.length} seen again ` +
        `(${regressed.length} regressed), ${plan.missed.length} missed, ${plan.resolved.length} resolved, ` +
        `${plan.duplicates.length} duplicate(s) merged`,
    );
  } else {
    toVerify = await insertAllFindings(supabaseAdmin, scan, repo, reported);
  }
  for (const f of findings) if (f.severity in counts) counts[f.severity] += 1;

  const securityScore = Number.isFinite(result.security_score) ? result.security_score! : 50;
  const startedAt = scan.started_at ? new Date(scan.started_at).getTime() : Date.now();
  const durationSec = Math.max(1, Math.round((Date.now() - startedAt) / 1000));

  await supabaseAdmin
    .from("repositories")
    .update({
      status: findings.length === 0 ? "secure" : "vulnerable",
      security_score: securityScore,
      last_scan_at: new Date().toISOString(),
    })
    .eq("id", repo.id);

  // Verification jobs are submitted, and each qualifying vulnerability marked
  // 'pending', BEFORE the scan itself is marked 'completed' below. If the
  // order were reversed, a weekly digest check running concurrently (from
  // another repo's callback in the same run) could see this scan as
  // "terminal" while its high/critical findings still show 'unverified' —
  // not yet 'pending' — and wrongly conclude nothing is outstanding.
  await submitVerifications(supabaseAdmin, scan, repo, toVerify, result.commit_sha);

  await supabaseAdmin
    .from("scans")
    .update({
      status: "completed",
      current_stage: "done",
      progress: 100,
      commit_sha: result.commit_sha ?? null,
      completed_at: new Date().toISOString(),
      duration_seconds: durationSec,
      critical_count: counts.critical,
      high_count: counts.high,
      medium_count: counts.medium,
      low_count: counts.low,
      security_score: securityScore,
    })
    .eq("id", scan.id);

  await insertScanLog(
    supabaseAdmin,
    scan.id,
    scan.user_id,
    "done",
    `Scan complete — score ${securityScore}, ${findings.length} finding(s)`,
  );

  if (scan.weekly_run_id) {
    try {
      const { maybeSendWeeklyDigest } = await import("@/lib/weekly-digest.server");
      await maybeSendWeeklyDigest(supabaseAdmin, scan.user_id, scan.weekly_run_id);
    } catch (err) {
      console.error("[scan-results] weekly digest check failed", err);
    }
  }

  return { findings: findings.length, score: securityScore };
}

/**
 * The pre-lifecycle behaviour: every reported finding becomes a new row. Only
 * used until the lifecycle migration is applied.
 */
async function insertAllFindings(
  supabaseAdmin: AdminClient,
  scan: { id: string; user_id: string },
  repo: { id: string },
  findings: ScanFinding[],
): Promise<Tables<"vulnerabilities">[]> {
  if (findings.length === 0) return [];
  const rows: TablesInsert<"vulnerabilities">[] = findings.map((f) => ({
    scan_id: scan.id,
    repository_id: repo.id,
    user_id: scan.user_id,
    title: f.title,
    severity: f.severity,
    status: "open",
    category: f.category,
    cwe_id: f.cwe_id,
    owasp_category: f.owasp_category,
    cvss_score: f.cvss_score,
    file_path: f.file_path,
    line_start: f.line_start,
    line_end: f.line_end,
    description: f.description,
    remediation_steps: f.remediation_steps ?? [],
    ai_analysis: f.ai_analysis,
    detected_by_agents: f.detected_by_agents ?? ["ai-static-analyzer"],
  }));
  const { data, error } = await supabaseAdmin.from("vulnerabilities").insert(rows).select();
  if (error) throw error;
  return data ?? [];
}

/**
 * Only high and critical findings are worth a container. Each row is claimed
 * with its job id BEFORE submission so a fast callback can't beat the write.
 */
async function submitVerifications(
  supabaseAdmin: AdminClient,
  scan: { id: string; user_id: string },
  repo: { id: string; full_name: string },
  candidates: Tables<"vulnerabilities">[],
  commitSha: string | undefined,
) {
  const worthVerifying = candidates.filter(
    (v) => v.severity === "high" || v.severity === "critical",
  );
  if (worthVerifying.length === 0 || !commitSha) return;

  const { getUserAccessToken } = await import("@/lib/github-token.server");
  let token: string;
  try {
    token = await getUserAccessToken(scan.user_id);
  } catch (err) {
    console.error("[scan-results] cannot verify without a GitHub token", err);
    return;
  }

  const [owner, name] = repo.full_name.split("/");

  for (const vulnerability of worthVerifying) {
    const jobId = crypto.randomUUID();
    await supabaseAdmin
      .from("vulnerabilities")
      .update({ sandbox_job_id: jobId, verification_status: "pending" })
      .eq("id", vulnerability.id);

    try {
      await submitVerificationJob({
        job_id: jobId,
        scan_id: scan.id,
        vulnerability_id: vulnerability.id,
        repository_id: repo.id,
        owner,
        repo: name,
        repo_clone_url: `https://github.com/${repo.full_name}.git`,
        repo_token: token,
        commit_sha: commitSha,
        severity: vulnerability.severity,
        category: vulnerability.category ?? "",
        file_path: vulnerability.file_path ?? undefined,
      });
    } catch (err) {
      console.error(`[scan-results] failed to submit ${vulnerability.id} for verification`, err);
      await supabaseAdmin
        .from("vulnerabilities")
        .update({
          verification_status: "failed",
          verification_evidence: `Sandbox submission failed: ${String(
            (err as Error)?.message ?? err,
          ).slice(0, 500)}`,
          verification_completed_at: new Date().toISOString(),
        })
        .eq("id", vulnerability.id);
    }
  }
}
