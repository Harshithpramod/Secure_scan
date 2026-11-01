import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { z } from "zod";
import { submitFixJob } from "@/lib/sandbox";

/**
 * Classic PATs (`ghp_`/`gho_`) report their scopes in the `x-oauth-scopes`
 * response header, so a missing `repo` scope can be caught up front with a
 * message the user can act on. Fine-grained PATs and GitHub App/OAuth tokens
 * send that header empty or not at all — there is nothing to check, so those
 * proceed and surface GitHub's real 403 later if write access is genuinely
 * absent. Best-effort by design: never block a token we simply can't inspect.
 */
async function assertWriteScope(token: string): Promise<void> {
  const res = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "PentestAI",
    },
  });
  if (!res.ok) {
    throw new Error("Your GitHub connection is no longer valid — reconnect GitHub in Settings.");
  }

  const scopeHeader = res.headers.get("x-oauth-scopes");
  if (!scopeHeader) return; // Not a classic PAT; nothing to verify.

  const scopes = scopeHeader
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (scopes.length === 0) return;

  if (!scopes.includes("repo") && !scopes.includes("public_repo")) {
    throw new Error(
      "Opening a pull request needs the 'repo' scope, but your GitHub token only has: " +
        `${scopes.join(", ")}. Reconnect GitHub in Settings with a token that includes 'repo'.`,
    );
  }
}

export const requestVulnerabilityFix = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ vulnerabilityId: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    const { getSupabaseAdmin } = await import("@/lib/supabase-admin.server");
    const { getUserAccessToken } = await import("@/lib/github-token.server");
    const supabaseAdmin = getSupabaseAdmin();

    // Scoped to the caller. The admin client bypasses RLS, so this .eq is the
    // only thing keeping one user from requesting a fix on another's finding.
    const { data: vuln, error: vulnErr } = await supabaseAdmin
      .from("vulnerabilities")
      .select("*, repositories(id, owner, name, full_name, default_branch, language)")
      .eq("id", data.vulnerabilityId)
      .eq("user_id", context.userId)
      .maybeSingle();
    if (vulnErr) throw vulnErr;
    if (!vuln) throw new Error("Vulnerability not found");

    // Fast path only — the authoritative check is the conditional claim below.
    // Two clicks landing together would both pass this one.
    if (vuln.fix_status === "pending") {
      throw new Error("A fix is already being generated for this finding.");
    }
    if (!vuln.file_path) {
      throw new Error(
        "This finding isn't tied to a specific file, so there's nothing to patch automatically.",
      );
    }

    const repo = vuln.repositories;
    if (!repo?.full_name) throw new Error("The repository for this finding is no longer connected");

    const token = await getUserAccessToken(context.userId);
    await assertWriteScope(token);

    // Claiming the row and checking nobody else has it are the SAME statement:
    // `UPDATE … WHERE fix_status <> 'pending'` is atomic in Postgres, so of two
    // requests racing on the same finding exactly one updates a row and the
    // other matches none. Checking first and then writing — which is what this
    // did — leaves a window where both pass the check, both submit, and the
    // user gets two pull requests for one vulnerability.
    //
    // Written before submission so a fast callback can't outrun the row.
    const jobId = crypto.randomUUID();
    const { data: claimed, error: claimErr } = await supabaseAdmin
      .from("vulnerabilities")
      .update({
        fix_status: "pending",
        fix_job_id: jobId,
        fix_requested_at: new Date().toISOString(),
        fix_error: null,
        fix_pr_url: null,
        fix_pr_number: null,
        fix_branch: null,
        fix_completed_at: null,
      })
      .eq("id", vuln.id)
      .eq("user_id", context.userId)
      .neq("fix_status", "pending")
      .select("id");
    if (claimErr) throw claimErr;
    if (!claimed || claimed.length === 0) {
      throw new Error("A fix is already being generated for this finding.");
    }

    const { recordEvents } = await import("@/lib/vuln-lifecycle.server");
    await recordEvents(supabaseAdmin, [
      {
        vulnerability_id: vuln.id,
        user_id: context.userId,
        repository_id: repo.id,
        scan_id: vuln.last_seen_scan_id ?? vuln.scan_id ?? null,
        kind: "fix_requested",
        message: "AI fix requested",
        data: { job_id: jobId },
      },
    ]);

    try {
      await submitFixJob({
        job_id: jobId,
        scan_id: vuln.scan_id ?? null,
        vulnerability_id: vuln.id,
        repository_id: repo.id,
        owner: repo.owner,
        repo: repo.name,
        repo_clone_url: `https://github.com/${repo.full_name}.git`,
        repo_token: token,
        default_branch: repo.default_branch ?? "main",
        // The fixer re-scans its patch with the scan prompt, which includes
        // the language — passing it keeps that re-scan identical to the scan.
        language: repo.language ?? null,
        title: vuln.title,
        description: vuln.description ?? null,
        severity: vuln.severity,
        category: vuln.category ?? null,
        cwe_id: vuln.cwe_id ?? null,
        owasp_category: vuln.owasp_category ?? null,
        file_path: vuln.file_path,
        line_start: vuln.line_start ?? null,
        line_end: vuln.line_end ?? null,
      });
    } catch (err) {
      // Nothing is coming to update this row — don't strand it in 'pending'.
      const message = String((err as Error)?.message ?? err).slice(0, 500);
      await supabaseAdmin
        .from("vulnerabilities")
        .update({
          fix_status: "failed",
          fix_error: `Could not reach the sandbox: ${message}`,
          fix_completed_at: new Date().toISOString(),
        })
        .eq("id", vuln.id);
      throw new Error(`Could not start the fix: ${message}`);
    }

    return { jobId, status: "pending" as const };
  });
