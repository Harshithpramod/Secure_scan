// Builds the security snapshot the chat assistant reasons over (server-only).
// Every query is scoped to the calling user — the admin client bypasses RLS,
// so the .eq("user_id", ...) filters are the only thing keeping tenants apart.
// Do not import from the browser.

import type { AdminClient } from "@/lib/supabase-admin.server";

type Sev = "critical" | "high" | "medium" | "low";

export type RepoVerdict = "secure" | "at risk" | "needs attention" | "not yet assessed";

const MAX_CONTEXT_BYTES = 12_000;

function truncate(value: string | null | undefined, max: number): string | null {
  if (!value) return null;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function emptyCounts(): Record<Sev, number> {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

/**
 * A repo is only "secure" once something has actually looked at it. Findings
 * the sandbox confirmed outrank unverified ones — a confirmed critical is a
 * reproduced exploit, an unverified one is still a hypothesis.
 */
function verdictFor(
  status: string | null,
  lastScanAt: string | null,
  counts: Record<Sev, number>,
): RepoVerdict {
  if (status === "never_scanned" || !lastScanAt) return "not yet assessed";
  if (counts.critical > 0 || counts.high > 0) return "at risk";
  if (counts.medium > 0 || counts.low > 0) return "needs attention";
  return "secure";
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Name has to appear as a whole token — otherwise a repo called "api" matches
 * the word "api" in every other sentence.
 */
function mentions(haystack: string, name: string): boolean {
  if (name.length < 3) return false;
  return new RegExp(`(^|[^a-z0-9])${escapeRegExp(name)}([^a-z0-9]|$)`, "i").test(haystack);
}

function resolveRepo(repos: any[], repoHint: string | null | undefined) {
  const hint = repoHint?.trim().toLowerCase();
  if (!hint) return undefined;

  const exact =
    repos.find((r) => String(r.full_name).toLowerCase() === hint) ??
    repos.find((r) => String(r.name).toLowerCase() === hint);
  if (exact) return exact;

  // Longest name first so "acme/web-api" wins over a sibling repo named "web".
  const byLength = [...repos].sort(
    (a, b) => String(b.full_name).length - String(a.full_name).length,
  );
  return byLength.find(
    (r) =>
      mentions(hint, String(r.full_name).toLowerCase()) ||
      mentions(hint, String(r.name).toLowerCase()),
  );
}

export async function buildSecurityContext(
  supabaseAdmin: AdminClient,
  userId: string,
  opts: { repoHint?: string | null } = {},
) {
  const [{ data: repoRows }, { data: openVulnRows }, { data: scanRows }] = await Promise.all([
    supabaseAdmin
      .from("repositories")
      .select(
        "id, full_name, name, owner, status, security_score, language, last_scan_at, scan_mode, repo_type",
      )
      .eq("user_id", userId)
      .order("last_scan_at", { ascending: false, nullsFirst: false }),
    supabaseAdmin
      .from("vulnerabilities")
      .select(
        "id, repository_id, scan_id, title, severity, cvss_score, cwe_id, owasp_category, category, file_path, line_start, line_end, description, remediation_steps, verification_status, detected_at",
      )
      .eq("user_id", userId)
      .eq("status", "open")
      .order("cvss_score", { ascending: false, nullsFirst: false }),
    supabaseAdmin
      .from("scans")
      .select(
        "id, repository_id, status, profile, progress, critical_count, high_count, medium_count, low_count, security_score, completed_at, created_at, error_message, current_stage",
      )
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(20),
  ]);

  const repos = (repoRows ?? []) as any[];
  const openVulns = (openVulnRows ?? []) as any[];
  const scans = (scanRows ?? []) as any[];

  // Resolve the hint to a single repository so "is this one secure?" can be
  // answered without the model guessing which repo the user means. The hint is
  // usually the user's whole message, so match repository names *inside* it
  // rather than the other way round.
  const focused = resolveRepo(repos, opts.repoHint);

  const countsByRepo = new Map<string, Record<Sev, number>>();
  const confirmedByRepo = new Map<string, number>();
  for (const v of openVulns) {
    const counts = countsByRepo.get(v.repository_id) ?? emptyCounts();
    if (v.severity in counts) counts[v.severity as Sev] += 1;
    countsByRepo.set(v.repository_id, counts);
    if (v.verification_status === "confirmed") {
      confirmedByRepo.set(v.repository_id, (confirmedByRepo.get(v.repository_id) ?? 0) + 1);
    }
  }

  const repositories = repos.map((r) => {
    const counts = countsByRepo.get(r.id) ?? emptyCounts();
    return {
      id: r.id,
      full_name: r.full_name,
      status: r.status,
      verdict: verdictFor(r.status, r.last_scan_at, counts),
      security_score: r.security_score,
      language: r.language,
      repo_type: r.repo_type,
      scan_mode: r.scan_mode,
      last_scan_at: r.last_scan_at,
      open_counts: counts,
      sandbox_confirmed_open: confirmedByRepo.get(r.id) ?? 0,
    };
  });

  const repoNameById = new Map(repos.map((r) => [r.id, r.full_name as string]));

  const scopedVulns = focused ? openVulns.filter((v) => v.repository_id === focused.id) : openVulns;
  const scopedScans = focused ? scans.filter((s) => s.repository_id === focused.id) : scans;

  const totals = emptyCounts();
  for (const v of openVulns) if (v.severity in totals) totals[v.severity as Sev] += 1;

  const context = {
    generated_at: new Date().toISOString(),
    focused_repository: focused ? (repositories.find((r) => r.id === focused.id) ?? null) : null,
    repositories,
    totals: {
      repositories: repositories.length,
      open_findings: openVulns.length,
      open_by_severity: totals,
      never_scanned: repositories.filter((r) => r.verdict === "not yet assessed").length,
    },
    recent_scans: scopedScans.slice(0, 5).map((s) => ({
      id: s.id,
      repository: repoNameById.get(s.repository_id) ?? null,
      link: `/scans/${s.id}`,
      status: s.status,
      profile: s.profile,
      progress: s.progress,
      counts: {
        critical: s.critical_count,
        high: s.high_count,
        medium: s.medium_count,
        low: s.low_count,
      },
      security_score: s.security_score,
      current_stage: s.current_stage,
      completed_at: s.completed_at ?? s.created_at,
      error_message: truncate(s.error_message, 200),
    })),
    top_open_findings: scopedVulns.slice(0, 25).map((v) => ({
      id: v.id,
      repository: repoNameById.get(v.repository_id) ?? null,
      title: v.title,
      severity: v.severity,
      cvss_score: v.cvss_score,
      cwe_id: v.cwe_id,
      owasp_category: v.owasp_category,
      category: v.category,
      file_path: v.file_path,
      line_start: v.line_start,
      line_end: v.line_end,
      verification_status: v.verification_status,
      scan_link: v.scan_id ? `/scans/${v.scan_id}` : null,
      description: truncate(v.description, 300),
      remediation_steps: v.remediation_steps ?? null,
    })),
  };

  // Trim the long tail rather than the summary — the per-repo verdicts and
  // totals are what most questions actually need.
  let serialized = JSON.stringify(context);
  while (serialized.length > MAX_CONTEXT_BYTES && context.top_open_findings.length > 3) {
    context.top_open_findings.pop();
    serialized = JSON.stringify(context);
  }

  return { context, serialized, repositoryIds: new Set(repos.map((r) => r.id as string)) };
}
