// Database side of the vulnerability lifecycle (server-only).
//
// Everything here tolerates the lifecycle migration not having been applied
// yet (20260924120000_vuln_lifecycle_and_job_logs.sql). Callers get `null` or
// a no-op instead of an exception, and fall back to the old behaviour — a scan
// must never fail because a timeline table is missing.

import type { AdminClient } from "@/lib/supabase-admin.server";
import type { Json, Tables, TablesInsert } from "@/integrations/supabase/types";
import {
  MISSES_TO_RESOLVE,
  type ExistingVuln,
  type FindingLike,
  type ReconcilePlan,
} from "@/lib/vuln-lifecycle";

type VulnRow = Tables<"vulnerabilities">;

/** Postgres/PostgREST errors meaning "that column or table doesn't exist (yet)". */
export function isMissingSchemaError(err: unknown): boolean {
  const e = err as { code?: string; message?: string } | null;
  if (!e) return false;
  if (["42703", "42P01", "PGRST204", "PGRST205"].includes(String(e.code))) return true;
  return /does not exist|could not find the .* (column|table)/i.test(String(e.message ?? ""));
}

let warnedMissingSchema = false;
function warnMissingSchemaOnce() {
  if (warnedMissingSchema) return;
  warnedMissingSchema = true;
  console.warn(
    "[lifecycle] migration 20260924120000_vuln_lifecycle_and_job_logs.sql is not applied — " +
      "findings will be stored the old way (one row per scan) until it is.",
  );
}

export type EventInsert = {
  vulnerability_id: string;
  user_id: string;
  repository_id?: string | null;
  scan_id?: string | null;
  kind: string;
  message?: string | null;
  data?: Json;
};

/** Best-effort: a timeline write must never fail the operation it describes. */
export async function recordEvents(supabaseAdmin: AdminClient, events: EventInsert[]) {
  if (events.length === 0) return;
  const { error } = await supabaseAdmin.from("vulnerability_events").insert(events);
  if (!error) return;
  if (isMissingSchemaError(error)) warnMissingSchemaOnce();
  else console.error("[lifecycle] could not record timeline events", error);
}

/**
 * The repository's current, canonical findings — or null when the lifecycle
 * columns don't exist yet, which tells the caller to use the old insert-all path.
 */
export async function loadLifecycleRows(
  supabaseAdmin: AdminClient,
  repositoryId: string,
  userId: string,
): Promise<VulnRow[] | null> {
  const { data, error } = await supabaseAdmin
    .from("vulnerabilities")
    .select("*")
    .eq("repository_id", repositoryId)
    .eq("user_id", userId)
    .is("duplicate_of", null);
  if (error) {
    if (isMissingSchemaError(error)) {
      warnMissingSchemaOnce();
      return null;
    }
    throw error;
  }
  return data ?? [];
}

export function toExistingVuln(row: VulnRow): ExistingVuln {
  return {
    id: row.id,
    title: row.title,
    severity: row.severity,
    cwe_id: row.cwe_id,
    category: row.category,
    file_path: row.file_path,
    line_start: row.line_start,
    line_end: row.line_end,
    status: row.status,
    detected_at: row.detected_at,
    missed_scans: row.missed_scans ?? 0,
    fix_status: row.fix_status,
    fix_pr_number: row.fix_pr_number,
  };
}

/**
 * Which of these rows' AI fix PRs have been merged. A merged, re-scan-verified
 * fix is strong enough evidence to resolve a finding on its first miss.
 * Best-effort: any GitHub error just means "not known to be merged".
 */
export async function findMergedFixes(
  rows: VulnRow[],
  repoFullName: string,
  userId: string,
): Promise<Set<string>> {
  const candidates = rows
    .filter(
      (r) =>
        (r.status === "open" || r.status === "in_progress") &&
        r.fix_status === "pr_created" &&
        r.fix_pr_number,
    )
    .slice(0, 20);
  const merged = new Set<string>();
  if (candidates.length === 0) return merged;

  let token: string;
  try {
    const { getUserAccessToken } = await import("@/lib/github-token.server");
    token = await getUserAccessToken(userId);
  } catch {
    return merged;
  }

  await Promise.all(
    candidates.map(async (r) => {
      try {
        const res = await fetch(
          `https://api.github.com/repos/${repoFullName}/pulls/${r.fix_pr_number}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: "application/vnd.github+json",
              "User-Agent": "PentestAI",
            },
          },
        );
        if (res.ok && (await res.json())?.merged_at) merged.add(r.id);
      } catch {
        // Unknown counts as not merged.
      }
    }),
  );
  return merged;
}

async function inBatches<T>(items: T[], size: number, fn: (item: T) => Promise<unknown>) {
  for (let i = 0; i < items.length; i += size) {
    await Promise.all(items.slice(i, i + size).map(fn));
  }
}

type ScanFindingInsert = FindingLike & {
  owasp_category: string | null;
  cvss_score: number | null;
  description: string | null;
  remediation_steps: string[];
  ai_analysis: string | null;
  detected_by_agents: string[];
};

/**
 * Writes a reconciliation plan. Returns the rows that need sandbox
 * verification: brand-new findings, plus regressions (the code changed since
 * they were last verified, so the old verdict no longer applies).
 */
export async function applyReconcilePlan(
  supabaseAdmin: AdminClient,
  scan: { id: string; user_id: string },
  repo: { id: string },
  plan: ReconcilePlan<ScanFindingInsert>,
  rowsById: Map<string, VulnRow>,
): Promise<{ inserted: VulnRow[]; regressed: VulnRow[] }> {
  const now = new Date().toISOString();
  const events: EventInsert[] = [];
  const base = { user_id: scan.user_id, repository_id: repo.id, scan_id: scan.id };
  const where = (f: FindingLike) =>
    f.file_path ? `${f.file_path}${f.line_start ? `:${f.line_start}` : ""}` : "an unspecified file";

  let inserted: VulnRow[] = [];
  if (plan.inserts.length > 0) {
    const rows: TablesInsert<"vulnerabilities">[] = plan.inserts.map((f) => ({
      scan_id: scan.id,
      last_seen_scan_id: scan.id,
      last_seen_at: now,
      repository_id: repo.id,
      user_id: scan.user_id,
      title: f.title,
      severity: f.severity as VulnRow["severity"],
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
    inserted = data ?? [];
    for (const v of inserted) {
      events.push({
        ...base,
        vulnerability_id: v.id,
        kind: "detected",
        message: `First detected at ${where(v)}`,
        data: { severity: v.severity, cwe_id: v.cwe_id, line_start: v.line_start },
      });
    }
  }

  const regressed: VulnRow[] = [];
  const dateLabel = new Date(now).toUTCString().slice(5, 16);

  const updates: { id: string; patch: Partial<VulnRow> }[] = [];
  for (const s of plan.seen) {
    const row = rowsById.get(s.id);
    if (!row) continue;
    const patch: Partial<VulnRow> = {
      last_seen_scan_id: scan.id,
      last_seen_at: now,
      missed_scans: 0,
      // Code moves between commits; the newest scan's location is the useful one.
      line_start: s.finding.line_start ?? row.line_start,
      line_end: s.finding.line_end ?? row.line_end,
    };
    if (s.regressed) {
      Object.assign(patch, {
        status: "open",
        // Dated so two regressions never carry an identical reason — the status
        // trigger uses "reason changed" to tell system changes from manual ones.
        status_reason: `Reappeared in the scan on ${dateLabel} after being marked fixed`,
        regression_count: (row.regression_count ?? 0) + 1,
        fixed_at: null,
      });
      regressed.push({ ...row, ...patch } as VulnRow);
    }
    updates.push({ id: s.id, patch });
    events.push({
      ...base,
      vulnerability_id: s.id,
      kind: "seen",
      message:
        row.status === "false_positive"
          ? "Reported again — still marked as a false positive"
          : s.regressed
            ? `Reported again at ${where(s.finding)} after being marked fixed`
            : `Still present at ${where(s.finding)}`,
      data: { line_start: s.finding.line_start, regressed: s.regressed },
    });
  }

  for (const m of plan.missed) {
    updates.push({ id: m.id, patch: { missed_scans: m.missedScans } });
    events.push({
      ...base,
      vulnerability_id: m.id,
      kind: "not_seen",
      message: `Not detected in this scan (${m.missedScans} of ${MISSES_TO_RESOLVE} consecutive misses needed to mark it fixed)`,
      data: { missed_scans: m.missedScans },
    });
  }

  for (const r of plan.resolved) {
    // The status trigger records this change on the timeline, reason included.
    updates.push({
      id: r.id,
      patch: {
        status: "fixed",
        status_reason: r.reason,
        fixed_at: now,
        missed_scans: r.missedScans,
      },
    });
  }

  for (const d of plan.duplicates) {
    updates.push({ id: d.id, patch: { duplicate_of: d.of } });
    const canonical = rowsById.get(d.of);
    events.push(
      {
        ...base,
        vulnerability_id: d.id,
        kind: "duplicate_merged",
        message: `Same issue as “${canonical?.title ?? "another finding"}” — merged into it`,
        data: { canonical_id: d.of },
      },
      {
        ...base,
        vulnerability_id: d.of,
        kind: "duplicate_merged",
        message: `Merged a duplicate report of this issue (“${rowsById.get(d.id)?.title ?? "untitled"}”)`,
        data: { duplicate_id: d.id },
      },
    );
  }

  await inBatches(updates, 8, async ({ id, patch }) => {
    const { error } = await supabaseAdmin.from("vulnerabilities").update(patch).eq("id", id);
    if (error) console.error(`[lifecycle] update of ${id} failed`, error);
  });

  await recordEvents(supabaseAdmin, events);
  return { inserted, regressed };
}

/**
 * Findings present in any of these scans. With findings carried across scans,
 * `scan_id` only means "first detected in", so a later scan's report or digest
 * would miss everything it merely re-confirmed. Present in scan X = first
 * detected in X, OR last seen in X, OR recorded as seen in X on the timeline.
 * Returns each row with the scans it was present in.
 */
export async function findingsForScans<T extends { id: string; scan_id: string | null }>(
  supabaseAdmin: AdminClient,
  scanIds: string[],
  columns: string,
): Promise<{ rows: T[]; presentIn: (row: T) => Set<string> }> {
  const ids = scanIds.join(",");
  const lifecycleColumns = `${columns}, last_seen_scan_id, duplicate_of`;

  let rows: (T & { last_seen_scan_id?: string | null; duplicate_of?: string | null })[] = [];
  const first = await supabaseAdmin
    .from("vulnerabilities")
    .select(lifecycleColumns)
    .or(`scan_id.in.(${ids}),last_seen_scan_id.in.(${ids})`);

  const scansByVuln = new Map<string, Set<string>>();
  if (first.error && isMissingSchemaError(first.error)) {
    const legacy = await supabaseAdmin
      .from("vulnerabilities")
      .select(columns)
      .in("scan_id", scanIds);
    if (legacy.error) throw legacy.error;
    rows = (legacy.data ?? []) as unknown as typeof rows;
  } else {
    if (first.error) throw first.error;
    rows = (first.data ?? []) as unknown as typeof rows;

    const { data: seenEvents, error: evErr } = await supabaseAdmin
      .from("vulnerability_events")
      .select("vulnerability_id, scan_id")
      .in("scan_id", scanIds)
      .in("kind", ["detected", "seen"]);
    if (!evErr) {
      for (const e of seenEvents ?? []) {
        if (!e.scan_id) continue;
        if (!scansByVuln.has(e.vulnerability_id)) scansByVuln.set(e.vulnerability_id, new Set());
        scansByVuln.get(e.vulnerability_id)!.add(e.scan_id);
      }
      const missing = [...scansByVuln.keys()].filter((id) => !rows.some((r) => r.id === id));
      if (missing.length > 0) {
        const extra = await supabaseAdmin
          .from("vulnerabilities")
          .select(lifecycleColumns)
          .in("id", missing);
        if (!extra.error) rows.push(...((extra.data ?? []) as unknown as typeof rows));
      }
    }
  }

  const wanted = new Set(scanIds);
  rows = rows.filter((r) => !r.duplicate_of);
  const presentIn = (row: T) => {
    const r = row as T & { last_seen_scan_id?: string | null };
    const set = new Set<string>(scansByVuln.get(r.id) ?? []);
    if (r.scan_id && wanted.has(r.scan_id)) set.add(r.scan_id);
    if (r.last_seen_scan_id && wanted.has(r.last_seen_scan_id)) set.add(r.last_seen_scan_id);
    return set;
  };
  return { rows: rows as unknown as T[], presentIn };
}
