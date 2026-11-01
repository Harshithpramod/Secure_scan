// Cross-scan identity for vulnerabilities (pure; no I/O).
//
// Every scan used to insert all of its findings as new rows, so one real bug
// became one row per scan and nothing ever closed. This decides, for a
// completed scan, which reported findings are the SAME issue as a row we
// already have, which are new, which existing rows the scan did not report,
// and which existing rows were duplicates of each other all along.
//
// The hard part is that the scanner is an LLM: across runs it re-words titles,
// relabels the same bug with a different CWE (seen live: CWE-312 in one scan,
// CWE-256 in the next), and reports slightly different line ranges — and
// between commits the lines move anyway. So identity is fuzzy by necessity:
// same file, plus the same place and/or the same kind and description. The
// same primitives drive the fix re-scan gate (sandbox/worker/fix-gate.js).

export type LifecycleStatus = "open" | "in_progress" | "fixed" | "false_positive";

export type FindingLike = {
  title: string;
  severity: string;
  cwe_id: string | null;
  category: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
};

export type ExistingVuln = FindingLike & {
  id: string;
  status: LifecycleStatus;
  detected_at: string;
  missed_scans: number;
  fix_status: string | null;
  fix_pr_number: number | null;
};

export type ScanCoverage = {
  /** Files this scan actually read. Null when the sandbox didn't report it (older builds). */
  scannedFiles: string[] | null;
  /** Every file in the repository at the scanned commit, when known. */
  treePaths: string[] | null;
};

export type ReconcilePlan<F extends FindingLike> = {
  /** Reported findings that match nothing we have: new rows. */
  inserts: F[];
  /** Existing rows this scan reported again. `regressed` = it had been marked fixed. */
  seen: { id: string; finding: F; regressed: boolean }[];
  /** Active rows whose file was scanned but which weren't reported; not resolved yet. */
  missed: { id: string; missedScans: number }[];
  /** Active rows now considered fixed, with the reason shown in the timeline. */
  resolved: { id: string; missedScans: number; reason: string }[];
  /** Existing rows that are the same issue as another existing row. */
  duplicates: { id: string; of: string }[];
  /** The scan's own findings, de-duplicated — what its severity counts should use. */
  scanFindings: F[];
};

/**
 * An AI scan that misses a finding once has not proven it fixed: the same
 * scanner skips real issues on some runs. Two consecutive misses (each one a
 * scan that did read the file) is the bar, unless there's stronger evidence.
 */
export const MISSES_TO_RESOLVE = 2;

const LINE_WINDOW = 5;
const ACTIVE = new Set<LifecycleStatus>(["open", "in_progress"]);
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const STOPWORDS = new Set([
  "the",
  "and",
  "for",
  "via",
  "with",
  "from",
  "into",
  "not",
  "use",
  "used",
  "using",
  "potential",
  "possible",
  "insecure",
  "vulnerability",
  "issue",
]);

export function normalizePath(p: string | null | undefined): string {
  return String(p ?? "")
    .replace(/\\/g, "/")
    .replace(/^(\.\/|\/)+/, "")
    .toLowerCase();
}

function cweKey(cwe: string | null | undefined): string | null {
  const m = /(\d+)/.exec(String(cwe ?? ""));
  return m ? `cwe:${Number(m[1])}` : null;
}

function categoryKey(category: string | null | undefined): string | null {
  const c = String(category ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
  return c ? `cat:${c}` : null;
}

function titleTokens(title: string | null | undefined): Set<string> {
  return new Set(
    String(title ?? "")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length >= 3 && !STOPWORDS.has(t))
      .map((t) => t.replace(/(ing|age|ed|es|s)$/, ""))
      .filter((t) => t.length >= 3),
  );
}

export function titlesSimilar(a: string, b: string): boolean {
  const ta = titleTokens(a);
  const tb = titleTokens(b);
  if (ta.size === 0 || tb.size === 0) return false;
  let shared = 0;
  for (const t of ta) if (tb.has(t)) shared++;
  return shared >= 2 || shared / Math.min(ta.size, tb.size) >= 0.6;
}

function findingKey(f: FindingLike): string {
  return (
    cweKey(f.cwe_id) ?? categoryKey(f.category) ?? `title:${[...titleTokens(f.title)].join(" ")}`
  );
}

function span(start: number, end: number | null): [number, number] {
  const e = Number.isInteger(end) ? (end as number) : start;
  return [Math.min(start, e), Math.max(start, e)];
}

function near(a: FindingLike, b: FindingLike): boolean {
  if (!Number.isInteger(a.line_start) || !Number.isInteger(b.line_start)) return false;
  const [as, ae] = span(a.line_start as number, a.line_end);
  const [bs, be] = span(b.line_start as number, b.line_end);
  return as <= be + LINE_WINDOW && ae >= bs - LINE_WINDOW;
}

/**
 * How strongly two findings look like the same issue. 0 = different.
 *   4  same place, same kind, same description
 *   3  same place and (same kind OR same description) — a re-worded title, or
 *      the same bug relabelled with another CWE
 *   2  same kind and description somewhere else in the file — the code moved
 * Never across files: a patch to one file can't move a bug into another.
 */
export function matchScore(a: FindingLike, b: FindingLike): number {
  if (normalizePath(a.file_path) !== normalizePath(b.file_path)) return 0;
  const keyEq = findingKey(a) === findingKey(b);
  const similar = titlesSimilar(a.title, b.title);
  const isNear = near(a, b);
  if (isNear && keyEq && similar) return 4;
  if (isNear && (keyEq || similar)) return 3;
  if (keyEq && similar) return 2;
  return 0;
}

/** Same place: the bar for calling two findings the same without other context. */
const SAME_PLACE = 3;

/** Within one scan, the model sometimes lists one issue twice. Keep the more severe. */
function dedupeWithinScan<F extends FindingLike>(found: F[]): F[] {
  const sorted = [...found].sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0),
  );
  const kept: F[] = [];
  for (const f of sorted) {
    if (!kept.some((k) => matchScore(k, f) >= SAME_PLACE)) kept.push(f);
  }
  return kept;
}

export function reconcileFindings<F extends FindingLike>({
  existing,
  found,
  coverage,
  mergedFixIds = new Set<string>(),
}: {
  existing: ExistingVuln[];
  found: F[];
  coverage: ScanCoverage;
  /** Rows whose AI fix PR has been merged — resolved on the first miss. */
  mergedFixIds?: Set<string>;
}): ReconcilePlan<F> {
  const scanFindings = dedupeWithinScan(found);

  // Best-first assignment. Scoring every pair and taking the strongest first
  // means two genuinely separate issues of one kind in one file each keep
  // their own row, instead of the first finding grabbing whichever matched.
  const statusRank = (s: LifecycleStatus) => (ACTIVE.has(s) ? 2 : 1);
  const pairs: { fi: number; ei: number; score: number }[] = [];
  scanFindings.forEach((f, fi) =>
    existing.forEach((e, ei) => {
      const score = matchScore(f, e);
      if (score > 0) pairs.push({ fi, ei, score });
    }),
  );
  pairs.sort(
    (a, b) =>
      b.score - a.score ||
      statusRank(existing[b.ei].status) - statusRank(existing[a.ei].status) ||
      existing[a.ei].detected_at.localeCompare(existing[b.ei].detected_at),
  );

  const claimedBy = new Map<number, number>(); // existing index -> found index
  const foundClaimed = new Map<number, number>(); // found index -> existing index
  for (const { fi, ei } of pairs) {
    if (claimedBy.has(ei) || foundClaimed.has(fi)) continue;
    claimedBy.set(ei, fi);
    foundClaimed.set(fi, ei);
  }

  // An unclaimed ACTIVE row that sits in the same place as a claimed row, and
  // also matches the finding that claimed it, is the same issue recorded
  // twice. "Same place" is required on purpose: two XSS sinks 70 lines apart
  // with similar titles are two bugs, even if this scan only reported one.
  const duplicates: { id: string; of: string }[] = [];
  const isDuplicate = new Set<number>();
  for (const [fi, ci] of foundClaimed) {
    const canonical = existing[ci];
    existing.forEach((e, ei) => {
      if (ei === ci || claimedBy.has(ei) || isDuplicate.has(ei) || !ACTIVE.has(e.status)) return;
      if (matchScore(canonical, e) >= SAME_PLACE && matchScore(scanFindings[fi], e) >= 2) {
        isDuplicate.add(ei);
        duplicates.push({ id: e.id, of: canonical.id });
      }
    });
  }

  const inserts: F[] = [];
  const seen: ReconcilePlan<F>["seen"] = [];
  scanFindings.forEach((f, fi) => {
    const ei = foundClaimed.get(fi);
    if (ei === undefined) inserts.push(f);
    else seen.push({ id: existing[ei].id, finding: f, regressed: existing[ei].status === "fixed" });
  });

  const missed: ReconcilePlan<F>["missed"] = [];
  const resolved: ReconcilePlan<F>["resolved"] = [];
  if (coverage.scannedFiles) {
    const scanned = new Set(coverage.scannedFiles.map(normalizePath));
    const tree = coverage.treePaths ? new Set(coverage.treePaths.map(normalizePath)) : null;
    existing.forEach((e, ei) => {
      if (claimedBy.has(ei) || isDuplicate.has(ei) || !ACTIVE.has(e.status)) return;
      const path = normalizePath(e.file_path);
      if (!path) return;
      const removed = tree !== null && !tree.has(path);
      // Only a scan that actually read the file can say anything about it —
      // the scanner samples ~18 files, and absence from an unread file means
      // nothing.
      if (!removed && !scanned.has(path)) return;

      const missedScans = e.missed_scans + 1;
      if (removed) {
        resolved.push({ id: e.id, missedScans, reason: "File no longer exists in the repository" });
      } else if (mergedFixIds.has(e.id)) {
        resolved.push({
          id: e.id,
          missedScans,
          reason: `Fixed by pull request${e.fix_pr_number ? ` #${e.fix_pr_number}` : ""} — not detected after it was merged`,
        });
      } else if (missedScans >= MISSES_TO_RESOLVE) {
        resolved.push({
          id: e.id,
          missedScans,
          reason: `Not detected in ${missedScans} consecutive scans`,
        });
      } else {
        missed.push({ id: e.id, missedScans });
      }
    });
  }

  return { inserts, seen, missed, resolved, duplicates, scanFindings };
}
