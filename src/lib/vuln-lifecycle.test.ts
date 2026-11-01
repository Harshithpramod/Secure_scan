import { describe, expect, it } from "vitest";
import {
  MISSES_TO_RESOLVE,
  matchScore,
  reconcileFindings,
  type ExistingVuln,
  type FindingLike,
} from "./vuln-lifecycle";

const finding = (over: Partial<FindingLike> = {}): FindingLike => ({
  title: "Finding",
  severity: "high",
  cwe_id: "CWE-89",
  category: "Injection",
  file_path: "script.js",
  ...over,
  // Single-line unless a range is given. Defaulting line_end independently
  // would turn "line 90" into the range 10-90, which overlaps everything.
  line_start: over.line_start ?? 10,
  line_end: over.line_end ?? over.line_start ?? 10,
});

let n = 0;
const existing = (over: Partial<ExistingVuln> = {}): ExistingVuln => ({
  ...finding(over),
  id: over.id ?? `v${++n}`,
  status: "open",
  detected_at: "2026-09-01T00:00:00Z",
  missed_scans: 0,
  fix_status: null,
  fix_pr_number: null,
  ...over,
});

const covered = { scannedFiles: ["script.js"], treePaths: ["script.js", "index.html"] };

// The real rows in the RESUME repo's database on 2026-09-23. Three of them are
// the same plaintext-password bug, recorded by three different scans.
const real = {
  clientAuth: existing({
    id: "2b81",
    title: "Client-Side Only Authentication and Authorization",
    cwe_id: "CWE-602",
    category: "Broken Authentication / Insecure Design",
    severity: "critical",
    line_start: 1,
    line_end: 79,
    detected_at: "2026-09-07T05:30:00Z",
  }),
  pwFixed: existing({
    id: "23eb",
    title: "Cleartext Storage of Passwords in Client-Side Local Storage",
    cwe_id: "CWE-312",
    category: "Data Exposure",
    severity: "critical",
    line_start: 33,
    line_end: 34,
    status: "fixed",
    detected_at: "2026-09-07T05:30:00Z",
  }),
  pw312: existing({
    id: "b1d2",
    title: "Plaintext Passwords Stored in Client-Side Local Storage",
    cwe_id: "CWE-312",
    category: "Sensitive Data Exposure / Weak Cryptography",
    severity: "critical",
    line_start: 40,
    line_end: 40,
    detected_at: "2026-09-10T00:00:00Z",
  }),
  pw256: existing({
    id: "e6e0",
    title: "Plaintext Password Storage in Local Storage",
    cwe_id: "CWE-256",
    category: "Cryptographic Failures",
    severity: "critical",
    line_start: 40,
    line_end: 41,
    detected_at: "2026-09-14T00:00:00Z",
  }),
  xss: existing({
    id: "a8c8",
    title: "Potential Cross-Site Scripting (XSS) via Stored User Input",
    cwe_id: "CWE-79",
    category: "Injection",
    severity: "medium",
    line_start: 37,
    line_end: 40,
  }),
};

describe("matchScore", () => {
  it("matches a re-labelled finding at the same place", () => {
    expect(matchScore(real.pw312, real.pw256)).toBeGreaterThanOrEqual(3);
  });
  it("never matches across files", () => {
    expect(matchScore(finding(), finding({ file_path: "other.js" }))).toBe(0);
  });
  it("matches the same kind and description after the code moved", () => {
    expect(
      matchScore(
        finding({ title: "SQL injection in login query", line_start: 10 }),
        finding({ title: "SQL injection in the login query", line_start: 90 }),
      ),
    ).toBe(2);
  });
});

describe("reconcileFindings — the real RESUME duplicates", () => {
  it("collapses the password bug to one row and marks the other a duplicate", () => {
    const plan = reconcileFindings({
      existing: Object.values(real),
      found: [
        finding({
          title: "Plaintext password stored in localStorage",
          cwe_id: "CWE-312",
          severity: "critical",
          line_start: 41,
          line_end: 41,
        }),
      ],
      coverage: covered,
    });
    expect(plan.inserts).toHaveLength(0);
    // The oldest active copy carries forward...
    expect(plan.seen.map((s) => s.id)).toEqual(["b1d2"]);
    // ...the relabelled CWE-256 copy is folded into it...
    expect(plan.duplicates).toEqual([{ id: "e6e0", of: "b1d2" }]);
    // ...and the manually-fixed older copy is left alone, not reopened.
    expect(plan.seen.some((s) => s.id === "23eb")).toBe(false);
  });
});

describe("reconcileFindings", () => {
  it("inserts a genuinely new finding", () => {
    const plan = reconcileFindings({ existing: [], found: [finding()], coverage: covered });
    expect(plan.inserts).toHaveLength(1);
  });

  it("carries an existing finding forward instead of duplicating it", () => {
    const e = existing({ title: "SQL injection in login" });
    const plan = reconcileFindings({
      existing: [e],
      found: [finding({ title: "SQL injection in the login handler", line_start: 12 })],
      coverage: covered,
    });
    expect(plan.inserts).toHaveLength(0);
    expect(plan.seen).toEqual([expect.objectContaining({ id: e.id, regressed: false })]);
  });

  it("flags a regression when a fixed finding comes back", () => {
    const e = existing({ status: "fixed" });
    const plan = reconcileFindings({ existing: [e], found: [finding()], coverage: covered });
    expect(plan.seen).toEqual([expect.objectContaining({ id: e.id, regressed: true })]);
  });

  it("keeps a false positive triaged when the scanner reports it again", () => {
    const e = existing({ status: "false_positive" });
    const plan = reconcileFindings({ existing: [e], found: [finding()], coverage: covered });
    expect(plan.inserts).toHaveLength(0);
    expect(plan.seen).toEqual([expect.objectContaining({ id: e.id, regressed: false })]);
  });

  it("gives two same-kind findings in one file their own rows", () => {
    const a = existing({ title: "Reflected XSS in search", cwe_id: "CWE-79", line_start: 10 });
    const b = existing({ title: "Reflected XSS in filter", cwe_id: "CWE-79", line_start: 80 });
    const plan = reconcileFindings({
      existing: [a, b],
      found: [
        finding({ title: "Reflected XSS in filter", cwe_id: "CWE-79", line_start: 82 }),
        finding({ title: "Reflected XSS in search", cwe_id: "CWE-79", line_start: 11 }),
      ],
      coverage: covered,
    });
    expect(plan.seen.map((s) => s.id).sort()).toEqual([a.id, b.id].sort());
    expect(plan.duplicates).toHaveLength(0);
  });

  it("does not merge a same-kind finding 70 lines away just because this scan missed it", () => {
    const a = existing({ title: "Reflected XSS in search", cwe_id: "CWE-79", line_start: 10 });
    const b = existing({ title: "Reflected XSS in filter", cwe_id: "CWE-79", line_start: 80 });
    const plan = reconcileFindings({
      existing: [a, b],
      found: [finding({ title: "Reflected XSS in search", cwe_id: "CWE-79", line_start: 11 })],
      coverage: covered,
    });
    expect(plan.duplicates).toHaveLength(0);
    expect(plan.missed).toEqual([{ id: b.id, missedScans: 1 }]);
  });

  it("de-duplicates one issue listed twice within a scan, keeping the more severe", () => {
    const plan = reconcileFindings({
      existing: [],
      found: [
        finding({ title: "Plaintext password storage", cwe_id: "CWE-256", severity: "high" }),
        finding({ title: "Plaintext passwords stored", cwe_id: "CWE-312", severity: "critical" }),
      ],
      coverage: covered,
    });
    expect(plan.scanFindings).toHaveLength(1);
    expect(plan.scanFindings[0].severity).toBe("critical");
  });
});

describe("reconcileFindings — resolving", () => {
  it("does not resolve on the first miss: the AI scanner skips real issues sometimes", () => {
    const e = existing();
    const plan = reconcileFindings({ existing: [e], found: [], coverage: covered });
    expect(plan.missed).toEqual([{ id: e.id, missedScans: 1 }]);
    expect(plan.resolved).toHaveLength(0);
  });

  it(`resolves after ${MISSES_TO_RESOLVE} consecutive misses`, () => {
    const e = existing({ missed_scans: MISSES_TO_RESOLVE - 1 });
    const plan = reconcileFindings({ existing: [e], found: [], coverage: covered });
    expect(plan.resolved).toEqual([
      { id: e.id, missedScans: 2, reason: "Not detected in 2 consecutive scans" },
    ]);
  });

  it("resolves on the first miss once its fix PR is merged", () => {
    const e = existing({ fix_status: "pr_created", fix_pr_number: 7 });
    const plan = reconcileFindings({
      existing: [e],
      found: [],
      coverage: covered,
      mergedFixIds: new Set([e.id]),
    });
    expect(plan.resolved[0].reason).toBe(
      "Fixed by pull request #7 — not detected after it was merged",
    );
  });

  it("resolves at once when its file was deleted", () => {
    const e = existing({ file_path: "old/auth.js" });
    const plan = reconcileFindings({ existing: [e], found: [], coverage: covered });
    expect(plan.resolved[0].reason).toBe("File no longer exists in the repository");
  });

  it("leaves a finding alone when this scan never read its file", () => {
    const e = existing({ file_path: "index.html" }); // in the tree, not scanned
    const plan = reconcileFindings({ existing: [e], found: [], coverage: covered });
    expect(plan.missed).toHaveLength(0);
    expect(plan.resolved).toHaveLength(0);
  });

  it("changes nothing about misses when the sandbox didn't report coverage", () => {
    const plan = reconcileFindings({
      existing: [existing()],
      found: [],
      coverage: { scannedFiles: null, treePaths: null },
    });
    expect(plan.missed).toHaveLength(0);
    expect(plan.resolved).toHaveLength(0);
  });

  it("never resolves a finding that was marked false positive or already fixed", () => {
    const plan = reconcileFindings({
      existing: [existing({ status: "false_positive" }), existing({ status: "fixed" })],
      found: [],
      coverage: covered,
    });
    expect(plan.missed).toHaveLength(0);
    expect(plan.resolved).toHaveLength(0);
  });
});
