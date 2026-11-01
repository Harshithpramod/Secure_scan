import { describe, expect, it, vi } from "vitest";
import {
  buildLineMap,
  cweKey,
  evaluatePatch,
  generateVerifiedFix,
  mergeFindings,
  normalizePath,
  unifiedDiff,
  titlesSimilar,
} from "./fix-gate.js";

const f = (over) => ({
  title: "Finding",
  severity: "high",
  category: "Injection",
  cwe_id: "CWE-89",
  description: "desc",
  ...over,
  // A single-line finding unless a range is given — never an inverted one.
  line_start: over.line_start ?? 10,
  line_end: over.line_end ?? over.line_start ?? 10,
});

// Modelled on the real RESUME repo: two unrelated findings in script.js.
const passwordTarget = {
  title: "Cleartext Storage of Passwords in Client-Side Storage",
  cwe_id: "CWE-312",
  category: "Sensitive Data Exposure",
  line_start: 33,
  line_end: 33,
};
const passwordFinding = f({
  title: "Cleartext Storage of Passwords in Client-Side Storage",
  cwe_id: "CWE-312",
  category: "Sensitive Data Exposure",
  line_start: 33,
  line_end: 33,
  severity: "critical",
});
const clientAuthFinding = f({
  title: "Client-Side Only Authentication and Authorization",
  cwe_id: "CWE-602",
  category: "Broken Authentication",
  line_start: 1,
  line_end: 20,
  severity: "critical",
});

describe("helpers", () => {
  it("normalizes CWE ids however the model writes them", () => {
    expect(cweKey("CWE-079")).toBe("cwe:79");
    expect(cweKey("cwe 79")).toBe("cwe:79");
    expect(cweKey("CWE-79: Cross-site Scripting")).toBe("cwe:79");
    expect(cweKey("")).toBeNull();
    expect(cweKey(null)).toBeNull();
  });

  it("normalizes paths the model may prefix", () => {
    expect(normalizePath("./src/App.js")).toBe("src/app.js");
    expect(normalizePath("/src\\App.js")).toBe("src/app.js");
  });

  it("treats differently-worded titles for the same issue as similar", () => {
    expect(
      titlesSimilar(
        "Cleartext Storage of Passwords in Client-Side Storage",
        "Plaintext password stored in localStorage",
      ),
    ).toBe(true);
    expect(titlesSimilar("SQL injection in login query", "Reflected XSS in search page")).toBe(
      false,
    );
  });
});

describe("evaluatePatch", () => {
  it("passes when the target is gone", () => {
    const v = evaluatePatch({ target: passwordTarget, baseline: [passwordFinding], after: [] });
    expect(v.ok).toBe(true);
    expect(v.baselineReproduced).toBe(true);
  });

  it("rejects when the target is still reported", () => {
    const v = evaluatePatch({
      target: passwordTarget,
      baseline: [passwordFinding],
      after: [{ ...passwordFinding, line_start: 35, line_end: 35 }],
    });
    expect(v.ok).toBe(false);
    expect(v.stillPresent).toHaveLength(1);
  });

  it("ignores an unrelated pre-existing finding in the same file", () => {
    // The real case: fixing the password bug must not be blocked by the
    // client-side-auth finding that the patch was never asked to touch.
    const v = evaluatePatch({
      target: passwordTarget,
      baseline: [clientAuthFinding, passwordFinding],
      after: [clientAuthFinding],
    });
    expect(v.ok).toBe(true);
    expect(v.introduced).toHaveLength(0);
  });

  it("still catches the target when the re-scan labels it with a different CWE", () => {
    // Recorded as CWE-312, but this scan run calls it CWE-256 at the same spot.
    const relabeled = f({
      title: "Plaintext password stored in localStorage",
      cwe_id: "CWE-256",
      category: "Credential Management",
      line_start: 33,
      line_end: 34,
    });
    const v = evaluatePatch({
      target: passwordTarget,
      baseline: [relabeled],
      after: [{ ...relabeled, line_start: 36, line_end: 37 }],
    });
    expect(v.ok).toBe(false);
    expect(v.stillPresent).toHaveLength(1);
  });

  it("treats a surviving sibling of the same kind as fixed, not still present", () => {
    const target = { title: "Reflected XSS in search", cwe_id: "CWE-79", line_start: 10 };
    const xssA = f({ title: "Reflected XSS in search", cwe_id: "CWE-79", line_start: 10 });
    const xssB = f({ title: "Stored XSS in comments", cwe_id: "CWE-79", line_start: 80 });
    const v = evaluatePatch({
      target,
      baseline: [xssA, xssB],
      after: [{ ...xssB, line_start: 78, line_end: 78 }],
    });
    expect(v.ok).toBe(true);
  });

  it("rejects when both findings of the target's kind survive", () => {
    const target = { title: "Reflected XSS in search", cwe_id: "CWE-79", line_start: 10 };
    const xssA = f({ title: "Reflected XSS in search", cwe_id: "CWE-79", line_start: 10 });
    const xssB = f({ title: "Stored XSS in comments", cwe_id: "CWE-79", line_start: 80 });
    const v = evaluatePatch({ target, baseline: [xssA, xssB], after: [xssA, xssB] });
    expect(v.ok).toBe(false);
  });

  it("rejects a patch that introduces a new medium-or-higher vulnerability", () => {
    const v = evaluatePatch({
      target: passwordTarget,
      baseline: [passwordFinding],
      after: [
        f({
          title: "SQL injection in new query",
          cwe_id: "CWE-89",
          severity: "high",
          line_start: 40,
        }),
      ],
    });
    expect(v.ok).toBe(false);
    expect(v.introduced).toHaveLength(1);
  });

  it("catches a relabel that moves away from the recorded line as an introduced finding", () => {
    // Can't be matched to the target by location after the patch, but its kind
    // is new to the file, so it still blocks.
    const v = evaluatePatch({
      target: passwordTarget,
      baseline: [passwordFinding],
      after: [
        f({
          title: "Insufficiently protected credentials",
          cwe_id: "CWE-522",
          severity: "high",
          line_start: 50,
        }),
      ],
    });
    expect(v.ok).toBe(false);
  });

  it("allows a new low-severity finding but reports it", () => {
    const v = evaluatePatch({
      target: passwordTarget,
      baseline: [passwordFinding],
      after: [
        f({ title: "Verbose error message", cwe_id: "CWE-209", severity: "low", line_start: 5 }),
      ],
    });
    expect(v.ok).toBe(true);
    expect(v.minor).toHaveLength(1);
  });

  it("passes but flags weak evidence when the baseline never reproduced the finding", () => {
    const v = evaluatePatch({ target: passwordTarget, baseline: [], after: [] });
    expect(v.ok).toBe(true);
    expect(v.baselineReproduced).toBe(false);
  });

  it("rejects when the baseline missed the finding but the patched file shows it", () => {
    const v = evaluatePatch({ target: passwordTarget, baseline: [], after: [passwordFinding] });
    expect(v.ok).toBe(false);
  });
});

describe("buildLineMap", () => {
  const lines = (n, prefix = "line") => Array.from({ length: n }, (_, i) => `${prefix} ${i + 1}`);

  it("is identity for an unchanged file", () => {
    const t = lines(20).join("\n");
    expect(buildLineMap(t, t)(12)).toBe(12);
  });

  it("follows lines pushed down by an insertion", () => {
    const before = lines(100);
    const after = [...before.slice(0, 39), ...lines(12, "new"), ...before.slice(39)];
    const map = buildLineMap(before.join("\n"), after.join("\n"));
    expect(map(10)).toBe(10);
    expect(map(70)).toBe(82);
  });

  it("follows lines pulled up by a deletion", () => {
    const before = lines(100);
    const after = [...before.slice(0, 29), ...before.slice(39)];
    expect(buildLineMap(before.join("\n"), after.join("\n"))(70)).toBe(60);
  });
});

describe("evaluatePatch — real regressions", () => {
  // Verbatim from the live replay of Harshithpramod/RESUME PR #1 (merged
  // 2026-08-30): removing the stored password also removed the password check.
  // The earlier count-per-CWE version PASSED this because the file already had
  // an unrelated CWE-287 finding.
  it("rejects PR #1: a new CWE-287 bug hiding behind an unrelated existing CWE-287", () => {
    const v = evaluatePatch({
      target: {
        title: "Plaintext Passwords Stored in Browser Local Storage",
        cwe_id: "CWE-312",
        category: "Data Exposure",
        line_start: 40,
        line_end: 40,
      },
      baseline: [
        f({
          title: "Plaintext Passwords Stored in Client-Side Local Storage",
          cwe_id: "CWE-312",
          severity: "critical",
          line_start: 34,
          line_end: 34,
        }),
        f({
          title: "Insecure Client-Side Authentication and Authorization",
          cwe_id: "CWE-287",
          severity: "critical",
          line_start: 48,
          line_end: 48,
        }),
      ],
      after: [
        f({
          title: "Broken Authentication: Password Not Stored or Verified",
          cwe_id: "CWE-287",
          severity: "critical",
          line_start: 40,
          line_end: 40,
        }),
      ],
    });
    expect(v.ok).toBe(false);
    expect(v.stillPresent).toHaveLength(0);
    expect(v.introduced.map((x) => x.title)).toEqual([
      "Broken Authentication: Password Not Stored or Verified",
    ]);
  });

  it("recognises a pre-existing finding the patch moved, even when reworded", () => {
    const before = Array.from({ length: 100 }, (_, i) => `line ${i + 1}`);
    const after = [
      ...before.slice(0, 39),
      ...Array.from({ length: 12 }, (_, i) => `new ${i}`),
      ...before.slice(39),
    ];
    const existing = f({
      title: "Client-Side Authentication Bypass",
      cwe_id: "CWE-602",
      line_start: 70,
      line_end: 70,
    });
    const moved = f({
      title: "Access control enforced only in browser",
      cwe_id: "CWE-602",
      line_start: 82,
      line_end: 82,
    });
    const args = { target: passwordTarget, baseline: [passwordFinding, existing], after: [moved] };

    expect(
      evaluatePatch({ ...args, mapLine: buildLineMap(before.join("\n"), after.join("\n")) }).ok,
    ).toBe(true);
    // Without the diff mapping the 12-line shift makes it look new.
    expect(evaluatePatch(args).ok).toBe(false);
  });

  it("recognises a pre-existing finding relabelled with a different CWE in the same place", () => {
    const v = evaluatePatch({
      target: passwordTarget,
      baseline: [
        passwordFinding,
        f({ title: "Client-Side Authentication Bypass", cwe_id: "CWE-602", line_start: 70 }),
      ],
      after: [
        f({
          title: "Client-side authentication bypass via localStorage",
          cwe_id: "CWE-287",
          line_start: 70,
        }),
      ],
    });
    expect(v.ok).toBe(true);
  });
});

describe("evaluatePatch — model quirks", () => {
  it("pairs findings even when the model returns an inverted line range", () => {
    const existing = {
      ...f({ title: "Client-Side Authentication Bypass", cwe_id: "CWE-602" }),
      line_start: 72,
      line_end: 70,
    };
    const v = evaluatePatch({
      target: passwordTarget,
      baseline: [passwordFinding, existing],
      after: [
        f({
          title: "Authentication enforced only in the browser",
          cwe_id: "CWE-602",
          line_start: 71,
        }),
      ],
    });
    expect(v.ok).toBe(true);
  });
});

describe("generateVerifiedFix", () => {
  const ORIGINAL = "localStorage.setItem('pw', password);\n";
  const GOOD = "// password is no longer stored\n";
  const BAD = "localStorage.setItem('pw', btoa(password));\n";

  // Scanner stub: anything still calling localStorage.setItem with the password is flagged.
  const analyze = vi.fn(async (content) =>
    content.includes("setItem('pw'") ? [passwordFinding] : [],
  );

  it("returns the first patch that passes", async () => {
    const propose = vi.fn(async () => ({ explanation: "removed", fixedContent: GOOD }));
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze,
      maxAttempts: 3,
    });
    expect(r.ok).toBe(true);
    expect(r.attempt).toBe(1);
    expect(r.fixedContent).toBe(GOOD);
    expect(propose).toHaveBeenCalledTimes(1);
  });

  it("feeds the re-scan result back and succeeds on a later attempt", async () => {
    const propose = vi
      .fn()
      .mockResolvedValueOnce({ explanation: "encoded it", fixedContent: BAD })
      .mockResolvedValueOnce({ explanation: "removed", fixedContent: GOOD });
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze,
      maxAttempts: 3,
    });
    expect(r.ok).toBe(true);
    expect(r.attempt).toBe(2);
    const second = propose.mock.calls[1][0];
    expect(second.feedback).toContain("STILL DETECTED");
    expect(second.feedback).toContain("Cleartext Storage of Passwords");
    expect(second.previous).toBe(BAD);
  });

  it("gives up after the attempt limit and never returns a failing patch", async () => {
    const propose = vi.fn(async () => ({ explanation: "encoded it", fixedContent: BAD }));
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze,
      maxAttempts: 3,
    });
    expect(r.ok).toBe(false);
    expect(r.fixedContent).toBeUndefined();
    expect(propose).toHaveBeenCalledTimes(3);
    expect(r.message).toContain("No pull request was opened");
    expect(r.message).toContain("still detected");
  });

  it("stops immediately when the model leaves the file unchanged", async () => {
    const propose = vi.fn(async () => ({ explanation: "false positive", fixedContent: ORIGINAL }));
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze,
      maxAttempts: 3,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("unchanged");
    expect(propose).toHaveBeenCalledTimes(1);
  });

  it("does not propose anything when the baseline scan fails", async () => {
    const propose = vi.fn();
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze: async () => {
        throw new Error("Gemini 503");
      },
      maxAttempts: 3,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("scan_failed");
    expect(propose).not.toHaveBeenCalled();
  });

  it("never passes a patch it could not re-scan", async () => {
    // Baseline works, every re-scan of a patch errors: an unverified patch must
    // not come back as a success.
    let calls = 0;
    const flaky = async () => {
      calls++;
      if (calls === 1) return [passwordFinding];
      throw new Error("Gemini 503");
    };
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose: async () => ({ explanation: "removed", fixedContent: GOOD }),
      analyze: flaky,
      maxAttempts: 2,
    });
    expect(r.ok).toBe(false);
    expect(r.fixedContent).toBeUndefined();
    expect(r.message).toContain("Gemini 503");
  });

  it("recovers from a transient model error", async () => {
    const propose = vi
      .fn()
      .mockRejectedValueOnce(new Error("OpenRouter 502"))
      .mockResolvedValueOnce({ explanation: "removed", fixedContent: GOOD });
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze,
      maxAttempts: 3,
    });
    expect(r.ok).toBe(true);
    expect(r.attempt).toBe(2);
  });
});

describe("mergeFindings", () => {
  it("keeps one copy of an issue both runs reported", () => {
    const m = mergeFindings([
      [passwordFinding],
      [{ ...passwordFinding, line_start: 34, line_end: 34 }],
    ]);
    expect(m).toHaveLength(1);
  });

  it("keeps an issue only one run reported", () => {
    expect(mergeFindings([[passwordFinding], [passwordFinding, clientAuthFinding]])).toHaveLength(
      2,
    );
  });

  it("treats a same-place, same-description relabel as the same issue", () => {
    const relabel = {
      ...passwordFinding,
      cwe_id: "CWE-256",
      title: "Plaintext password stored in localStorage",
    };
    expect(mergeFindings([[passwordFinding], [relabel]])).toHaveLength(1);
  });
});

describe("generateVerifiedFix — baseline", () => {
  const ORIGINAL = "localStorage.setItem('pw', password);\n";
  const GOOD = "// password is no longer stored\n";

  // Live-observed flakiness: the scanner mentions the pre-existing client-side
  // auth issue on some runs and not others.
  function flakyScanner() {
    let call = 0;
    return async (content) => {
      call++;
      if (content === ORIGINAL)
        return call === 1 ? [passwordFinding] : [passwordFinding, clientAuthFinding];
      return [clientAuthFinding]; // the patch fixed the password; auth issue is old
    };
  }
  const propose = async () => ({ explanation: "removed", fixedContent: GOOD });

  it("does not blame the patch for an old issue one baseline run missed", async () => {
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze: flakyScanner(),
      maxAttempts: 1,
    });
    expect(r.ok).toBe(true);
  });

  it("would have wrongly rejected it with a single baseline run", async () => {
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze: flakyScanner(),
      maxAttempts: 1,
      baselineRuns: 1,
    });
    expect(r.ok).toBe(false);
  });

  it("carries on when only the second baseline run fails", async () => {
    let call = 0;
    const analyze = async (content) => {
      call++;
      if (call === 2) throw new Error("Gemini 503");
      return content === ORIGINAL ? [passwordFinding] : [];
    };
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze,
      maxAttempts: 1,
    });
    expect(r.ok).toBe(true);
  });

  it("says 'not in the unpatched scan', not 'introduced', when it rejects", async () => {
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze: async (c) =>
        c === ORIGINAL
          ? [passwordFinding]
          : [f({ title: "SQL injection in report query", severity: "high", line_start: 70 })],
      maxAttempts: 1,
    });
    expect(r.ok).toBe(false);
    expect(r.message).toContain(
      "new findings not in the unpatched scan: SQL injection in report query",
    );
  });
});

describe("generateVerifiedFix — independent re-scans", () => {
  const ORIGINAL = "if (localStorage.getItem('auth')) showResume();" + String.fromCharCode(10);
  const DISGUISED = "if (simulatedServerCheck(token)) showResume();" + String.fromCharCode(10);
  const authTarget = {
    title: "Client-Side Only Authentication",
    cwe_id: "CWE-602",
    category: "Broken Authentication",
    line_start: 1,
  };
  const authFinding = f({ ...authTarget, severity: "critical", line_end: 1 });

  it("rejects a disguised fix that only the second re-scan catches", async () => {
    // Live-observed: a "simulated server-side check" passed one re-scan.
    let patchedScans = 0;
    const analyze = vi.fn(async (c) => {
      if (c === ORIGINAL) return [authFinding];
      patchedScans++;
      return patchedScans % 2 === 1 ? [] : [authFinding];
    });
    const r = await generateVerifiedFix({
      target: authTarget,
      originalContent: ORIGINAL,
      propose: async () => ({ explanation: "simulated", fixedContent: DISGUISED }),
      analyze,
      maxAttempts: 1,
    });
    expect(r.ok).toBe(false);
    expect(r.lastVerdict.stillPresent).toHaveLength(1);
  });

  it("skips the second re-scan when the first already rejects", async () => {
    const analyze = vi.fn(async () => [authFinding]);
    await generateVerifiedFix({
      target: authTarget,
      originalContent: ORIGINAL,
      propose: async () => ({ explanation: "x", fixedContent: DISGUISED }),
      analyze,
      maxAttempts: 1,
    });
    // 2 baseline + 1 re-scan, not 2 + 2.
    expect(analyze).toHaveBeenCalledTimes(3);
  });

  it("does not pass a patch whose second re-scan errored", async () => {
    let patchedScans = 0;
    const r = await generateVerifiedFix({
      target: authTarget,
      originalContent: ORIGINAL,
      propose: async () => ({ explanation: "x", fixedContent: DISGUISED }),
      analyze: async (c) => {
        if (c === ORIGINAL) return [authFinding];
        patchedScans++;
        if (patchedScans === 2) throw new Error("Gemini 503");
        return [];
      },
      maxAttempts: 1,
    });
    expect(r.ok).toBe(false);
    expect(r.attempts[0].outcome).toBe("scan_error");
  });
});

describe("unifiedDiff", () => {
  const NL = String.fromCharCode(10);
  const lines = (n) => Array.from({ length: n }, (_, i) => `line ${i + 1}`);

  it("renders one hunk with context for a single-line change", () => {
    const before = lines(10);
    const after = [...before];
    after[4] = "line 5 (patched)";
    const d = unifiedDiff(before.join(NL), after.join(NL), { context: 1 });
    expect(d.added).toBe(1);
    expect(d.removed).toBe(1);
    expect(d.diff.split(NL)).toEqual([
      "@@ -4,3 +4,3 @@",
      " line 4",
      "-line 5",
      "+line 5 (patched)",
      " line 6",
    ]);
  });

  it("splits far-apart changes into separate hunks", () => {
    const before = lines(40);
    const after = [...before];
    after[2] = "changed early";
    after[35] = "changed late";
    const d = unifiedDiff(before.join(NL), after.join(NL), { context: 2 });
    expect(d.diff.split(NL).filter((l) => l.startsWith("@@"))).toHaveLength(2);
  });

  it("reports an unchanged file as an empty diff", () => {
    expect(unifiedDiff("a" + NL + "b", "a" + NL + "b").diff).toBe("");
  });

  it("caps a huge rewrite and says so", () => {
    const d = unifiedDiff(
      lines(300).join(NL),
      lines(300)
        .map((l) => l + "!")
        .join(NL),
      { maxLines: 50 },
    );
    expect(d.truncated).toBe(true);
    expect(d.diff.split(NL)).toHaveLength(50);
  });
});

describe("generateVerifiedFix — live console events", () => {
  const ORIGINAL = "localStorage.setItem('pw', password);" + String.fromCharCode(10);
  const BAD = "localStorage.setItem('pw', btoa(password));" + String.fromCharCode(10);
  const GOOD = "// password is no longer stored" + String.fromCharCode(10);

  it("narrates baseline, each attempt's patch and re-scans, and the outcome", async () => {
    const events = [];
    const propose = vi
      .fn()
      .mockResolvedValueOnce({ explanation: "encoded it", fixedContent: BAD })
      .mockResolvedValueOnce({ explanation: "removed it", fixedContent: GOOD });
    const r = await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose,
      analyze: async (c) => (c.includes("setItem('pw'") ? [passwordFinding] : []),
      maxAttempts: 3,
      onEvent: (e) => events.push(e),
    });
    expect(r.ok).toBe(true);
    expect(events.map((e) => e.type)).toEqual([
      "baseline",
      "baseline",
      "baseline_done",
      "propose",
      "patch",
      "rescan", // attempt 1: rejected on the first re-scan, so no second one
      "rejected",
      "propose",
      "patch",
      "rescan",
      "rescan", // attempt 2: must pass both
      "passed",
    ]);
    const firstRescan = events.find((e) => e.type === "rescan");
    expect(firstRescan.ok).toBe(false);
    expect(firstRescan.stillPresent[0].title).toBe(passwordFinding.title);
    const patch = events.find((e) => e.type === "patch");
    expect(patch.diff).toContain("+localStorage.setItem('pw', btoa(password));");
    expect(events[7].retrying).toBe(true);
  });

  it("reports a model that declined to change the file", async () => {
    const events = [];
    await generateVerifiedFix({
      target: passwordTarget,
      originalContent: ORIGINAL,
      propose: async () => ({ explanation: "needs a backend", fixedContent: ORIGINAL }),
      analyze: async () => [passwordFinding],
      onEvent: (e) => events.push(e),
    });
    expect(events.at(-1)).toMatchObject({ type: "unchanged", explanation: "needs a backend" });
  });
});
