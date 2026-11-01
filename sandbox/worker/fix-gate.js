// Re-scan gate for "Fix with AI".
//
// A patch only becomes a pull request if the scanner that reported the finding
// no longer reports it once the patch is applied. The fixer re-runs the scan on
// the repository as it would look after merging (the patched file swapped in),
// compares against a scan of the unpatched repository, and only opens a PR when
// the comparison passes. If it fails, the model is told what the re-scan still
// found and tries again, up to a fixed number of attempts.
//
// Everything here is pure: the model call and the scan are injected, so the
// decision logic is testable without a network.

/** New findings at these severities block the PR. New "low" ones are reported but allowed. */
export const BLOCKING_SEVERITIES = new Set(["critical", "high", "medium"]);

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/** How far (in lines) a baseline finding may sit from the recorded location and still be it. */
const LINE_WINDOW = 5;

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

export function normalizePath(p) {
  return String(p ?? "")
    .replace(/\\/g, "/")
    .replace(/^(\.\/|\/)+/, "")
    .toLowerCase();
}

/** "CWE-079", "cwe 79", "CWE-79: XSS" → "cwe:79". */
export function cweKey(cwe) {
  const m = /(\d+)/.exec(String(cwe ?? ""));
  return m ? `cwe:${Number(m[1])}` : null;
}

function categoryKey(category) {
  const c = String(category ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
  return c ? `cat:${c}` : null;
}

function titleTokens(title) {
  return new Set(
    String(title ?? "")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length >= 3 && !STOPWORDS.has(t))
      // Crude stemming so "passwords"/"password" and "stored"/"storage" meet.
      .map((t) => t.replace(/(ing|age|ed|es|s)$/, ""))
      .filter((t) => t.length >= 3),
  );
}

export function titlesSimilar(a, b) {
  const ta = titleTokens(a);
  const tb = titleTokens(b);
  if (ta.size === 0 || tb.size === 0) return false;
  let shared = 0;
  for (const t of ta) if (tb.has(t)) shared++;
  return shared >= 2 || shared / Math.min(ta.size, tb.size) >= 0.6;
}

/**
 * What "kind" of issue a finding is. CWE when the model gave one (it is a
 * required field of the scan schema, so usually), else the category.
 */
export function findingKey(f) {
  return (
    cweKey(f.cwe_id) ?? categoryKey(f.category) ?? `title:${[...titleTokens(f.title)].join(" ")}`
  );
}

/**
 * [start, end] with end defaulting to start and the two put in order — the
 * model occasionally returns line_end < line_start, which would otherwise make
 * a finding look like it covers nothing (or everything).
 */
function span(start, end) {
  const e = Number.isInteger(end) ? end : start;
  return [Math.min(start, e), Math.max(start, e)];
}

function nearTarget(f, target) {
  if (!Number.isInteger(target.line_start) || !Number.isInteger(f.line_start)) return true;
  const [ts, te] = span(target.line_start, target.line_end);
  const [fs, fe] = span(f.line_start, f.line_end);
  return fs <= te + LINE_WINDOW && fe >= ts - LINE_WINDOW;
}

/**
 * Every key the target finding might be reported under. The re-scan can label
 * the same issue with a different CWE than the scan that originally found it
 * (CWE-312 vs CWE-256 for a cleartext password, say), so any baseline finding
 * sitting at the recorded location with a similar description contributes its
 * key too. Line numbers are only trusted on the BASELINE, which is the same
 * code the finding was recorded against; after patching, lines move.
 */
export function targetKeys(target, baseline) {
  const keys = new Set([cweKey(target.cwe_id), categoryKey(target.category)].filter(Boolean));
  for (const f of baseline) {
    if (!nearTarget(f, target)) continue;
    if (
      titlesSimilar(f.title, target.title) ||
      (categoryKey(f.category) && categoryKey(f.category) === categoryKey(target.category))
    ) {
      keys.add(findingKey(f));
    }
  }
  return keys;
}

function bySeverityDesc(a, b) {
  return (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
}

/** Above this many line pairs the LCS table gets too big; fall back to identity. */
const MAX_DIFF_CELLS = 4_000_000;

const splitLines = (text) => String(text ?? "").split(/\r?\n/);

/**
 * Line-level diff via longest common subsequence: a list of
 * { op: "eq" | "del" | "ins", a, b } where a/b are 0-based line indexes into
 * before/after. Null when the files are too large for the O(n·m) table.
 */
export function diffOps(A, B) {
  const n = A.length;
  const m = B.length;
  if (n * m > MAX_DIFF_CELLS) return null;

  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const ops = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) ops.push({ op: "eq", a: i++, b: j++ });
    else if (dp[i + 1][j] >= dp[i][j + 1]) ops.push({ op: "del", a: i++ });
    else ops.push({ op: "ins", b: j++ });
  }
  while (i < n) ops.push({ op: "del", a: i++ });
  while (j < m) ops.push({ op: "ins", b: j++ });
  return ops;
}

/**
 * A unified diff (with @@ hunk headers) of a patch, for showing what each fix
 * attempt changed. Capped at `maxLines` so a model that rewrote a whole file
 * can't produce a megabyte console line; `truncated` says when that happened.
 */
export function unifiedDiff(before, after, { context = 2, maxLines = 160 } = {}) {
  const A = splitLines(before);
  const B = splitLines(after);
  const ops = diffOps(A, B);
  if (!ops) return { diff: null, added: null, removed: null, truncated: false };

  const added = ops.filter((o) => o.op === "ins").length;
  const removed = ops.filter((o) => o.op === "del").length;
  const changed = ops.map((o, k) => (o.op === "eq" ? -1 : k)).filter((k) => k >= 0);
  if (changed.length === 0) return { diff: "", added, removed, truncated: false };

  // Merge change positions into hunks that include `context` lines around them.
  const hunks = [];
  for (const k of changed) {
    const last = hunks[hunks.length - 1];
    if (last && k - context <= last.end + context + 1) last.end = k;
    else hunks.push({ start: k, end: k });
  }

  const out = [];
  for (const h of hunks) {
    const from = Math.max(0, h.start - context);
    const to = Math.min(ops.length - 1, h.end + context);
    const slice = ops.slice(from, to + 1);
    const firstA = slice.find((o) => o.a !== undefined)?.a ?? 0;
    const firstB = slice.find((o) => o.b !== undefined)?.b ?? 0;
    const aLen = slice.filter((o) => o.op !== "ins").length;
    const bLen = slice.filter((o) => o.op !== "del").length;
    out.push(`@@ -${firstA + 1},${aLen} +${firstB + 1},${bLen} @@`);
    for (const o of slice) {
      if (o.op === "eq") out.push(` ${A[o.a]}`);
      else if (o.op === "del") out.push(`-${A[o.a]}`);
      else out.push(`+${B[o.b]}`);
    }
  }
  const truncated = out.length > maxLines;
  return {
    diff: (truncated ? out.slice(0, maxLines) : out).join("\n"),
    added,
    removed,
    truncated,
  };
}

/**
 * Maps a line number in `before` to where that line ended up in `after`, using
 * a longest-common-subsequence line diff. Lines the patch touched map to the
 * nearest unchanged line above them, keeping their offset. Lets a baseline
 * finding be recognised after the patch even though the edit moved it.
 */
export function buildLineMap(before, after) {
  const A = splitLines(before);
  const B = splitLines(after);
  const n = A.length;
  const ops = diffOps(A, B);
  if (!ops) return (line) => line;

  const map = new Int32Array(n + 1); // 1-based; 0 = line didn't survive unchanged
  for (const o of ops) if (o.op === "eq") map[o.a + 1] = o.b + 1;

  return (line) => {
    if (!Number.isInteger(line) || line < 1) return line;
    const l = Math.min(line, n);
    if (map[l] > 0) return map[l];
    for (let k = l - 1; k >= 1; k--) if (map[k] > 0) return map[k] + (l - k);
    return l;
  };
}

/** Both findings have line numbers and their ranges sit within LINE_WINDOW. */
function rangesNear(a, bStart, bEnd) {
  if (!Number.isInteger(a.line_start) || !Number.isInteger(bStart)) return false;
  const [as, ae] = span(a.line_start, a.line_end);
  const [bs, be] = span(bStart, bEnd);
  return as <= be + LINE_WINDOW && ae >= bs - LINE_WINDOW;
}

/**
 * Union of several scans of the SAME (unpatched) file, without duplicates. The
 * AI scanner reports a slightly different set each run, so a single baseline
 * can miss an issue that is really there. The re-scan of the patch then
 * reports it, and the gate wrongly calls it "introduced" (seen on a live run
 * against a real repo). Scanning the original twice and merging makes the
 * baseline far less forgetful. Two runs "agree" on a finding by the same rules
 * the gate uses: same kind at the same place, or same place and description.
 */
export function mergeFindings(runs) {
  const merged = [];
  for (const run of runs) {
    for (const f of run) {
      const dup = merged.some(
        (m) =>
          (findingKey(m) === findingKey(f) &&
            (rangesNear(f, m.line_start, m.line_end) || titlesSimilar(f.title, m.title))) ||
          (rangesNear(f, m.line_start, m.line_end) && titlesSimilar(f.title, m.title)),
      );
      if (!dup) merged.push(f);
    }
  }
  return merged;
}

/**
 * Decides whether a patch passes, comparing findings in the patched file before
 * (`baseline`) and after (`after`) the change.
 *
 * Counting rather than matching individual findings is deliberate: the same
 * file can hold two issues of one kind (two XSS sinks, say) and the patch was
 * only asked to fix one. The target counts as fixed when findings of its kind
 * go DOWN; the survivor is its untouched sibling, not the target coming back.
 *
 * Everything else is matched finding-by-finding, not counted. An earlier
 * version compared counts per CWE, and a real patch slipped through it: it
 * removed a password check, creating an "anyone can log in" bug (CWE-287) in a
 * file that already had an unrelated CWE-287 finding. One before, one after —
 * same count, different issue. Now each post-patch finding must pair with a
 * baseline finding at the same (diff-mapped) location or with a matching
 * description; whatever is left unpaired is new.
 *
 * - stillPresent: findings of the target's kind that did not go down.
 * - introduced:   unpaired new findings at medium+; these block the PR.
 * - minor:        unpaired new "low" findings; reported, never blocking.
 *
 * `mapLine` translates a baseline line number to its post-patch position (see
 * buildLineMap). Defaults to identity, for callers without both file versions.
 */
export function evaluatePatch({ target, baseline, after, mapLine = (l) => l }) {
  const keys = targetKeys(target, baseline);
  const isTarget = (f) => keys.has(findingKey(f));

  const baseTarget = baseline.filter(isTarget);
  const afterTarget = after.filter(isTarget);
  const stillPresent =
    baseTarget.length > 0
      ? afterTarget.length >= baseTarget.length
        ? afterTarget
        : []
      : afterTarget;

  const pool = baseline
    .filter((f) => !isTarget(f))
    .map((b) => ({
      b,
      key: findingKey(b),
      start: mapLine(b.line_start),
      end: mapLine(Number.isInteger(b.line_end) ? b.line_end : b.line_start),
      used: false,
    }));
  const sameIssue = (a, p) => rangesNear(a, p.start, p.end) || titlesSimilar(a.title, p.b.title);

  const newlyFound = [];
  for (const a of after.filter((f) => !isTarget(f)).sort(bySeverityDesc)) {
    const k = findingKey(a);
    const match =
      pool.find((p) => !p.used && p.key === k && sameIssue(a, p)) ??
      // The same pre-existing issue, relabelled with a different CWE by this
      // scan run: same place AND same description.
      pool.find(
        (p) => !p.used && rangesNear(a, p.start, p.end) && titlesSimilar(a.title, p.b.title),
      );
    if (match) match.used = true;
    else newlyFound.push(a);
  }
  const introduced = newlyFound.filter((f) => BLOCKING_SEVERITIES.has(f.severity));
  const minor = newlyFound.filter((f) => !BLOCKING_SEVERITIES.has(f.severity));

  return {
    ok: stillPresent.length === 0 && introduced.length === 0,
    stillPresent,
    introduced,
    minor,
    // False when the unpatched file didn't reproduce the finding at all — the
    // check then shows only that the patched file is clean, which is weaker.
    baselineReproduced: baseTarget.length > 0,
  };
}

function describeFinding(f) {
  const where = Number.isInteger(f.line_start) ? ` (line ${f.line_start})` : "";
  return `${f.title}${where}${f.cwe_id ? ` [${f.cwe_id}]` : ""}`;
}

/** Feedback for the model's next attempt. */
export function describeRejection(verdict) {
  const parts = [];
  if (verdict.stillPresent.length) {
    parts.push(
      "The original vulnerability is STILL DETECTED in your patched file:\n" +
        verdict.stillPresent
          .map((f) => `- ${describeFinding(f)}: ${String(f.description ?? "").slice(0, 400)}`)
          .join("\n"),
    );
  }
  if (verdict.introduced.length) {
    parts.push(
      "The re-scan of your patched file also reported these, which the scan of the original file did not:\n" +
        verdict.introduced
          .map(
            (f) =>
              `- ${describeFinding(f)} (${f.severity}): ${String(f.description ?? "").slice(0, 400)}`,
          )
          .join("\n"),
    );
  }
  return parts.join("\n\n");
}

/** Short, user-facing summary of why no PR was opened. */
export function summarizeFailure(result) {
  const last = result.lastVerdict;
  const bits = [];
  if (last?.stillPresent?.length) {
    bits.push(`still detected: ${last.stillPresent.map(describeFinding).join("; ")}`);
  }
  if (last?.introduced?.length) {
    bits.push(
      `new findings not in the unpatched scan: ${last.introduced.map(describeFinding).join("; ")}`,
    );
  }
  return bits.join(" — ");
}

/**
 * Generate → re-scan → retry loop. Returns the first patch that passes the
 * re-scan, or a failure explaining why none did. Never returns a patch that
 * was not re-scanned: if the scan itself errors, that attempt fails.
 *
 * @param {object}   args
 * @param {object}   args.target          the finding being fixed (title, cwe_id, category, line_start, line_end)
 * @param {string}   args.originalContent the file as it exists on the default branch now
 * @param {Function} args.propose         ({ feedback, previous }) => { explanation, fixedContent }
 * @param {Function} args.analyze         (content) => findings in the target file after scanning
 * @param {number}   args.maxAttempts
 * @param {number}   [args.baselineRuns] scans of the original, merged (default 2)
 * @param {number}   [args.rescanRuns]   re-scans a patch must ALL pass (default 2)
 * @param {Function} [args.log]
 * @param {Function} [args.onEvent] structured progress for the live sandbox
 *   console: { type, ... } for baseline, propose, patch, rescan, passed,
 *   rejected, model_error, scan_error, unchanged, empty
 */
export async function generateVerifiedFix({
  target,
  originalContent,
  propose,
  analyze,
  maxAttempts = 3,
  baselineRuns = 2,
  rescanRuns = 2,
  log = () => {},
  onEvent = () => {},
}) {
  const brief = (list) =>
    list.map((f) => ({
      title: f.title,
      severity: f.severity,
      cwe_id: f.cwe_id ?? null,
      line_start: f.line_start ?? null,
    }));
  const errText = (err) => String(err?.message ?? err).slice(0, 300);

  const runs = [];
  for (let i = 0; i < baselineRuns; i++) {
    try {
      runs.push(await analyze(originalContent));
      onEvent({
        type: "baseline",
        run: i + 1,
        of: baselineRuns,
        count: runs[runs.length - 1].length,
        findings: brief(runs[runs.length - 1]),
      });
    } catch (err) {
      onEvent({ type: "baseline_error", run: i + 1, of: baselineRuns, error: errText(err) });
      // The first run is required; later ones only sharpen the baseline, so a
      // flaky extra run shouldn't sink the whole fix.
      if (runs.length === 0) {
        return {
          ok: false,
          reason: "scan_failed",
          message: `Could not scan the unpatched file, so no patch could be verified: ${err?.message ?? err}`,
          attempts: [],
        };
      }
      log(`baseline run ${i + 1} failed, continuing with ${runs.length}: ${err?.message ?? err}`);
    }
  }
  const baseline = mergeFindings(runs);
  onEvent({ type: "baseline_done", count: baseline.length, findings: brief(baseline) });
  log(
    `baseline: ${baseline.length} finding(s) in the target file ` +
      `(${runs.map((r) => r.length).join(" + ")} across ${runs.length} run(s))`,
  );

  const attempts = [];
  let feedback = null;
  let previous = null;
  let lastVerdict = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let proposal;
    onEvent({ type: "propose", attempt, of: maxAttempts, retrying: Boolean(feedback) });
    try {
      proposal = await propose({ feedback, previous });
    } catch (err) {
      onEvent({ type: "model_error", attempt, error: errText(err) });
      attempts.push({
        attempt,
        outcome: "model_error",
        detail: String(err?.message ?? err).slice(0, 300),
      });
      log(`attempt ${attempt}: model error — ${err?.message ?? err}`);
      continue;
    }

    const { explanation, fixedContent } = proposal;
    if (!fixedContent || !fixedContent.trim()) {
      onEvent({ type: "empty", attempt });
      attempts.push({ attempt, outcome: "empty" });
      feedback = "Your previous reply contained an empty file. Return the complete patched file.";
      continue;
    }
    if (fixedContent === originalContent) {
      // The model is saying it can't fix this within the file (or disagrees
      // with the finding). Pushing it to change something anyway just
      // manufactures a bad patch, so stop here.
      onEvent({ type: "unchanged", attempt, explanation: String(explanation ?? "").slice(0, 600) });
      return {
        ok: false,
        reason: "unchanged",
        message:
          "The model did not change the file — it may consider the finding a false positive, or the " +
          `fix may need changes outside this file. ${explanation ?? ""}`.trim(),
        attempts: [...attempts, { attempt, outcome: "unchanged" }],
      };
    }

    // A patch must survive `rescanRuns` independent re-scans; one flag from any
    // of them rejects it. A single sample of an AI scanner can miss a
    // disguised fix that the next scan catches (observed live: a "simulated
    // server-side check" in a browser-only file passed one re-scan). The next
    // run only happens if the previous one passed, so rejections cost nothing
    // extra. Every run must succeed: a patch that couldn't be fully re-scanned
    // is an unverified patch.
    const mapLine = buildLineMap(originalContent, fixedContent);
    const { diff, added, removed, truncated } = unifiedDiff(originalContent, fixedContent);
    onEvent({
      type: "patch",
      attempt,
      of: maxAttempts,
      added,
      removed,
      diff,
      truncated,
      explanation: String(explanation ?? "").slice(0, 600),
    });
    const afterRuns = [];
    let verdict;
    let scanError = null;
    for (let run = 0; run < rescanRuns; run++) {
      try {
        afterRuns.push(await analyze(fixedContent));
      } catch (err) {
        scanError = err;
        onEvent({ type: "scan_error", attempt, run: run + 1, of: rescanRuns, error: errText(err) });
        break;
      }
      verdict = evaluatePatch({ target, baseline, after: mergeFindings(afterRuns), mapLine });
      onEvent({
        type: "rescan",
        attempt,
        run: run + 1,
        of: rescanRuns,
        ok: verdict.ok,
        stillPresent: brief(verdict.stillPresent),
        introduced: brief(verdict.introduced),
        minor: brief(verdict.minor),
      });
      if (!verdict.ok) break;
    }
    if (scanError) {
      attempts.push({
        attempt,
        outcome: "scan_error",
        detail: String(scanError?.message ?? scanError).slice(0, 300),
      });
      log(
        `attempt ${attempt}: re-scan ${afterRuns.length + 1} failed — ${scanError?.message ?? scanError}`,
      );
      // A completed run that already rejected the patch is still useful feedback.
      if (verdict && !verdict.ok) {
        lastVerdict = verdict;
        feedback = describeRejection(verdict);
        previous = fixedContent;
      }
      continue;
    }
    lastVerdict = verdict;
    attempts.push({
      attempt,
      outcome: verdict.ok ? "passed" : "rejected",
      still_present: verdict.stillPresent.length,
      introduced: verdict.introduced.length,
    });
    log(
      `attempt ${attempt}: ${verdict.ok ? "PASSED" : "rejected"} after ${afterRuns.length} re-scan(s) ` +
        `(still present ${verdict.stillPresent.length}, introduced ${verdict.introduced.length})`,
    );

    onEvent({ type: verdict.ok ? "passed" : "rejected", attempt, of: maxAttempts });
    if (verdict.ok) {
      return {
        ok: true,
        attempt,
        maxAttempts,
        explanation,
        fixedContent,
        verdict,
        attempts,
      };
    }
    feedback = describeRejection(verdict);
    previous = fixedContent;
  }

  const failure = { ok: false, reason: "rejected", attempts, lastVerdict };
  const detail = summarizeFailure(failure);
  const errorsOnly = !lastVerdict;
  failure.message = errorsOnly
    ? `No patch could be generated and re-scanned after ${maxAttempts} attempt(s): ` +
      attempts.map((a) => a.detail ?? a.outcome).join("; ")
    : `No pull request was opened: after ${maxAttempts} attempt(s), every patch still failed the ` +
      `re-scan${detail ? ` (${detail})` : ""}. This finding likely needs a manual fix.`;
  return failure;
}
