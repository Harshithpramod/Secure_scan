// A recorded-style "Fix with AI" run for the /demo page, in exactly the shape
// the real sandbox console consumes (JobLogLine[]), plus a matching timeline.
// Pure data: nothing here touches the network or Supabase.

import type { JobLogLine, VulnEvent } from "@/lib/activity-format";
import type { DemoVulnerability } from "@/lib/demo-data";

/** Small LCS line diff with @@ hunks, mirroring sandbox/worker/fix-gate.js. */
export function demoUnifiedDiff(before: string, after: string, context = 2): string {
  const A = before.split("\n");
  const B = after.split("\n");
  const n = A.length;
  const m = B.length;
  const dp = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);

  type Op = { op: "eq" | "del" | "ins"; a?: number; b?: number };
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) ops.push({ op: "eq", a: i++, b: j++ });
    else if (dp[i + 1][j] >= dp[i][j + 1]) ops.push({ op: "del", a: i++ });
    else ops.push({ op: "ins", b: j++ });
  }
  while (i < n) ops.push({ op: "del", a: i++ });
  while (j < m) ops.push({ op: "ins", b: j++ });

  const changed = ops.map((o, k) => (o.op === "eq" ? -1 : k)).filter((k) => k >= 0);
  const hunks: { start: number; end: number }[] = [];
  for (const k of changed) {
    const last = hunks[hunks.length - 1];
    if (last && k - context <= last.end + context + 1) last.end = k;
    else hunks.push({ start: k, end: k });
  }
  const out: string[] = [];
  for (const h of hunks) {
    const slice = ops.slice(
      Math.max(0, h.start - context),
      Math.min(ops.length, h.end + context + 1),
    );
    const a0 = slice.find((o) => o.a !== undefined)?.a ?? 0;
    const b0 = slice.find((o) => o.b !== undefined)?.b ?? 0;
    out.push(
      `@@ -${a0 + 1},${slice.filter((o) => o.op !== "ins").length} +${b0 + 1},${slice.filter((o) => o.op !== "del").length} @@`,
    );
    for (const o of slice) {
      if (o.op === "eq") out.push(` ${A[o.a!]}`);
      else if (o.op === "del") out.push(`-${A[o.a!]}`);
      else out.push(`+${B[o.b!]}`);
    }
  }
  return out.join("\n");
}

function countChanges(diff: string) {
  const lines = diff.split("\n");
  return {
    added: lines.filter((l) => l.startsWith("+")).length,
    removed: lines.filter((l) => l.startsWith("-")).length,
  };
}

type Step = { stage: string; level?: string; message: string; data?: unknown; delay: number };

/**
 * The script for one demo fix run. For the SQL-injection finding the first
 * attempt is a classic incomplete fix (escaping quotes) that the re-scan
 * rejects; the second — a parameterised query — passes both re-scans.
 */
export function demoFixSteps(v: DemoVulnerability): Step[] {
  const container = `fixer-${v.id.replace(/[^a-z0-9]/gi, "")}a91c`;
  const steps: Step[] = [
    {
      stage: "sandbox",
      message: "Starting an isolated fixer container",
      delay: 400,
      data: {
        isolation: {
          container,
          image: "pentestai/fixer:latest",
          network:
            "fixer_net — internet egress for GitHub and the AI APIs; cannot reach the queue or API",
          cpus: "1.0",
          memory: "512m",
          processes: "128",
          filesystem: "read-only (+ 256m tmpfs scratch)",
          repository: "not cloned — one file read over the GitHub API",
          capabilities: "all dropped",
          privileges: "no-new-privileges, uid 1000",
          credentials: "GitHub token + API keys via environment, never argv",
          timeout: "600s",
        },
      },
    },
    {
      stage: "read",
      message: `Read ${v.file_path} from main @ 4f2a9c1 (${v.snippet.split("\n").length + 60} lines)`,
      delay: 700,
    },
    {
      stage: "context",
      message: "Loaded 17 other file(s) the scanner reads, so re-scans see the same context",
      delay: 700,
    },
    {
      stage: "baseline",
      message: `Baseline scan 1/2 of the current code: 2 finding(s) in ${v.file_path}`,
      delay: 1500,
    },
    {
      stage: "baseline",
      message: `Baseline scan 2/2 of the current code: 2 finding(s) in ${v.file_path}`,
      delay: 1400,
    },
    {
      stage: "baseline",
      message: `Baseline: 2 known finding(s) in ${v.file_path}. A patch may not add to these.`,
      delay: 300,
    },
  ];

  const passing = demoUnifiedDiff(v.snippet, v.suggested_fix);

  if (v.id === "v-001") {
    // A function replacer: the replacement text is full of `$` and `'`, which a
    // replacement *string* would interpret as $-patterns.
    const escaped = v.snippet.replace(
      "`SELECT * FROM orders WHERE id = '${id}' LIMIT 1`",
      () => "`SELECT * FROM orders WHERE id = '${id.replace(/'/g, \"''\")}' LIMIT 1`",
    );
    const firstDiff = demoUnifiedDiff(v.snippet, escaped);
    steps.push(
      { stage: "patch", message: "Attempt 1/3: asking qwen/qwen3-coder for a patch", delay: 900 },
      {
        stage: "patch",
        message: `Attempt 1: patch changes +${countChanges(firstDiff).added} −${countChanges(firstDiff).removed} line(s)`,
        delay: 2600,
        data: { attempt: 1, diff: firstDiff },
      },
      {
        stage: "rescan",
        level: "warn",
        message: `Re-scan 1/2: rejected — still detected: ${v.title} (line ${v.line_start})`,
        delay: 1800,
        data: {
          attempt: 1,
          ok: false,
          stillPresent: [{ title: v.title, line_start: v.line_start, severity: v.severity }],
          introduced: [],
        },
      },
      {
        stage: "rescan",
        level: "warn",
        message: "Attempt 1 rejected — sending the re-scan's findings back to the model",
        delay: 500,
      },
      {
        stage: "patch",
        message:
          "Attempt 2/3: asking qwen/qwen3-coder for a patch (with the re-scan's findings as feedback)",
        delay: 700,
      },
    );
  } else {
    steps.push({
      stage: "patch",
      message: "Attempt 1/3: asking qwen/qwen3-coder for a patch",
      delay: 900,
    });
  }

  const attempt = v.id === "v-001" ? 2 : 1;
  const { added, removed } = countChanges(passing);
  steps.push(
    {
      stage: "patch",
      message: `Attempt ${attempt}: patch changes +${added} −${removed} line(s)`,
      delay: 2800,
      data: { attempt, diff: passing },
    },
    {
      stage: "rescan",
      level: "success",
      message: "Re-scan 1/2 of the patched code: clean",
      delay: 1800,
      data: { attempt, ok: true, stillPresent: [], introduced: [] },
    },
    {
      stage: "rescan",
      level: "success",
      message: "Re-scan 2/2 of the patched code: clean",
      delay: 1700,
      data: { attempt, ok: true, stillPresent: [], introduced: [] },
    },
    {
      stage: "rescan",
      level: "success",
      message: `Attempt ${attempt} passed 2 independent re-scans`,
      delay: 300,
    },
    {
      stage: "publish",
      message: `Opening a pull request from pentestai/fix-${v.id} into main`,
      delay: 900,
    },
    {
      stage: "done",
      level: "success",
      message: "Opened pull request #482 (demo — nothing was actually opened)",
      delay: 900,
    },
  );
  return steps;
}

/** Turn the first `count` steps into console lines, timed from `startedAt`. */
export function demoFixLines(v: DemoVulnerability, count: number, startedAt: number): JobLogLine[] {
  let t = startedAt;
  return demoFixSteps(v)
    .slice(0, count)
    .map((s, seq) => {
      t += s.delay;
      return {
        id: `demo-${v.id}-${seq}`,
        job_id: `demo-fix-${v.id}`,
        job_kind: "fix",
        seq,
        stage: s.stage,
        level: s.level ?? "info",
        message: s.message,
        data: s.data ?? {},
        created_at: new Date(t).toISOString(),
      };
    });
}

/** A plausible history for a demo finding, plus the fix run's events once it finished. */
export function demoTimeline(v: DemoVulnerability, fixDoneAt: number | null): VulnEvent[] {
  const detected = Date.parse(v.detected_at);
  const at = (ms: number) => new Date(ms).toISOString();
  const events: VulnEvent[] = [
    {
      id: `${v.id}-detected`,
      kind: "detected",
      message: `First detected at ${v.file_path}:${v.line_start}`,
      data: {},
      created_at: at(detected),
    },
  ];
  if (v.verification_status === "confirmed" || v.verification_status === "not_exploitable") {
    events.push({
      id: `${v.id}-verify`,
      kind: "verification",
      message:
        v.verification_status === "confirmed"
          ? "Sandbox verification: confirmed"
          : "Sandbox verification: not confirmed",
      data: { status: v.verification_status, evidence: v.verification_evidence ?? "" },
      created_at: at(detected + 4 * 60_000),
    });
  }
  if (fixDoneAt) {
    events.push(
      {
        id: `${v.id}-fix-requested`,
        kind: "fix_requested",
        message: "AI fix requested",
        data: {},
        created_at: at(fixDoneAt - 20_000),
      },
      {
        id: `${v.id}-fix-pr`,
        kind: "fix_pr_opened",
        message: `Verified fix opened as pull request #482 (passed the re-scan on attempt ${v.id === "v-001" ? 2 : 1} of 3)`,
        data: {},
        created_at: at(fixDoneAt),
      },
    );
  }
  return events.sort((a, b) => a.created_at.localeCompare(b.created_at));
}
