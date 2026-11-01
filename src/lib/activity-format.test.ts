import { describe, expect, it } from "vitest";
import { groupJobRuns, toTimeline, type JobLogLine, type VulnEvent } from "./activity-format";

let t = 0;
const at = () => new Date(Date.UTC(2026, 8, 1) + (t += 60_000)).toISOString();
const ev = (kind: string, over: Partial<VulnEvent> = {}): VulnEvent => ({
  id: `e${t}`,
  kind,
  message: null,
  data: {},
  created_at: at(),
  ...over,
});

describe("toTimeline", () => {
  it("tells the story of a regression", () => {
    const items = toTimeline([
      ev("detected", { message: "First detected at script.js:40" }),
      ev("seen"),
      ev("seen"),
      ev("seen"),
      ev("fix_requested"),
      ev("fix_pr_opened", {
        message: "Verified fix opened as pull request #7",
        data: { pr_url: "https://github.com/o/r/pull/7" },
      }),
      ev("not_seen"),
      ev("status_changed", {
        message: "Fixed by pull request #7 — not detected after it was merged",
        data: { from: "open", to: "fixed", by: "system" },
      }),
      ev("seen", { data: { regressed: true } }),
      ev("status_changed", {
        message: "Reappeared in the scan on 24 Sep 2026 after being marked fixed",
        data: { from: "fixed", to: "open", by: "system" },
      }),
    ]);
    expect(items.map((i) => [i.icon, i.title])).toEqual([
      ["detected", "First detected"],
      ["seen", "Seen again in 3 scans"],
      ["fix_requested", "AI fix requested"],
      ["fix_pr", "Verified fix opened as pull request #7"],
      ["not_seen", "Not detected in a scan"],
      ["fixed", "Marked fixed"],
      ["regressed", "Regressed"],
    ]);
    expect(items.find((i) => i.icon === "fix_pr")?.href).toBe("https://github.com/o/r/pull/7");
    expect(items.find((i) => i.icon === "regressed")?.tone).toBe("bad");
  });

  it("adds a synthetic first detection for rows older than the timeline", () => {
    const items = toTimeline([ev("seen")], "2026-08-30T10:00:00Z");
    expect(items[0]).toMatchObject({ icon: "detected", at: "2026-08-30T10:00:00Z" });
  });

  it("shows a manual triage change with its reason", () => {
    const [item] = toTimeline([
      ev("status_changed", {
        message: "Changed manually",
        data: { from: "open", to: "false_positive", by: "user" },
      }),
    ]);
    expect(item).toMatchObject({ icon: "false_positive", detail: "Changed manually" });
  });

  it("colours verification verdicts by what they mean", () => {
    const items = toTimeline([
      ev("verification", {
        message: "Sandbox verification: confirmed",
        data: { status: "confirmed" },
      }),
      ev("verification", {
        message: "Sandbox verification: not confirmed",
        data: { status: "not_exploitable" },
      }),
    ]);
    expect(items.map((i) => i.tone)).toEqual(["bad", "good"]);
  });
});

describe("groupJobRuns", () => {
  const line = (
    job: string,
    kind: string,
    seq: number,
    stage: string,
    level = "info",
    data: unknown = {},
  ): JobLogLine => ({
    id: `${job}-${seq}`,
    job_id: job,
    job_kind: kind,
    seq,
    stage,
    level,
    message: `${stage} ${seq}`,
    data,
    created_at: at(),
  });

  it("groups by job, orders by seq (not arrival), newest job first", () => {
    const older = [line("j1", "fix", 1, "patch"), line("j1", "fix", 0, "sandbox")];
    const newer = [line("j2", "verify", 0, "prepare")];
    const runs = groupJobRuns([...older, ...newer]);
    expect(runs.map((r) => r.jobId)).toEqual(["j2", "j1"]);
    expect(runs[1].lines.map((l) => l.seq)).toEqual([0, 1]);
  });

  it("knows a fix is finished at 'done' and a verification at 'verdict'", () => {
    const fix = groupJobRuns([
      line("f", "fix", 0, "sandbox"),
      line("f", "fix", 1, "done", "success"),
    ])[0];
    const verify = groupJobRuns([
      line("v", "verify", 0, "done"),
      line("v", "verify", 1, "verdict", "warn"),
    ])[0];
    const running = groupJobRuns([line("r", "fix", 0, "rescan")])[0];
    expect([fix.finished, fix.finalLevel]).toEqual([true, "success"]);
    expect([verify.finished, verify.finalLevel]).toEqual([true, "warn"]);
    expect(running.finished).toBe(false);
  });

  it("pulls the container's isolation settings from its start line", () => {
    const run = groupJobRuns([
      line("f", "fix", 0, "sandbox", "info", {
        isolation: { network: "fixer_net", memory: "512m" },
      }),
    ])[0];
    expect(run.isolation).toEqual({ network: "fixer_net", memory: "512m" });
  });
});
