import { describe, expect, it } from "vitest";
import {
  MAX_EVENTS_PER_JOB,
  createJobReporter,
  lineSplitter,
  redactDeep,
  redactText,
} from "./job-stream.js";

describe("lineSplitter", () => {
  it("reassembles lines split across chunks and handles CRLF", () => {
    const lines = [];
    const feed = lineSplitter((l) => lines.push(l));
    feed('@@progress {"a"');
    feed(":1}\r\nsecond li");
    feed("ne\nthird");
    feed(null);
    expect(lines).toEqual(['@@progress {"a":1}', "second line", "third"]);
  });
});

describe("redactText", () => {
  it.each([
    ["AWS key", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"],
    ["GitHub token", "token ghp_" + "a".repeat(36), "ghp_" + "a".repeat(36)],
    ["quoted secret in a diff line", '-const API_KEY = "abc123def456";', "abc123def456"],
    ["quoted password literal", "password: 'hunter2hunter2'", "hunter2hunter2"],
    [".env line", "+DATABASE_PASSWORD=s3cr3tvalue", "s3cr3tvalue"],
    ["JWT", "Bearer eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl", "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"],
  ])("hides a %s", (_label, input, secret) => {
    const out = redactText(input);
    expect(out).not.toContain(secret);
    expect(out).toContain("[redacted]");
  });

  // Real lines from the RESUME repo's script.js and the fix that passed its
  // re-scan. Over-eager redaction would turn every fix diff into mush.
  it.each([
    "    const password = document.getElementById('password').value;",
    "      if (user.username === loginU && user.password === loginP) {",
    "+      const hashedPassword = await hashPassword(password);",
    "+      const user = { fullname, username, password: hashedPassword, gender, dob };",
    "-    // Save new user (with password)",
  ])("leaves ordinary code alone: %s", (line) => {
    expect(redactText(line)).toBe(line);
  });
});

describe("redactDeep", () => {
  it("redacts strings at any depth and drops non-JSON values", () => {
    const out = redactDeep({
      diff: '+const TOKEN = "abcdef123456"',
      findings: [{ title: "Hardcoded AKIAIOSFODNN7EXAMPLE" }],
      fn: () => 1,
    });
    expect(JSON.stringify(out)).not.toContain("abcdef123456");
    expect(JSON.stringify(out)).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out.fn).toBeNull();
  });
});

describe("createJobReporter", () => {
  const job = { id: "job-1", vulnerability_id: "vuln-1", scan_id: "scan-1" };

  it("sequences lines and delivers them in order", async () => {
    const sent = [];
    const r = createJobReporter(job, "fix", async (p) => sent.push(p));
    r.emit("sandbox", "starting");
    r.relay({ stage: "patch", message: "attempt 1", level: "warn", data: { attempt: 1 } });
    await r.flush();
    expect(sent.map((p) => [p.seq, p.stage, p.level])).toEqual([
      [0, "sandbox", "info"],
      [1, "patch", "warn"],
    ]);
    expect(sent[0]).toMatchObject({
      kind: "job_progress",
      job_kind: "fix",
      job_id: "job-1",
      vulnerability_id: "vuln-1",
    });
  });

  it("re-validates what a container sends", async () => {
    const sent = [];
    const r = createJobReporter(job, "verify", async (p) => sent.push(p));
    r.relay(null);
    r.relay({ stage: "x".repeat(100), message: "m".repeat(5000), level: "<b>" });
    r.relay({ message: 42 });
    await r.flush();
    expect(sent).toHaveLength(1);
    expect(sent[0].stage).toHaveLength(40);
    expect(sent[0].message).toHaveLength(1000);
    expect(sent[0].level).toBe("info");
  });

  it("stops at the per-job cap with a visible notice", async () => {
    const sent = [];
    const r = createJobReporter(job, "fix", async (p) => sent.push(p));
    for (let i = 0; i < MAX_EVENTS_PER_JOB + 50; i++) r.emit("x", `line ${i}`);
    await r.flush();
    expect(sent).toHaveLength(MAX_EVENTS_PER_JOB);
    expect(sent.at(-1).stage).toBe("limit");
  });

  it("keeps going when one delivery fails", async () => {
    const sent = [];
    let first = true;
    const r = createJobReporter(job, "fix", async (p) => {
      if (first) {
        first = false;
        throw new Error("network");
      }
      sent.push(p);
    });
    r.emit("a", "one");
    r.emit("b", "two");
    await r.flush();
    expect(sent.map((p) => p.message)).toEqual(["two"]);
  });
});
