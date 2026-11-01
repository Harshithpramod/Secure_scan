import { describe, it, expect, beforeEach, vi } from "vitest";
import { createHmac } from "node:crypto";

const SECRET = "test-hmac-secret";

// Records every .eq() so tests can assert what a callback actually bound to —
// the binding is the security property here: it is what stops a replayed or
// stray callback from overwriting a different scan's verdict.
type Recorded = { table: string; update: Record<string, unknown>; eq: Record<string, unknown> };
let recorded: Recorded[] = [];
let updateResult: { data: unknown[] | null; error: unknown } = {
  data: [{ id: "v1" }],
  error: null,
};
let selectRow: unknown = null;
// Inserts (timeline events, job logs) and select filters, recorded for assertions.
let inserted: { table: string; row: Record<string, unknown> }[] = [];
let selects: Recorded[] = [];
let insertError: unknown = null;

function makeQuery(table: string, mode: "update" | "select", update: Record<string, unknown> = {}) {
  const entry: Recorded = { table, update, eq: {} };
  if (mode === "update") recorded.push(entry);
  else selects.push(entry);
  const chain: any = {
    eq(col: string, val: unknown) {
      entry.eq[col] = val;
      return chain;
    },
    select: () => (mode === "update" ? Promise.resolve(updateResult) : chain),
    maybeSingle: () => Promise.resolve({ data: selectRow, error: null }),
    then: (res: any) => Promise.resolve(updateResult).then(res),
  };
  return chain;
}

const supabaseStub = {
  from(table: string) {
    return {
      update: (values: Record<string, unknown>) => makeQuery(table, "update", values),
      select: () => makeQuery(table, "select"),
      insert: (rows: Record<string, unknown> | Record<string, unknown>[]) => {
        for (const row of Array.isArray(rows) ? rows : [rows]) inserted.push({ table, row });
        return Promise.resolve({ data: null, error: table === "job_logs" ? insertError : null });
      },
    };
  },
};

vi.mock("@/lib/supabase-admin.server", () => ({
  getSupabaseAdmin: () => supabaseStub,
}));

function sign(body: string, secret = SECRET) {
  return createHmac("sha256", secret).update(body).digest("hex");
}

function request(payload: unknown, opts: { signature?: string; secret?: string } = {}) {
  const body = JSON.stringify(payload);
  return new Request("https://app.test/api/public/sandbox-callback", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-sandbox-signature": opts.signature ?? sign(body, opts.secret ?? SECRET),
    },
    body,
  });
}

const verifyPayload = {
  kind: "verify",
  job_id: "job-1",
  scan_id: "scan-1",
  vulnerability_id: "vuln-1",
  verdict: { status: "confirmed", evidence: "found it" },
  duration_ms: 1234,
};

let handleSandboxCallback: (r: Request) => Promise<Response>;

beforeEach(async () => {
  recorded = [];
  inserted = [];
  selects = [];
  insertError = null;
  updateResult = { data: [{ id: "v1" }], error: null };
  selectRow = null;
  process.env.CALLBACK_HMAC_SECRET = SECRET;
  vi.resetModules();
  ({ handleSandboxCallback } = await import("./sandbox-callback.server"));
});

describe("HMAC verification", () => {
  it("accepts a correctly signed payload", async () => {
    expect((await handleSandboxCallback(request(verifyPayload))).status).toBe(200);
  });

  it("rejects a wrong signature", async () => {
    const res = await handleSandboxCallback(request(verifyPayload, { signature: "0".repeat(64) }));
    expect(res.status).toBe(401);
  });

  it("rejects a signature made with a different secret", async () => {
    const res = await handleSandboxCallback(request(verifyPayload, { secret: "other-secret" }));
    expect(res.status).toBe(401);
  });

  it("rejects a missing signature", async () => {
    const res = await handleSandboxCallback(request(verifyPayload, { signature: "" }));
    expect(res.status).toBe(401);
  });

  // timingSafeEqual throws on length mismatch; the handler must length-check first.
  it("rejects a short signature without throwing", async () => {
    const res = await handleSandboxCallback(request(verifyPayload, { signature: "abc" }));
    expect(res.status).toBe(401);
  });

  it("rejects a body altered after signing", async () => {
    const original = JSON.stringify(verifyPayload);
    const tampered = JSON.stringify({
      ...verifyPayload,
      verdict: { status: "not_exploitable", evidence: "" },
    });
    const res = await handleSandboxCallback(
      new Request("https://app.test/cb", {
        method: "POST",
        headers: { "x-sandbox-signature": sign(original) },
        body: tampered,
      }),
    );
    expect(res.status).toBe(401);
  });

  it("refuses to run at all when no secret is configured", async () => {
    delete process.env.CALLBACK_HMAC_SECRET;
    vi.resetModules();
    const mod = await import("./sandbox-callback.server");
    expect((await mod.handleSandboxCallback(request(verifyPayload))).status).toBe(500);
  });
});

describe("verify callbacks", () => {
  // sandbox_job_id is a fresh random id per submission, overwritten by the
  // next one, so it alone rejects stale/replayed callbacks. scan_id is NOT part
  // of the binding any more: a finding spans scans, and a re-scan moving it on
  // must not orphan a verification that is still running.
  it("binds the update to id AND sandbox_job_id", async () => {
    await handleSandboxCallback(request(verifyPayload));
    const update = recorded.find((r) => r.table === "vulnerabilities");
    expect(update?.eq).toEqual({ id: "vuln-1", sandbox_job_id: "job-1" });
  });

  it("accepts a verdict whose finding has since been seen by a newer scan", async () => {
    const { scan_id, ...noScan } = verifyPayload;
    expect((await handleSandboxCallback(request(noScan))).status).toBe(200);
  });

  it("puts the verdict on the finding's timeline", async () => {
    updateResult = {
      data: [{ id: "vuln-1", user_id: "owner-1", repository_id: "repo-1" }],
      error: null,
    };
    await handleSandboxCallback(request(verifyPayload));
    const ev = inserted.find((i) => i.table === "vulnerability_events");
    expect(ev?.row).toMatchObject({
      vulnerability_id: "vuln-1",
      user_id: "owner-1",
      kind: "verification",
      message: "Sandbox verification: confirmed",
    });
  });

  it("writes the verdict through", async () => {
    await handleSandboxCallback(request(verifyPayload));
    const update = recorded.find((r) => r.table === "vulnerabilities");
    expect(update?.update.verification_status).toBe("confirmed");
    expect(update?.update.verification_evidence).toBe("found it");
  });

  it("404s when the job id matches no row, instead of reporting success", async () => {
    updateResult = { data: [], error: null };
    expect((await handleSandboxCallback(request(verifyPayload))).status).toBe(404);
  });

  it("rejects a verdict status outside the allowed set", async () => {
    const res = await handleSandboxCallback(
      request({ ...verifyPayload, verdict: { status: "definitely_fine", evidence: "" } }),
    );
    expect(res.status).toBe(400);
  });

  it("treats a payload with no kind as a verify job (older sandbox builds)", async () => {
    const { kind, ...noKind } = verifyPayload;
    await handleSandboxCallback(request(noKind));
    expect(recorded.find((r) => r.table === "vulnerabilities")?.eq.sandbox_job_id).toBe("job-1");
  });

  it("rejects missing required fields", async () => {
    const res = await handleSandboxCallback(request({ ...verifyPayload, vulnerability_id: "" }));
    expect(res.status).toBe(400);
  });
});

describe("fix callbacks", () => {
  const fixPayload = {
    kind: "fix",
    job_id: "fixjob-1",
    scan_id: null,
    vulnerability_id: "vuln-1",
    verdict: {
      status: "pr_created",
      evidence: "opened",
      details: {
        pr_url: "https://github.com/o/r/pull/7",
        pr_number: 7,
        branch: "pentestai/fix-abc",
      },
    },
    duration_ms: 900,
  };

  // scan_id is nullable (ON DELETE SET NULL) and a fix can be requested long
  // after its scan is gone, so binding on scan_id would miss those rows.
  it("binds on id and fix_job_id only", async () => {
    await handleSandboxCallback(request(fixPayload));
    expect(recorded.find((r) => r.table === "vulnerabilities")?.eq).toEqual({
      id: "vuln-1",
      fix_job_id: "fixjob-1",
    });
  });

  it("records the PR details", async () => {
    await handleSandboxCallback(request(fixPayload));
    const u = recorded.find((r) => r.table === "vulnerabilities")!.update;
    expect(u.fix_status).toBe("pr_created");
    expect(u.fix_pr_url).toBe("https://github.com/o/r/pull/7");
    expect(u.fix_pr_number).toBe(7);
    expect(u.fix_error).toBeNull();
  });

  // "PR created" with no link is a broken result, not a success — the whole
  // point of the feature is handing the user something to open.
  it("downgrades pr_created with no URL to failed", async () => {
    await handleSandboxCallback(
      request({ ...fixPayload, verdict: { status: "pr_created", evidence: "hm", details: {} } }),
    );
    expect(recorded.find((r) => r.table === "vulnerabilities")!.update.fix_status).toBe("failed");
  });

  it("stores the failure reason where the UI can show it", async () => {
    await handleSandboxCallback(
      request({ ...fixPayload, verdict: { status: "failed", evidence: "file was deleted" } }),
    );
    const u = recorded.find((r) => r.table === "vulnerabilities")!.update;
    expect(u.fix_status).toBe("failed");
    expect(u.fix_error).toBe("file was deleted");
  });

  it("rejects an unknown fix status", async () => {
    const res = await handleSandboxCallback(
      request({ ...fixPayload, verdict: { status: "merged", evidence: "" } }),
    );
    expect(res.status).toBe(400);
  });
});

describe("scan callbacks", () => {
  const progressPayload = {
    kind: "scan_progress",
    job_id: "scanjob-1",
    scan_id: "scan-1",
    stage: "analyzing",
    progress: 65,
    message: "Running AI security analysis…",
    level: "info",
  };

  it("404s when the job id does not match the scan row", async () => {
    selectRow = null;
    expect((await handleSandboxCallback(request(progressPayload))).status).toBe(404);
  });

  it("updates stage and progress for a live scan", async () => {
    selectRow = {
      id: "scan-1",
      user_id: "u1",
      repository_id: "r1",
      status: "running",
      started_at: null,
    };
    await handleSandboxCallback(request(progressPayload));
    const u = recorded.find((r) => r.table === "scans")!.update;
    expect(u.current_stage).toBe("analyzing");
    expect(u.progress).toBe(65);
    expect(u.status).toBe("running");
  });

  it("ignores an out-of-range progress value rather than writing it", async () => {
    selectRow = {
      id: "scan-1",
      user_id: "u1",
      repository_id: "r1",
      status: "running",
      started_at: null,
    };
    await handleSandboxCallback(request({ ...progressPayload, progress: 900 }));
    expect(recorded.find((r) => r.table === "scans")!.update).not.toHaveProperty("progress");
  });

  // A late progress callback must not resurrect a scan that already finished.
  it("does not reopen an already-completed scan", async () => {
    selectRow = {
      id: "scan-1",
      user_id: "u1",
      repository_id: "r1",
      status: "completed",
      started_at: null,
    };
    const res = await handleSandboxCallback(request(progressPayload));
    expect(res.status).toBe(200);
    expect(recorded.filter((r) => r.table === "scans")).toHaveLength(0);
  });

  it("marks the scan failed when the sandbox reports a failure", async () => {
    selectRow = {
      id: "scan-1",
      user_id: "u1",
      repository_id: "r1",
      status: "running",
      started_at: null,
      repositories: { id: "r1", full_name: "o/r", default_branch: "main" },
    };
    await handleSandboxCallback(
      request({
        kind: "scan",
        job_id: "scanjob-1",
        scan_id: "scan-1",
        verdict: { status: "failed", evidence: "GEMINI_API_KEY is not configured" },
        duration_ms: 10,
      }),
    );
    const u = recorded.find((r) => r.table === "scans")!.update;
    expect(u.status).toBe("failed");
    expect(u.error_message).toContain("GEMINI_API_KEY");
  });

  // Duplicate delivery must not insert the same findings twice.
  it("ignores a result for a scan that already reached a terminal state", async () => {
    selectRow = {
      id: "scan-1",
      user_id: "u1",
      repository_id: "r1",
      status: "completed",
      started_at: null,
      repositories: { id: "r1", full_name: "o/r", default_branch: "main" },
    };
    const res = await handleSandboxCallback(
      request({
        kind: "scan",
        job_id: "scanjob-1",
        scan_id: "scan-1",
        verdict: { status: "completed", evidence: "", details: { findings: [] } },
        duration_ms: 10,
      }),
    );
    expect(res.status).toBe(200);
    expect(recorded.filter((r) => r.table === "scans")).toHaveLength(0);
  });
});

describe("job_progress (live sandbox console)", () => {
  const progress = {
    kind: "job_progress",
    job_kind: "fix",
    job_id: "job-9",
    vulnerability_id: "vuln-1",
    seq: 3,
    stage: "rescan",
    level: "warn",
    message: "Attempt 1 re-scan: rejected",
    data: { attempt: 1 },
  };
  const logRow = () => inserted.find((i) => i.table === "job_logs")?.row;

  beforeEach(() => {
    selectRow = { id: "vuln-1", user_id: "owner-1" };
  });

  it("only accepts a line for the job the finding currently owns", async () => {
    await handleSandboxCallback(request(progress));
    expect(selects.find((q) => q.table === "vulnerabilities")?.eq).toEqual({
      id: "vuln-1",
      fix_job_id: "job-9",
    });
  });

  it("binds verify lines on sandbox_job_id", async () => {
    await handleSandboxCallback(request({ ...progress, job_kind: "verify" }));
    expect(selects.find((q) => q.table === "vulnerabilities")?.eq).toEqual({
      id: "vuln-1",
      sandbox_job_id: "job-9",
    });
  });

  it("404s a line for a job the finding doesn't own", async () => {
    selectRow = null;
    expect((await handleSandboxCallback(request(progress))).status).toBe(404);
    expect(logRow()).toBeUndefined();
  });

  it("takes the owner from the finding, never from the payload", async () => {
    await handleSandboxCallback(request({ ...progress, user_id: "someone-else" }));
    expect(logRow()).toMatchObject({ user_id: "owner-1", seq: 3, level: "warn", stage: "rescan" });
  });

  it("clamps an unknown level and an overlong message", async () => {
    await handleSandboxCallback(
      request({ ...progress, level: "<script>", message: "x".repeat(5000) }),
    );
    expect(logRow()?.level).toBe("info");
    expect(String(logRow()?.message)).toHaveLength(1000);
  });

  it("drops an oversized data payload but keeps the line", async () => {
    await handleSandboxCallback(request({ ...progress, data: { diff: "y".repeat(50_000) } }));
    expect(logRow()?.data).toEqual({ truncated: true });
  });

  it("accepts and drops lines before the migration creates job_logs", async () => {
    insertError = { code: "PGRST205", message: "Could not find the table 'public.job_logs'" };
    expect((await handleSandboxCallback(request(progress))).status).toBe(202);
  });

  it("treats a re-sent line (same job and seq) as already stored", async () => {
    insertError = { code: "23505", message: "duplicate key" };
    expect((await handleSandboxCallback(request(progress))).status).toBe(200);
  });

  it("rejects an unknown job kind or a missing sequence number", async () => {
    expect((await handleSandboxCallback(request({ ...progress, job_kind: "scan" }))).status).toBe(
      400,
    );
    const { seq, ...noSeq } = progress;
    expect((await handleSandboxCallback(request(noSeq))).status).toBe(400);
  });
});
