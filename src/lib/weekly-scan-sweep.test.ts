import { describe, it, expect, beforeEach, vi } from "vitest";

const TOKEN = "test-sandbox-token";

let dueRepos: Array<{ id: string; user_id: string; full_name: string }> = [];
let reposError: unknown = null;

const supabaseStub = {
  from: (table: string) => {
    if (table !== "repositories") throw new Error(`unexpected table ${table}`);
    const chain: any = {
      select: () => chain,
      eq: () => chain,
      or: () => Promise.resolve({ data: dueRepos, error: reposError }),
    };
    return chain;
  },
};

vi.mock("@/lib/supabase-admin.server", () => ({
  getSupabaseAdmin: () => supabaseStub,
}));

const triggerScanMock = vi.fn();
vi.mock("@/lib/scan-trigger.server", () => ({
  triggerScan: (...args: unknown[]) => triggerScanMock(...args),
}));

function request(headers: Record<string, string> = { authorization: `Bearer ${TOKEN}` }) {
  return new Request("https://app.test/api/public/run-weekly-scans", {
    method: "POST",
    headers,
  });
}

let handleWeeklySweepRequest: typeof import("./weekly-scan-sweep.server").handleWeeklySweepRequest;

beforeEach(async () => {
  dueRepos = [];
  reposError = null;
  triggerScanMock.mockReset();
  triggerScanMock.mockResolvedValue({ ok: true, scanId: "scan-x" });
  process.env.SANDBOX_API_TOKEN = TOKEN;
  delete process.env.WEEKLY_SWEEP_INTERVAL_HOURS;
  vi.resetModules();
  ({ handleWeeklySweepRequest } = await import("./weekly-scan-sweep.server"));
});

describe("auth", () => {
  it("rejects a missing token", async () => {
    const res = await handleWeeklySweepRequest(request({}));
    expect(res.status).toBe(401);
  });

  it("rejects a wrong token", async () => {
    const res = await handleWeeklySweepRequest(request({ authorization: "Bearer wrong" }));
    expect(res.status).toBe(401);
  });

  it("accepts the token the app already uses for app->sandbox job submission", async () => {
    const res = await handleWeeklySweepRequest(request());
    expect(res.status).toBe(200);
  });

  it("refuses to run if SANDBOX_API_TOKEN isn't configured, rather than accepting anything", async () => {
    delete process.env.SANDBOX_API_TOKEN;
    const res = await handleWeeklySweepRequest(request());
    expect(res.status).toBe(500);
  });
});

describe("sweep", () => {
  it("does nothing and reports zero when no repository is due", async () => {
    dueRepos = [];
    const res = await handleWeeklySweepRequest(request());
    const body = await res.json();
    expect(body).toEqual({ weeklyRunId: null, triggered: 0, skipped: 0 });
    expect(triggerScanMock).not.toHaveBeenCalled();
  });

  it("triggers every due repository with trigger='scheduled' and one shared weekly_run_id", async () => {
    dueRepos = [
      { id: "r1", user_id: "u1", full_name: "u1/repo-a" },
      { id: "r2", user_id: "u2", full_name: "u2/repo-b" },
    ];
    const res = await handleWeeklySweepRequest(request());
    const body = await res.json();

    expect(triggerScanMock).toHaveBeenCalledTimes(2);
    const call1 = triggerScanMock.mock.calls[0][1];
    const call2 = triggerScanMock.mock.calls[1][1];
    expect(call1.trigger).toBe("scheduled");
    expect(call1.weeklyRunId).toBe(body.weeklyRunId);
    expect(call2.weeklyRunId).toBe(call1.weeklyRunId);
    expect(body.triggered).toBe(2);
    expect(body.skipped).toBe(0);
  });

  it("counts a rejected trigger (e.g. already running) as skipped, not an error", async () => {
    dueRepos = [{ id: "r1", user_id: "u1", full_name: "u1/repo-a" }];
    triggerScanMock.mockResolvedValueOnce({
      ok: false,
      reason: "already_running",
      message: "A scan is already running for this repository.",
    });
    const res = await handleWeeklySweepRequest(request());
    const body = await res.json();
    expect(body).toEqual({ weeklyRunId: expect.any(String), triggered: 0, skipped: 1 });
  });

  it("one repository throwing (e.g. no GitHub token) does not abort the rest of the sweep", async () => {
    dueRepos = [
      { id: "r1", user_id: "u1", full_name: "u1/broken" },
      { id: "r2", user_id: "u2", full_name: "u2/fine" },
    ];
    triggerScanMock
      .mockRejectedValueOnce(new Error("GitHub is not connected"))
      .mockResolvedValueOnce({ ok: true, scanId: "scan-2" });

    const res = await handleWeeklySweepRequest(request());
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.triggered).toBe(1);
    expect(body.skipped).toBe(1);
  });

  it("surfaces a database error without silently reporting success", async () => {
    reposError = { message: "connection refused" };
    const res = await handleWeeklySweepRequest(request());
    expect(res.status).toBe(500);
    expect(triggerScanMock).not.toHaveBeenCalled();
  });
});
