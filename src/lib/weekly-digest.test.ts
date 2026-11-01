import { describe, it, expect, beforeEach, vi } from "vitest";
import type { AdminClient } from "@/lib/supabase-admin.server";

// sendEmail is mocked so tests assert "would this have sent" without any
// real SMTP involved, and so we can assert exactly what was sent.
type SendEmailArgs = { to: string; subject: string; html: string; text: string };
const sendEmailMock = vi.fn(async (_args: SendEmailArgs) => {});
vi.mock("@/lib/email.server", () => ({ sendEmail: sendEmailMock }));

type Scan = { id: string; status: string; repository_id: string; security_score: number | null };
type Vuln = {
  id: string;
  scan_id: string;
  severity: string;
  verification_status: string;
  last_seen_scan_id?: string;
};

let scans: Scan[] = [];
let vulns: Vuln[] = [];
let prefs: { email_enabled: boolean; weekly_summary: boolean } | null = {
  email_enabled: true,
  weekly_summary: true,
};
let userEmail: string | null = "user@example.com";
let digestLogRows: Array<{ weekly_run_id: string; user_id: string }> = [];

function makeQuery(table: string) {
  const chain: any = {
    _filters: {} as Record<string, unknown>,
    eq(col: string, val: unknown) {
      chain._filters[col] = val;
      return chain;
    },
    in(col: string, vals: unknown[]) {
      chain._filters[col] = vals;
      return chain;
    },
    // findingsForScans asks for "scan_id.in.(…),last_seen_scan_id.in.(…)".
    or(expr: string) {
      chain._filters.or_ids = (/\(([^)]*)\)/.exec(expr)?.[1] ?? "").split(",");
      return chain;
    },
    select() {
      return chain;
    },
    maybeSingle() {
      if (table === "notification_preferences")
        return Promise.resolve({ data: prefs, error: null });
      return Promise.resolve({ data: null, error: null });
    },
    // Awaiting the chain directly (no maybeSingle) is how scans/vulnerabilities are read.
    then(resolve: any) {
      if (table === "scans") {
        return Promise.resolve({ data: scans, error: null }).then(resolve);
      }
      if (table === "vulnerabilities") {
        const orIds = chain._filters.or_ids as string[] | undefined;
        const ids = chain._filters.scan_id as string[] | undefined;
        const filtered = orIds
          ? vulns.filter(
              (v) =>
                orIds.includes(v.scan_id) ||
                (v.last_seen_scan_id !== undefined && orIds.includes(v.last_seen_scan_id)),
            )
          : ids
            ? vulns.filter((v) => ids.includes(v.scan_id))
            : vulns;
        return Promise.resolve({ data: filtered, error: null }).then(resolve);
      }
      return Promise.resolve({ data: null, error: null }).then(resolve);
    },
    insert(row: { weekly_run_id: string; user_id: string }) {
      const dup = digestLogRows.some(
        (r) => r.weekly_run_id === row.weekly_run_id && r.user_id === row.user_id,
      );
      if (dup) {
        return Promise.resolve({
          data: null,
          error: { code: "23505", message: "duplicate key value violates unique constraint" },
        });
      }
      digestLogRows.push(row);
      return Promise.resolve({ data: [row], error: null });
    },
  };
  return chain;
}

// Implements only the handful of methods maybeSendWeeklyDigest touches, so it
// is cast rather than made to satisfy the full SupabaseClient surface — the
// cast is the honest description of a stub, and keeping it here means the call
// sites below stay readable.
const supabaseStub = {
  from: (table: string) => makeQuery(table),
  auth: {
    admin: {
      getUserById: async () =>
        userEmail
          ? { data: { user: { email: userEmail } }, error: null }
          : { data: { user: null }, error: null },
    },
  },
} as unknown as AdminClient;

let maybeSendWeeklyDigest: typeof import("./weekly-digest.server").maybeSendWeeklyDigest;

beforeEach(async () => {
  scans = [];
  vulns = [];
  digestLogRows = [];
  prefs = { email_enabled: true, weekly_summary: true };
  userEmail = "user@example.com";
  sendEmailMock.mockClear();
  ({ maybeSendWeeklyDigest } = await import("./weekly-digest.server"));
});

const RUN = "11111111-1111-1111-1111-111111111111";
const USER = "22222222-2222-2222-2222-222222222222";

describe("maybeSendWeeklyDigest", () => {
  it("does nothing when the scan has no weekly_run_id (a manual scan)", async () => {
    await maybeSendWeeklyDigest(supabaseStub, USER, null);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("does not send while any scan in the run is still queued/running", async () => {
    scans = [
      { id: "s1", status: "completed", repository_id: "r1", security_score: 90 },
      { id: "s2", status: "running", repository_id: "r2", security_score: null },
    ];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("does not send while any finding is still pending verification", async () => {
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 40 }];
    vulns = [{ id: "v1", scan_id: "s1", severity: "high", verification_status: "pending" }];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("sends once every scan is terminal and every verification is resolved", async () => {
    scans = [
      { id: "s1", status: "completed", repository_id: "r1", security_score: 40 },
      { id: "s2", status: "failed", repository_id: "r2", security_score: null },
    ];
    vulns = [
      { id: "v1", scan_id: "s1", severity: "critical", verification_status: "confirmed" },
      { id: "v2", scan_id: "s1", severity: "low", verification_status: "unverified" },
    ];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(sendEmailMock.mock.calls[0][0].to).toBe("user@example.com");
  });

  // Findings are carried across scans: an issue first detected weeks ago and
  // re-confirmed by this week's scan keeps its original scan_id. Counting only
  // "detected in this run" would report a still-vulnerable repo as clean.
  it("counts a finding first detected earlier but seen again by this week's scan", async () => {
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 40 }];
    vulns = [
      {
        id: "v-old",
        scan_id: "s-last-month",
        last_seen_scan_id: "s1",
        severity: "critical",
        verification_status: "confirmed",
      },
    ];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    // Attributed to this week's scan in the per-repository line, not just the total.
    expect(sendEmailMock.mock.calls[0][0].html).toContain("score 40/100, 1 critical, 0 high");
    expect(sendEmailMock.mock.calls[0][0].text).toContain("1 high/critical finding this week");
  });

  it("still waits for a carried-over finding's pending re-verification", async () => {
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 40 }];
    vulns = [
      {
        id: "v-regressed",
        scan_id: "s-last-month",
        last_seen_scan_id: "s1",
        severity: "high",
        verification_status: "pending",
      },
    ];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("a failed scan counts as terminal, not stuck", async () => {
    scans = [{ id: "s1", status: "failed", repository_id: "r1", security_score: null }];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
  });

  it("does not send when email_enabled is off", async () => {
    prefs = { email_enabled: false, weekly_summary: true };
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 90 }];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("does not send when weekly_summary is off", async () => {
    prefs = { email_enabled: true, weekly_summary: false };
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 90 }];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("does not send (and does not throw) when the user has no email on file", async () => {
    userEmail = null;
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 90 }];
    await expect(maybeSendWeeklyDigest(supabaseStub, USER, RUN)).resolves.toBeUndefined();
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("does not log a send attempt for an opted-out user", async () => {
    prefs = { email_enabled: false, weekly_summary: true };
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 90 }];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(digestLogRows).toHaveLength(0);
  });

  // The core race guard: two callbacks (a scan finishing and a verification
  // finishing) can both independently decide "the run is done" moments apart.
  it("sends only once even when called twice for the same run", async () => {
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 90 }];
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    await maybeSendWeeklyDigest(supabaseStub, USER, RUN);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
  });

  it("treats a duplicate-key error on the claim as a benign skip, not a throw", async () => {
    digestLogRows.push({ weekly_run_id: RUN, user_id: USER });
    scans = [{ id: "s1", status: "completed", repository_id: "r1", security_score: 90 }];
    await expect(maybeSendWeeklyDigest(supabaseStub, USER, RUN)).resolves.toBeUndefined();
    expect(sendEmailMock).not.toHaveBeenCalled();
  });
});
