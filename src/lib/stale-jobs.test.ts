import { describe, it, expect, beforeEach, vi } from "vitest";
import type { AdminClient } from "@/lib/supabase-admin.server";

const failScanMock = vi.fn(async (..._args: unknown[]) => {});
vi.mock("@/lib/scan-results.server", () => ({ failScan: failScanMock }));
const digestMock = vi.fn(async (..._args: unknown[]) => {});
vi.mock("@/lib/weekly-digest.server", () => ({ maybeSendWeeklyDigest: digestMock }));

type Call = { table: string; update?: Record<string, unknown>; filters: Record<string, unknown> };
let calls: Call[] = [];
let staleScans: Record<string, unknown>[] = [];

// Records every filter, and answers each query when awaited.
function stub() {
  return {
    from(table: string) {
      const call: Call = { table, filters: {} };
      calls.push(call);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- self-referencing query-builder stub
      const chain: any = {
        select: () => chain,
        update(values: Record<string, unknown>) {
          call.update = values;
          return chain;
        },
        in(col: string, v: unknown) {
          call.filters[`${col}.in`] = v;
          return chain;
        },
        eq(col: string, v: unknown) {
          call.filters[`${col}.eq`] = v;
          return chain;
        },
        lt(col: string, v: unknown) {
          call.filters[`${col}.lt`] = v;
          return chain;
        },
        then: (resolve: (v: unknown) => unknown) =>
          Promise.resolve({
            data: table === "scans" ? staleScans : [{ id: "v1" }],
            error: null,
          }).then(resolve),
      };
      return chain;
    },
  } as unknown as AdminClient;
}

describe("reapStaleJobs", () => {
  const NOW = Date.parse("2026-11-14T12:00:00Z");

  beforeEach(() => {
    calls = [];
    staleScans = [];
    failScanMock.mockClear();
    digestMock.mockClear();
  });

  it("fails silent scans, pending verifications and pending fixes past their cutoffs", async () => {
    const { reapStaleJobs, STALE_AFTER_MS } = await import("@/lib/stale-jobs.server");
    staleScans = [
      { id: "s1", user_id: "u1", repository_id: "r1", weekly_run_id: null },
      { id: "s2", user_id: "u1", repository_id: "r2", weekly_run_id: "w1" },
    ];

    const reaped = await reapStaleJobs(stub(), NOW);

    expect(reaped).toEqual({ scans: 2, verifications: 1, fixes: 1 });
    const iso = (ms: number) => new Date(NOW - ms).toISOString();

    const [scans, verifications, fixes] = calls;
    // Only in-flight scans, judged by last sign of life — never completed ones.
    expect(scans.filters).toEqual({
      "status.in": ["queued", "running"],
      "updated_at.lt": iso(STALE_AFTER_MS.scan),
    });
    expect(failScanMock).toHaveBeenCalledTimes(2);
    expect(failScanMock.mock.calls[0][1]).toMatchObject({ id: "s1" });

    expect(verifications.update).toMatchObject({ verification_status: "failed" });
    expect(verifications.filters).toEqual({
      "verification_status.eq": "pending",
      "updated_at.lt": iso(STALE_AFTER_MS.verification),
    });

    expect(fixes.update).toMatchObject({ fix_status: "failed" });
    expect(fixes.filters).toEqual({
      "fix_status.eq": "pending",
      "fix_requested_at.lt": iso(STALE_AFTER_MS.fix),
    });

    // Only the scan that belonged to a weekly run nudges its digest.
    expect(digestMock).toHaveBeenCalledTimes(1);
    expect(digestMock.mock.calls[0].slice(1)).toEqual(["u1", "w1"]);
  });

  it("the quiet variant swallows a database failure", async () => {
    const { reapStaleJobsQuietly } = await import("@/lib/stale-jobs.server");
    const broken = {
      from: () => {
        throw new Error("db down");
      },
    } as unknown as AdminClient;
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(reapStaleJobsQuietly(broken)).resolves.toBeUndefined();
    spy.mockRestore();
  });
});
