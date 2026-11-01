// Pure shaping of lifecycle events and sandbox job logs for display. Kept out
// of the components so the rules (what collapses, what counts as a
// regression, when a job is finished) are testable without rendering.

export type VulnEvent = {
  id: string;
  kind: string;
  message: string | null;
  data: unknown;
  created_at: string;
  scan_id?: string | null;
};

export type TimelineTone = "neutral" | "good" | "bad" | "warn" | "accent";
export type TimelineIcon =
  | "detected"
  | "seen"
  | "not_seen"
  | "fixed"
  | "regressed"
  | "status"
  | "false_positive"
  | "duplicate"
  | "verify_confirmed"
  | "verify_clear"
  | "verify_failed"
  | "fix_requested"
  | "fix_pr"
  | "fix_rejected";

export type TimelineItem = {
  key: string;
  icon: TimelineIcon;
  tone: TimelineTone;
  title: string;
  detail?: string;
  at: string;
  /** For collapsed runs of "seen again": the last one. */
  until?: string;
  count?: number;
  href?: string;
};

const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  in_progress: "Triaged",
  fixed: "Fixed",
  false_positive: "False positive",
};

const obj = (d: unknown): Record<string, unknown> =>
  d && typeof d === "object" && !Array.isArray(d) ? (d as Record<string, unknown>) : {};

/**
 * Chronological timeline items. Consecutive "seen again" events collapse into
 * one row ("Seen again in 5 scans"): a finding that sits unfixed for months
 * would otherwise bury everything that actually happened to it.
 */
export function toTimeline(events: VulnEvent[], detectedAt?: string | null): TimelineItem[] {
  const sorted = [...events].sort((a, b) => a.created_at.localeCompare(b.created_at));
  const items: TimelineItem[] = [];

  // Rows created before the lifecycle migration have no "detected" event.
  if (detectedAt && !sorted.some((e) => e.kind === "detected")) {
    items.push({
      key: "detected-synthetic",
      icon: "detected",
      tone: "neutral",
      title: "First detected",
      at: detectedAt,
    });
  }

  for (const e of sorted) {
    const d = obj(e.data);
    const last = items[items.length - 1];
    switch (e.kind) {
      case "detected":
        items.push({
          key: e.id,
          icon: "detected",
          tone: "neutral",
          title: "First detected",
          detail: e.message ?? undefined,
          at: e.created_at,
        });
        break;
      case "seen":
        // A regression's "seen" is told by its status change instead.
        if (d.regressed) break;
        if (last?.icon === "seen") {
          last.count = (last.count ?? 1) + 1;
          last.until = e.created_at;
          last.title = `Seen again in ${last.count} scans`;
        } else {
          items.push({
            key: e.id,
            icon: "seen",
            tone: "neutral",
            title: "Seen again in a scan",
            detail: e.message ?? undefined,
            at: e.created_at,
            count: 1,
          });
        }
        break;
      case "not_seen":
        items.push({
          key: e.id,
          icon: "not_seen",
          tone: "warn",
          title: "Not detected in a scan",
          detail: e.message ?? undefined,
          at: e.created_at,
        });
        break;
      case "status_changed": {
        const from = String(d.from ?? "");
        const to = String(d.to ?? "");
        const reason = e.message ?? undefined;
        if (from === "fixed" && (to === "open" || to === "in_progress")) {
          items.push({
            key: e.id,
            icon: "regressed",
            tone: "bad",
            title: "Regressed",
            detail: reason,
            at: e.created_at,
          });
        } else if (to === "fixed") {
          items.push({
            key: e.id,
            icon: "fixed",
            tone: "good",
            title: "Marked fixed",
            detail: reason,
            at: e.created_at,
          });
        } else if (to === "false_positive") {
          items.push({
            key: e.id,
            icon: "false_positive",
            tone: "neutral",
            title: "Marked as a false positive",
            detail: reason,
            at: e.created_at,
          });
        } else {
          items.push({
            key: e.id,
            icon: "status",
            tone: "neutral",
            title: `Status: ${STATUS_LABEL[from] ?? from} → ${STATUS_LABEL[to] ?? to}`,
            detail: reason,
            at: e.created_at,
          });
        }
        break;
      }
      case "duplicate_merged":
        items.push({
          key: e.id,
          icon: "duplicate",
          tone: "neutral",
          title: "Duplicate merged",
          detail: e.message ?? undefined,
          at: e.created_at,
        });
        break;
      case "verification": {
        const status = String(d.status ?? "");
        items.push({
          key: e.id,
          icon:
            status === "confirmed"
              ? "verify_confirmed"
              : status === "failed"
                ? "verify_failed"
                : "verify_clear",
          tone: status === "confirmed" ? "bad" : status === "failed" ? "warn" : "good",
          title: e.message ?? "Sandbox verification",
          detail: typeof d.evidence === "string" && d.evidence ? d.evidence : undefined,
          at: e.created_at,
        });
        break;
      }
      case "fix_requested":
        items.push({
          key: e.id,
          icon: "fix_requested",
          tone: "accent",
          title: "AI fix requested",
          at: e.created_at,
        });
        break;
      case "fix_pr_opened":
        items.push({
          key: e.id,
          icon: "fix_pr",
          tone: "good",
          title: e.message ?? "Verified fix opened",
          at: e.created_at,
          href: typeof d.pr_url === "string" ? d.pr_url : undefined,
        });
        break;
      case "fix_rejected":
        items.push({
          key: e.id,
          icon: "fix_rejected",
          tone: "warn",
          title: "AI fix not opened",
          detail: e.message ?? undefined,
          at: e.created_at,
        });
        break;
      default:
        items.push({
          key: e.id,
          icon: "status",
          tone: "neutral",
          title: e.kind,
          detail: e.message ?? undefined,
          at: e.created_at,
        });
    }
  }
  return items;
}

// ---------------------------------------------------------------------------
// Sandbox job logs
// ---------------------------------------------------------------------------

export type JobLogLine = {
  id: string;
  job_id: string;
  job_kind: string;
  seq: number;
  stage: string | null;
  level: string;
  message: string;
  data: unknown;
  created_at: string;
};

export type JobRun = {
  jobId: string;
  kind: "verify" | "fix";
  lines: JobLogLine[];
  startedAt: string;
  lastAt: string;
  finished: boolean;
  /** Level of the final line once finished: "success", "warn" or "error". */
  finalLevel: string | null;
  isolation: Record<string, string> | null;
};

/** The worker's and containers' last words: nothing follows these. */
const FINAL_STAGES: Record<string, string> = { fix: "done", verify: "verdict" };

/** One run per job, newest first, lines in the order they were emitted. */
export function groupJobRuns(lines: JobLogLine[]): JobRun[] {
  const byJob = new Map<string, JobLogLine[]>();
  for (const l of lines) {
    if (!byJob.has(l.job_id)) byJob.set(l.job_id, []);
    byJob.get(l.job_id)!.push(l);
  }
  const runs: JobRun[] = [];
  for (const [jobId, list] of byJob) {
    list.sort((a, b) => a.seq - b.seq);
    const kind = list[0].job_kind === "verify" ? "verify" : "fix";
    const final = list[list.length - 1];
    const finished = final.stage === FINAL_STAGES[kind];
    const isolationLine = list.find(
      (l) => obj(obj(l.data).isolation) && Object.keys(obj(obj(l.data).isolation)).length > 0,
    );
    const times = list.map((l) => l.created_at).sort();
    runs.push({
      jobId,
      kind,
      lines: list,
      startedAt: times[0],
      lastAt: times[times.length - 1],
      finished,
      finalLevel: finished ? final.level : null,
      isolation: isolationLine
        ? (Object.fromEntries(
            Object.entries(obj(obj(isolationLine.data).isolation)).map(([k, v]) => [k, String(v)]),
          ) as Record<string, string>)
        : null,
    });
  }
  return runs.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
}
