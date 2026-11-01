import { useEffect, useRef, useState } from "react";
import { ChevronRight, ExternalLink, Lock, Terminal } from "lucide-react";
import type { JobLogLine, JobRun } from "@/lib/activity-format";

const LEVEL_CLASS: Record<string, string> = {
  info: "text-foreground/85",
  warn: "text-medium",
  error: "text-critical",
  success: "text-low",
};

const ISOLATION_LABELS: [key: string, label: string][] = [
  ["network", "Network"],
  ["filesystem", "Filesystem"],
  ["repository", "Repository"],
  ["capabilities", "Capabilities"],
  ["privileges", "Privileges"],
  ["credentials", "Credentials"],
  ["cpus", "CPU"],
  ["memory", "Memory"],
  ["processes", "Max processes"],
  ["timeout", "Hard timeout"],
];

const obj = (d: unknown): Record<string, unknown> =>
  d && typeof d === "object" && !Array.isArray(d) ? (d as Record<string, unknown>) : {};

type BriefFinding = { title?: string; line_start?: number | null; severity?: string };

function statusOf(run: JobRun): { label: string; className: string } {
  if (!run.finished) return { label: "live", className: "text-low" };
  if (run.kind === "fix") {
    return run.finalLevel === "success"
      ? { label: "PR opened", className: "text-low" }
      : { label: "no PR", className: "text-critical" };
  }
  if (run.finalLevel === "warn") return { label: "confirmed", className: "text-medium" };
  if (run.finalLevel === "error") return { label: "failed", className: "text-critical" };
  return { label: "not confirmed", className: "text-low" };
}

function DiffView({ diff, truncated }: { diff: string; truncated?: boolean }) {
  return (
    <div className="mt-1.5 overflow-x-auto rounded-md border border-border bg-muted/30">
      <pre className="min-w-max px-3 py-2 text-[0.6875rem] leading-5">
        {diff.split("\n").map((l, i) => (
          <div
            key={i}
            className={
              l.startsWith("@@")
                ? "text-accent-fg"
                : l.startsWith("+")
                  ? "bg-low/10 text-low"
                  : l.startsWith("-")
                    ? "bg-critical/10 text-critical"
                    : "text-muted-foreground"
            }
          >
            {l || " "}
          </div>
        ))}
        {truncated && <div className="italic text-muted-foreground">… diff truncated</div>}
      </pre>
    </div>
  );
}

function FindingList({
  label,
  items,
  tone,
}: {
  label: string;
  items: BriefFinding[];
  tone: string;
}) {
  if (items.length === 0) return null;
  return (
    <div className="mt-1 space-y-0.5 pl-[7.5rem]">
      {items.map((f, i) => (
        <div key={i} className={`flex gap-1.5 ${tone}`}>
          <span aria-hidden>•</span>
          <span className="min-w-0 break-words">
            <span className="text-muted-foreground">{label}:</span> {f.title}
            {f.line_start ? (
              <span className="text-muted-foreground"> · line {f.line_start}</span>
            ) : null}
          </span>
        </div>
      ))}
    </div>
  );
}

function ConsoleLine({
  line,
  t0,
  diffOpenByDefault,
}: {
  line: JobLogLine;
  t0: number;
  diffOpenByDefault: boolean;
}) {
  const d = obj(line.data);
  const [diffOpen, setDiffOpen] = useState(diffOpenByDefault);
  const offset = Math.max(0, Math.round((Date.parse(line.created_at) - t0) / 1000));
  const diff = typeof d.diff === "string" && d.diff ? d.diff : null;
  const prUrl = typeof d.pr_url === "string" ? d.pr_url : null;

  return (
    <div>
      <div className="flex gap-2">
        <span className="w-11 shrink-0 text-right tabular-nums text-muted-foreground/60">
          +{offset}s
        </span>
        <span className="w-[4.25rem] shrink-0 truncate text-muted-foreground/70">
          {line.stage ?? ""}
        </span>
        <span className={`min-w-0 break-words ${LEVEL_CLASS[line.level] ?? LEVEL_CLASS.info}`}>
          {line.message}
          {prUrl && (
            <a
              href={prUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-2 inline-flex items-center gap-1 text-accent-fg underline-offset-2 hover:underline"
            >
              view <ExternalLink aria-hidden className="h-3 w-3" />
            </a>
          )}
        </span>
      </div>
      <FindingList
        label="still detected"
        items={(Array.isArray(d.stillPresent) ? d.stillPresent : []) as BriefFinding[]}
        tone="text-critical"
      />
      <FindingList
        label="new"
        items={(Array.isArray(d.introduced) ? d.introduced : []) as BriefFinding[]}
        tone="text-medium"
      />
      {diff && (
        <div className="pl-[7.5rem]">
          <button
            type="button"
            onClick={() => setDiffOpen((o) => !o)}
            aria-expanded={diffOpen}
            className="mt-1 inline-flex cursor-pointer items-center gap-1 rounded text-[0.6875rem] text-accent-fg hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            <ChevronRight
              aria-hidden
              className={`h-3 w-3 transition-transform motion-reduce:transition-none ${diffOpen ? "rotate-90" : ""}`}
            />
            {diffOpen ? "Hide" : "Show"} the patch
          </button>
          {diffOpen && <DiffView diff={diff} truncated={Boolean(d.truncated)} />}
        </div>
      )}
    </div>
  );
}

const ATTEMPT_START = /^Attempt (\d+)\/(\d+): asking/;

/**
 * Live view of one sandbox job: the container's real isolation settings and
 * every progress line it emitted. For fix jobs that includes each attempt's
 * patch and what the re-scan said about it.
 */
export function SandboxConsole({
  run,
  waitingLabel,
}: {
  run: JobRun | null;
  /** Shown when a job is queued but has produced no lines yet. */
  waitingLabel?: string;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);
  const lineCount = run?.lines.length ?? 0;
  const live = run ? !run.finished : Boolean(waitingLabel);

  useEffect(() => {
    const el = scrollRef.current;
    if (el && live && stickToBottom.current) el.scrollTop = el.scrollHeight;
  }, [lineCount, live]);

  const status = run ? statusOf(run) : { label: "queued", className: "text-muted-foreground" };
  const container =
    run?.isolation?.container ?? (run ? `${run.kind}-${run.jobId.slice(0, 8)}` : "waiting");
  const t0 = run ? Date.parse(run.startedAt) : 0;
  const lastPatchSeq = run
    ? [...run.lines].reverse().find((l) => typeof obj(l.data).diff === "string")?.seq
    : undefined;
  const seconds = run ? Math.round((Date.parse(run.lastAt) - t0) / 1000) : 0;

  return (
    // contain: inline-size — the console takes its width from its container
    // and never from its contents. Without it, one long unbreakable line (a
    // diff, a file path) propagated its width up through the dialog's grid and
    // gave the whole dialog a horizontal scrollbar; the diffs' own
    // overflow-x-auto boxes can't stop that in block layout.
    <div className="overflow-hidden rounded-lg border border-border bg-background [contain:inline-size]">
      <div className="flex items-center gap-2 border-b border-border bg-muted/40 px-3 py-2">
        <span aria-hidden className="h-2 w-2 rounded-full bg-critical/60" />
        <span aria-hidden className="h-2 w-2 rounded-full bg-medium/60" />
        <span aria-hidden className="h-2 w-2 rounded-full bg-low/60" />
        <span className="ml-2 flex min-w-0 items-center gap-1.5 font-mono text-xs text-muted-foreground">
          <Terminal aria-hidden className="h-3.5 w-3.5 shrink-0" />
          <span className="truncate">sandbox · {container}</span>
        </span>
        <span
          className={`ml-auto flex shrink-0 items-center gap-1.5 font-mono text-[0.6875rem] ${status.className}`}
        >
          {live && (
            <span
              aria-hidden
              className="h-1.5 w-1.5 animate-pulse rounded-full bg-current motion-reduce:animate-none"
            />
          )}
          {status.label}
          {run?.finished && <span className="text-muted-foreground">· {seconds}s</span>}
        </span>
      </div>

      {run?.isolation && (
        <details open={!run.finished} className="group border-b border-border px-3 py-2">
          <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[0.6875rem] text-muted-foreground select-none hover:text-foreground">
            <ChevronRight
              aria-hidden
              className="h-3 w-3 transition-transform group-open:rotate-90 motion-reduce:transition-none"
            />
            <Lock aria-hidden className="h-3 w-3" />
            Isolation — the settings this container actually runs with
          </summary>
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[0.6875rem]">
            {ISOLATION_LABELS.filter(([k]) => run.isolation?.[k]).map(([k, label]) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="font-mono break-words text-foreground/85">{run.isolation![k]}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}

      <div
        ref={scrollRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
        className="max-h-96 overflow-y-auto px-3 py-2.5"
      >
        {run ? (
          <ol role="log" aria-live="polite" className="space-y-1 font-mono text-[0.71875rem] leading-5">
            {run.lines.map((line) => {
              const m = ATTEMPT_START.exec(line.message);
              return (
                <li key={line.id}>
                  {m && (
                    <div
                      aria-hidden
                      className="my-2 flex items-center gap-2 text-[0.625rem] tracking-wide text-muted-foreground uppercase"
                    >
                      <span className="h-px flex-1 bg-border" />
                      Attempt {m[1]} of {m[2]}
                      <span className="h-px flex-1 bg-border" />
                    </div>
                  )}
                  <ConsoleLine
                    line={line}
                    t0={t0}
                    diffOpenByDefault={line.seq === lastPatchSeq && live}
                  />
                </li>
              );
            })}
            {live && (
              <li aria-hidden className="pl-[7.5rem] text-muted-foreground">
                <span className="animate-pulse motion-reduce:animate-none">▍</span>
              </li>
            )}
          </ol>
        ) : (
          <p className="font-mono text-[0.71875rem] text-muted-foreground">
            {waitingLabel}
            <span aria-hidden className="ml-1 animate-pulse motion-reduce:animate-none">
              ▍
            </span>
          </p>
        )}
      </div>
    </div>
  );
}
