import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  AlertCircle,
  Bot,
  Calendar,
  Clock,
  FileText,
  GitBranch,
  GitPullRequest,
  Github,
  History,
  Loader2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Terminal,
  Wrench,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SeverityBadge, StatusBadge, SectionCard, EmptyState } from "@/components/app/ui";
import { SandboxConsole } from "@/components/app/sandbox-console";
import { VulnerabilityTimeline } from "@/components/app/vuln-timeline";
import { groupJobRuns, toTimeline } from "@/lib/activity-format";
import { demoFixLines, demoFixSteps, demoTimeline } from "@/lib/demo-fix-run";
import {
  DEMO_REPOSITORIES,
  DEMO_SCANS,
  DEMO_SEVERITY_COUNTS,
  DEMO_VULNERABILITIES,
  type DemoScan,
  type DemoSeverity,
  type DemoVulnerability,
} from "@/lib/demo-data";

/* ------------------------------------------------------------------ shared */

function timeAgo(iso: string | null) {
  if (!iso) return "never";
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

function CodeBlock({ children, tone = "muted" }: { children: string; tone?: "muted" | "good" }) {
  return (
    <pre
      className={`overflow-x-auto rounded-md border p-3 font-mono text-xs leading-relaxed whitespace-pre ${
        tone === "good"
          ? "border-low/30 bg-low/10 text-foreground"
          : "border-border bg-muted/40 text-foreground"
      }`}
    >
      <code>{children}</code>
    </pre>
  );
}

function StatCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "critical" | "good";
}) {
  const valueTone =
    tone === "critical" ? "text-critical-fg" : tone === "good" ? "text-low-fg" : "text-foreground";
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="text-[11px] tracking-wide text-muted-foreground uppercase">{label}</div>
      <div className={`mt-2 text-3xl font-bold tabular-nums ${valueTone}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
    </div>
  );
}

/** Proportional severity bar — the same palette the real app uses. */
function SeverityBar() {
  const total = DEMO_VULNERABILITIES.length;
  const bars: Array<{ key: DemoSeverity; cls: string }> = [
    { key: "critical", cls: "bg-critical" },
    { key: "high", cls: "bg-high" },
    { key: "medium", cls: "bg-medium" },
    { key: "low", cls: "bg-low" },
  ];
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-full bg-muted">
        {bars.map((b) => (
          <div
            key={b.key}
            className={b.cls}
            style={{ width: `${(DEMO_SEVERITY_COUNTS[b.key] / total) * 100}%` }}
          />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2">
        {bars.map((b) => (
          <div key={b.key} className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 rounded-full ${b.cls}`} />
            <span className="text-sm text-muted-foreground capitalize">{b.key}</span>
            <span className="text-sm font-semibold tabular-nums text-foreground">
              {DEMO_SEVERITY_COUNTS[b.key]}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- dashboard */

export function DemoDashboard({ onGoTo }: { onGoTo: (s: string) => void }) {
  const open = DEMO_VULNERABILITIES.filter((v) => v.status !== "fixed");
  const top = [...open].sort((a, b) => b.cvss_score - a.cvss_score).slice(0, 4);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Repositories" value={DEMO_REPOSITORIES.length} hint="2 on weekly scans" />
        <StatCard label="Open findings" value={open.length} hint="across all repositories" />
        <StatCard
          label="Critical"
          value={DEMO_SEVERITY_COUNTS.critical}
          hint="sandbox-confirmed"
          tone="critical"
        />
        <StatCard label="Security score" value="42" hint="acme-commerce" tone="critical" />
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.3fr_1fr]">
        <SectionCard
          title="Findings by severity"
          description="acme-corp/acme-commerce · last scan 18m ago"
        >
          <SeverityBar />
        </SectionCard>

        <SectionCard
          title="Scan activity"
          action={
            <Button variant="outline" size="sm" onClick={() => onGoTo("scans")}>
              View all
            </Button>
          }
          bodyClassName="p-0"
        >
          <ul className="divide-y divide-border">
            {DEMO_SCANS.slice(0, 3).map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 px-5 py-3.5">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-foreground">{s.repository}</div>
                  <div className="text-xs text-muted-foreground">
                    {s.trigger} · {timeAgo(s.started_at)}
                  </div>
                </div>
                <StatusBadge status={s.status} />
              </li>
            ))}
          </ul>
        </SectionCard>
      </div>

      <SectionCard
        title="Highest-risk findings"
        description="Ranked by CVSS. Open one to see the AI analysis and suggested fix."
        action={
          <Button variant="outline" size="sm" onClick={() => onGoTo("vulnerabilities")}>
            All findings
          </Button>
        }
        bodyClassName="p-0"
      >
        <ul className="divide-y divide-border">
          {top.map((v) => (
            <li key={v.id} className="flex items-start justify-between gap-4 px-5 py-4">
              <div className="min-w-0">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={v.severity} />
                  <span className="text-xs text-muted-foreground">{v.cwe_id}</span>
                  {v.verification_status === "confirmed" && (
                    <span className="inline-flex items-center gap-1 text-xs text-critical-fg">
                      <ShieldAlert className="h-3 w-3" /> Confirmed
                    </span>
                  )}
                </div>
                <div className="font-medium text-foreground">{v.title}</div>
                <div className="mt-1 font-mono text-xs text-muted-foreground">
                  {v.file_path}:{v.line_start}
                </div>
              </div>
              <div className="shrink-0 text-right">
                <div className="text-[11px] text-muted-foreground">CVSS</div>
                <div className="text-lg font-bold tabular-nums">{v.cvss_score}</div>
              </div>
            </li>
          ))}
        </ul>
      </SectionCard>
    </div>
  );
}

/* ------------------------------------------------------------ repositories */

export function DemoRepositories({ onNotify }: { onNotify: (m: string) => void }) {
  const [weekly, setWeekly] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(DEMO_REPOSITORIES.map((r) => [r.id, r.scan_mode === "weekly"])),
  );

  return (
    <SectionCard
      title="Repositories"
      description="Connected GitHub repositories. Toggle weekly auto-scanning per repository."
      bodyClassName="p-0"
    >
      <ul className="divide-y divide-border">
        {DEMO_REPOSITORIES.map((r) => (
          <li key={r.id} className="flex flex-wrap items-center justify-between gap-4 p-4">
            <div className="flex min-w-0 items-center gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-lg bg-primary/15 text-accent-fg">
                <Github className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="truncate font-medium text-foreground">{r.full_name}</div>
                <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <GitBranch className="h-3 w-3" /> {r.default_branch}
                  </span>
                  <span>{r.language}</span>
                  {r.is_private && <span>Private</span>}
                  {r.files_scanned > 0 && (
                    <span>{r.files_scanned.toLocaleString()} files scanned</span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex shrink-0 items-center gap-3 sm:gap-4">
              <StatusBadge status={r.status} />
              <div className="hidden w-16 text-right sm:block">
                <div className="text-[11px] tracking-wide text-muted-foreground uppercase">
                  Score
                </div>
                <div className="font-semibold tabular-nums">{r.security_score ?? "—"}</div>
              </div>
              <label
                className="hidden cursor-pointer items-center gap-2 sm:flex"
                title="Automatically re-scan roughly once a week"
              >
                <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                <Switch
                  checked={!!weekly[r.id]}
                  onCheckedChange={(v) => {
                    setWeekly((prev) => ({ ...prev, [r.id]: v }));
                    onNotify(
                      v
                        ? `Weekly auto-scan enabled for ${r.name} (demo)`
                        : `Weekly auto-scan disabled for ${r.name} (demo)`,
                    );
                  }}
                />
              </label>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onNotify(`Scan queued for ${r.name} — simulated in demo mode`)}
              >
                <ShieldAlert className="mr-1 h-3 w-3" /> Scan
              </Button>
            </div>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

/* -------------------------------------------------------------------- scans */

export function DemoScans() {
  const [selected, setSelected] = useState<DemoScan | null>(null);

  return (
    <div className="space-y-6">
      <SectionCard
        title="Scan history"
        description="Select a scan to inspect its execution log."
        bodyClassName="p-0"
      >
        <ul className="divide-y divide-border">
          {DEMO_SCANS.map((s) => (
            <li key={s.id}>
              <button
                onClick={() => setSelected(s)}
                className={`flex w-full cursor-pointer flex-wrap items-center justify-between gap-4 p-4 text-left transition-colors hover:bg-muted/40 ${
                  selected?.id === s.id ? "bg-muted/40" : ""
                }`}
              >
                <div className="min-w-0">
                  <div className="truncate font-medium text-foreground">{s.repository}</div>
                  <div className="text-xs text-muted-foreground">
                    {s.profile} · {s.trigger} · {timeAgo(s.started_at)} ·{" "}
                    <span className="font-mono">{s.commit_sha}</span>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="hidden text-xs text-muted-foreground md:block">
                    {s.counts.critical} crit · {s.counts.high} high · {s.counts.medium} med
                  </div>
                  <div className="text-right">
                    <div className="text-[11px] text-muted-foreground">Score</div>
                    <div className="font-semibold tabular-nums">{s.security_score ?? "—"}</div>
                  </div>
                  <StatusBadge status={s.status} />
                </div>
              </button>
            </li>
          ))}
        </ul>
      </SectionCard>

      <AnimatePresence mode="wait">
        {selected && (
          <motion.div
            key={selected.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.18 }}
          >
            <SectionCard
              title={`Execution log — ${selected.id}`}
              description={`${selected.files_scanned.toLocaleString()} files · ${
                selected.duration_seconds ?? 0
              }s · branch ${selected.branch}`}
            >
              <ol className="space-y-2">
                {selected.logs.map((l, i) => (
                  <li key={i} className="flex gap-3 font-mono text-xs">
                    <span className="w-16 shrink-0 text-muted-foreground">{timeAgo(l.at)}</span>
                    <span
                      className={`w-24 shrink-0 uppercase ${
                        l.level === "warn"
                          ? "text-medium-fg"
                          : l.level === "error"
                            ? "text-critical-fg"
                            : "text-accent-fg"
                      }`}
                    >
                      {l.stage}
                    </span>
                    <span className="text-foreground">{l.message}</span>
                  </li>
                ))}
              </ol>
            </SectionCard>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ---------------------------------------------------------- vulnerabilities */

const SEVERITIES = ["all", "critical", "high", "medium", "low"] as const;

const verificationConfig: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  unverified: { label: "Unverified", color: "text-muted-foreground", icon: Shield },
  pending: { label: "Verifying…", color: "text-accent-fg", icon: Loader2 },
  confirmed: { label: "Confirmed exploitable", color: "text-critical-fg", icon: ShieldAlert },
  not_exploitable: { label: "Not exploitable", color: "text-low-fg", icon: ShieldCheck },
  failed: { label: "Verification failed", color: "text-medium-fg", icon: AlertCircle },
};

type FixState = "none" | "pending" | "pr_created";

export function DemoVulnerabilities({ onNotify }: { onNotify: (m: string) => void }) {
  const [filter, setFilter] = useState<(typeof SEVERITIES)[number]>("all");
  const [selected, setSelected] = useState<DemoVulnerability | null>(null);
  const [fixes, setFixes] = useState<Record<string, FixState>>({});
  // Replay of a recorded-style fix run: how many console lines are revealed,
  // when it started, and when it finished (for the timeline).
  const [runs, setRuns] = useState<
    Record<string, { startedAt: number; revealed: number; doneAt: number | null }>
  >({});
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const filtered = useMemo(
    () =>
      filter === "all"
        ? DEMO_VULNERABILITIES
        : DEMO_VULNERABILITIES.filter((v) => v.severity === filter),
    [filter],
  );

  const requestFix = (v: DemoVulnerability) => {
    setFixes((p) => ({ ...p, [v.id]: "pending" }));
    onNotify("Replaying a fix run: simulated, no pull request is actually opened");
    // Replays the same console the real sandbox streams: each line appears
    // after its recorded delay, then the PR "arrives".
    const startedAt = Date.now();
    setRuns((p) => ({ ...p, [v.id]: { startedAt, revealed: 0, doneAt: null } }));
    const steps = demoFixSteps(v);
    let elapsed = 0;
    steps.forEach((step, i) => {
      elapsed += step.delay;
      timers.current.push(
        setTimeout(() => {
          setRuns((p) => ({ ...p, [v.id]: { ...p[v.id], revealed: i + 1 } }));
          if (i === steps.length - 1) {
            setFixes((p) => ({ ...p, [v.id]: "pr_created" }));
            setRuns((p) => ({ ...p, [v.id]: { ...p[v.id], doneAt: Date.now() } }));
          }
        }, elapsed),
      );
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {SEVERITIES.map((s) => (
          <Button
            key={s}
            variant={filter === s ? "default" : "outline"}
            size="sm"
            className="capitalize"
            onClick={() => setFilter(s)}
          >
            {s}
            {s !== "all" && (
              <span className="ml-1.5 tabular-nums opacity-70">
                {DEMO_SEVERITY_COUNTS[s as DemoSeverity]}
              </span>
            )}
          </Button>
        ))}
      </div>

      <div className="overflow-hidden rounded-xl border border-border bg-card">
        {filtered.length === 0 ? (
          <EmptyState
            icon={AlertCircle}
            title="No findings"
            description="Nothing at this severity."
          />
        ) : (
          <ul className="divide-y divide-border">
            {filtered.map((v) => {
              const fix = fixes[v.id] ?? "none";
              return (
                <li key={v.id}>
                  <button
                    onClick={() => setSelected(v)}
                    className="flex w-full cursor-pointer items-start justify-between gap-4 p-4 text-left transition-colors hover:bg-muted/40"
                  >
                    <div className="min-w-0">
                      <div className="mb-1 flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={v.severity} />
                        <span className="text-xs text-muted-foreground">{v.cwe_id}</span>
                        <StatusBadge status={v.status} />
                        {v.verification_status === "confirmed" && (
                          <span className="inline-flex items-center gap-1 text-xs text-critical-fg">
                            <ShieldAlert className="h-3 w-3" /> Confirmed
                          </span>
                        )}
                        {fix === "pr_created" && (
                          <span className="inline-flex items-center gap-1 text-xs text-low-fg">
                            <GitPullRequest className="h-3 w-3" /> Fix PR open
                          </span>
                        )}
                      </div>
                      <div className="font-medium text-foreground">{v.title}</div>
                      <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">
                        {v.description}
                      </p>
                      <div className="mt-2 font-mono text-xs text-muted-foreground">
                        {v.file_path}:{v.line_start}
                      </div>
                    </div>
                    <div className="shrink-0 text-right">
                      <div className="text-[11px] text-muted-foreground">CVSS</div>
                      <div className="text-lg font-bold tabular-nums">{v.cvss_score}</div>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
          {selected && (
            <>
              <DialogHeader>
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <span className="text-xs text-muted-foreground">{selected.cwe_id}</span>
                  <span className="text-xs text-muted-foreground">CVSS {selected.cvss_score}</span>
                  <StatusBadge status={selected.status} />
                </div>
                <DialogTitle className="text-left">{selected.title}</DialogTitle>
              </DialogHeader>

              <div className="space-y-5 text-sm">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-lg border border-border bg-muted/30 p-3">
                    <div className="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
                      <Target className="h-3.5 w-3.5" /> Repository
                    </div>
                    <div className="truncate font-medium">{selected.repository}</div>
                  </div>
                  <div className="rounded-lg border border-border bg-muted/30 p-3">
                    <div className="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
                      <Calendar className="h-3.5 w-3.5" /> Detected
                    </div>
                    <div className="font-medium">{timeAgo(selected.detected_at)}</div>
                  </div>
                </div>

                <div>
                  <div className="mb-1 text-xs text-muted-foreground">Location</div>
                  <div className="rounded border border-border bg-muted/40 p-2 font-mono text-xs break-all">
                    {selected.file_path}:{selected.line_start}–{selected.line_end}
                  </div>
                </div>

                <SandboxPanel vuln={selected} />

                <div>
                  <div className="mb-1 text-xs text-muted-foreground">Description</div>
                  <p className="text-muted-foreground">{selected.description}</p>
                </div>

                <div>
                  <div className="mb-2 text-xs text-muted-foreground">Vulnerable code</div>
                  <CodeBlock>{selected.snippet}</CodeBlock>
                </div>

                <div>
                  <div className="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
                    <Bot className="h-3.5 w-3.5" /> AI analysis
                  </div>
                  <p className="whitespace-pre-wrap text-muted-foreground">
                    {selected.ai_analysis}
                  </p>
                </div>

                <div>
                  <div className="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
                    <Wrench className="h-3.5 w-3.5" /> Remediation steps
                  </div>
                  <ol className="ml-5 list-decimal space-y-1 text-muted-foreground">
                    {selected.remediation_steps.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                </div>

                <FixPanel
                  state={fixes[selected.id] ?? "none"}
                  vuln={selected}
                  onRequest={() => requestFix(selected)}
                />

                <DemoFindingActivity vuln={selected} run={runs[selected.id] ?? null} />
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function SandboxPanel({ vuln }: { vuln: DemoVulnerability }) {
  const cfg = verificationConfig[vuln.verification_status] ?? verificationConfig.unverified;
  const Icon = cfg.icon;
  return (
    <div className="space-y-3 rounded-lg border border-border bg-muted/30 p-4">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Shield className="h-3.5 w-3.5" /> Sandbox verification
      </div>
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${cfg.color}`} />
        <span className={`font-medium ${cfg.color}`}>{cfg.label}</span>
      </div>
      {vuln.verification_evidence && (
        <p className="rounded border border-border bg-muted/60 p-2 text-xs whitespace-pre-wrap text-muted-foreground">
          {vuln.verification_evidence}
        </p>
      )}
      {vuln.verification_status === "unverified" && (
        <p className="text-xs text-muted-foreground">
          Only high and critical findings are re-run in the sandbox — this one was reported by
          static analysis alone.
        </p>
      )}
    </div>
  );
}

/** The demo's sandbox console replay and the finding's timeline. */
function DemoFindingActivity({
  vuln,
  run,
}: {
  vuln: DemoVulnerability;
  run: { startedAt: number; revealed: number; doneAt: number | null } | null;
}) {
  const consoleRun = useMemo(
    () =>
      run && run.revealed > 0
        ? (groupJobRuns(demoFixLines(vuln, run.revealed, run.startedAt))[0] ?? null)
        : null,
    [vuln, run],
  );
  const timeline = useMemo(
    () => toTimeline(demoTimeline(vuln, run?.doneAt ?? null), vuln.detected_at),
    [vuln, run?.doneAt],
  );
  return (
    <>
      {run && (
        <section className="space-y-2">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Terminal className="h-3.5 w-3.5" /> Sandbox activity
          </div>
          <SandboxConsole
            run={consoleRun}
            waitingLabel={
              consoleRun ? undefined : "Queued. Waiting for the sandbox to start the fixer…"
            }
          />
        </section>
      )}
      <section className="space-y-3">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <History className="h-3.5 w-3.5" /> Timeline
        </div>
        <VulnerabilityTimeline items={timeline} />
      </section>
    </>
  );
}

function FixPanel({
  state,
  vuln,
  onRequest,
}: {
  state: FixState;
  vuln: DemoVulnerability;
  onRequest: () => void;
}) {
  return (
    <div className="space-y-3 rounded-lg border border-border bg-muted/30 p-4">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Sparkles className="h-3.5 w-3.5" /> AI remediation
      </div>

      {state === "none" && (
        <>
          <p className="text-xs text-muted-foreground">
            Generates a patch, re-scans the code with it applied, and opens a pull request only if
            the finding is gone — never a direct commit to your default branch.
          </p>
          <Button size="sm" onClick={onRequest}>
            <Sparkles className="mr-2 h-4 w-4" /> Fix with AI
          </Button>
        </>
      )}

      {state === "pending" && (
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-accent-fg" />
          <span className="font-medium text-accent-fg">Generating and re-scanning fix…</span>
          <span className="text-xs text-muted-foreground">Watch it below.</span>
        </div>
      )}

      {state === "pr_created" && (
        <>
          <div className="flex items-center gap-2">
            <GitPullRequest className="h-4 w-4 text-low-fg" />
            <span className="font-medium text-low-fg">Pull request #482 opened</span>
          </div>
          <div>
            <div className="mb-2 text-xs text-muted-foreground">Proposed patch</div>
            <CodeBlock tone="good">{vuln.suggested_fix}</CodeBlock>
          </div>
          <p className="text-xs text-muted-foreground">
            Opened only after the patch passed two independent re-scans. It hasn&apos;t been
            compiled or tested, so review it like any other patch.
          </p>
          <Button size="sm" variant="outline" disabled title="Disabled in demo mode">
            <GitPullRequest className="mr-2 h-4 w-4" /> View PR (disabled in demo)
          </Button>
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ reports */

export function DemoReports({ onNotify }: { onNotify: (m: string) => void }) {
  const scan = DEMO_SCANS[0];
  return (
    <div className="space-y-6">
      <SectionCard
        title="Scan report"
        description={`${scan.repository} · ${scan.id} · ${timeAgo(scan.started_at)}`}
        action={
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onNotify("PDF export is simulated in demo mode")}
            >
              <FileText className="mr-1 h-3.5 w-3.5" /> PDF
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => onNotify("JSON export is simulated in demo mode")}
            >
              JSON
            </Button>
          </div>
        }
      >
        <div className="space-y-5">
          <p className="text-sm text-muted-foreground">
            Scan of <span className="font-medium text-foreground">{scan.repository}</span> completed{" "}
            {timeAgo(scan.started_at)}. {DEMO_VULNERABILITIES.length} findings:{" "}
            {DEMO_SEVERITY_COUNTS.critical} critical, {DEMO_SEVERITY_COUNTS.high} high,{" "}
            {DEMO_SEVERITY_COUNTS.medium} medium, {DEMO_SEVERITY_COUNTS.low} low. Security score{" "}
            <span className="font-medium text-foreground">{scan.security_score}/100</span>.
          </p>

          <SeverityBar />

          <div className="grid gap-4 sm:grid-cols-3">
            <StatCard label="Files scanned" value={scan.files_scanned.toLocaleString()} />
            <StatCard label="Duration" value={`${scan.duration_seconds}s`} />
            <StatCard
              label="Sandbox-confirmed"
              value={
                DEMO_VULNERABILITIES.filter((v) => v.verification_status === "confirmed").length
              }
              tone="critical"
            />
          </div>
        </div>
      </SectionCard>

      <SectionCard title="Findings included" bodyClassName="p-0">
        <ul className="divide-y divide-border">
          {DEMO_VULNERABILITIES.map((v) => (
            <li key={v.id} className="flex items-center justify-between gap-4 px-5 py-3">
              <div className="flex min-w-0 items-center gap-3">
                <SeverityBadge severity={v.severity} />
                <span className="truncate text-sm text-foreground">{v.title}</span>
              </div>
              <span className="hidden shrink-0 font-mono text-xs text-muted-foreground sm:block">
                {v.file_path}:{v.line_start}
              </span>
            </li>
          ))}
        </ul>
      </SectionCard>
    </div>
  );
}

/* ------------------------------------------------------------ activity feed */

export function DemoActivity() {
  const recent = DEMO_VULNERABILITIES.filter(
    (v) => v.severity === "critical" || v.severity === "high",
  );
  return (
    <SectionCard
      title="Notifications"
      description="Critical and high findings raised by the most recent scans."
      bodyClassName="p-0"
    >
      <ul className="divide-y divide-border">
        {recent.map((v) => (
          <li key={v.id} className="flex items-start gap-3 px-5 py-3.5">
            <AlertCircle
              className={`mt-0.5 h-4 w-4 shrink-0 ${
                v.severity === "critical" ? "text-critical-fg" : "text-high-fg"
              }`}
            />
            <div className="min-w-0">
              <p className="text-sm leading-snug text-foreground">
                Detected a {v.severity} vulnerability: {v.title}
              </p>
              <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
                {v.file_path}
              </p>
              <div className="mt-1 flex items-center gap-2">
                <SeverityBadge severity={v.severity} className="text-[10px]" />
                <span className="text-[11px] text-muted-foreground">{timeAgo(v.detected_at)}</span>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}
