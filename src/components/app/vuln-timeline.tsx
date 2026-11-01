import { format } from "date-fns";
import {
  CheckCircle2,
  Copy,
  EyeOff,
  ExternalLink,
  GitPullRequest,
  Radar,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  ScanEye,
  CircleSlash,
  CircleDot,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import type { TimelineIcon, TimelineItem, TimelineTone } from "@/lib/activity-format";

const ICONS: Record<TimelineIcon, LucideIcon> = {
  detected: Radar,
  seen: ScanEye,
  not_seen: EyeOff,
  fixed: CheckCircle2,
  regressed: RotateCcw,
  status: CircleDot,
  false_positive: CircleSlash,
  duplicate: Copy,
  verify_confirmed: ShieldAlert,
  verify_clear: ShieldCheck,
  verify_failed: ShieldX,
  fix_requested: Sparkles,
  fix_pr: GitPullRequest,
  fix_rejected: XCircle,
};

const TONE: Record<TimelineTone, string> = {
  neutral: "text-muted-foreground border-border bg-muted/50",
  good: "text-low border-low/40 bg-low/10",
  bad: "text-critical border-critical/40 bg-critical/10",
  warn: "text-medium border-medium/40 bg-medium/10",
  accent: "text-accent-fg border-accent-fg/40 bg-accent-fg/10",
};

function when(item: TimelineItem) {
  const start = format(new Date(item.at), "MMM d, p");
  if (!item.until) return start;
  return `${format(new Date(item.at), "MMM d")} – ${format(new Date(item.until), "MMM d")}`;
}

/** The life of one finding, oldest first. */
export function VulnerabilityTimeline({ items }: { items: TimelineItem[] }) {
  if (items.length === 0) {
    return <p className="text-sm text-muted-foreground">No history recorded yet.</p>;
  }
  return (
    <ol className="relative space-y-4">
      {items.map((item, i) => {
        const Icon = ICONS[item.icon];
        return (
          <li key={item.key} className="relative flex gap-3">
            {i < items.length - 1 && (
              <span
                aria-hidden
                className="absolute top-8 bottom-[-1rem] left-[0.9375rem] w-px bg-border"
              />
            )}
            <span
              aria-hidden
              className={`relative z-10 grid h-8 w-8 shrink-0 place-items-center rounded-full border ${TONE[item.tone]}`}
            >
              <Icon className="h-4 w-4" />
            </span>
            <div className="min-w-0 pt-1">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="text-sm font-medium text-foreground">{item.title}</span>
                <time dateTime={item.at} className="text-xs text-muted-foreground">
                  {when(item)}
                </time>
              </div>
              {item.detail && (
                <p className="mt-0.5 text-xs break-words text-muted-foreground">{item.detail}</p>
              )}
              {item.href && (
                <a
                  href={item.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-0.5 inline-flex items-center gap-1 text-xs text-accent-fg hover:underline"
                >
                  View pull request <ExternalLink aria-hidden className="h-3 w-3" />
                </a>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
