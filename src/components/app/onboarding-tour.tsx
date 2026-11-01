import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Bot, ArrowRight, Sparkles } from "lucide-react";

export type TourStep = {
  /** Matches a `data-tour="…"` attribute on the element to spotlight. */
  target: string;
  text: string;
  /** Preferred side; the tour flips it when there isn't room. */
  placement?: Side;
};

type Side = "right" | "left" | "top" | "bottom";

type Rect = { top: number; left: number; width: number; height: number };

const CARD_WIDTH = 320;
const CARD_HEIGHT = 190;
const SPOTLIGHT_PAD = 8;
const GAP = 18;
const VIEWPORT_MARGIN = 12;

function readRect(target: string): Rect | null {
  if (typeof document === "undefined") return null;
  const el = document.querySelector<HTMLElement>(`[data-tour="${target}"]`);
  if (!el) return null;
  const r = el.getBoundingClientRect();
  // A zero-size box means the element is present but hidden (the sidebar is
  // display:none on mobile), which should fall back to the centred card.
  if (r.width === 0 || r.height === 0) return null;
  return { top: r.top, left: r.left, width: r.width, height: r.height };
}

/** Places the card beside the spotlight, flipping sides and clamping to the viewport. */
function placeCard(rect: Rect | null, preferred: Side): { top: number; left: number } | null {
  if (typeof window === "undefined" || !rect) return null;
  const vw = window.innerWidth;
  const vh = window.innerHeight;

  const fits: Record<Side, boolean> = {
    right: rect.left + rect.width + GAP + CARD_WIDTH <= vw - VIEWPORT_MARGIN,
    left: rect.left - GAP - CARD_WIDTH >= VIEWPORT_MARGIN,
    bottom: rect.top + rect.height + GAP + CARD_HEIGHT <= vh - VIEWPORT_MARGIN,
    top: rect.top - GAP - CARD_HEIGHT >= VIEWPORT_MARGIN,
  };
  // Try the requested side first, then the rest — never overlapping the target.
  const side = ([preferred, "right", "bottom", "left", "top"] as Side[]).find((s) => fits[s]);
  if (!side) return null;

  const clamp = (v: number, min: number, max: number) => Math.max(min, Math.min(v, max));

  if (side === "right" || side === "left") {
    return {
      left: side === "right" ? rect.left + rect.width + GAP : rect.left - GAP - CARD_WIDTH,
      top: clamp(
        rect.top + rect.height / 2 - CARD_HEIGHT / 2,
        VIEWPORT_MARGIN,
        vh - CARD_HEIGHT - VIEWPORT_MARGIN,
      ),
    };
  }
  return {
    top: side === "bottom" ? rect.top + rect.height + GAP : rect.top - GAP - CARD_HEIGHT,
    left: clamp(
      rect.left + rect.width / 2 - CARD_WIDTH / 2,
      VIEWPORT_MARGIN,
      vw - CARD_WIDTH - VIEWPORT_MARGIN,
    ),
  };
}

export function OnboardingTour({
  steps,
  startIndex = 0,
  onStepChange,
  onFinish,
}: {
  steps: TourStep[];
  startIndex?: number;
  onStepChange?: (index: number) => void;
  onFinish: (reason: "completed" | "skipped") => void;
}) {
  const [index, setIndex] = useState(() => Math.min(Math.max(startIndex, 0), steps.length - 1));
  const [rect, setRect] = useState<Rect | null>(null);
  const [done, setDone] = useState(false);
  const nextRef = useRef<HTMLButtonElement>(null);

  const step = steps[index];
  const isLast = index === steps.length - 1;

  // Re-measure on step change, resize and scroll so the spotlight tracks the
  // element rather than a stale position.
  useLayoutEffect(() => {
    if (done) return;
    let frame = 0;
    const measure = () => setRect(readRect(step.target));

    const el = document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`);
    el?.scrollIntoView({ block: "nearest", inline: "nearest", behavior: "smooth" });
    // One frame later so the smooth scroll has started before the first read.
    frame = requestAnimationFrame(measure);

    const onChange = () => setRect(readRect(step.target));
    window.addEventListener("resize", onChange);
    window.addEventListener("scroll", onChange, true);
    const interval = window.setInterval(onChange, 400);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", onChange);
      window.removeEventListener("scroll", onChange, true);
      window.clearInterval(interval);
    };
  }, [step.target, done]);

  useEffect(() => {
    onStepChange?.(index);
  }, [index, onStepChange]);

  useEffect(() => {
    nextRef.current?.focus({ preventScroll: true });
  }, [index, done]);

  const advance = useCallback(() => {
    if (isLast) setDone(true);
    else setIndex((i) => i + 1);
  }, [isLast]);

  // Escape skips; Enter/Space advance without needing to hit the button.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onFinish("skipped");
      } else if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        if (done) onFinish("completed");
        else advance();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [advance, done, onFinish]);

  const cardPos = done ? null : placeCard(rect, step.placement ?? "right");
  // Centre the card when the target is missing/hidden, or nothing fits around it.
  const centred = !cardPos;

  // The padded hole, shared by the blur panels and the spotlight ring so they
  // can never drift apart.
  const spot =
    rect && !done
      ? {
          top: rect.top - SPOTLIGHT_PAD,
          left: rect.left - SPOTLIGHT_PAD,
          width: rect.width + SPOTLIGHT_PAD * 2,
          height: rect.height + SPOTLIGHT_PAD * 2,
        }
      : null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Product tour"
      className="fixed inset-0 z-[100]"
    >
      {spot ? (
        <>
          {/* backdrop-filter applies to everything behind the element's own box,
              so a single full-screen blur layer blurs the highlighted element
              too. Tile the blur into four panels around the spotlight instead,
              leaving the hole completely untouched and therefore crisp. */}
          {(
            [
              { top: 0, left: 0, right: 0, height: Math.max(spot.top, 0) },
              { top: spot.top + spot.height, left: 0, right: 0, bottom: 0 },
              { top: spot.top, left: 0, width: Math.max(spot.left, 0), height: spot.height },
              { top: spot.top, left: spot.left + spot.width, right: 0, height: spot.height },
            ] as const
          ).map((panel, i) => (
            <div
              key={i}
              className="absolute bg-background/20 backdrop-blur-[3px] transition-[top,left,width,height] duration-300 ease-out"
              style={panel}
            />
          ))}

          {/* Geometry goes through `style` with a CSS transition rather than
              motion's `animate`: motion interpolates from the computed value,
              and an absolutely-positioned box starts at `top/left/width/height:
              auto`, which it cannot animate from — the spotlight collapses to
              0×0. */}
          <div
            className="pointer-events-none absolute rounded-xl ring-2 ring-primary-strong transition-[top,left,width,height] duration-300 ease-out"
            style={{
              top: spot.top,
              left: spot.left,
              width: spot.width,
              height: spot.height,
              // The huge spread darkens everything outside the hole in one node.
              boxShadow:
                "0 0 0 9999px rgba(2, 6, 23, 0.74), 0 0 0 4px rgba(139, 92, 246, 0.35), 0 0 34px 6px rgba(139, 92, 246, 0.45)",
            }}
          />
        </>
      ) : (
        // Nothing to keep crisp, so one full-screen wash is fine.
        <div className="absolute inset-0 bg-[rgba(2,6,23,0.74)] backdrop-blur-[3px]" />
      )}

      {/* Deliberately not mode="wait": that defers mounting the next card until
          the previous one's exit animation finishes, so a stalled animation
          (background tab, reduced-motion, throttled rAF) leaves the tour stuck
          on the old step. Cross-fading is both smoother and non-blocking. */}
      <AnimatePresence>
        {done ? (
          <motion.div
            key="finish"
            initial={{ opacity: 0, scale: 0.95, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.25, ease: "easeOut" }}
            className="absolute top-1/2 left-1/2 w-[min(22rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border bg-card p-6 text-center shadow-2xl"
          >
            <div className="mx-auto grid h-14 w-14 place-items-center rounded-full bg-primary-strong">
              <Sparkles aria-hidden className="h-7 w-7 text-white" />
            </div>
            <p className="mt-4 text-lg font-semibold text-foreground">You&apos;re all set! 🎉</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Connect a repository whenever you&apos;re ready — I&apos;ll be here if you need a
              hand.
            </p>
            <button
              ref={nextRef}
              onClick={() => onFinish("completed")}
              className="mt-5 w-full cursor-pointer rounded-lg bg-primary-strong px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-primary-hover focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-card focus-visible:outline-none"
            >
              Get Started
            </button>
          </motion.div>
        ) : (
          <motion.div
            key="card"
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            // Position via style + CSS transition, for the same reason as the
            // spotlight above; motion only handles the fade/scale here.
            style={
              centred ? undefined : { width: CARD_WIDTH, top: cardPos!.top, left: cardPos!.left }
            }
            className={
              centred
                ? "absolute top-1/2 left-1/2 w-[min(20rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border bg-card p-4 shadow-2xl"
                : "absolute rounded-2xl border border-border bg-card p-4 shadow-2xl transition-[top,left] duration-300 ease-out"
            }
          >
            <div className="flex items-start gap-3">
              {/* The guide. Bobs gently so it reads as a character, not an icon. */}
              <motion.span
                animate={{ y: [0, -3, 0] }}
                transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }}
                className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-primary-strong shadow-lg"
              >
                <Bot aria-hidden className="h-5 w-5 text-white" />
              </motion.span>
              <p className="pt-0.5 text-sm leading-snug text-foreground">{step.text}</p>
            </div>

            <div className="mt-4 flex items-center justify-between gap-3">
              <span className="text-xs font-medium text-muted-foreground tabular-nums">
                {index + 1} of {steps.length}
              </span>
              <div className="flex items-center gap-1">
                {steps.map((s, i) => (
                  <span
                    key={s.target}
                    aria-hidden
                    className={`h-1.5 rounded-full transition-all duration-300 ${
                      i === index ? "w-4 bg-primary-strong" : "w-1.5 bg-border"
                    }`}
                  />
                ))}
              </div>
            </div>

            <div className="mt-3 flex items-center justify-between gap-2">
              <button
                onClick={() => onFinish("skipped")}
                className="cursor-pointer rounded-md px-2 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                Skip tour
              </button>
              <button
                ref={nextRef}
                onClick={advance}
                className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-primary-strong px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-hover focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-card focus-visible:outline-none"
              >
                {isLast ? "Finish" : "Next"}
                <ArrowRight aria-hidden className="h-3.5 w-3.5" />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
