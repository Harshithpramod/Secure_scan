import { useCallback, useEffect, useRef, useState } from "react";

// Keeps a fixed-position element out of the way of meaningful page content.
//
// The element lives in the bottom-right corner by default and only relocates
// when that corner would cover something worth seeing — a button, a heading, a
// table cell. When the corner clears again it comes home.
//
// The naive version of this ("is the element over another element?") answers
// yes everywhere, because every pixel of a page sits inside some div. Two
// things avoid that trap:
//
//   1. Only the TOPMOST element at each sample point is classified, via the
//      browser's own hit-testing. Landing on a layout wrapper's padding means
//      empty space inside a container, which is exactly where this thing is
//      allowed to sit. Hit-testing also handles z-index, clipping and
//      visibility for free, which a getBoundingClientRect() sweep over the DOM
//      would have to reimplement — slowly, and worse.
//   2. Slots are SCORED rather than judged clear/not-clear, so a dense page
//      with no truly empty corner still yields a least-bad answer instead of
//      thrashing between equally bad ones.

export type Slot =
  "bottom-right" | "bottom-left" | "top-right" | "top-left" | "middle-right" | "middle-left";

export const DEFAULT_SLOT: Slot = "bottom-right";

// Order matters twice: it is the preference order for ties, and the loop below
// only replaces its running best when a later slot is clearly better — so an
// earlier entry wins whenever the difference is marginal.
const SLOT_ORDER: Slot[] = [
  "bottom-right",
  "bottom-left",
  "top-right",
  "top-left",
  "middle-right",
  "middle-left",
];

/** Breathing room around the element that also has to stay clear. */
const CLEARANCE = 8;
/** Score above which the current slot counts as genuinely obstructed. */
const MOVE_THRESHOLD = 3;
/** How much better a different slot must be before it's worth moving to. */
const IMPROVEMENT_MARGIN = 2;
const MOVE_COOLDOWN_MS = 1200;
/** Trailing debounce, so one scroll gesture is one evaluation. */
const SETTLE_MS = 180;
/** Consecutive clear readings required before returning to the default slot. */
const RETURN_DWELL = 2;
const RETURN_RECHECK_MS = 400;
/** Images below this are icons/decoration, not content worth protecting. */
const MIN_MEDIA_PX = 16;

const W_BLOCKING = 3;
const W_CONTENT = 2;
const W_SURFACE = 1;

const INTERACTIVE_SELECTOR =
  'a[href], button, input, select, textarea, label, summary, [role="button"], [role="link"], [role="menuitem"], [role="tab"], [role="switch"], [role="checkbox"], [contenteditable="true"], [tabindex]:not([tabindex="-1"])';

const NAV_SELECTOR =
  'nav, [role="navigation"], [role="menu"], [role="menubar"], [role="listbox"], [role="dialog"], [role="alertdialog"], [data-radix-popper-content-wrapper]';

const TEXT_SELECTOR = "h1,h2,h3,h4,h5,h6,p,li,td,th,dt,dd,code,pre,blockquote,figcaption";

const MEDIA_SELECTOR = "img, svg, canvas, video";

/** Marks the widget's own nodes so it never treats itself as an obstacle. */
const OWN_NODE_SELECTOR = "[data-chat-widget]";

// 3x3 grid plus the four quarter points — 13 samples across the padded box.
const SAMPLE_FRACTIONS: Array<[number, number]> = [
  [0, 0],
  [0.5, 0],
  [1, 0],
  [0, 0.5],
  [0.5, 0.5],
  [1, 0.5],
  [0, 1],
  [0.5, 1],
  [1, 1],
  [0.25, 0.25],
  [0.75, 0.25],
  [0.25, 0.75],
  [0.75, 0.75],
];

/** Matches the launcher's own CSS offsets (right-4 sm:right-6, bottom-6). */
function marginX(viewportWidth: number) {
  return viewportWidth < 640 ? 16 : 24;
}
const MARGIN_Y = 24;

/**
 * The layout viewport, excluding the scrollbar. `innerWidth` includes it, which
 * would place every right-hand slot ~15px further right than the CSS default
 * corner — so the launcher would visibly jump sideways on its first move, and
 * right-edge samples would land on the scrollbar rather than on content.
 */
function viewport() {
  const el = document.documentElement;
  return { vw: el.clientWidth || window.innerWidth, vh: el.clientHeight || window.innerHeight };
}

type Point = { left: number; top: number };

function slotPosition(slot: Slot, size: number, vw: number, vh: number): Point {
  const mx = marginX(vw);
  const left = slot.endsWith("right") ? Math.max(mx, vw - size - mx) : mx;
  const top = slot.startsWith("bottom")
    ? Math.max(MARGIN_Y, vh - size - MARGIN_Y)
    : slot.startsWith("top")
      ? MARGIN_Y
      : Math.round((vh - size) / 2);
  return { left, top };
}

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}

/** A fixed element spanning the viewport is a modal/overlay, not an obstacle. */
function isFullViewportFixed(el: Element, vw: number, vh: number): boolean {
  const style = window.getComputedStyle(el);
  if (style.position !== "fixed") return false;
  const r = el.getBoundingClientRect();
  return r.width >= vw * 0.9 && r.height >= vh * 0.9;
}

function hasOwnText(el: Element): boolean {
  for (const node of el.childNodes) {
    if (node.nodeType === Node.TEXT_NODE && node.textContent?.trim()) return true;
  }
  return false;
}

/**
 * A card: something with its own painted background AND a border. Weighted
 * lowest of everything, so a card's empty gutter is a last resort rather than
 * a hard block — on a dashboard that is wall-to-wall cards there would
 * otherwise be nowhere left to stand.
 */
function isSurface(el: Element): boolean {
  const style = window.getComputedStyle(el);
  const bg = style.backgroundColor;
  const painted = Boolean(bg) && bg !== "transparent" && !/^rgba\(.*,\s*0\)$/.test(bg);
  if (!painted) return false;
  return (
    parseFloat(style.borderTopWidth) > 0 ||
    parseFloat(style.borderBottomWidth) > 0 ||
    parseFloat(style.borderLeftWidth) > 0 ||
    parseFloat(style.borderRightWidth) > 0
  );
}

type Weight = number | "overlay";

function classify(el: Element, vw: number, vh: number): Weight {
  if (el === document.body || el === document.documentElement) return 0;
  if (isFullViewportFixed(el, vw, vh)) return "overlay";

  // closest() rather than matches() here: the topmost hit inside a button is
  // usually its icon or label, not the button itself. These selectors are
  // specific enough that walking up can't swallow the whole page.
  if (el.closest(INTERACTIVE_SELECTOR) || el.closest(NAV_SELECTOR)) return W_BLOCKING;
  if (el.closest(TEXT_SELECTOR)) return W_CONTENT;

  if (el.matches(MEDIA_SELECTOR)) {
    const r = el.getBoundingClientRect();
    return r.width >= MIN_MEDIA_PX && r.height >= MIN_MEDIA_PX ? W_CONTENT : 0;
  }

  if (hasOwnText(el)) return W_CONTENT;
  if (isSurface(el)) return W_SURFACE;
  return 0;
}

function weightAt(x: number, y: number, vw: number, vh: number): Weight {
  for (const el of document.elementsFromPoint(x, y)) {
    if (!(el instanceof Element)) continue;
    if (el.closest(OWN_NODE_SELECTOR)) continue;
    return classify(el, vw, vh);
  }
  return 0;
}

function scoreSlot(slot: Slot, size: number, vw: number, vh: number): Weight {
  const { left, top } = slotPosition(slot, size, vw, vh);
  const box = size + CLEARANCE * 2;
  let total = 0;
  for (const [fx, fy] of SAMPLE_FRACTIONS) {
    const x = clamp(left - CLEARANCE + box * fx, 1, vw - 1);
    const y = clamp(top - CLEARANCE + box * fy, 1, vh - 1);
    const weight = weightAt(x, y, vw, vh);
    if (weight === "overlay") return "overlay";
    total += weight;
  }
  return total;
}

type Options = {
  /** Square edge length of the element, in px. */
  size: number;
  /** False disables repositioning entirely (e.g. the user parked it by hand). */
  enabled: boolean;
  /** True freezes it where it is without disabling it (panel open, mid-drag). */
  suspended: boolean;
};

export function useObstacleAwarePosition({ size, enabled, suspended }: Options) {
  const [slot, setSlot] = useState<Slot>(DEFAULT_SLOT);
  const [pos, setPos] = useState<Point | null>(null);
  /** Bumped only when the element moves *because it was in the way*. */
  const [movedAt, setMovedAt] = useState<number | null>(null);

  const slotRef = useRef<Slot>(DEFAULT_SLOT);
  const lastMoveAtRef = useRef(0);
  const clearStreakRef = useRef(0);
  const timerRef = useRef<number | null>(null);
  const activeRef = useRef(false);
  const evaluateRef = useRef<() => void>(() => {});

  const schedule = useCallback((delay: number = SETTLE_MS) => {
    if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      evaluateRef.current();
    }, delay);
  }, []);

  const commit = useCallback((next: Slot, announce: boolean) => {
    slotRef.current = next;
    lastMoveAtRef.current = Date.now();
    clearStreakRef.current = 0;
    setSlot(next);
    if (announce) setMovedAt(Date.now());
  }, []);

  const evaluate = useCallback(() => {
    if (!activeRef.current) return;

    const { vw, vh } = viewport();
    // Too cramped for the slots to be meaningfully different from each other.
    if (vw < size * 3 || vh < size * 3) return;

    const sinceMove = Date.now() - lastMoveAtRef.current;
    if (sinceMove < MOVE_COOLDOWN_MS) {
      schedule(MOVE_COOLDOWN_MS - sinceMove);
      return;
    }

    const current = slotRef.current;
    const defaultScore = scoreSlot(DEFAULT_SLOT, size, vw, vh);
    // A modal covers everything, so there is no clear spot to find. Staying put
    // is the right answer; hunting would just be motion for its own sake.
    if (defaultScore === "overlay") return;

    // Home is clear — but only go back once it has stayed that way, so
    // scrolling past a gap doesn't yank the element there and back.
    if (current !== DEFAULT_SLOT && defaultScore === 0) {
      clearStreakRef.current += 1;
      if (clearStreakRef.current >= RETURN_DWELL) commit(DEFAULT_SLOT, false);
      else schedule(RETURN_RECHECK_MS);
      return;
    }
    clearStreakRef.current = 0;

    const currentScore = current === DEFAULT_SLOT ? defaultScore : scoreSlot(current, size, vw, vh);
    if (currentScore === "overlay") return;
    if (currentScore <= MOVE_THRESHOLD) return;

    let best = current;
    let bestScore = currentScore;
    for (const candidate of SLOT_ORDER) {
      if (candidate === current) continue;
      const score = candidate === DEFAULT_SLOT ? defaultScore : scoreSlot(candidate, size, vw, vh);
      if (score === "overlay") return;
      // Compared against the running best, not the original, so a later slot
      // has to beat everything before it — earlier slots win near-ties.
      if (score + IMPROVEMENT_MARGIN <= bestScore) {
        best = candidate;
        bestScore = score;
      }
    }

    if (best !== current) commit(best, best !== DEFAULT_SLOT);
  }, [size, schedule, commit]);

  useEffect(() => {
    evaluateRef.current = evaluate;
  }, [evaluate]);

  useEffect(() => {
    const active = enabled && !suspended;
    activeRef.current = active;
    if (!active) return;

    const onEvent = () => schedule();

    // Capture phase so scrolling inside a nested container counts too, not
    // just the document.
    window.addEventListener("scroll", onEvent, { passive: true, capture: true });
    window.addEventListener("resize", onEvent, { passive: true });

    const observer = new MutationObserver((records) => {
      for (const record of records) {
        const target = record.target instanceof Element ? record.target : null;
        // Ignore our own DOM writes, or moving the element would re-trigger
        // the observer that moved it.
        if (target?.closest(OWN_NODE_SELECTOR)) continue;
        onEvent();
        return;
      }
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["class", "style", "hidden", "data-state"],
    });

    // One pass once the page has had a moment to render its content.
    schedule(SETTLE_MS * 2);

    return () => {
      activeRef.current = false;
      window.removeEventListener("scroll", onEvent, true);
      window.removeEventListener("resize", onEvent);
      observer.disconnect();
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [enabled, suspended, schedule]);

  // Resolve the slot to pixels. Kept in an effect so nothing reads `window`
  // during render, and so a resize re-anchors the element to its slot.
  useEffect(() => {
    if (slot === DEFAULT_SLOT) {
      setPos(null);
      return;
    }
    const apply = () => {
      const { vw, vh } = viewport();
      setPos(slotPosition(slot, size, vw, vh));
    };
    apply();
    window.addEventListener("resize", apply, { passive: true });
    return () => window.removeEventListener("resize", apply);
  }, [slot, size]);

  return {
    slot,
    /**
     * Undefined while the element is at its default slot, so the CSS corner
     * classes stay in charge and the default placement needs no JavaScript.
     */
    style: pos ? ({ left: `${pos.left}px`, top: `${pos.top}px` } as const) : undefined,
    isTop: slot.startsWith("top"),
    isLeft: slot.endsWith("left"),
    /** Timestamp of the last "I was in the way" move; null if it never moved. */
    movedAt,
  };
}
