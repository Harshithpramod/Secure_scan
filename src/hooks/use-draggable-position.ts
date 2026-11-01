import { useCallback, useEffect, useRef, useState } from "react";

// Lets a fixed-position element be dragged and parked anywhere in the viewport.
//
// It does NOT move on its own. While the element has never been dragged this
// hook returns no inline position at all, so the element keeps whatever CSS
// corner its classes give it — the default placement stays pure CSS with no
// JavaScript in the path. Only once the user drags does an explicit position
// take over.

type Placement = { left: number; top: number };

type Options = {
  /** Square edge length of the element, in px. Used for bounds clamping. */
  size: number;
  /** localStorage key for the dragged position. Omit to disable persistence. */
  storageKey?: string;
};

const DRAG_THRESHOLD = 5; // px of movement before a press counts as a drag

function marginFor(viewportWidth: number) {
  return viewportWidth < 640 ? 16 : 24;
}

/** Keeps the element fully on-screen, with the same margin the CSS default uses. */
function clampToViewport(pos: Placement, size: number): Placement {
  const m = marginFor(window.innerWidth);
  return {
    left: Math.min(Math.max(pos.left, m), Math.max(m, window.innerWidth - size - m)),
    top: Math.min(Math.max(pos.top, m), Math.max(m, window.innerHeight - size - m)),
  };
}

function loadPinned(storageKey?: string): Placement | null {
  if (!storageKey || typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return typeof parsed?.left === "number" && typeof parsed?.top === "number" ? parsed : null;
  } catch {
    return null;
  }
}

export function useDraggablePosition({ size, storageKey }: Options) {
  // null = never dragged, so the element's CSS default corner applies.
  const [pinned, setPinned] = useState<Placement | null>(() => loadPinned(storageKey));
  const [dragging, setDragging] = useState(false);

  const elRef = useRef<HTMLElement | null>(null);
  /** Set when a press turned into a drag, so the trailing click can be ignored. */
  const didDrag = useRef(false);

  const persist = useCallback(
    (next: Placement | null) => {
      if (!storageKey) return;
      try {
        if (next) window.localStorage.setItem(storageKey, JSON.stringify(next));
        else window.localStorage.removeItem(storageKey);
      } catch {
        /* storage unavailable — the position just won't survive a reload */
      }
    },
    [storageKey],
  );

  // A window that shrinks below a parked position would otherwise strand the
  // element off-screen. This is the only thing that moves it without a drag.
  useEffect(() => {
    if (!pinned) return;
    const onResize = () => {
      setPinned((prev) => {
        if (!prev) return prev;
        const next = clampToViewport(prev, size);
        return next.left === prev.left && next.top === prev.top ? prev : next;
      });
    };
    window.addEventListener("resize", onResize, { passive: true });
    return () => window.removeEventListener("resize", onResize);
  }, [pinned, size]);

  // Pointer events cover mouse, touch and pen in one path. During the drag the
  // element's style is written directly rather than through state, so a 60Hz
  // pointer stream doesn't re-render on every move.
  const onPointerDown = useCallback(
    (e: React.PointerEvent<HTMLElement>) => {
      if (e.pointerType === "mouse" && e.button !== 0) return;
      const el = elRef.current;
      if (!el) return;

      const startX = e.clientX;
      const startY = e.clientY;
      const rect = el.getBoundingClientRect();
      const offsetX = startX - rect.left;
      const offsetY = startY - rect.top;
      didDrag.current = false;

      const move = (ev: PointerEvent) => {
        if (!didDrag.current) {
          if (Math.hypot(ev.clientX - startX, ev.clientY - startY) < DRAG_THRESHOLD) return;
          didDrag.current = true;
          setDragging(true);
          el.setPointerCapture?.(ev.pointerId);
        }
        const next = clampToViewport(
          { left: ev.clientX - offsetX, top: ev.clientY - offsetY },
          size,
        );
        el.style.left = `${next.left}px`;
        el.style.top = `${next.top}px`;
        // The CSS default corner is expressed with right/bottom; clear them or
        // they fight the left/top being set here.
        el.style.right = "auto";
        el.style.bottom = "auto";
      };

      const up = (ev: PointerEvent) => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
        window.removeEventListener("pointercancel", up);
        if (!didDrag.current) return; // a plain click — leave it entirely alone

        setDragging(false);
        const dropped = clampToViewport(
          { left: ev.clientX - offsetX, top: ev.clientY - offsetY },
          size,
        );
        setPinned(dropped);
        persist(dropped);
      };

      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
      window.addEventListener("pointercancel", up);
    },
    [size, persist],
  );

  // Only meaningful once dragged; before that the element sits bottom-right.
  const isLeft = pinned ? pinned.left + size / 2 < window.innerWidth / 2 : false;
  const isTop = pinned ? pinned.top + size / 2 < window.innerHeight / 2 : false;

  return {
    /** Inline position once dragged; undefined so CSS classes win before that. */
    style: pinned ? { left: `${pinned.left}px`, top: `${pinned.top}px` } : undefined,
    ref: elRef,
    isTop,
    isLeft,
    dragging,
    isPinned: pinned !== null,
    /** Spread onto the element to make it draggable. */
    dragHandlers: { onPointerDown },
    /** Check in onClick to swallow the click that ends a drag. */
    didDragRef: didDrag,
  };
}
