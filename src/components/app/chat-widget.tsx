import { useCallback, useEffect, useId, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { AnimatePresence, motion } from "motion/react";
import { X, ArrowUp, Zap, Loader2, RotateCcw } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { AssistantOrb } from "@/components/app/assistant-orb";
import { ChatMarkdown } from "@/components/app/chat-markdown";
import { useDraggablePosition } from "@/hooks/use-draggable-position";
import { useObstacleAwarePosition } from "@/hooks/use-obstacle-aware-position";
import { askSecurityAssistant } from "@/lib/chat.functions";
import { startScan } from "@/lib/scans.functions";

const STORAGE_KEY = "pentestai:chat";

// Matches the h-14 launcher. Needed as a number so a drag can be clamped to
// the viewport; it can't be inferred from the Tailwind class alone.
const LAUNCHER_SIZE = 56;
// Remembers a position the user dragged the launcher to.
const POSITION_KEY = "pentestai:chat-position";
// Gap between the launcher and its hover greeting.
const GREETING_GAP = 12;
// Matches the position transition below, so the "moving aside" note appears
// once the launcher has arrived rather than pointing at where it used to be.
const MOVE_ANIMATION_MS = 320;
const MOVE_NOTE_MS = 1800;

function greetingFor(date: Date): string {
  const hour = date.getHours();
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

type ActionState = "pending" | "running" | "done" | "dismissed";

type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  error?: boolean;
  scan?: { repositoryId: string; repositoryName: string; state: ActionState };
};

const SUGGESTIONS = [
  "Are my repos secure?",
  "Show my critical vulnerabilities",
  "How do I fix SQL injection?",
  "Explain OWASP A01",
];

function newId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function loadHistory(): ChatMessage[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ChatMessage[]) : [];
  } catch {
    return [];
  }
}

function TypingDots() {
  return (
    <div className="flex items-center gap-1 px-1 py-2" aria-label="Assistant is typing">
      {[0, 1, 2].map((i) => (
        <motion.span
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-muted-foreground"
          animate={{ opacity: [0.3, 1, 0.3] }}
          transition={{ duration: 1.2, repeat: Infinity, delay: i * 0.18 }}
        />
      ))}
    </div>
  );
}

export function ChatWidget() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>(loadHistory);
  const [input, setInput] = useState("");

  const panelRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const titleId = useId();

  const {
    style: pinnedStyle,
    ref: anchorRef,
    isTop: pinnedIsTop,
    isLeft: pinnedIsLeft,
    isPinned,
    dragging,
    dragHandlers,
    didDragRef,
  } = useDraggablePosition({
    size: LAUNCHER_SIZE,
    storageKey: POSITION_KEY,
  });

  // Keeps the launcher off meaningful content. Disabled outright once the user
  // has parked it by hand — an explicit placement outranks the heuristic — and
  // frozen while the panel is open, since the panel is anchored to the launcher
  // and would otherwise slide across the screen mid-conversation.
  const auto = useObstacleAwarePosition({
    size: LAUNCHER_SIZE,
    enabled: !isPinned,
    suspended: open || dragging,
  });

  const anchorStyle = isPinned ? pinnedStyle : auto.style;
  const isTop = isPinned ? pinnedIsTop : auto.isTop;
  const isLeft = isPinned ? pinnedIsLeft : auto.isLeft;

  // One bubble, two reasons to show it: the hover greeting, and a note when the
  // launcher has just moved out of something's way. Measured from the
  // launcher's live rect rather than assumed to be in a corner, because it can
  // end up anywhere — including mid-screen, where corner offsets would be wrong.
  const [bubble, setBubble] = useState<{
    variant: "greeting" | "moving";
    text: string;
    style: React.CSSProperties;
  } | null>(null);

  const bubbleStyleFor = useCallback((el: HTMLElement): React.CSSProperties => {
    const r = el.getBoundingClientRect();
    const onRight = r.left + r.width / 2 > window.innerWidth / 2;
    const onBottom = r.top + r.height / 2 > window.innerHeight / 2;
    return {
      position: "fixed",
      // Sits on whichever side has room, and aligns its edge to the launcher's
      // so it never runs off-screen.
      ...(onBottom
        ? { bottom: `${window.innerHeight - r.top + GREETING_GAP}px` }
        : { top: `${r.bottom + GREETING_GAP}px` }),
      ...(onRight ? { right: `${window.innerWidth - r.right}px` } : { left: `${r.left}px` }),
    };
  }, []);

  const showGreeting = useCallback(() => {
    const el = triggerRef.current;
    if (!el || open || dragging) return;
    setBubble({ variant: "greeting", text: greetingFor(new Date()), style: bubbleStyleFor(el) });
  }, [open, dragging, bubbleStyleFor]);

  const hideGreeting = useCallback(() => {
    setBubble((b) => (b?.variant === "greeting" ? null : b));
  }, []);

  // Opening the panel or starting a drag both make the bubble redundant.
  useEffect(() => {
    if (open || dragging) setBubble(null);
  }, [open, dragging]);

  // Announce an obstruction move, once the launcher has finished travelling —
  // measuring earlier would anchor the note to the position it just left.
  useEffect(() => {
    if (!auto.movedAt) return;
    const show = window.setTimeout(() => {
      const el = triggerRef.current;
      if (!el) return;
      setBubble({
        variant: "moving",
        text: "Oops, I'm in the way — moving aside!",
        style: bubbleStyleFor(el),
      });
    }, MOVE_ANIMATION_MS);
    const hide = window.setTimeout(
      () => setBubble((b) => (b?.variant === "moving" ? null : b)),
      MOVE_ANIMATION_MS + MOVE_NOTE_MS,
    );
    return () => {
      window.clearTimeout(show);
      window.clearTimeout(hide);
    };
  }, [auto.movedAt, bubbleStyleFor]);

  const qc = useQueryClient();
  const askFn = useServerFn(askSecurityAssistant);
  const scanFn = useServerFn(startScan);

  useEffect(() => {
    try {
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(messages.slice(-40)));
    } catch {
      /* private mode / quota — history is a convenience, not a requirement */
    }
  }, [messages]);

  const ask = useMutation({
    mutationFn: async (history: ChatMessage[]) =>
      askFn({
        data: {
          messages: history.slice(-10).map((m) => ({ role: m.role, content: m.content })),
        },
      }),
    onSuccess: (res: any) => {
      setMessages((prev) => [
        ...prev,
        {
          id: newId(),
          role: "assistant",
          content: res.reply,
          error: Boolean(res.error),
          scan:
            res.action?.kind === "start_scan"
              ? {
                  repositoryId: res.action.repositoryId,
                  repositoryName: res.action.repositoryName,
                  state: "pending" as ActionState,
                }
              : undefined,
        },
      ]);
    },
    onError: (e: Error) => {
      // A bare fetch TypeError ("Failed to fetch") means the request never
      // reached the server at all — say that instead of echoing the raw text.
      const offline = /failed to fetch|networkerror|load failed|connection/i.test(e.message);
      setMessages((prev) => [
        ...prev,
        {
          id: newId(),
          role: "assistant",
          content: offline
            ? "Couldn't reach the server — the request never got through. Check that the dev server is still running, then Retry."
            : e.message,
          error: true,
        },
      ]);
    },
  });

  const runScan = useMutation({
    mutationFn: async (vars: { messageId: string; repositoryId: string }) => {
      setMessages((prev) =>
        prev.map((m) =>
          m.id === vars.messageId && m.scan
            ? { ...m, scan: { ...m.scan, state: "running" as ActionState } }
            : m,
        ),
      );
      return scanFn({ data: { repositoryId: vars.repositoryId } });
    },
    onSuccess: (res: any, vars) => {
      qc.invalidateQueries({ queryKey: ["repositories"] });
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
      setMessages((prev) => [
        ...prev.map((m) =>
          m.id === vars.messageId && m.scan
            ? { ...m, scan: { ...m.scan, state: "done" as ActionState } }
            : m,
        ),
        {
          id: newId(),
          role: "assistant",
          content: `Scan finished — **${res.findings}** finding(s), security score **${res.score}/100**. [Open the scan detail](/scans/${res.scanId})`,
        },
      ]);
      toast.success(`Scan complete — ${res.findings} finding(s)`);
    },
    onError: (e: Error, vars) => {
      setMessages((prev) =>
        prev.map((m) =>
          m.id === vars.messageId && m.scan
            ? { ...m, scan: { ...m.scan, state: "pending" as ActionState } }
            : m,
        ),
      );
      toast.error(e.message);
    },
  });

  const send = useCallback(
    (text: string) => {
      const trimmed = text.trim();
      if (!trimmed || ask.isPending) return;
      const next: ChatMessage[] = [
        ...messages,
        { id: newId(), role: "user" as const, content: trimmed },
      ];
      setMessages(next);
      setInput("");
      ask.mutate(next);
    },
    [messages, ask],
  );

  const retry = useCallback(() => {
    const lastUser = [...messages].reverse().find((m) => m.role === "user");
    if (!lastUser) return;
    const upToLastUser = messages.slice(0, messages.lastIndexOf(lastUser) + 1);
    setMessages(upToLastUser);
    ask.mutate(upToLastUser);
  }, [messages, ask]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, ask.isPending]);

  useEffect(() => {
    if (open) inputRef.current?.focus();
    else triggerRef.current?.focus({ preventScroll: true });
  }, [open]);

  // Escape closes; Tab stays inside the panel while it is open.
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        return;
      }
      if (e.key !== "Tab" || !panelRef.current) return;
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), textarea, input, a[href], [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  const lastMessage = messages[messages.length - 1];
  const lastIsFailedAssistant = lastMessage?.role === "assistant" && lastMessage?.error;

  return (
    <>
      <AnimatePresence>
        {open && (
          <motion.div
            ref={panelRef}
            data-chat-widget
            role="dialog"
            aria-modal="false"
            aria-labelledby={titleId}
            initial={{ opacity: 0, y: 16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.97 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            // Anchored to whichever corner the launcher currently occupies, so
            // the panel opens away from the viewport edge rather than off it.
            style={{
              [isTop ? "top" : "bottom"]: `${LAUNCHER_SIZE + 40}px`,
              [isLeft ? "left" : "right"]: "1rem",
            }}
            className="fixed z-50 flex h-[560px] max-h-[70vh] w-[calc(100vw-2rem)] flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl sm:w-[380px]"
          >
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div className="flex items-center gap-2">
                <AssistantOrb className="h-8 w-8 shrink-0 rounded-full bg-black object-cover" />
                <div>
                  <p id={titleId} className="text-sm font-semibold text-foreground">
                    Security Assistant
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Your repos, findings &amp; general security
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                {messages.length > 0 && (
                  <button
                    onClick={() => setMessages([])}
                    aria-label="Clear conversation"
                    className="grid h-8 w-8 cursor-pointer place-items-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                  >
                    <RotateCcw aria-hidden className="h-4 w-4" />
                  </button>
                )}
                <button
                  onClick={() => setOpen(false)}
                  aria-label="Close security assistant"
                  className="grid h-8 w-8 cursor-pointer place-items-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                >
                  <X aria-hidden className="h-4 w-4" />
                </button>
              </div>
            </div>

            <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto px-4 py-4">
              {messages.length === 0 && (
                <div className="space-y-3">
                  <p className="text-sm text-muted-foreground">
                    Ask about a repository&apos;s security posture, a specific finding, or anything
                    security-related.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {SUGGESTIONS.map((s) => (
                      <button
                        key={s}
                        onClick={() => send(s)}
                        className="cursor-pointer rounded-full border border-border bg-background/60 px-3 py-1.5 text-xs text-foreground transition-colors hover:border-primary-strong hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {messages.map((m) =>
                m.role === "user" ? (
                  <div key={m.id} className="flex justify-end">
                    <div className="max-w-[85%] rounded-lg rounded-br-sm bg-primary-strong px-3 py-2 text-sm whitespace-pre-wrap text-white">
                      {m.content}
                    </div>
                  </div>
                ) : (
                  <div key={m.id} className="space-y-2">
                    <div
                      className={`max-w-[92%] rounded-lg rounded-bl-sm border px-3 py-2 ${
                        m.error ? "border-high/40 bg-high/10" : "border-border bg-background/50"
                      }`}
                    >
                      <ChatMarkdown text={m.content} />
                    </div>

                    {m.scan && m.scan.state !== "dismissed" && m.scan.state !== "done" && (
                      <div className="rounded-lg border border-primary-strong/40 bg-primary/10 px-3 py-2.5">
                        <p className="text-xs text-foreground">
                          Run a scan on{" "}
                          <span className="font-mono font-medium">{m.scan.repositoryName}</span>?
                        </p>
                        <p className="mt-0.5 text-[11px] text-muted-foreground">
                          This starts a real pen test against the repository.
                        </p>
                        <div className="mt-2 flex gap-2">
                          <Button
                            size="sm"
                            className="h-8 bg-primary-strong text-xs text-white hover:bg-primary-hover"
                            disabled={m.scan.state === "running"}
                            onClick={() =>
                              runScan.mutate({
                                messageId: m.id,
                                repositoryId: m.scan!.repositoryId,
                              })
                            }
                          >
                            {m.scan.state === "running" ? (
                              <>
                                <Loader2 aria-hidden className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                                Scanning…
                              </>
                            ) : (
                              <>
                                <Zap aria-hidden className="mr-1.5 h-3.5 w-3.5" />
                                Run scan
                              </>
                            )}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-8 text-xs"
                            disabled={m.scan.state === "running"}
                            onClick={() =>
                              setMessages((prev) =>
                                prev.map((x) =>
                                  x.id === m.id && x.scan
                                    ? {
                                        ...x,
                                        scan: { ...x.scan, state: "dismissed" as ActionState },
                                      }
                                    : x,
                                ),
                              )
                            }
                          >
                            Cancel
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                ),
              )}

              {ask.isPending && <TypingDots />}

              {lastIsFailedAssistant && !ask.isPending && (
                <button
                  onClick={retry}
                  className="cursor-pointer text-xs text-accent-fg underline underline-offset-2 hover:text-accent-fg/80"
                >
                  Retry
                </button>
              )}
            </div>

            <div className="border-t border-border p-3">
              <div className="flex items-end gap-2">
                <textarea
                  ref={inputRef}
                  rows={1}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      send(input);
                    }
                  }}
                  placeholder="Ask about your repos or security…"
                  aria-label="Message the security assistant"
                  className="max-h-28 min-h-11 flex-1 resize-none rounded-md border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                />
                <Button
                  size="icon"
                  aria-label="Send message"
                  disabled={!input.trim() || ask.isPending}
                  onClick={() => send(input)}
                  className="h-11 w-11 shrink-0 bg-primary-strong text-white hover:bg-primary-hover"
                >
                  <ArrowUp aria-hidden className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Decorative: aria-hidden because the button's own aria-label already
          tells assistive tech what this control is, and dragging is a pointer
          interaction anyway. */}
      <AnimatePresence>
        {bubble && (
          <motion.div
            aria-hidden
            data-chat-widget
            initial={{ opacity: 0, scale: 0.95, y: 4 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 4 }}
            transition={{ duration: 0.15, ease: "easeOut" }}
            style={bubble.style}
            className="pointer-events-none z-50 max-w-[16rem] rounded-lg border border-border bg-card px-3 py-2 shadow-lg"
          >
            <span className="block text-sm font-semibold text-foreground">{bubble.text}</span>
            {bubble.variant === "greeting" && (
              <span className="mt-0.5 block text-xs text-muted-foreground">
                Ask me anything about your repositories&apos; security — or drag me anywhere.
              </span>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      <button
        ref={(node) => {
          triggerRef.current = node;
          anchorRef.current = node;
        }}
        data-tour="assistant"
        data-chat-widget
        {...dragHandlers}
        onMouseEnter={showGreeting}
        onMouseLeave={hideGreeting}
        onClick={() => {
          // Releasing a drag also fires a click; ignore that one so parking the
          // launcher doesn't open the panel.
          if (didDragRef.current) {
            didDragRef.current = false;
            return;
          }
          setOpen((v) => !v);
        }}
        aria-label={open ? "Close security assistant" : "Open security assistant"}
        aria-expanded={open}
        // Only set once the launcher has been dragged or has moved out of
        // something's way. Until then it is undefined and the bottom-right
        // Tailwind offsets below apply, so the default placement is pure CSS
        // and survives even if JS never runs.
        style={anchorStyle}
        // bg-black matches the orb clip's own background, so the video reads as
        // the button itself rather than as a video pasted onto a coloured disc.
        className={`fixed z-50 grid h-14 w-14 touch-none place-items-center rounded-full bg-black text-white shadow-lg focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-none ${
          anchorStyle ? "" : "right-4 bottom-6 sm:right-6"
        } ${
          dragging
            ? // No position transition at all: the launcher only moves under the
              // pointer, where any easing would just lag behind it.
              "scale-110 cursor-grabbing shadow-2xl transition-none"
            : // left/top are transitioned too, so an automatic move out of
              // something's way glides instead of teleporting.
              "cursor-grab transition-[transform,left,top] duration-300 ease-out hover:scale-105 motion-reduce:transition-none"
        }`}
      >
        {open ? (
          <X aria-hidden className="h-6 w-6" />
        ) : (
          // Clipped by its own wrapper rather than by overflow-hidden on the
          // button, so the unread badge below can still overhang the circle.
          <span className="absolute inset-0 overflow-hidden rounded-full">
            <AssistantOrb className="h-full w-full object-cover" />
          </span>
        )}
      </button>
    </>
  );
}
