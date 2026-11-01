import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { X, ArrowUp, RotateCcw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { AssistantOrb } from "@/components/app/assistant-orb";
import { ChatMarkdown } from "@/components/app/chat-markdown";
import { DEMO_ASSISTANT_SUGGESTIONS, demoAssistantReply } from "@/lib/demo-data";

/**
 * The demo's assistant. Visually the same widget as the real one, but every
 * reply comes from a lookup table in demo-data.ts — no server function, no
 * model call, no network request of any kind.
 */

type Msg = { id: string; role: "user" | "assistant"; content: string };

const newId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

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

export function DemoAssistant() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [thinking, setThinking] = useState(false);

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, thinking]);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const send = useCallback((text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;
    setMessages((prev) => [...prev, { id: newId(), role: "user", content: trimmed }]);
    setInput("");
    setThinking(true);
    // A short pause so the reply reads as considered rather than instant.
    timer.current = setTimeout(() => {
      setThinking(false);
      setMessages((prev) => [
        ...prev,
        { id: newId(), role: "assistant", content: demoAssistantReply(trimmed) },
      ]);
    }, 650);
  }, []);

  return (
    <>
      <AnimatePresence>
        {open && (
          <motion.div
            role="dialog"
            aria-label="Demo security assistant"
            initial={{ opacity: 0, y: 16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.97 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            className="fixed right-4 bottom-24 z-50 flex h-[520px] max-h-[70vh] w-[calc(100vw-2rem)] flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl sm:right-6 sm:w-[380px]"
          >
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div className="flex items-center gap-2">
                <AssistantOrb className="h-8 w-8 shrink-0 rounded-full bg-black object-cover" />
                <div>
                  <p className="text-sm font-semibold text-foreground">Security Assistant</p>
                  <p className="text-xs text-muted-foreground">Demo — scripted replies</p>
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
                  aria-label="Close assistant"
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
                    Ask about this demo repository&apos;s security posture. Replies are scripted for
                    the demo — the real assistant answers from your own scan data.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {DEMO_ASSISTANT_SUGGESTIONS.map((s) => (
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
                  <div
                    key={m.id}
                    className="max-w-[92%] rounded-lg rounded-bl-sm border border-border bg-background/50 px-3 py-2"
                  >
                    <ChatMarkdown text={m.content} />
                  </div>
                ),
              )}

              {thinking && <TypingDots />}
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
                  placeholder="Ask about this demo repo…"
                  aria-label="Message the demo assistant"
                  className="max-h-28 min-h-11 flex-1 resize-none rounded-md border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                />
                <Button
                  size="icon"
                  aria-label="Send message"
                  disabled={!input.trim() || thinking}
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

      <button
        onClick={() => setOpen((v) => !v)}
        aria-label={open ? "Close security assistant" : "Open security assistant"}
        aria-expanded={open}
        className="fixed right-4 bottom-6 z-50 grid h-14 w-14 cursor-pointer place-items-center rounded-full bg-black text-white shadow-lg transition-transform hover:scale-105 focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-none sm:right-6"
      >
        {open ? (
          <X aria-hidden className="h-6 w-6" />
        ) : (
          <span className="absolute inset-0 overflow-hidden rounded-full">
            <AssistantOrb className="h-full w-full object-cover" />
          </span>
        )}
      </button>
    </>
  );
}
