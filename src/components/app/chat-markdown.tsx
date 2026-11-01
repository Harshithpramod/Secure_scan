import { useNavigate } from "@tanstack/react-router";
import { Fragment, type ReactNode } from "react";

// Deliberately hand-rolled and node-based: assistant output is model text and
// must never reach dangerouslySetInnerHTML. Covers the subset the assistant is
// told to emit — headings, lists, bold/italic, inline + fenced code, links.

const INLINE = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*]+\*)|(\[[^\]]+\]\([^)\s]+\))/g;

// Model output decides these hrefs, so anything that isn't an in-app path or a
// plain web/mail URL (javascript:, data:, vbscript:) is rendered as text.
function safeHref(href: string): string | null {
  if (href.startsWith("/") && !href.startsWith("//")) return href;
  return /^(https?:|mailto:)/i.test(href) ? href : null;
}

function InternalLink({ href, children }: { href: string; children: ReactNode }) {
  const navigate = useNavigate();
  return (
    <a
      href={href}
      onClick={(e) => {
        e.preventDefault();
        navigate({ to: href as never });
      }}
      className="text-accent-fg underline underline-offset-2 hover:text-accent-fg/80"
    >
      {children}
    </a>
  );
}

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  let match: RegExpExecArray | null;
  INLINE.lastIndex = 0;

  while ((match = INLINE.exec(text)) !== null) {
    if (match.index > last) nodes.push(text.slice(last, match.index));
    const token = match[0];
    const key = `${keyPrefix}-${match.index}`;

    if (token.startsWith("`")) {
      nodes.push(
        <code
          key={key}
          className="rounded bg-background/70 px-1 py-0.5 font-mono text-[0.85em] text-foreground"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else if (token.startsWith("**")) {
      nodes.push(
        <strong key={key} className="font-semibold text-foreground">
          {token.slice(2, -2)}
        </strong>,
      );
    } else if (token.startsWith("*")) {
      nodes.push(<em key={key}>{token.slice(1, -1)}</em>);
    } else {
      const split = token.indexOf("](");
      const label = token.slice(1, split);
      const href = safeHref(token.slice(split + 2, -1));
      nodes.push(
        href === null ? (
          label
        ) : href.startsWith("/") ? (
          <InternalLink key={key} href={href}>
            {label}
          </InternalLink>
        ) : (
          <a
            key={key}
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent-fg underline underline-offset-2 hover:text-accent-fg/80"
          >
            {label}
          </a>
        ),
      );
    }
    last = match.index + token.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

export function ChatMarkdown({ text }: { text: string }) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let paragraph: string[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;

  const flushParagraph = () => {
    if (!paragraph.length) return;
    const key = `p-${blocks.length}`;
    blocks.push(
      <p key={key} className="leading-relaxed whitespace-pre-wrap">
        {renderInline(paragraph.join(" "), key)}
      </p>,
    );
    paragraph = [];
  };

  const flushList = () => {
    if (!list) return;
    const key = `l-${blocks.length}`;
    const items = list.items.map((item, i) => (
      <li key={`${key}-${i}`} className="leading-relaxed">
        {renderInline(item, `${key}-${i}`)}
      </li>
    ));
    blocks.push(
      list.ordered ? (
        <ol key={key} className="list-decimal space-y-1 pl-5">
          {items}
        </ol>
      ) : (
        <ul key={key} className="list-disc space-y-1 pl-5">
          {items}
        </ul>
      ),
    );
    list = null;
  };

  const flushAll = () => {
    flushParagraph();
    flushList();
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.trimStart().startsWith("```")) {
      flushAll();
      const lang = line.trim().slice(3).trim();
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) body.push(lines[i++]);
      blocks.push(
        <pre
          key={`c-${blocks.length}`}
          className="overflow-x-auto rounded-md border border-border bg-background/70 p-3"
        >
          <code className="font-mono text-xs text-foreground">{body.join("\n")}</code>
          {lang && <span className="sr-only">{`Language: ${lang}`}</span>}
        </pre>,
      );
      continue;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flushAll();
      const key = `h-${blocks.length}`;
      blocks.push(
        <p key={key} className="mt-1 font-semibold text-foreground">
          {renderInline(heading[2], key)}
        </p>,
      );
      continue;
    }

    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (bullet || numbered) {
      flushParagraph();
      const ordered = Boolean(numbered);
      if (!list || list.ordered !== ordered) {
        flushList();
        list = { ordered, items: [] };
      }
      list.items.push((bullet ?? numbered)![1]);
      continue;
    }

    if (!line.trim()) {
      flushAll();
      continue;
    }

    flushList();
    paragraph.push(line.trim());
  }
  flushAll();

  return (
    <div className="space-y-2 text-sm text-foreground/90">
      {blocks.map((b, i) => (
        <Fragment key={i}>{b}</Fragment>
      ))}
    </div>
  );
}
