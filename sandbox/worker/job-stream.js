// Live sandbox console: relays progress lines from verify/fix containers to
// the app, one signed callback per line.
//
// Containers write `@@progress {json}` lines to stderr. Only those lines are
// relayed — never raw stderr — so tool output about untrusted code can't put
// arbitrary text in front of a user. Every string is also redacted before it
// leaves the worker: fix diffs in particular show real file contents, and a
// finding about a hardcoded key would otherwise print the key.

import { SECRET_PATTERNS } from "./scan.js";

export const PROGRESS_MARKER = "@@progress ";

/** Lines per job. A runaway container can't flood the database. */
export const MAX_EVENTS_PER_JOB = 300;
const MAX_MESSAGE = 1000;
const MAX_DATA_STRING = 20_000; // room for a capped unified diff
const LEVELS = new Set(["info", "warn", "error", "success"]);

// Literal credential values only. A rule like "anything assigned to a variable
// named *password*" would mangle ordinary code (`const password =
// document.getElementById('password')`) all over a diff, so:
//   - a QUOTED literal assigned to a sensitive-looking name, in any case;
//   - an UNQUOTED value only for ALL-CAPS env/config names (API_KEY=abc123).
// The name's prefix is optional: a variable called exactly `password` or
// `TOKEN` counts. An earlier version required one and missed both.
const QUOTED_SENSITIVE =
  /\b([A-Za-z0-9_]*(?:key|secret|token|password|passwd|pwd|credential)[A-Za-z0-9_]*["']?\s*[:=]\s*)(["'])([^"'\s]{6,})\2/gi;
const ENV_SENSITIVE =
  /^([+\- ]?\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|DSN)[A-Z0-9_]*\s*=\s*)([^\s#"']{6,})/gm;

export function redactText(text) {
  let out = String(text ?? "");
  for (const { re } of SECRET_PATTERNS) {
    out = out.replace(new RegExp(re.source, re.flags), "[redacted]");
  }
  out = out.replace(QUOTED_SENSITIVE, (_m, name, q) => `${name}${q}[redacted]${q}`);
  out = out.replace(ENV_SENSITIVE, (_m, name) => `${name}[redacted]`);
  return out;
}

export function redactDeep(value, depth = 0) {
  if (depth > 5) return null;
  if (typeof value === "string") return redactText(value.slice(0, MAX_DATA_STRING));
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redactDeep(v, depth + 1));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value).slice(0, 40)) out[k] = redactDeep(v, depth + 1);
    return out;
  }
  return typeof value === "number" || typeof value === "boolean" || value === null ? value : null;
}

/**
 * Splits a byte stream into lines. Call with each chunk, then with null at
 * end of stream to flush an unterminated final line.
 */
export function lineSplitter(onLine) {
  let buf = "";
  return (chunk) => {
    if (chunk === null) {
      if (buf) onLine(buf);
      buf = "";
      return;
    }
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf("\n")) !== -1) {
      onLine(buf.slice(0, nl).replace(/\r$/, ""));
      buf = buf.slice(nl + 1);
    }
  };
}

/**
 * Per-job relay. Lines are sequenced (the app orders by `seq`, since
 * callbacks can land out of order) and sent one after another through a
 * promise chain; `flush()` waits for all of them, so a job's console lines are
 * delivered before its final verdict.
 */
export function createJobReporter(job, jobKind, post) {
  let seq = 0;
  let queue = Promise.resolve();
  let capped = false;

  const send = (stage, message, level, data) => {
    if (capped) return;
    if (seq === MAX_EVENTS_PER_JOB - 1) {
      capped = true;
      stage = "limit";
      message = `Console limit of ${MAX_EVENTS_PER_JOB} lines reached; further lines are not shown`;
      level = "warn";
      data = {};
    }
    const payload = {
      kind: "job_progress",
      job_kind: jobKind,
      job_id: job.id,
      vulnerability_id: job.vulnerability_id,
      scan_id: job.scan_id ?? null,
      seq: seq++,
      stage: String(stage ?? "").slice(0, 40),
      level: LEVELS.has(level) ? level : "info",
      message: redactText(String(message ?? "")).slice(0, MAX_MESSAGE),
      data: redactDeep(data && typeof data === "object" ? data : {}),
    };
    queue = queue.then(() => post(payload)).catch(() => {});
  };

  return {
    /** A line the worker itself writes. */
    emit(stage, message, { level = "info", data } = {}) {
      send(stage, message, level, data);
    },
    /** A line a container wrote; its fields are untrusted and re-validated. */
    relay(p) {
      if (!p || typeof p !== "object" || typeof p.message !== "string") return;
      send(p.stage, p.message, p.level, p.data);
    },
    flush() {
      return queue;
    },
  };
}
