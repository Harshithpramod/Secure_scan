# PentestAI — Architecture & Code Guide

A detailed walkthrough of what this codebase is, how it is put together, and what
each part actually does.

> **On accuracy.** This document describes the code as it exists, including the
> places where the implementation is narrower than the product language around
> it. Those are called out inline rather than left for you to discover later.
> See [Known gaps](#12-known-gaps-and-honest-caveats).

---

## 1. What the product does

PentestAI connects to a user's GitHub repositories and runs automated security
analysis on them. For each repository it can:

1. **Scan** the source for vulnerabilities (an LLM reads selected files, plus a
   deterministic regex pass for committed secrets).
2. **Verify** each finding by re-analysing the repository inside an isolated,
   network-less Docker container, to filter false positives.
3. **Fix** a finding by asking a code model for a patch and opening a GitHub
   pull request with it.
4. **Re-scan weekly** on a rolling schedule and email the user a digest.
5. **Answer questions** about findings through a chat assistant grounded in the
   user's own scan data.

There is also a fully simulated **live demo** at `/demo` requiring no sign-in.

---

## 2. Technology stack

| Layer           | Choice                                                                  |
| --------------- | ----------------------------------------------------------------------- |
| Framework       | TanStack Start (SSR) + TanStack Router (file-based routes)              |
| UI              | React 19, Tailwind CSS v4, shadcn/ui (46 primitives over Radix)         |
| Data fetching   | TanStack Query                                                          |
| Animation       | `motion` (Framer Motion successor), three.js for the landing shader     |
| Database / auth | Supabase (Postgres + Row Level Security + GitHub OAuth)                 |
| Server logic    | TanStack **server functions** (`createServerFn`), `*.server.ts` modules |
| Sandbox         | Docker Compose — Caddy, Fastify API, Redis, worker, one-shot runners    |
| Static analysis | CodeQL + Semgrep (bundled offline rules)                                |
| AI              | Google Gemini (scanning + chat), OpenRouter (AI fixes only)             |
| Email           | nodemailer over SMTP                                                    |
| Tests           | Vitest (~184 tests)                                                     |
| Tooling         | TypeScript, ESLint (flat config), Prettier                              |

---

## 3. Repository layout

```
src/
  routes/                     file-based routes (URL = filename)
    index.tsx                 public landing page
    auth.tsx                  GitHub sign-in
    demo.tsx                  simulated product tour, no auth
    _authenticated/           layout that redirects signed-out users
      route.tsx               the auth guard itself
      dashboard.tsx  repositories.tsx  scans.tsx
      scans.$scanId.tsx       one scan, with a live log feed
      vulnerabilities.tsx  reports.tsx  settings.tsx
  lib/
    *.functions.ts            server functions callable from the client
    *.server.ts               server-only modules (never bundled to browser)
    demo-data.ts              static fixtures for /demo
  integrations/supabase/      browser client, server client, auth middleware, types
  components/
    app/                      chat widget, onboarding, shared UI atoms
    demo/                     demo-only components
    backgrounds/              vendored React Bits shaders (ColorBends, DotField)
    ui/                       shadcn primitives
  server.ts                   server entry — intercepts two public API routes
sandbox/
  docker-compose.yml          the whole sandbox topology
  api/server.js               Fastify job-submission API
  worker/worker.js            persistent job loop
  worker/scan.js              the scan pipeline
  worker/scheduler.js         weekly sweep pinger
  runners/                    one-shot verification image (probe.sh, sarif_verdict.py)
  worker/fix-gate.js          re-scan gate an AI patch must pass before a PR
  worker/job-stream.js        relays @@progress lines from containers, redacted
  fixer/fixer.js              one-shot AI-fix + PR image
supabase/migrations/          schema, applied by hand
```

### The two file-naming conventions in `lib/`

This distinction matters and is easy to miss:

- **`*.functions.ts`** export `createServerFn(...)` values. They are _imported by
  React components_ and called like ordinary async functions; TanStack turns the
  call into an RPC. They run on the server but are referenced from client code.
- **`*.server.ts`** are server-only modules. They are never imported by a
  component. They hold secrets (service-role key, SMTP password, HMAC secret) and
  are dynamically imported so they never reach the browser bundle.

---

## 4. System architecture

Two independent halves that talk over HTTP:

```
┌───────────────────────────────┐         ┌──────────────────────────────────┐
│  App (TanStack Start, Node)   │         │  Sandbox (Docker Compose)        │
│                               │         │                                  │
│  routes/  →  *.functions.ts   │  POST   │  caddy → api (Fastify)           │
│                    │          ├────────►│            │                     │
│                    ▼          │  job    │            ▼                     │
│              sandbox.ts       │         │          redis  (queue)          │
│                               │         │            │                     │
│  server.ts                    │         │            ▼                     │
│   /api/public/sandbox-callback│◄────────┤          worker (persistent)     │
│   /api/public/run-weekly-scans│  HMAC   │            │                     │
│         │                     │ callback│            ├─ scan.js (in-proc)  │
│         ▼                     │         │            ├─ runner  (one-shot) │
│      Supabase ◄───────────────┼─────────┤            └─ fixer   (one-shot) │
└───────────────────────────────┘         └──────────────────────────────────┘
```

The app never runs untrusted code. The sandbox never holds a database
credential. Everything between them is a signed HTTP message.

### Why a separate sandbox at all

Cloning and analysing arbitrary user repositories is hostile input. Putting that
work in disposable containers on isolated Docker networks means a malicious
repository cannot reach the app, the database, or the internet.

### Network topology (`docker-compose.yml`)

| Network      | `internal` | Who is on it                                               |
| ------------ | ---------- | ---------------------------------------------------------- |
| `edge`       | no         | caddy — the only public entry point                        |
| `internal`   | **yes**    | api, worker, redis                                         |
| `runner_net` | **yes**    | verification runners                                       |
| `fixer_net`  | no         | the fixer, which _needs_ egress to reach GitHub/OpenRouter |

`internal: true` means no route to the outside world at all.

> Compose prunes networks nothing is attached to, so `worker` is deliberately
> attached to `runner_net` and `fixer_net` even though it doesn't use them
> directly — otherwise the one-shot containers fail with "network not found".

---

## 5. Data model

All tables live in `public` with **Row Level Security enabled**. The standard
policy is `auth.uid() = user_id`, so a user can only ever see their own rows,
enforced by Postgres rather than application code.

### Core tables

**`repositories`** — a connected GitHub repo.
Key columns: `full_name`, `default_branch`, `scan_mode` (`manual` | `weekly`),
`last_scan_at`, `status`, `security_score`.
`UNIQUE (user_id, full_name)` prevents duplicate imports.

**`scans`** — one scan run.
`status` (`queued` → `running` → `completed` | `failed`), `current_stage`,
`progress` (0–100), severity counts, `security_score`, `trigger`
(`manual` | `scheduled` | `push`), `sandbox_job_id`, `weekly_run_id`.

**`vulnerabilities`** — one finding. Carries three independent lifecycles:

- _triage_: `status` (`open`/`fixed`/`false_positive`), `severity`, `cvss_score`, `cwe_id`
- _verification_: `verification_status`, `verification_evidence`, `verification_details`, `sandbox_job_id`
- _fix_: `fix_status`, `fix_job_id`, `fix_pr_url`, `fix_branch`, `fix_error`

**`scan_logs`** — append-only progress lines. This is what powers the live feed;
the UI subscribes to it over Supabase Realtime.

**`github_connections`** — the user's GitHub token, encrypted at rest. Has an
explicit **"No client access"** policy: unreachable from the browser under any
circumstances, service-role only.

**`weekly_digest_log`** — `PRIMARY KEY (weekly_run_id, user_id)`. Not really a
log; it is an **idempotency lock**. Whichever callback first notices a weekly run
has finished inserts here and wins the right to send the email. Everyone else
gets a unique-violation and silently skips. This is why a digest can't be sent
twice.

**`notification_preferences`** — `email_enabled`, `weekly_summary`, etc.

**`vulnerability_events`** — the timeline of one finding (`detected`, `seen`,
`not_seen`, `status_changed`, `duplicate_merged`, `verification`,
`fix_requested`, `fix_pr_opened`, `fix_rejected`). Read-only to clients. A
`SECURITY DEFINER` trigger adds a `status_changed` row on every status change.

**`job_logs`** — live console lines from verify/fix containers, ordered by a
worker-assigned `seq` (`UNIQUE (job_id, seq)`), since callbacks can arrive out
of order. Read-only to clients.

Both tables come from `20260924120000_vuln_lifecycle_and_job_logs.sql`, which
also adds the cross-scan columns on `vulnerabilities` (`last_seen_scan_id`,
`missed_scans`, `regression_count`, `duplicate_of`, `status_reason`). See
[Vulnerability lifecycle](#vulnerability-lifecycle).

### The two job-id indexes

`idx_scans_sandbox_job_id` and `idx_vulns_fix_job_id` exist to support _callback
binding_, described in §7.3.

---

## 6. Authentication and the security model

### Sign-in

GitHub OAuth via Supabase. `_authenticated/route.tsx` has a `beforeLoad` that
redirects signed-out visitors to `/auth`. `/demo` is deliberately **not** nested
under it — that is why the demo works without an account.

### Two Supabase clients, never confused

| Client                     | Key          | Respects RLS | Where       |
| -------------------------- | ------------ | ------------ | ----------- |
| `client.ts`                | anon         | yes          | browser     |
| `supabase-admin.server.ts` | service-role | **no**       | server only |

Every admin-client query manually filters by `user_id`, because RLS is not there
to help. `requireSupabaseAuth` (middleware) resolves the caller's identity from
their JWT so a server function can never be tricked about who is asking.

### GitHub tokens at rest — `token-crypto.server.ts`

Tokens are encrypted with **AES-256-GCM** via WebCrypto and stored as
`v1.<iv>.<ciphertext>`. The versioned prefix allows key rotation later.
`isEncryptedToken()` detects legacy plaintext rows, and `getUserAccessToken()`
transparently re-encrypts them on read, so the migration happens gradually with
no downtime and no migration script.

### Tokens in transit — the clone problem

A naive implementation clones `https://<token>@github.com/...`, which leaks the
token into `.git/config`, into `ps` output, and into any error message. Instead
`worker.js` uses a **git credential helper** that reads the token from an
environment variable:

- never in `argv` (so not visible in `ps`)
- never written to `.git/config`
- the prepared repo is mounted into the runner **without** the credential

### Callback authentication

The sandbox calls back over plain HTTP, so every callback body is signed with
**HMAC-SHA256** using `CALLBACK_HMAC_SECRET` and compared with
`timingSafeEqual` (constant-time, so the comparison itself leaks nothing).

---

## 7. The scan lifecycle, end to end

This is the central flow. Worth following completely.

### 7.1 Trigger

`startScan` (`scans.functions.ts`) authenticates the caller, then delegates to
`triggerScan()` in `scan-trigger.server.ts`. That shared helper is used by both
manual scans and the weekly sweep, so the two paths cannot drift apart. It:

1. loads the repository (checking ownership),
2. refuses if a scan is already `queued`/`running` for that repo,
3. decrypts the user's GitHub token,
4. **generates the job id itself**,
5. inserts the `scans` row with that `sandbox_job_id` already set,
6. submits the job to the sandbox.

> **Why the caller generates the job id.** If the sandbox assigned it, the
> sandbox could finish and call back _before_ the app had written the id to the
> database — the callback would match no row and the result would be lost.
> Generating it first makes the race impossible.

### 7.2 Execution — `sandbox/worker/scan.js`

The worker pops the job from Redis and runs `runScan()`, which reports progress
at each stage:

| Stage         | %     | What happens                                   |
| ------------- | ----- | ---------------------------------------------- |
| `fetch`       | 15–25 | resolve default branch, enumerate the git tree |
| `select`      | ~35   | choose which files to analyse                  |
| `downloading` | 45    | fetch file contents                            |
| `analyzing`   | 65    | secret regex pass, then the LLM call           |
| `persisting`  | 85    | hand findings back to the app                  |

**File selection (`pickScannable`)** is the most consequential logic in the file.
It filters out `node_modules`, `dist`, `build`, `vendor`, `.git`, minified files
and lockfiles, then _ranks_ what remains by how security-relevant the path looks
(`auth`, `token`, `sql`, `upload`, `config`…), with secret-bearing files first.
It then takes the top **`MAX_FILES = 18`**, capped at **250 KB total**.

> Exclusion is by **path segment**, not substring. An earlier version tested for
> `"/dist/"`, which missed a _top-level_ `dist/` — the usual place it is — so
> generated bundles quietly consumed the file budget. It also avoids false
> matches like `redistribute/`.

**Secret detection (`scanForSecrets`)** runs _before_ the LLM and is pure regex,
so a committed `.env` or API key is caught deterministically even if the model
overlooks it. `penalizeScore()` then forces the security score down when secrets
are present, so the model cannot "average away" a critical leak.

**`sanitizeFindings()`** truncates and shape-checks everything the model returns
before it goes near the database — model output is untrusted input.

### 7.3 The callback — `sandbox-callback.server.ts`

`server.ts` intercepts `POST /api/public/sandbox-callback` _before_ the router,
so it is a plain HTTP endpoint with no session. The handler:

1. verifies the HMAC (constant-time) → 401 on mismatch,
2. parses JSON → 400 on garbage,
3. dispatches on `kind`.

| `kind`          | Handler              | Effect                                           |
| --------------- | -------------------- | ------------------------------------------------ |
| `scan_progress` | `applyScanProgress`  | updates stage/percent, appends a `scan_logs` row |
| `scan`          | `applyScanVerdict`   | persists findings, or fails the scan             |
| `verify`        | `applyVerifyVerdict` | writes the verification verdict                  |
| `fix`           | `applyFixVerdict`    | writes the PR URL, or the failure                |
| `job_progress`  | `applyJobProgress`   | stores one live console line in `job_logs`       |

**Callback binding** is the security-critical part. Each handler updates rows
matched on _both_ the entity id and the job id we issued:

```ts
.eq("id", vulnerability_id)
.eq("scan_id", scan_id)
.eq("sandbox_job_id", job_id)
```

A stray, replayed, or forged callback carrying the wrong job id matches zero
rows and changes nothing. Fixes bind on `(id, fix_job_id)` only — a fix can be
requested long after its scan, so `scan_id` is not part of that binding.

Terminal scans are also guarded: a late progress callback can never reopen a
scan that already completed.

### 7.4 Persisting results — `scan-results.server.ts`

`persistScanResults()` writes the findings, updates the scan's counts and score,
updates the repository's status, and then submits verification jobs.

> **Ordering matters.** Verification jobs are submitted _before_ the scan flips
> to `completed`. Reversed, the weekly digest could observe "all scans done, no
> verifications pending" in the instant between the two writes and email a
> digest missing every verification result.

### 7.5 Live progress in the UI

`scans.$scanId.tsx` subscribes to Supabase Realtime on
`` `scan-logs-${scanId}` `` and receives `postgres_changes` events as rows are
inserted. No polling; log lines appear as the worker emits them.

---

## 8. Verification — `sandbox/runners/`

Each finding gets a verification job. The worker clones the repo, then runs the
**runner** container with:

- `--network none` — no network access whatsoever
- read-only root filesystem (only `/tmp` writable)
- a hard `SIGKILL` timeout
- the git credential _removed_ before the untrusted code is mounted

`probe.sh` runs **CodeQL** (building a database for the detected language) and
falls back to **Semgrep** with bundled offline rules. `sarif_verdict.py` then
reads the SARIF output and maps the probe category to expected CWEs, so an SQLi
probe cannot be "confirmed" by an unrelated XSS hit. The verdict is emitted as
the **last line of stdout** as JSON, which `parseVerdict()` reads.

Outcomes: `confirmed`, `not_exploitable`, or `failed` (the probe itself crashed —
kept distinct so the UI never presents a crash as a clean result).

> **Important:** see [§12](#12-known-gaps-and-honest-caveats) — this is a second
> _static_ analysis pass, not exploitation. Nothing is executed.

---

## 9. Fix with AI — `sandbox/fixer/fixer.js`

Triggered by `requestVulnerabilityFix`. The fixer container:

1. fetches the single affected file through the GitHub API (**no clone** — the
   change is one file, so cloning a whole repository would be wasteful),
2. loads the same surrounding files a real scan would read (`pickScannable`),
   and scans the repository **as it is** to get a baseline,
3. sends the file to a code model via OpenRouter (default `qwen/qwen3-coder`)
   with the finding as context,
4. **re-scans the repository with the patch swapped in** and compares against
   the baseline (`worker/fix-gate.js`): the patch passes only if the finding is
   gone and no new medium/high/critical finding appeared in that file,
5. on a failed re-scan, sends the model what the re-scan found and retries, up
   to `FIX_MAX_ATTEMPTS` (default 3). If nothing passes, it fails with the
   reason and **opens no PR**,
6. only for a passing patch: creates a branch, commits it, and opens a
   **pull request**.

Because the scanner is AI and varies between runs, the unpatched file is
scanned twice and merged, and a patch must pass **two** independent re-scans
(the second only runs if the first passed). A live run showed why: a
"simulated server-side check" written into a browser-only file passed a single
re-scan. The fixer prompt now also forbids simulated or placeholder security
controls outright.

The re-scan uses the scanner's own `analyzeFiles()`, imported from
`worker/scan.js`, so "the re-scan is clean" means the same thing as "a real
scan would be clean". Findings are compared one by one, not by counting CWEs.
The first version counted, and a replay of a real merged PR showed the flaw: a
patch that removed a password check created a new CWE-287 bug in a file that
already had an unrelated CWE-287 finding. Same count, different issue. Now each
post-patch finding must pair with a baseline finding at the same diff-mapped
line or with a matching description. Anything unpaired is new.

The PR URL comes back via the `fix` callback. A `pr_created` verdict with no URL
is deliberately recorded as a **failure** — a fix that leads nowhere is worse
than an admitted failure.

The fixer is the one component with internet egress, hence its own network.

---

## 10. Weekly scanning and email

### Scheduling

The app is request-driven with no cron. The sandbox **worker** is a permanently
running process, so it owns the clock: `scheduler.js` periodically POSTs to
`/api/public/run-weekly-scans`, authenticated with a bearer token that reuses
`SANDBOX_API_TOKEN` (both sides already hold it — no third secret to rotate).

`weekly-scan-sweep.server.ts` decides what is actually due, by comparing
`repositories.last_scan_at` against `WEEKLY_SWEEP_INTERVAL_HOURS`. Only repos
with `scan_mode = 'weekly'` are considered — auto-scanning is **opt-in per
repository**.

> The due-check lives in the app, not the worker, because the sandbox's Redis
> deliberately does not persist to disk; a worker-side "last run" timestamp
> would be forgotten on restart.

All scans from one sweep share a `weekly_run_id`.

### The digest

`maybeSendWeeklyDigest()` runs after _every_ scan and verification belonging to a
weekly run. It:

1. checks every scan in the run is terminal **and** no verification is still pending,
2. checks the user's preferences (`email_enabled && weekly_summary`) **before** claiming,
3. claims the send by inserting into `weekly_digest_log` (a 23505 unique-violation means someone else already won — skip silently),
4. builds and sends the email via `email.server.ts`.

No timeout fallback is needed: the sandbox guarantees a terminal callback for
every job it accepts, including worker exceptions, so nothing waits forever.

Email failures are caught and logged — they must never fail the scan write.

---

## 11. Other subsystems

### Chat assistant

`chat.functions.ts` + `chat-context.server.ts` build a context bundle from the
user's _own_ scan data and send it through `ai-gateway.server.ts`, which calls
**Gemini** (`gemini-2.5-flash`) through its OpenAI-compatible endpoint — chosen
so the request shape stays portable to any OpenAI-style provider.
The widget (`chat-widget.tsx`) is a draggable orb: it stays in the bottom-right
by default and only moves when dragged (`use-draggable-position.ts` leaves
`style` undefined until a drag happens, so the CSS default corner applies).

### Onboarding

`onboarding.functions.ts` tracks `profiles.onboarding_completed`;
`onboarding-tour.tsx` renders the guided tour.

### Vulnerability lifecycle

A finding is one row for its whole life, not one row per scan.
`persistScanResults` reconciles each scan against the repository's existing
rows (`vuln-lifecycle.ts`, pure and unit-tested): a reported finding that
matches a row updates it; an unmatched one is inserted; a match for a `fixed`
row reopens it as a regression and re-verifies it; a `false_positive` stays
triaged. An active row the scan did not report counts as a miss only if the
scan actually read its file (the scan samples ~18 files). It is resolved after
two consecutive misses, on the first miss if its AI fix PR was merged, or
immediately if the file was deleted. Rows found to be the same issue as
another (the scanner once recorded one bug as CWE-312 and CWE-256) get
`duplicate_of` and are hidden. Every step is written to `vulnerability_events`;
status changes, manual or automatic, are logged by a database trigger. The UI
shows this as a timeline on each finding.

Reports and the weekly digest count "findings present in a scan" (first seen,
last seen, or recorded as seen in it), not just `scan_id`, which now only means
"first detected in".

### Live sandbox console

Verify and fix containers write `@@progress {json}` lines to stderr. The worker
reads stderr line by line (`job-stream.js`), relays only those marked lines
(never raw tool output about untrusted code), redacts secret-shaped values
(the scanner's own secret patterns plus quoted/env-style credential
assignments), caps each job at 300 lines, and posts each as a signed
`job_progress` callback. The app binds each line to the job the finding
currently owns and stores it in `job_logs`. The finding dialog streams it via
Realtime, with polling as a fallback: the container's real isolation settings,
each fix attempt's diff, and what each re-scan said.

Both features need `20260924120000_vuln_lifecycle_and_job_logs.sql`. Until it
is applied, every path detects the missing schema and falls back to the old
behaviour.

### Reports

`reports.functions.ts` generates and stores report payloads. **JSON only** today.

### Demo mode (`/demo`)

A complete simulated product tour reading from `lib/demo-data.ts`. No Supabase
client, no server function and no `fetch` is imported anywhere in that subtree,
so no interaction can touch real data. Assistant replies come from a lookup
table.

### Landing page

`index.tsx` renders a `ColorBends` WebGL shader (vendored from React Bits), sized
to 150% of the hero and pulled up 50%, with a CSS mask standing in for the
upstream `fadeTop` prop. `prefers-reduced-motion` bypasses WebGL entirely for a
static gradient.

### Error handling

`server.ts` wraps the SSR handler because h3 swallows in-handler throws into an
opaque `{"unhandled":true,"message":"HTTPError"}` 500 that a `try/catch` never
sees. `normalizeCatastrophicSsrResponse()` detects that specific shape and
renders a real error page instead.

---

## 12. Known gaps and honest caveats

These are real limitations of the current implementation.

**Scan coverage is very narrow.** A scan is an LLM reading at most **18 files /
250 KB**, chosen by filename heuristics. For a repository of any size this is a
small sample, and because it is model-driven the results are not deterministic —
the same commit scanned twice can differ. Semgrep and CodeQL are installed in the
runner image but are _not_ used during scanning.

**"Verification" does not verify exploitability.** Despite the `not_exploitable`
verdict name, the runner has `--network none` and executes nothing. It runs
static analysis a second time and checks CWE agreement. "Confirmed" means _two
static tools agreed_, not _we proved it is exploitable_.

**Callback delivery is best-effort, not guaranteed.** `postCallback()` used to
ignore the HTTP status entirely, so a rejected result vanished and its row sat
in `queued` forever (this happened in practice). It now logs every non-2xx and
retries final results on network errors and 5xx, three times with backoff. A
4xx is not retried, since the app has said the payload itself is wrong. If
the app is down for longer than the retries, the result is still lost: there
is no durable outbox.

**Finding identity across scans is heuristic.** Because the scanner is an LLM
that re-words titles and relabels CWEs between runs, "is this the same bug"
is decided by file, location and description similarity (`vuln-lifecycle.ts`),
not an exact key. Two different issues at the same spot with similar titles can
be merged; a heavily re-worded one can appear as new. Resolution requires two
consecutive misses for the same reason.

**Dropped jobs are never retried.** A worker restart mid-job leaves the scan
`running` with nothing to move it on. This is also why Redis does not persist.

**AI fixes are re-scanned, not tested.** A PR opens only if a re-scan with the
patch applied no longer reports the finding, but nothing is compiled or
executed. The re-scan is also AI-driven, so an unchanged patch can pass on one
run and fail on the next. A human still has to read and test the patch.

**Email needs a real TCP socket.** nodemailer/SMTP works because the app runs as
a persistent Node process; it would not work on Cloudflare Workers. The fix, if
that ever matters, is contained to `email.server.ts`.

**Weekly scheduling is coarse.** Rolling "every N hours since last scan" only.
`schedule_day` / `schedule_hour` / `timezone` exist in the schema but are unwired.

**Test coverage is targeted, not broad.** ~184 tests cover token encryption,
callback binding rules, the weekly sweep and digest, the scan pipeline's pure
functions, the fix gate, log redaction, and the lifecycle rules. React components and the GitHub/OpenRouter integration paths are
untested.

**Leftover SQL and a dead client.** `pentestai_security_hardening.sql` (repo
root, outside `migrations/`) still creates policies on `api_keys`, which a
later migration dropped, so it errors if run as-is.
`integrations/supabase/client.server.ts` exports a second service-role client
(reading `SUPABASE_SERVICE_ROLE_KEY`) that nothing imports. The real one is
`lib/supabase-admin.server.ts`.

**Caddy ships TLS config** but needs real DNS pointed at the host before it can
issue a certificate.

---

## 13. Running it locally

```bash
npm install
npm run dev          # app on :8080
```

```bash
cd sandbox
docker compose up -d --build
```

Apply `supabase/migrations/*.sql` by hand, in filename order.

### Required environment

Root `.env`:

| Variable                                   | Purpose                                                 |
| ------------------------------------------ | ------------------------------------------------------- |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` | client connection                                       |
| `PENTEST_SUPABASE_SERVICE_ROLE_KEY`        | RLS-bypassing admin client                              |
| `TOKEN_ENCRYPTION_KEY`                     | AES-256-GCM key for GitHub tokens at rest               |
| `CALLBACK_HMAC_SECRET`                     | signs/verifies sandbox callbacks                        |
| `SANDBOX_API_TOKEN`                        | app→sandbox job submission, and the weekly-sweep bearer |
| `SANDBOX_URL`                              | where to submit jobs                                    |
| `GEMINI_API_KEY`                           | chat assistant                                          |
| `APP_URL`                                  | link building in emails                                 |
| `SMTP_HOST/PORT/USER/PASS/SECURE/FROM`     | digest email                                            |
| `WEEKLY_SWEEP_INTERVAL_HOURS`              | optional; defaults to one week                          |

`sandbox/.env`: `PENTESTAI_CALLBACK_URL`, `GEMINI_API_KEY` (scanning),
`OPENROUTER_API_KEY` (the fixer), plus `CALLBACK_HMAC_SECRET` and
`SANDBOX_API_TOKEN` — these two **must be byte-identical to the app's**, or every
callback is rejected with a 401 that the worker does not log.

> On Docker Desktop, the app is reachable from containers as
> `host.docker.internal`, **not** `localhost` — inside a container `localhost` is
> the container itself.

### Verification commands

```bash
npx tsc --noEmit
npx vitest run
npx eslint .
npm run build
```

### Useful debugging

```bash
docker compose logs -f worker                     # what the worker is doing
docker compose exec redis redis-cli KEYS 'job:*'  # queued/finished jobs
docker compose exec redis redis-cli HGETALL job:<id>
```

If a scan is stuck in `queued` but Redis shows the job `completed`, the callback
is being rejected — check that `CALLBACK_HMAC_SECRET` matches on both sides and
that the app understands the `kind` being sent.
