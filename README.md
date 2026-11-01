# PentestAI

Automated penetration testing for GitHub repositories. Connect a repo, and
PentestAI reads the code with an LLM, then **re-runs every high and critical
finding inside an isolated container** to check whether the vulnerability is
actually reachable — so the report tells you what's exploitable, not just what
looks suspicious.

> **Only scan repositories you own or are explicitly authorised to test.**

---

## How it works

```
GitHub repo
    │  the app queues a scan job and returns immediately
    ▼
Sandbox worker
    │  regex secret scan (runs first, catches committed .env files)
    │  LLM static analysis
    │
    ├─ HMAC-signed progress callbacks ──►  live stage + % on the scan page
    │
    ▼
HMAC-signed result callback  ──►  app writes findings
    │
    │  high + critical findings only
    ▼
Sandbox runner (isolated, no network)
    │  CodeQL security-extended · dataflow/taint tracking
    ▼
HMAC-signed callback  ──►  verdict + evidence written to the finding
```

The scan itself runs as a queued job rather than inside the HTTP request that
started it, so a large repository can't run into a serverless CPU or wall-time
limit, and closing the browser tab doesn't abandon the work.

The verification step is the point of the project. Pattern matching can tell
you a line _looks_ like a SQL query; it can't tell you whether user input
actually reaches it. CodeQL builds a real database of the code and runs
taint-tracking queries, so a finding comes back `confirmed` with the dataflow
that proved it, or `not_exploitable`, or `failed` when the tooling itself
errored — a distinction that matters, because "the scanner crashed" and "the
code is safe" are not the same answer.

| Verdict           | Meaning                                                           |
| ----------------- | ----------------------------------------------------------------- |
| `confirmed`       | Reachable. Evidence attached.                                     |
| `not_exploitable` | Analysed and not reachable.                                       |
| `failed`          | The probe errored — inconclusive, **not** a clean bill of health. |
| `pending`         | Submitted to the sandbox, awaiting a result.                      |

## Fix with AI

Any open finding tied to a file can be handed back to an LLM to patch. The fix
runs in the same sandbox, in its own ephemeral container, and always arrives as
a **pull request** — never a direct commit to your default branch, so there is
a human review gate between the model and your code.

```
finding  ──►  fixer container (isolated, egress-only to GitHub + OpenRouter)
                  │  read current default-branch tip + current file
                  │  LLM patches that one file
                  │  re-scan the repo with the patch applied ◄──┐
                  │  still flagged / new vuln? → retry with ─────┘
                  │  the re-scan's findings (max FIX_MAX_ATTEMPTS)
                  ▼  passed
              blob → tree → commit → branch → PR
                  │
              HMAC-signed callback ──►  fix_status + PR link on the finding
```

- **A PR only opens if the patch passes a re-scan.** The fixer re-runs the
  scanner on the repository with the patch applied. If the finding is still
  reported, or the patch introduced a new medium-or-higher finding, the model is
  told why and retries (default 3 attempts). If nothing passes, no PR is opened
  and the finding shows the reason.
- The re-scan is static analysis, not a test run: nothing is compiled or
  executed, and AI results vary between runs. That's why the original is
  scanned twice and every patch must pass two re-scans. Review the PR before
  merging.
- **Watch it live:** every fix and verification job streams its progress
  into the finding's dialog: the container's isolation settings, each
  attempt's diff, and each re-scan's verdict. Secret-looking values are
  redacted before they leave the sandbox.
- **Quota:** a fix uses up to 8 Gemini calls (default settings). The Gemini
  free tier allows only 20 `gemini-2.5-flash` requests per day, shared with
  scans, so enable billing on the key for anything beyond a demo.
- It always reads the branch tip as it is _now_, not the commit the scan ran
  against, so a fix requested weeks later doesn't revert intervening work.
- Needs a GitHub token with the `repo` scope, and `OPENROUTER_API_KEY` set on
  the sandbox. Without the key, fix jobs return a clear "not configured"
  verdict; verification is unaffected.
- Only one fix runs per finding at a time; requesting a second while one is
  pending is rejected rather than opening a duplicate PR.

## Weekly scans

A repository switched to "Auto-scan weekly" on the Repositories page gets
re-scanned automatically, roughly every `WEEKLY_SWEEP_INTERVAL_HOURS`. Off
(`scan_mode = 'manual'`) by default for every repository — auto-scanning
costs a GitHub API pass and an LLM call per repo, so nothing runs until you
opt a repo in.

```
sandbox worker (pings hourly, holds no memory of "last run" —
                the sandbox's Redis isn't persisted)
    │  POST /api/public/run-weekly-scans   (Bearer: SANDBOX_API_TOKEN)
    ▼
app: which weekly-mode repos have last_scan_at older than the interval
     (or have never been scanned)? triggers each exactly like the
     "Scan" button does, tagged trigger='scheduled'
    ▼
...normal scan + verify flow...
    ▼
once every scan AND every verification from that run is done,
one digest email per user (gated on the "Weekly summary" toggle in Settings)
```

The interval check lives in the app, against `repositories.last_scan_at`
(durable in Postgres), not in the worker — a worker restart must not cause an
early re-trigger, and the sandbox's Redis is deliberately non-persistent (see
"Credential handling" in `sandbox/README.md`), so the worker can't be trusted
to remember anything across a restart either.

**Local testing without waiting a week**: set `WEEKLY_SWEEP_INTERVAL_HOURS=0`
in the app's `.env`, flip a test repo to weekly mode, then either wait for the
worker's next hourly ping or trigger one on demand:

```bash
curl -X POST -H "Authorization: Bearer $SANDBOX_API_TOKEN" $APP_URL/api/public/run-weekly-scans
```

**Local testing of the email itself** without a real mailbox: run
[Mailpit](https://github.com/axllent/mailpit) (open source, MIT-licensed fake
SMTP server + web UI):

```bash
docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit
```

Point `SMTP_HOST=localhost`, `SMTP_PORT=1025`, `SMTP_SECURE=false` at it — sent
mail shows up at `http://localhost:8025` instead of leaving the machine.

## Stack

| Layer     | Choice                                                           |
| --------- | ---------------------------------------------------------------- |
| Framework | TanStack Start (React 19, TypeScript)                            |
| Styling   | Tailwind CSS v4, shadcn/ui, Lucide icons                         |
| Backend   | Supabase — Postgres with row-level security, Auth (GitHub OAuth) |
| AI        | Gemini                                                           |
| Deploy    | Nitro → Cloudflare Workers                                       |
| Sandbox   | Docker Compose — Caddy, Fastify, Redis, worker, one-shot runner  |
| Analysis  | CodeQL (JS/TS, Python) · semgrep · trufflehog3                   |

## Getting started

Requires Node 20+ and a Supabase project.

```bash
npm install
```

Create `.env` in the repo root:

```bash
# Supabase
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_PUBLISHABLE_KEY=<anon key>
PENTEST_SUPABASE_SERVICE_ROLE_KEY=<service role key>

# Client-side equivalents
VITE_SUPABASE_URL=https://<project-ref>.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=<anon key>

# AI
GEMINI_API_KEY=<key>

# Encrypts GitHub tokens at rest. REQUIRED — connecting GitHub fails without
# it. Losing or changing it means every user must reconnect GitHub.
TOKEN_ENCRYPTION_KEY=<openssl rand -hex 32>

# Sandbox (optional — scans still run, findings stay unverified without it)
SANDBOX_URL=https://sandbox.example.com
SANDBOX_API_TOKEN=<openssl rand -hex 32>
CALLBACK_HMAC_SECRET=<openssl rand -hex 32>

# Public base URL of this deployment. Used to build links in emails and
# authenticate the sandbox's weekly-scan requests (see "Weekly scans" below).
APP_URL=http://localhost:8080

# Email (weekly digest). Optional — without it, weekly scans still run, they
# just don't email anyone. nodemailer + SMTP; any provider works, including a
# local Mailpit instance for testing (see "Weekly scans" below).
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM="PentestAI <alerts@example.com>"
# "true" for implicit TLS (port 465). Auto-detected from the port otherwise.
SMTP_SECURE=

# How long a repository in weekly mode can go unscanned before it's due
# again. Blank = 168 (7 days). Lower this for local testing.
WEEKLY_SWEEP_INTERVAL_HOURS=
```

`.env` is gitignored. Never commit it — the service role key bypasses every
RLS policy in the database.

Apply the migrations in `supabase/migrations/` in filename order, either with
the CLI or by pasting them into the Supabase SQL editor:

```bash
supabase link --project-ref <project-ref>
supabase db push
```

If earlier migrations were applied by hand, `db push` will try to replay them
and fail. Check `supabase migration list` first; to apply a single file
without touching migration history:

```bash
supabase db query --linked -f supabase/migrations/<file>.sql
```

Then run it:

```bash
npm run dev
```

| Script            | Does                                  |
| ----------------- | ------------------------------------- |
| `npm run dev`     | Dev server                            |
| `npm run build`   | Production build (Nitro → Cloudflare) |
| `npm run preview` | Preview the build                     |
| `npm run test`    | Vitest (app + sandbox modules)        |
| `npm run lint`    | ESLint                                |
| `npm run format`  | Prettier                              |

## The sandbox

Verification runs on hardware you control, never on the app host. Runners get
`--read-only`, `cap-drop=ALL`, `no-new-privileges`, a non-root uid, CPU/memory/
PID limits, and an `internal: true` network with no outbound access. The
repository is mounted read-only and the container is destroyed after each job.

Deploy it separately — see [`sandbox/README.md`](sandbox/README.md). Building
the runner image pulls the CodeQL CLI bundle (~850 MB), so the first build
takes a few minutes.

```bash
cd sandbox
cp .env.example .env        # fill in, generate secrets with: openssl rand -hex 32
docker build -t pentestai/runner:latest runners
docker build -t pentestai/fixer:latest -f fixer/Dockerfile .   # context is sandbox/, see note
docker compose --env-file .env up -d --build
```

The `fixer` image handles "Fix with AI" jobs. Unlike the runner it needs
outbound network (GitHub + OpenRouter), so it runs on its own `fixer_net`
bridge rather than the runner's zero-egress network — `sandbox/README.md` has
the smoke test that proves `fixer_net` still can't reach the rest of the stack.

CodeQL covers JavaScript/TypeScript and Python here — the two languages whose
extractors work without a build step, which is the constraint for a runner that
has to handle arbitrary repositories unattended. Everything else falls back to
semgrep with offline rules.

## Project layout

```
src/
  routes/                    landing (/), auth, and the authenticated app
  lib/                       server functions — scans, reports, GitHub, sandbox
  components/app/ui.tsx      shared app primitives (badges, states, skeletons)
  integrations/supabase/     client, admin client, auth middleware
sandbox/                     self-hosted verification stack
supabase/migrations/         schema, RLS policies, and later additions
docs/DESIGN-SYSTEM.md        design tokens and the measurements behind them
```

## Security notes

- Repository access is **read-only**; the scanner never writes to your code.
- `github_connections` has no client-facing RLS policy — tokens are reachable
  only via the service role, server-side.
- Sandbox callbacks are HMAC-signed and bound to the originating scan and job,
  so a replayed or stray callback can't overwrite another scan's verdict.
- Findings are scoped per-user by RLS on every table.

- GitHub tokens are encrypted at rest with AES-256-GCM under
  `TOKEN_ENCRYPTION_KEY`; the column name finally means what it says. Rows
  written before this existed are plaintext and are re-encrypted in place the
  first time they're read.
- Tokens are never interpolated into clone URLs. They reach `git` through an
  environment variable and a credential helper, so they stay out of process
  arguments and out of the clone's `.git/config` — which is mounted into the
  analysis runner alongside untrusted repository code.

**Known gaps**, kept here rather than in a comment nobody reads:

- `sandbox/docker-compose.yml` ships a `caddy` service for TLS, but you must
  point real DNS at the host before it can issue a certificate.
- AI-generated fixes are re-scanned before the PR opens, but not compiled,
  run or tested, and the re-scan is AI-driven so it can vary between runs. A
  reviewer still has to read and test the patch.
- Test coverage is targeted, not broad: it covers token encryption, the
  callback binding rules, and the scan pipeline's pure functions. The React
  components and the GitHub/OpenRouter integration paths are untested.
- A scan job that dies mid-run (worker restart) leaves its scan row in
  `running` with nothing to move it on. Nothing retries dropped jobs — that is
  also why the sandbox's Redis deliberately does not persist to disk.
- Email is sent directly from the app via nodemailer/SMTP, which needs a real
  TCP socket — this works today because the app runs as a persistent Node
  process, but it will not work as-is if this is ever deployed to genuine
  Cloudflare Workers (no raw sockets). The fix, if that happens, is contained
  to `src/lib/email.server.ts`.
- Weekly scanning has no per-repo day/hour/timezone control, only a rolling
  "every N hours since it was last scanned" — `repositories.schedule_day` /
  `schedule_hour` / `timezone` exist in the schema for finer control later but
  aren't wired up.

## License

No license file. All rights reserved by default — add one before making the
repository public if you intend to allow reuse.
