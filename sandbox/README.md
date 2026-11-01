# PentestAI Self-Hosted Sandbox

Docker Compose stack that verifies vulnerabilities in ephemeral, isolated
containers. PentestAI submits jobs over HTTPS; the sandbox runs each job in a
short-lived runner container and posts a signed result back.

## Architecture

```text
 PentestAI app
        │  POST /api/jobs (Bearer token)
        ▼
   ┌─────────┐        ┌─────────┐        ┌────────────────┐
   │  caddy  │──────▶│   api   │──lpush▶│     redis      │
   └─────────┘        └─────────┘        └────────────────┘
                                                 │ brpop
                                                 ▼
                                            ┌─────────┐
                                            │ worker  │──spawn──▶ runner (ephemeral)
                                            └─────────┘             │
                                                 ▲                  │ clone + probe
                                                 └──── stdout ──────┘
                          POST callback (HMAC signed)
        ◀────────────────────── worker ──────────────────────
```

- **caddy** — the only internet-facing service. Terminates TLS (automatic
  Let's Encrypt certs for `SANDBOX_HOSTNAME`), routes `/api/*` to `api`, and
  returns a bare 404 for everything else — `api` itself publishes no host
  port, so it's unreachable except through caddy.
- **api** — Fastify, validates the bearer token, enqueues jobs.
- **worker** — pulls jobs, launches hardened `docker run --rm` job containers,
  and runs `scan` jobs itself (see [Job kinds](#job-kinds)).
- **runner** — one-shot image for `kind: "verify"` jobs. Verifies
  javascript/typescript and python findings with CodeQL's `security-extended`
  query suite (real dataflow/taint analysis, not pattern matching); falls back
  to semgrep (bundled offline rules) for every other language, for the `secret`
  probe's non-file-specific case, and whenever CodeQL itself errors.
  trufflehog3 verifies the `secret` probe against the exact flagged file.
  Prints a JSON verdict.
- **fixer** — one-shot image for `kind: "fix"` jobs. Asks an LLM (via
  OpenRouter) to patch the single file a finding points at, **re-scans the
  repository with the patch applied**, and opens a pull request through GitHub's
  Git Data API only if the re-scan no longer reports the finding. No git, no
  clone, no volume mount — see [Fix jobs](#fix-jobs).
- **redis** — internal-only queue + job status store.

## Job kinds

Both kinds enter through the same `POST /api/jobs` endpoint and report back
through the same HMAC-signed callback. `kind` defaults to `"verify"`.

| Kind     | Runs in           | Network      | Egress | Verdict statuses                           |
| -------- | ----------------- | ------------ | ------ | ------------------------------------------ |
| `scan`   | the worker itself | worker's own | yes    | `completed` / `failed`                     |
| `verify` | `runner`          | `runner_net` | none   | `confirmed` / `not_exploitable` / `failed` |
| `fix`    | `fixer`           | `fixer_net`  | yes    | `pr_created` / `failed`                    |

`scan` jobs run in-process rather than in a spawned container. That looks
inconsistent until you notice what the isolation is actually for: `runner`
executes analysis tooling over untrusted repository code, so it gets a
locked-down container with no network. A scan only *reads* text through the
GitHub API and posts it to a model — there is no untrusted execution to
isolate, and a container would add a build and a spawn for nothing.

The worker holds the AI key for this, but still gets **no Supabase
credentials**: it posts findings back over the signed callback and the app
writes them. See `sandbox/worker/scan.js`.

The job id is supplied by the app, not generated here (the API still generates
one if a caller omits it). PentestAI writes that id to its database *before*
submitting, so a job that finishes quickly can't call back before the row that
is meant to receive the result carries the id — a race that used to strand
findings in `pending` indefinitely.

### Credential handling

Jobs carry a GitHub token: read-scoped for verify, **write-scoped** for fix.

- The token is a separate `repo_token` field, never interpolated into the clone
  URL. Embedding it in the URL put it in the worker's process arguments and
  baked it into the clone's `.git/config` — a directory that is then mounted
  into the runner alongside untrusted repository code.
- `git` receives it through `$GITHUB_TOKEN` and a credential helper; `fixer`
  receives it the same way and only ever sends it in an `Authorization` header.
- The worker strips `repo_token` and `repo_clone_url` from the `JOB_JSON` it
  hands to the runner.
- **Redis runs with `--appendonly no` and `--save ""`.** With the AOF enabled,
  every queued job — credential included — was durably written to disk, where a
  low-traffic sandbox could leave it for a long time before compaction. Nothing
  retries a dropped job today, so surviving a Redis restart is not worth
  persisting credentials for. If you ever add retry semantics, revisit this.

### Fix jobs

`fixer` deliberately contains no git. The change is a single file, so cloning a
whole repository into a container to edit it would mean tmpfs sizing,
credential helpers and volume plumbing for no benefit. Instead it resolves the
branch tip, reads the file, calls the model, then writes blob → tree → commit →
ref → PR as plain HTTPS calls. The image is a few megabytes rather than the
runner's ~850 MB.

It always re-resolves the **current** default-branch tip and the **current**
file contents — never the scan's original `commit_sha`. A fix can be requested
weeks after the scan ran, and branching from a stale commit would open a PR
full of reverts. If the file no longer exists at the tip, the job fails fast
with a verdict saying so.

**Every patch is re-scanned before a PR opens.** The fixer scans the repository
twice with the scanner's own `analyzeFiles()` (imported from `worker/scan.js`,
so the prompt, model and secret patterns are identical to a real scan): once as
it is, once with the patched file swapped in. `worker/fix-gate.js` compares the
two for the patched file. The PR opens only if the finding is gone **and** no
new medium/high/critical finding appeared. Otherwise the model is told what the
re-scan found and tries again, up to `FIX_MAX_ATTEMPTS` (default 3). If no
attempt passes, the job fails with the reason and **no PR is opened**.

Because the scanner is AI and varies between runs, the original is scanned
**twice** and merged (so an old issue one run missed isn't blamed on the
patch), and a patch must pass **two** independent re-scans (so a disguised fix
that slips past one run is still caught by the other). Cost per fix: up to 2 +
(2 × attempts) scanner calls, i.e. at most 8 with the default 3 attempts.
**The Gemini free tier allows only 20 `gemini-2.5-flash` requests per day**,
shared with ordinary scans. Enable billing on the key for real use. A
per-day quota error fails immediately with that explanation instead of retrying.

The comparison matches findings one by one (by diff-mapped line and by
description), not by counting CWEs. A patch that swaps one bug for another of
the same CWE is caught. It is still a static AI + pattern check: it does not
compile, run or test the code, and AI output varies between runs, so the PR
still needs review.

Because the fixer imports from `worker/`, **its image is built from `sandbox/`,
not `sandbox/fixer/`** (see the build command below).

### Why CodeQL over pattern matching

Semgrep-only verification was producing false "not_exploitable" verdicts on
real, critical findings because pattern matching can't confirm most classes
of injection/traversal bugs — it doesn't trace whether tainted input actually
reaches a dangerous sink. CodeQL builds a real code database and runs
dataflow/taint-tracking queries, so it can confirm e.g. "this request param
flows unsanitized into this SQL string" rather than just "this line looks
like a query". It's the primary engine for javascript/typescript and python
(both extract straight from source, no build step needed); other languages
still use semgrep here since a generic runner can't reliably build an
arbitrary Java/Go/etc. project.

`sarif_verdict.py` classifies CodeQL's SARIF output per probe: a result in the
AI-flagged file wins outright, otherwise a result tagged with the CWE that
probe cares about (SQLi → CWE-089, SSRF → CWE-918, etc.) counts as evidence;
unrelated security-extended findings elsewhere in the repo do not.

## Deploy on your VPS

1. Install Docker Engine + Compose plugin. Create a non-root user in the
   `docker` group.
2. Copy this `sandbox/` folder to the VPS.
3. `cp .env.example .env` and fill in real values. Generate secrets with
   `openssl rand -hex 32`.
4. Point DNS `A` record for `SANDBOX_HOSTNAME` at the VPS. Open only
   ports 80/443 in the firewall.
5. Build the one-shot job images:
   ```bash
   docker build -t pentestai/runner:latest runners
   docker build -t pentestai/fixer:latest -f fixer/Dockerfile .   # context is sandbox/, see note
   ```
   The runner downloads the ~850 MB CodeQL CLI bundle at build time (needs
   internet on the build host only — the built image and `runner_net` stay
   fully offline). Expect several minutes depending on bandwidth. The fixer
   image is a few megabytes and builds in seconds.
6. Start the stack:
   ```bash
   docker compose --env-file .env up -d --build
   ```
7. Health check:
   ```bash
   curl https://$SANDBOX_HOSTNAME/api/health
   ```
8. Confirm `fixer_net` is isolated — see below. Worth doing once, since this
   is the only network in the stack with egress.

## Verifying fixer_net isolation

`fixer_net` is a plain bridge network, not `internal: true`, because the fixer
needs to reach GitHub and OpenRouter. It must still be unable to reach the rest
of the stack. Docker gives each bridge its own subnet and installs iptables
rules that drop traffic between bridges, so a container attached only to
`fixer_net` cannot reach `redis` or `api` — by name or by IP.

`worker` is attached to `fixer_net` in `docker-compose.yml`. That is not
because it needs to talk over it: Compose only creates networks that some
service attaches to, and without it the per-job `docker run --network
fixer_net` fails with "network not found". `runner_net` is listed on `worker`
for exactly the same reason. The consequence is that a fix container can reach
the worker over `fixer_net` — same as a runner can over `runner_net`. The
worker listens on no port, so there is nothing there to talk to.

Confirm it rather than assuming it:

```bash
docker run --rm --network pentestai-sandbox_fixer_net alpine sh -c \
  "nslookup redis 2>&1 | tail -2; nc -z -w3 redis 6379 && echo REACHABLE || echo blocked; nc -z -w3 api 8080 && echo REACHABLE || echo blocked"
```

Both probes must print `blocked` (DNS resolution of `redis`/`api` should also
fail — they are not on this network). Then confirm egress does work:

```bash
docker run --rm --network pentestai-sandbox_fixer_net alpine sh -c \
  "nc -z -w5 api.github.com 443 && echo github-ok"
```

## Hardening notes

- Runners get `--read-only`, `cap-drop=ALL`, `no-new-privileges`, non-root uid,
  cpu/memory/pids limits, and are attached to an `internal: true` bridge
  network (no outbound internet). Adjust `RUNNER_*` env vars in `docker-compose.yml`.
- Fixers get the same flags (`FIXER_*` env vars) but on `fixer_net`, which has
  egress. They mount no volumes at all and get a 256 MB tmpfs.
- Redis is not exposed outside `internal` network, and no longer persists to
  disk — see "Credential handling" above for why.
- The worker mounts the Docker socket so it can spawn sibling job containers.
  That is an accepted trade-off of this design, and it means the worker is the
  one component whose compromise is equivalent to root on the host: it is the
  only service that never executes untrusted repository code, and neither the
  runner nor the fixer can reach it. Keep it that way — do not add repo-derived
  input to anything the worker itself evaluates.
- Never mount host paths into runners.
- Rotate `SANDBOX_API_TOKEN` and `CALLBACK_HMAC_SECRET` periodically.
- Consider running the whole stack under a dedicated VM/VPS with automatic
  security updates and no other workloads.
- CodeQL needs materially more CPU/RAM/time than semgrep alone did — the
  `RUNNER_CPU`/`RUNNER_MEMORY`/`RUNNER_TMPFS_SIZE`/`RUNNER_TIMEOUT_SECONDS`
  defaults in `docker-compose.yml` reflect that. `RUNNER_TMPFS_SIZE` backs
  `$HOME` (CodeQL database + caches) on the read-only runner filesystem — it's
  RAM-backed, so keep it comfortably under `RUNNER_MEMORY` or the container
  gets OOM-killed mid-analysis.

## Known gaps

- CodeQL only covers javascript/typescript and python here (languages whose
  CodeQL extractor works without a build step). Java/Go/PHP/etc. repos still
  get semgrep-only verification.

## Local testing without a real domain

Caddy's automatic HTTPS only activates for an address that looks like a
public domain. For local testing, set `SANDBOX_HOSTNAME=:80` (or any other
`.env` value that isn't a real hostname) — Caddy then serves plain HTTP on
port 80 with no ACME/Let's Encrypt attempt, so you can verify routing without
DNS or a public IP:

```bash
docker compose up -d caddy api redis
curl http://localhost/api/health
```

Editing `caddy/Caddyfile` while the stack is running does not take effect
automatically — bind-mounting doesn't make Caddy re-read it. Run
`docker restart <caddy-container>` (or `docker compose restart caddy`) after
a config change.
