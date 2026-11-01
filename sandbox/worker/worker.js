import dns from "node:dns";

dns.setDefaultResultOrder("ipv4first");
import Redis from "ioredis";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { runScan } from "./scan.js";
import { startWeeklySweepScheduler } from "./scheduler.js";
import { createJobReporter, lineSplitter, PROGRESS_MARKER } from "./job-stream.js";

const redis = new Redis(process.env.REDIS_URL);

const RUNNER_IMAGE = process.env.RUNNER_IMAGE || "pentestai/runner:latest";
const RUNNER_NETWORK = process.env.RUNNER_NETWORK || "sandbox_runner_net";
// CodeQL database creation + security-extended analysis needs materially more
// CPU/RAM/time than a semgrep pattern scan, so these defaults are higher than
// what plain semgrep required. Tune down if the box is small and every repo
// is falling back to semgrep anyway (unsupported language).
const RUNNER_CPU = process.env.RUNNER_CPU || "2.0";
const RUNNER_MEMORY = process.env.RUNNER_MEMORY || "3g";
const RUNNER_PIDS = process.env.RUNNER_PIDS || "512";
const RUNNER_TIMEOUT = Number(process.env.RUNNER_TIMEOUT_SECONDS || 1200);
// tmpfs backs $HOME (CodeQL DB build products, semgrep cache) — it's RAM, so
// it must stay comfortably under RUNNER_MEMORY or the container gets OOM-killed.
const RUNNER_TMPFS_SIZE = process.env.RUNNER_TMPFS_SIZE || "2g";

// The fixer does no cloning and no static analysis — it's a handful of HTTPS
// calls — so it needs a fraction of the runner's budget. It does need egress,
// which is why it lives on its own network rather than runner_net.
const FIXER_IMAGE = process.env.FIXER_IMAGE || "pentestai/fixer:latest";
const FIXER_NETWORK = process.env.FIXER_NETWORK || "pentestai-sandbox_fixer_net";
const FIXER_CPU = process.env.FIXER_CPU || "1.0";
const FIXER_MEMORY = process.env.FIXER_MEMORY || "512m";
const FIXER_PIDS = process.env.FIXER_PIDS || "128";
// Up to FIX_MAX_ATTEMPTS rounds of (model rewrite + re-scan), plus the baseline
// scan. 300s was sized for a single model call and no re-scan.
const FIXER_TIMEOUT = Number(process.env.FIXER_TIMEOUT_SECONDS || 600);
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || "";
const FIXER_MODEL = process.env.FIXER_MODEL || "";
const FIX_MAX_ATTEMPTS = process.env.FIX_MAX_ATTEMPTS || "";
const APP_URL = process.env.APP_URL || "";

const CALLBACK_URL = process.env.PENTESTAI_CALLBACK_URL;
const HMAC_SECRET = process.env.CALLBACK_HMAC_SECRET;
const ARTIFACTS_VOLUME = process.env.ARTIFACTS_VOLUME || "pentestai_artifacts";

async function runDocker(args, { timeoutMs, env, onProgress } = {}) {
  return new Promise((resolve) => {
    // `env` supplies values for bare `-e NAME` flags. Passing secrets this way
    // keeps them out of argv (visible in `ps` on the host) entirely.
    const child = spawn("docker", args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: env ? { ...process.env, ...env } : process.env,
    });
    let out = "",
      err = "";
    child.stdout.on("data", (d) => (out += d.toString()));
    // stderr is read line by line so progress lines reach the UI while the
    // container is still running. Marked lines are peeled off and relayed;
    // everything else stays in `err` for the fallback evidence, as before.
    const onLine = lineSplitter((line) => {
      if (onProgress && line.startsWith(PROGRESS_MARKER)) {
        try {
          onProgress(JSON.parse(line.slice(PROGRESS_MARKER.length)));
        } catch {
          // A malformed progress line is dropped, not surfaced.
        }
        return;
      }
      err += line + "\n";
    });
    child.stderr.on("data", (d) => onLine(d.toString()));
    const timer = timeoutMs ? setTimeout(() => child.kill("SIGKILL"), timeoutMs) : null;
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      onLine(null); // flush a final unterminated line
      resolve({ code, stdout: out, stderr: err });
    });
  });
}

/**
 * Reads the runner/fixer contract: the last line of stdout is a single JSON
 * verdict object. Anything else on stdout is treated as noise.
 */
function parseVerdict(result, fallback) {
  try {
    const lastLine = result.stdout.trim().split("\n").pop();
    if (lastLine) return { ...fallback, ...JSON.parse(lastLine) };
  } catch {
    // Keep the fallback verdict.
  }
  return fallback;
}

// ---------------------------------------------------------------------------
// verify: clone the repo, then run static analysis on it in an offline runner.
// ---------------------------------------------------------------------------

// Clone, fetch and checkout in one container so the credential configuration
// lives in exactly one place. The token reaches git through $GITHUB_TOKEN and a
// credential helper, so it never appears in argv and — critically — never gets
// written into .git/config, which is mounted into the runner alongside
// untrusted repository code.
const PREPARE_REPO_SCRIPT = `
set -eu
CRED='!f(){ echo username=x-access-token; echo "password=$GITHUB_TOKEN"; };f'
if [ -n "\${GITHUB_TOKEN:-}" ]; then
  set -- -c "credential.helper=$CRED"
else
  set --
fi
git "$@" clone --depth 1 --no-tags "$CLONE_URL" "$DEST" || exit 10
cd "$DEST"
if [ -n "\${COMMIT_SHA:-}" ]; then
  git "$@" fetch --depth 1 origin "$COMMIT_SHA" || true
  git checkout --quiet "$COMMIT_SHA" || exit 11
fi
`;

async function prepareRepo(job) {
  const cloneUrl = job.repo_clone_url || `https://github.com/${job.owner}/${job.repo}.git`;
  console.log("worker: cloning repository", cloneUrl);

  await runDocker([
    "run",
    "--rm",
    "-v",
    `${ARTIFACTS_VOLUME}:/artifacts`,
    "alpine",
    "mkdir",
    "-p",
    `/artifacts/${job.id}`,
  ]);

  return runDocker(
    [
      "run",
      "--rm",
      "--network",
      "host",
      "-v",
      `${ARTIFACTS_VOLUME}:/artifacts`,
      "-e",
      "GITHUB_TOKEN",
      "-e",
      "CLONE_URL",
      "-e",
      "DEST",
      "-e",
      "COMMIT_SHA",
      "--entrypoint",
      "sh",
      "alpine/git",
      "-c",
      PREPARE_REPO_SCRIPT,
    ],
    {
      timeoutMs: 180000,
      env: {
        GITHUB_TOKEN: job.repo_token || "",
        CLONE_URL: cloneUrl,
        DEST: `/artifacts/${job.id}/repo`,
        COMMIT_SHA: job.commit_sha || "",
      },
    },
  );
}

async function verify(job) {
  const report = createJobReporter(job, "verify", postCallback);
  try {
    report.emit(
      "prepare",
      `Cloning ${job.owner}/${job.repo}` +
        (job.commit_sha ? ` at ${String(job.commit_sha).slice(0, 7)}` : "") +
        " (shallow; token passed via a credential helper, never written to disk)",
    );
    const prepared = await prepareRepo(job);

    if (prepared.code !== 0) {
      const phase = prepared.code === 11 ? "commit checkout" : "clone";
      report.emit("prepare", `Repository ${phase} failed`, { level: "error" });
      await report.flush();
      return {
        verdict: {
          status: "not_exploitable",
          evidence: `${phase} failed: ${prepared.stderr.slice(-2000)}`,
        },
        exit_code: prepared.code,
        duration_ms: 0,
      };
    }

    report.emit("prepare", "Repository ready", { level: "success" });
    const started = Date.now();
    report.emit("sandbox", "Starting an isolated runner container", {
      data: {
        isolation: {
          container: `runner-${String(job.id).slice(0, 8)}`,
          image: RUNNER_IMAGE,
          network: "internal only — no internet access",
          cpus: RUNNER_CPU,
          memory: RUNNER_MEMORY,
          processes: RUNNER_PIDS,
          filesystem: `read-only (+ ${RUNNER_TMPFS_SIZE} tmpfs scratch)`,
          repository: "mounted read-only",
          capabilities: "all dropped",
          privileges: "no-new-privileges, uid 1000",
          credentials: "none (token removed before start)",
          timeout: `${RUNNER_TIMEOUT}s`,
        },
      },
    });

    // Runner has NO network access.
    // Repository is mounted read-only.
    const args = [
      "run",
      "--rm",
      "--name",
      `runner-${job.id}`,
      "--network",
      RUNNER_NETWORK,
      "--cpus",
      RUNNER_CPU,
      "--memory",
      RUNNER_MEMORY,
      "--pids-limit",
      RUNNER_PIDS,
      "--read-only",
      "--tmpfs",
      `/tmp:rw,size=${RUNNER_TMPFS_SIZE}`,
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--user",
      "1000:1000",

      // Prepared repository is available to the runner.
      "-v",
      `${ARTIFACTS_VOLUME}:/work:ro`,

      // The runner analyses untrusted code — it must never see the credential.
      "-e",
      `JOB_JSON=${JSON.stringify({ ...job, repo_clone_url: undefined, repo_token: undefined })}`,
      "-e",
      `REPO_PATH=/work/${job.id}/repo`,

      RUNNER_IMAGE,
    ];

    const result = await runDocker(args, {
      timeoutMs: RUNNER_TIMEOUT * 1000,
      onProgress: (p) => report.relay(p),
    });

    const verdict = parseVerdict(result, {
      status: "not_exploitable",
      evidence: result.stderr.slice(-4000),
    });
    const seconds = Math.round((Date.now() - started) / 1000);
    report.emit("done", `Runner exited after ${seconds}s (exit code ${result.code})`);
    report.emit(
      "verdict",
      `Verdict: ${String(verdict.status).replace("_", " ")} — ${String(verdict.evidence ?? "").slice(0, 300)}`,
      {
        level:
          verdict.status === "confirmed"
            ? "warn"
            : verdict.status === "failed"
              ? "error"
              : "success",
      },
    );
    await report.flush();
    return { verdict, exit_code: result.code, duration_ms: Date.now() - started };
  } finally {
    await runDocker([
      "run",
      "--rm",
      "-v",
      `${ARTIFACTS_VOLUME}:/artifacts`,
      "alpine",
      "rm",
      "-rf",
      `/artifacts/${job.id}`,
    ]);
  }
}

// ---------------------------------------------------------------------------
// fix: generate a remediation PR. No clone, no volume mount — the fixer edits
// a single file entirely through GitHub's REST API.
// ---------------------------------------------------------------------------

async function fix(job) {
  if (!OPENROUTER_API_KEY) {
    return {
      verdict: {
        status: "failed",
        evidence: "OPENROUTER_API_KEY is not configured on the sandbox worker.",
      },
      exit_code: 1,
      duration_ms: 0,
    };
  }
  // The fixer re-scans every patch before opening a PR, with the scanner's key.
  if (!process.env.GEMINI_API_KEY) {
    return {
      verdict: {
        status: "failed",
        evidence:
          "GEMINI_API_KEY is not configured on the sandbox worker — it is needed to re-scan a patch before a PR is opened.",
      },
      exit_code: 1,
      duration_ms: 0,
    };
  }

  const started = Date.now();
  const report = createJobReporter(job, "fix", postCallback);
  report.emit("sandbox", "Starting an isolated fixer container", {
    data: {
      isolation: {
        container: `fixer-${String(job.id).slice(0, 8)}`,
        image: FIXER_IMAGE,
        network:
          "fixer_net — internet egress for GitHub and the AI APIs; cannot reach the queue or API",
        cpus: FIXER_CPU,
        memory: FIXER_MEMORY,
        processes: FIXER_PIDS,
        filesystem: "read-only (+ 256m tmpfs scratch)",
        repository: "not cloned — one file read over the GitHub API",
        capabilities: "all dropped",
        privileges: "no-new-privileges, uid 1000",
        credentials: "GitHub token + API keys via environment, never argv",
        timeout: `${FIXER_TIMEOUT}s`,
      },
    },
  });

  const args = [
    "run",
    "--rm",
    "--name",
    `fixer-${job.id}`,
    "--network",
    FIXER_NETWORK,
    "--cpus",
    FIXER_CPU,
    "--memory",
    FIXER_MEMORY,
    "--pids-limit",
    FIXER_PIDS,
    "--read-only",
    "--tmpfs",
    "/tmp:rw,size=256m",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--user",
    "1000:1000",

    // All secrets by reference, never by value in argv.
    "-e",
    "JOB_JSON",
    "-e",
    "GITHUB_TOKEN",
    "-e",
    "OPENROUTER_API_KEY",
    "-e",
    "FIXER_MODEL",
    "-e",
    "APP_URL",
    "-e",
    "GEMINI_API_KEY",
    "-e",
    "SCAN_MODEL",
    "-e",
    "FIX_MAX_ATTEMPTS",

    FIXER_IMAGE,
  ];

  const result = await runDocker(args, {
    timeoutMs: FIXER_TIMEOUT * 1000,
    onProgress: (p) => report.relay(p),
    env: {
      // The fixer reads the credential from GITHUB_TOKEN; strip it from the
      // job payload so it isn't duplicated into a second place.
      JOB_JSON: JSON.stringify({ ...job, repo_token: undefined }),
      GITHUB_TOKEN: job.repo_token || "",
      OPENROUTER_API_KEY,
      FIXER_MODEL,
      APP_URL,
      GEMINI_API_KEY: process.env.GEMINI_API_KEY,
      SCAN_MODEL: process.env.SCAN_MODEL || "",
      FIX_MAX_ATTEMPTS,
    },
  });

  const verdict = parseVerdict(result, {
    status: "failed",
    evidence: result.stderr.slice(-4000) || `fixer exited with code ${result.code}`,
  });
  const seconds = Math.round((Date.now() - started) / 1000);
  // A SIGKILL from the timeout leaves no verdict line of the fixer's own.
  if (result.code !== 0 && !result.stdout.trim()) {
    report.emit("done", `Fixer was stopped after ${seconds}s (exit code ${result.code})`, {
      level: "error",
    });
  } else {
    report.emit("done", `Fixer exited after ${seconds}s`);
  }
  await report.flush();
  return { verdict, exit_code: result.code, duration_ms: Date.now() - started };
}

/**
 * Delivers a signed callback. Returns true when the app accepted it.
 *
 * This used to fire and forget: a 400/401/404 from the app was never looked
 * at, so a rejected result vanished and its row sat in "queued" forever with
 * nothing in any log. Non-2xx responses are now logged, and final results
 * (`retries` > 0) are retried on network errors and 5xx. A 4xx is not retried:
 * the app has already said the payload itself is wrong.
 */
async function postCallback(payload, { retries = 0 } = {}) {
  if (!CALLBACK_URL || !HMAC_SECRET) return false;
  const body = JSON.stringify(payload);
  const sig = createHmac("sha256", HMAC_SECRET).update(body).digest("hex");
  for (let attempt = 0; ; attempt++) {
    let status = 0;
    try {
      const res = await fetch(CALLBACK_URL, {
        method: "POST",
        headers: { "content-type": "application/json", "x-sandbox-signature": sig },
        body,
      });
      status = res.status;
      if (res.ok) return true;
      const text = (await res.text().catch(() => "")).slice(0, 200);
      console.error(
        `callback ${payload.kind ?? "verify"} ${payload.job_id} rejected: HTTP ${status} ${text}`,
      );
    } catch (e) {
      console.error(
        `callback ${payload.kind ?? "verify"} ${payload.job_id} failed:`,
        e?.message ?? e,
      );
    }
    const retryable = status === 0 || status >= 500;
    if (!retryable || attempt >= retries) return false;
    await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
  }
}

// ---------------------------------------------------------------------------
// scan: read a repository over the GitHub API and analyse it with an LLM.
// Runs in-process rather than in a spawned container — unlike `runner`, this
// never executes repository code, so there is no untrusted execution to
// isolate. See scan.js.
// ---------------------------------------------------------------------------

async function scan(job) {
  const started = Date.now();

  // Progress callbacks keep the app's scan row live, exactly as the inline
  // implementation did. They are best-effort: a dropped progress update must
  // never fail the scan itself.
  const onProgress = async (stage, progress, message, level = "info") => {
    await postCallback({
      kind: "scan_progress",
      job_id: job.id,
      scan_id: job.scan_id,
      stage,
      progress,
      message,
      level,
    });
  };

  const verdict = await runScan(job, { onProgress });
  return {
    verdict,
    exit_code: verdict.status === "completed" ? 0 : 1,
    duration_ms: Date.now() - started,
  };
}

async function loop() {
  console.log("worker: ready");
  while (true) {
    const item = await redis.brpop("jobs:pending", 5);
    if (!item) continue;
    const job = JSON.parse(item[1]);
    const kind = job.kind ?? "verify";
    console.log("worker: picked job", job.id, kind, job.probe ?? "");
    await redis.hset(`job:${job.id}`, { status: "running", started_at: Date.now() });
    try {
      const run = kind === "fix" ? fix : kind === "scan" ? scan : verify;
      const { verdict, exit_code, duration_ms } = await run(job);
      await redis.hset(`job:${job.id}`, {
        status: "completed",
        completed_at: Date.now(),
        exit_code,
        duration_ms,
        verdict: JSON.stringify(verdict),
      });
      await postCallback(
        {
          kind,
          job_id: job.id,
          scan_id: job.scan_id ?? null,
          vulnerability_id: job.vulnerability_id,
          verdict,
          duration_ms,
        },
        { retries: 3 },
      );
    } catch (err) {
      console.error("worker: job failed", err);
      await redis.hset(`job:${job.id}`, { status: "failed", error: String(err) });
      // Without this the app's row sits in 'pending' until someone notices.
      await postCallback(
        {
          kind,
          job_id: job.id,
          scan_id: job.scan_id ?? null,
          vulnerability_id: job.vulnerability_id,
          verdict: { status: "failed", evidence: `worker error: ${String(err).slice(0, 2000)}` },
          duration_ms: 0,
        },
        { retries: 3 },
      );
    }
  }
}

startWeeklySweepScheduler();

loop().catch((err) => {
  console.error(err);
  process.exit(1);
});
