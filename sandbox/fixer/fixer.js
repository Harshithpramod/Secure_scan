#!/usr/bin/env node
// One-shot fix job. Reads $JOB_JSON plus credentials from the environment,
// asks an LLM to patch the single file a vulnerability points at, re-scans the
// repository with the patch applied, and opens a pull request ONLY if that
// re-scan no longer reports the vulnerability (and no new medium+ ones). A
// rejected patch is sent back to the model with what the re-scan found, up to
// FIX_MAX_ATTEMPTS times; if none passes, no PR is opened at all.
//
// The re-scan uses the scanner's own analyzeFiles() from worker/scan.js — the
// same prompt, schema, model and secret patterns that produced the finding.
//
// Contract, identical in shape to runners/probe.sh: everything diagnostic goes
// to stderr, and the LAST line of stdout is a single JSON verdict object:
//   {"status":"pr_created"|"failed","evidence":"...","details":{...}}
//
// There is deliberately no git here. The change is one file, so cloning a whole
// repository into a container to edit it would mean tmpfs sizing, credential
// helpers and volume plumbing for no benefit. Working through the Git Data API
// means the token only ever exists in an Authorization header — never in argv,
// never on disk, never in a .git/config.

import { pathToFileURL } from "node:url";

import { generateVerifiedFix, normalizePath } from "../worker/fix-gate.js";
import {
  analyzeFiles,
  MAX_FILE_BYTES as SCAN_MAX_FILE_BYTES,
  pickScannable,
  resolveScanModel,
} from "../worker/scan.js";

const GITHUB_API = "https://api.github.com";
const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";

// Open-weight coding model with a large context window. Override with
// FIXER_MODEL to use anything else OpenRouter serves.
const DEFAULT_MODEL = "qwen/qwen3-coder";

// Well under any model's context window, and well under the point where asking
// for a full-file rewrite stops being reliable.
const MAX_FILE_BYTES = 60_000;

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const FIXER_MODEL = process.env.FIXER_MODEL || DEFAULT_MODEL;
const APP_URL = process.env.APP_URL || "";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
// Each attempt is one model rewrite plus one re-scan. Clamped so a typo in the
// env can't turn a fix into a runaway loop of paid API calls.
const MAX_ATTEMPTS = Math.min(5, Math.max(1, Number(process.env.FIX_MAX_ATTEMPTS) || 3));

function emit(verdict) {
  process.stdout.write(JSON.stringify(verdict) + "\n");
  process.exit(0);
}

/**
 * One line for the live sandbox console. Written to stderr with a marker the
 * worker looks for; the worker redacts secret-shaped values and relays it to
 * the app over the signed callback. Only these lines are relayed — never raw
 * stderr — so what reaches the UI is exactly what this file chooses to say.
 */
function progress(stage, message, data, level = "info") {
  process.stderr.write(
    `@@progress ${JSON.stringify({ stage, message, level, data: data ?? {} })}\n`,
  );
}

function fail(evidence, details) {
  progress("done", `No pull request opened — ${String(evidence).slice(0, 600)}`, {}, "error");
  emit({ status: "failed", evidence: String(evidence).slice(0, 4000), details: details ?? {} });
}

const titles = (list) =>
  list.map((f) => `${f.title}${f.line_start ? ` (line ${f.line_start})` : ""}`).join("; ");

/** Turns the fix loop's structured events into console lines. */
function narrate(e, { filePath, model, rescanRuns }) {
  switch (e.type) {
    case "baseline":
      return progress(
        "baseline",
        `Baseline scan ${e.run}/${e.of} of the current code: ${e.count} finding(s) in ${filePath}`,
        { findings: e.findings },
      );
    case "baseline_error":
      return progress("baseline", `Baseline scan ${e.run}/${e.of} failed: ${e.error}`, {}, "warn");
    case "baseline_done":
      return progress(
        "baseline",
        `Baseline: ${e.count} known finding(s) in ${filePath}. A patch may not add to these.`,
        { findings: e.findings },
      );
    case "propose":
      return progress(
        "patch",
        `Attempt ${e.attempt}/${e.of}: asking ${model} for a patch` +
          (e.retrying ? " (with the re-scan's findings as feedback)" : ""),
      );
    case "model_error":
      return progress("patch", `Attempt ${e.attempt}: model error — ${e.error}`, {}, "error");
    case "empty":
      return progress("patch", `Attempt ${e.attempt}: model returned an empty file`, {}, "warn");
    case "unchanged":
      return progress(
        "patch",
        `Model left the file unchanged${e.explanation ? `: ${e.explanation}` : ""}`,
        {},
        "warn",
      );
    case "patch":
      return progress(
        "patch",
        e.added === null
          ? `Attempt ${e.attempt}: patch ready (file too large to diff)`
          : `Attempt ${e.attempt}: patch changes +${e.added} −${e.removed} line(s)`,
        {
          attempt: e.attempt,
          diff: e.diff,
          truncated: e.truncated,
          explanation: e.explanation,
        },
      );
    case "rescan": {
      const bits = [];
      if (e.stillPresent.length) bits.push(`still detected: ${titles(e.stillPresent)}`);
      if (e.introduced.length) bits.push(`new: ${titles(e.introduced)}`);
      return progress(
        "rescan",
        e.ok
          ? `Re-scan ${e.run}/${e.of} of the patched code: clean`
          : `Re-scan ${e.run}/${e.of}: rejected — ${bits.join(" · ")}`,
        {
          attempt: e.attempt,
          ok: e.ok,
          stillPresent: e.stillPresent,
          introduced: e.introduced,
          minor: e.minor,
        },
        e.ok ? "success" : "warn",
      );
    }
    case "scan_error":
      return progress("rescan", `Re-scan ${e.run}/${e.of} failed: ${e.error}`, {}, "error");
    case "passed":
      return progress(
        "rescan",
        `Attempt ${e.attempt} passed ${rescanRuns} independent re-scans`,
        { attempt: e.attempt },
        "success",
      );
    case "rejected":
      return progress(
        "rescan",
        e.attempt < e.of
          ? `Attempt ${e.attempt} rejected — sending the re-scan's findings back to the model`
          : `Attempt ${e.attempt} rejected — that was the last attempt`,
        { attempt: e.attempt },
        "warn",
      );
    default:
      return undefined;
  }
}

async function gh(path, { method = "GET", body } = {}) {
  const res = await fetch(`${GITHUB_API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "PentestAI-Fixer",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // Non-JSON error body; keep the raw text for the message.
  }

  return { ok: res.ok, status: res.status, json, text };
}

function ghError(label, res) {
  const message = res.json?.message ?? res.text?.slice(0, 300) ?? "";
  if (res.status === 403 || res.status === 404) {
    return (
      `${label} failed (${res.status}): ${message}. This usually means the connected ` +
      `GitHub token can't write to this repository — reconnect GitHub with a token ` +
      `that has the 'repo' scope and write access.`
    );
  }
  return `${label} failed (${res.status}): ${message}`;
}

/**
 * Walks the tree one path segment at a time to find the blob's file mode.
 * A recursive tree fetch would be one request but can return megabytes (and is
 * silently truncated on large repos); this is a handful of small requests and
 * is always exact. Falls back to a regular file if anything is unexpected —
 * losing an executable bit is better than failing the whole fix.
 */
async function resolveBlobMode(owner, repo, rootTreeSha, filePath) {
  const parts = filePath.split("/").filter(Boolean);
  let treeSha = rootTreeSha;

  for (let i = 0; i < parts.length; i++) {
    const res = await gh(`/repos/${owner}/${repo}/git/trees/${treeSha}`);
    if (!res.ok || !Array.isArray(res.json?.tree)) return "100644";
    const entry = res.json.tree.find((e) => e.path === parts[i]);
    if (!entry) return "100644";
    if (i === parts.length - 1) return entry.mode || "100644";
    if (entry.type !== "tree") return "100644";
    treeSha = entry.sha;
  }
  return "100644";
}

function buildPrompt(job, fileContent, { feedback, previous } = {}) {
  const lineRange =
    job.line_start && job.line_end && job.line_end !== job.line_start
      ? `${job.line_start}-${job.line_end}`
      : job.line_start
        ? String(job.line_start)
        : "not specified";

  const system = `You are a senior application security engineer producing a minimal, correct patch for ONE specific vulnerability.

RULES
- Fix ONLY the vulnerability described. Do not refactor, reformat, rename, reorder imports, add comments elsewhere, or "improve" unrelated code.
- Preserve the file's existing style, indentation, quoting and language exactly.
- The fix must be complete and syntactically valid on its own — no TODOs, no placeholders, no "..." elisions.
- If the vulnerability cannot be fixed within this single file (for example it needs a new dependency, a schema change, a server/backend that does not exist, or edits elsewhere), say so in the explanation and return the file completely unchanged. Returning the file unchanged is the CORRECT answer in that case, not a failure.
- Never write a simulated, mock, placeholder, "conceptual" or demonstration security control. Code running in the browser cannot act as a server, so a "server-side check" written in client-side JavaScript is not a fix. Neither is moving data to a different client-side store, encoding it (base64, btoa) or making a forgeable token. A patch like that will be re-scanned, rejected, and never shipped.
- Never introduce a new secret, credential or hardcoded value. If the fix is to remove a hardcoded credential, replace it with a read from an environment variable and mention the required variable in your explanation.

OUTPUT FORMAT — reply with exactly this structure and nothing else:
<<<EXPLANATION>>>
Two to four sentences: what was wrong, what you changed, and anything the reviewer must do by hand (rotating a leaked credential, setting a new env var).
<<<FIXED_FILE>>>
The complete contents of the file after your fix. The entire file, from its first line to its last. No code fences, no commentary.
<<<END>>>`;

  let user = `Repository: ${job.owner}/${job.repo}
File: ${job.file_path}
Vulnerable lines: ${lineRange}

VULNERABILITY
Title: ${job.title}
Severity: ${job.severity}
${job.cwe_id ? `CWE: ${job.cwe_id}\n` : ""}${job.owasp_category ? `OWASP: ${job.owasp_category}\n` : ""}${job.category ? `Category: ${job.category}\n` : ""}
${job.description ?? "No further description was recorded."}

CURRENT FILE CONTENTS OF ${job.file_path}
${fileContent}`;

  if (feedback) {
    user += `

PREVIOUS ATTEMPT REJECTED
Your previous patch was applied and the repository was re-scanned by the same security scanner that reported this finding. The patch was rejected:

${feedback}
${previous ? `\nYOUR PREVIOUS (REJECTED) VERSION OF ${job.file_path}, for reference only:\n${previous}\n` : ""}
Write a new patch. Start again from the CURRENT FILE CONTENTS above, not from your rejected version, and actually remove the vulnerable behaviour rather than disguising it (encoding, obfuscating or renaming a value does not fix it). Keep the change minimal.`;
  }

  return { system, user };
}

/**
 * Delimiter-parsed rather than JSON-parsed. Asking a model to return a whole
 * source file as a JSON string value means every quote, backslash and newline
 * has to survive escaping intact, which open-weight models get wrong often
 * enough to matter. Delimiters sidestep escaping entirely. A JSON-shaped reply
 * is still accepted, since some models will produce one regardless.
 */
function parseModelReply(raw) {
  const text = raw.trim();

  const explanationMatch = text.match(/<<<EXPLANATION>>>([\s\S]*?)<<<FIXED_FILE>>>/);
  const fileMatch = text.match(/<<<FIXED_FILE>>>([\s\S]*?)(?:<<<END>>>|$)/);

  if (fileMatch) {
    let content = fileMatch[1].replace(/^\r?\n/, "").replace(/\r?\n\s*$/, "\n");
    // Some models wrap the file in a fence despite being told not to.
    const fenced = content.match(/^```[a-zA-Z0-9_+-]*\r?\n([\s\S]*?)\r?\n?```\s*$/);
    if (fenced) content = fenced[1];
    return {
      explanation: (explanationMatch?.[1] ?? "").trim(),
      fixedContent: content,
    };
  }

  try {
    const stripped = text
      .replace(/^```(?:json)?/i, "")
      .replace(/```$/, "")
      .trim();
    const parsed = JSON.parse(stripped);
    if (typeof parsed.fixed_content === "string") {
      return {
        explanation: String(parsed.explanation ?? "").trim(),
        fixedContent: parsed.fixed_content,
      };
    }
  } catch {
    // Fall through to the null result below.
  }

  return null;
}

async function callModel(job, fileContent, retry) {
  const { system, user } = buildPrompt(job, fileContent, retry);

  const res = await fetch(OPENROUTER_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "X-Title": "PentestAI",
    },
    body: JSON.stringify({
      model: FIXER_MODEL,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
      temperature: 0.1,
      max_tokens: 16000,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OpenRouter error ${res.status}: ${text.slice(0, 300)}`);
  }

  const json = await res.json();
  const content = json.choices?.[0]?.message?.content ?? "";
  if (!content.trim()) throw new Error("The model returned an empty response.");

  const parsed = parseModelReply(content);
  if (!parsed) {
    throw new Error(
      `Could not parse the model's reply — no <<<FIXED_FILE>>> section found. ` +
        `First 200 characters: ${content.slice(0, 200)}`,
    );
  }
  return parsed;
}

/**
 * The other files a real scan of this commit would read, so the re-scan sees
 * the patched file in the same context the original finding was made in. A
 * finding can hinge on another file (how a helper is called, say); re-scanning
 * the target alone would miss that and pass patches the next full scan flags.
 *
 * Uses the scanner's own pickScannable(), minus the target file, which the
 * caller adds back in either its original or patched form. Fetched once and
 * reused for the baseline and every attempt.
 */
async function loadScanContext(owner, repo, tipSha, filePath) {
  const treeRes = await gh(`/repos/${owner}/${repo}/git/trees/${tipSha}?recursive=1`);
  if (!treeRes.ok || !Array.isArray(treeRes.json?.tree)) {
    throw new Error(ghError("Reading the repository tree", treeRes));
  }
  const files = treeRes.json.tree
    .filter((n) => n.type === "blob" && typeof n.size === "number")
    .map((n) => ({ path: n.path, size: n.size, sha: n.sha }));

  const target = normalizePath(filePath);
  const selected = pickScannable(files).filter((f) => normalizePath(f.path) !== target);

  const contents = [];
  for (const f of selected) {
    const blobRes = await gh(`/repos/${owner}/${repo}/git/blobs/${f.sha}`);
    if (!blobRes.ok || blobRes.json?.encoding !== "base64") continue;
    const text = Buffer.from(blobRes.json.content, "base64").toString("utf8");
    contents.push({ path: f.path, content: text.slice(0, SCAN_MAX_FILE_BYTES) });
  }
  return contents;
}

async function main() {
  if (!process.env.JOB_JSON) fail("missing JOB_JSON");
  if (!GITHUB_TOKEN) fail("missing GITHUB_TOKEN");
  if (!OPENROUTER_API_KEY) fail("missing OPENROUTER_API_KEY");
  // Without the scanner's key there is no way to re-scan the patch, and an
  // unverified patch is exactly what this job must never turn into a PR.
  if (!GEMINI_API_KEY) {
    fail("missing GEMINI_API_KEY — it is needed to re-scan the patch before opening a PR");
  }

  let job;
  try {
    job = JSON.parse(process.env.JOB_JSON);
  } catch (err) {
    fail(`JOB_JSON is not valid JSON: ${err.message}`);
  }

  const { owner, repo, file_path: filePath, default_branch: baseBranch } = job;
  if (!owner || !repo || !filePath || !baseBranch) {
    fail("job is missing owner, repo, file_path or default_branch");
  }

  // 1. Resolve the CURRENT tip of the default branch. The scan's commit_sha is
  //    deliberately not used — a fix can be requested weeks after the scan ran,
  //    and branching from a stale commit would open a PR full of reverts.
  const refRes = await gh(
    `/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(baseBranch)}`,
  );
  if (!refRes.ok) fail(ghError(`Reading branch '${baseBranch}'`, refRes));
  const tipSha = refRes.json?.object?.sha;
  if (!tipSha) fail(`Branch '${baseBranch}' has no commit to branch from.`);

  const commitRes = await gh(`/repos/${owner}/${repo}/git/commits/${tipSha}`);
  if (!commitRes.ok) fail(ghError("Reading the tip commit", commitRes));
  const baseTreeSha = commitRes.json?.tree?.sha;
  if (!baseTreeSha) fail("Could not resolve the base tree for the tip commit.");

  // 2. Read the file as it exists NOW, not as it existed at scan time.
  const contentRes = await gh(
    `/repos/${owner}/${repo}/contents/${filePath.split("/").map(encodeURIComponent).join("/")}?ref=${tipSha}`,
  );
  if (contentRes.status === 404) {
    fail(
      `${filePath} no longer exists on '${baseBranch}'. It was moved or deleted since the scan ran, ` +
        `so there is nothing to patch. Re-scan the repository to refresh this finding.`,
    );
  }
  if (!contentRes.ok) fail(ghError(`Reading ${filePath}`, contentRes));

  const meta = contentRes.json;
  if (meta?.type !== "file" || typeof meta.content !== "string" || !meta.content) {
    fail(`${filePath} is not a regular text file that can be patched (type: ${meta?.type}).`);
  }
  if (meta.size > MAX_FILE_BYTES) {
    fail(
      `${filePath} is ${meta.size} bytes, over the ${MAX_FILE_BYTES}-byte limit for automated fixes. ` +
        `Patch this one by hand.`,
    );
  }

  const originalContent = Buffer.from(meta.content, "base64").toString("utf8");
  // A NUL byte means this isn't text, so there is nothing sensible to patch.
  if (originalContent.includes(String.fromCharCode(0))) {
    fail(`${filePath} looks like a binary file.`);
  }

  progress(
    "read",
    `Read ${filePath} from ${baseBranch} @ ${tipSha.slice(0, 7)} (${originalContent.split("\n").length} lines)`,
  );

  // 3. Generate a patch and re-scan it; retry with the re-scan's findings until
  //    one passes. Nothing below this block runs unless a patch passed.
  let context = [];
  try {
    context = await loadScanContext(owner, repo, tipSha, filePath);
  } catch (err) {
    // Still a real re-scan, just with less surrounding code. Recorded in the
    // verdict so it's visible that this one ran without context.
    console.error(
      `fixer: could not load scan context, re-scanning ${filePath} alone: ${err.message}`,
    );
  }
  console.error(`fixer: re-scan context is ${context.length} other file(s)`);
  progress(
    "context",
    context.length
      ? `Loaded ${context.length} other file(s) the scanner reads, so re-scans see the same context`
      : `Re-scanning ${filePath} on its own (the rest of the repository could not be loaded)`,
    {},
    context.length ? "info" : "warn",
  );

  const scanModel = resolveScanModel();
  const target = normalizePath(filePath);
  const analyze = async (content) => {
    const { findings } = await analyzeFiles(
      GEMINI_API_KEY,
      scanModel,
      [...context, { path: filePath, content }],
      { fullName: `${owner}/${repo}`, language: job.language },
    );
    // A patch to one file is only judged on that file. Findings elsewhere can
    // shift between two AI runs for reasons that have nothing to do with it.
    return findings.filter((f) => normalizePath(f.file_path) === target);
  };

  console.error(`fixer: patching ${filePath} with ${FIXER_MODEL}, re-scanning with ${scanModel}`);
  const result = await generateVerifiedFix({
    target: job,
    originalContent,
    propose: (retry) => callModel(job, originalContent, retry),
    analyze,
    maxAttempts: MAX_ATTEMPTS,
    log: (m) => console.error(`fixer: ${m}`),
    onEvent: (e) => narrate(e, { filePath, model: FIXER_MODEL, rescanRuns: 2 }),
  });

  if (!result.ok) {
    fail(result.message, {
      rescan: { passed: false, attempts: result.attempts, context_files: context.length },
    });
  }

  const { fixedContent, verdict } = result;
  const explanation = [
    result.explanation,
    `Verified: a re-scan with this patch applied no longer reports the finding` +
      (result.attempt > 1 ? ` (passed on attempt ${result.attempt} of ${MAX_ATTEMPTS}).` : "."),
  ]
    .filter(Boolean)
    .join("\n\n");

  const mode = await resolveBlobMode(owner, repo, baseTreeSha, filePath);

  // 4. blob -> tree -> commit -> branch -> PR.
  const blobRes = await gh(`/repos/${owner}/${repo}/git/blobs`, {
    method: "POST",
    body: { content: fixedContent, encoding: "utf-8" },
  });
  if (!blobRes.ok) fail(ghError("Writing the patched file", blobRes));

  const treeRes = await gh(`/repos/${owner}/${repo}/git/trees`, {
    method: "POST",
    body: {
      base_tree: baseTreeSha,
      tree: [{ path: filePath, mode, type: "blob", sha: blobRes.json.sha }],
    },
  });
  if (!treeRes.ok) fail(ghError("Building the commit tree", treeRes));

  const shortId = String(job.vulnerability_id ?? "").slice(0, 8) || "finding";
  const commitMessage =
    `fix(security): ${job.title}`.slice(0, 72) +
    `\n\n${job.cwe_id ? `${job.cwe_id} — ` : ""}${filePath}` +
    `\n\nGenerated by PentestAI. Review before merging.`;

  const newCommitRes = await gh(`/repos/${owner}/${repo}/git/commits`, {
    method: "POST",
    body: { message: commitMessage, tree: treeRes.json.sha, parents: [tipSha] },
  });
  if (!newCommitRes.ok) fail(ghError("Creating the commit", newCommitRes));

  // A previous attempt may have left the branch behind; suffix and retry once
  // rather than failing on a name collision.
  let branch = `pentestai/fix-${shortId}`;
  let refCreate = await gh(`/repos/${owner}/${repo}/git/refs`, {
    method: "POST",
    body: { ref: `refs/heads/${branch}`, sha: newCommitRes.json.sha },
  });
  if (!refCreate.ok && refCreate.status === 422) {
    branch = `${branch}-${Date.now().toString(36)}`;
    refCreate = await gh(`/repos/${owner}/${repo}/git/refs`, {
      method: "POST",
      body: { ref: `refs/heads/${branch}`, sha: newCommitRes.json.sha },
    });
  }
  if (!refCreate.ok) fail(ghError("Creating the fix branch", refCreate));

  const lineRef = job.line_start ? `${filePath}:${job.line_start}` : filePath;
  const prBody = [
    `## ${job.title}`,
    "",
    `| | |`,
    `|---|---|`,
    `| **Severity** | ${job.severity} |`,
    ...(job.cwe_id ? [`| **CWE** | ${job.cwe_id} |`] : []),
    ...(job.owasp_category ? [`| **OWASP** | ${job.owasp_category} |`] : []),
    `| **Location** | \`${lineRef}\` |`,
    "",
    ...(job.description ? ["### The finding", "", job.description, ""] : []),
    "### What this PR changes",
    "",
    result.explanation || "_The model did not provide an explanation._",
    "",
    "### Re-scan",
    "",
    "Before this pull request was opened, PentestAI re-ran its scan on the repository with this patch applied:",
    "",
    "- ✅ The original finding is no longer detected",
    "- ✅ No new medium, high or critical findings were introduced in this file",
    `- Passed on attempt ${result.attempt} of ${MAX_ATTEMPTS}`,
    ...(verdict.minor.length
      ? [
          "",
          "New **low**-severity finding(s) the re-scan reported (not blocking):",
          ...verdict.minor.map(
            (m) => `- ${m.title}${m.line_start ? ` (line ${m.line_start})` : ""}`,
          ),
        ]
      : []),
    ...(!verdict.baselineReproduced
      ? [
          "",
          "_Note: the re-scan did not reproduce this finding on the unpatched code either, so this check " +
            "confirms the patched file scans clean rather than that this exact issue was removed._",
        ]
      : []),
    ...(context.length === 0
      ? [
          "",
          "_Note: the re-scan covered this file only; the rest of the repository could not be loaded._",
        ]
      : []),
    "",
    "---",
    "",
    "> [!WARNING]",
    "> **This patch was generated by an AI model.** The re-scan above is the same static",
    "> AI and pattern analysis that found the issue. It does not compile, run or test the",
    "> code, and AI analysis can vary between runs. Review and test it before merging.",
    "",
    ...(APP_URL ? [`[View this finding in PentestAI](${APP_URL}/vulnerabilities)`, ""] : []),
    `<sub>Opened automatically by PentestAI · finding \`${shortId}\`</sub>`,
  ].join("\n");

  progress("publish", `Opening a pull request from ${branch} into ${baseBranch}`);
  const prRes = await gh(`/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    body: {
      title: `fix(security): ${job.title}`.slice(0, 200),
      head: branch,
      base: baseBranch,
      body: prBody,
      maintainer_can_modify: true,
    },
  });
  if (!prRes.ok) fail(ghError("Opening the pull request", prRes), { branch });

  console.error(`fixer: opened ${prRes.json.html_url}`);
  progress(
    "done",
    `Opened pull request #${prRes.json.number}`,
    { pr_url: prRes.json.html_url, pr_number: prRes.json.number },
    "success",
  );
  emit({
    status: "pr_created",
    evidence: `Opened pull request #${prRes.json.number} on ${owner}/${repo} from branch ${branch}.`,
    details: {
      pr_url: prRes.json.html_url,
      pr_number: prRes.json.number,
      branch,
      explanation,
      rescan: {
        passed: true,
        attempt: result.attempt,
        max_attempts: MAX_ATTEMPTS,
        attempts: result.attempts,
        baseline_reproduced: verdict.baselineReproduced,
        minor: verdict.minor.map((m) => m.title),
        context_files: context.length,
      },
    },
  });
}

// Exported so the patch/re-scan loop can be exercised without a container or a
// real pull request. Only runs as a job when executed directly.
export { buildPrompt, callModel, parseModelReply };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    fail(`unexpected fixer error: ${err?.stack ?? err}`);
  });
}
