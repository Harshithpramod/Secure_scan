// Job submission to the self-hosted sandbox.
//
// Three job kinds share the same intake endpoint and the same signed-callback
// path back:
//   - "scan"   — read a repository and analyse it with an LLM.
//   - "verify" — re-run a finding through CodeQL/semgrep to see if it's real.
//   - "fix"    — generate a remediation PR for a finding.
//
// Both carry a caller-supplied `job_id`. The app writes that id to the database
// before submitting, so a callback can never arrive before the row that is
// meant to receive it.

type BaseJob = {
  job_id: string;
  vulnerability_id?: string;
  repository_id: string;

  owner: string;
  repo: string;

  /**
   * Clean HTTPS clone URL with no credentials in it. The token is passed
   * separately as `repo_token` so it never ends up in process arguments or in
   * the clone's .git/config.
   */
  repo_clone_url: string;
  repo_token: string;
};

export interface SandboxScanJob extends BaseJob {
  kind: "scan";
  scan_id: string;
  full_name: string;
  default_branch: string;
  language: string | null;
}

export interface SandboxVerifyJob extends BaseJob {
  kind: "verify";
  vulnerability_id: string;
  scan_id: string;
  commit_sha: string;
  severity: string;
  category: string;
  file_path?: string;
  line?: number;
  probe: string;
}

export interface SandboxFixJob extends BaseJob {
  kind: "fix";
  vulnerability_id: string;
  scan_id: string | null;
  default_branch: string;
  language: string | null;

  title: string;
  description: string | null;
  severity: string;
  category: string | null;
  cwe_id: string | null;
  owasp_category: string | null;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
}

function mapProbe(category: string): string {
  const c = category.toLowerCase();

  if (c.includes("secret")) return "secret";
  if (c.includes("sql")) return "sqli";
  if (c.includes("ssrf")) return "ssrf";
  if (c.includes("command")) return "rce";

  return "semgrep";
}

async function postJob(payload: Record<string, unknown>): Promise<{ job_id: string }> {
  const sandboxUrl = process.env.SANDBOX_URL;
  const sandboxToken = process.env.SANDBOX_API_TOKEN;

  if (!sandboxUrl) {
    throw new Error("SANDBOX_URL is not configured");
  }

  if (!sandboxToken) {
    throw new Error("SANDBOX_API_TOKEN is not configured");
  }

  const response = await fetch(`${sandboxUrl}/api/jobs`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${sandboxToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Sandbox request failed (${response.status}): ${errorText}`);
  }

  return response.json() as Promise<{ job_id: string }>;
}

export async function submitVerificationJob(
  job: Omit<SandboxVerifyJob, "kind" | "probe">,
): Promise<{ job_id: string }> {
  const { job_id, ...rest } = job;
  return postJob({
    ...rest,
    id: job_id,
    kind: "verify",
    probe: mapProbe(job.category),
  });
}

export async function submitFixJob(job: Omit<SandboxFixJob, "kind">): Promise<{ job_id: string }> {
  const { job_id, ...rest } = job;
  return postJob({
    ...rest,
    id: job_id,
    kind: "fix",
  });
}

export async function submitScanJob(
  job: Omit<SandboxScanJob, "kind">,
): Promise<{ job_id: string }> {
  const { job_id, ...rest } = job;
  return postJob({
    ...rest,
    id: job_id,
    kind: "scan",
  });
}
