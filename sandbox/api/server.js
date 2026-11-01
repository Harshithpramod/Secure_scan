import Fastify from "fastify";
import Redis from "ioredis";
import { randomUUID } from "node:crypto";
import { z } from "zod";

const app = Fastify({ logger: true, bodyLimit: 1024 * 512 });
const redis = new Redis(process.env.REDIS_URL);

const API_TOKEN = process.env.SANDBOX_API_TOKEN;
if (!API_TOKEN) throw new Error("SANDBOX_API_TOKEN missing");

// Auth: PentestAI presents a bearer token
app.addHook("onRequest", async (req, reply) => {
  if (req.url === "/api/health") return;
  const auth = req.headers.authorization ?? "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!token || token.length !== API_TOKEN.length)
    return reply.code(401).send({ error: "unauthorized" });
  // constant-time-ish compare
  let diff = 0;
  for (let i = 0; i < token.length; i++) diff |= token.charCodeAt(i) ^ API_TOKEN.charCodeAt(i);
  if (diff !== 0) return reply.code(401).send({ error: "unauthorized" });
});

app.get("/api/health", async () => ({ ok: true }));

// Job intake. PentestAI calls this once per vulnerability it wants verified,
// or once per vulnerability it wants a remediation PR for.
const JobSchema = z
  .object({
    // Caller-supplied job id. PentestAI writes this to its database *before*
    // submitting, so a job that finishes fast can't call back before the row
    // that is supposed to receive the result carries the id. Falls back to a
    // generated id for older callers that don't send one.
    id: z.string().uuid().optional(),

    kind: z.enum(["verify", "fix", "scan"]).default("verify"),

    // Nullable for fix jobs: a vulnerability's scan_id is cleared if its scan
    // is deleted, and a fix can be requested long after that.
    scan_id: z.string().uuid().nullish(),
    // Scan jobs are per-repository, not per-finding.
    vulnerability_id: z.string().uuid().nullish(),

    repository_id: z.string().uuid(),

    owner: z.string().min(1),
    repo: z.string().min(1),

    // Plain HTTPS clone URL, no credentials. zod strips unrecognized keys by
    // default, so omitting this field here silently dropped it — the worker
    // then fell back to a public github.com URL and every private-repo clone
    // failed, masking real vulnerabilities as "not_exploitable" via a
    // clone-failure verdict.
    repo_clone_url: z.string().url().optional(),

    // The credential travels as its own field and is handed to git/GitHub via
    // an environment variable, never interpolated into the clone URL — that
    // put it in process arguments and in the clone's .git/config, which is
    // mounted into the runner next to untrusted repository code.
    repo_token: z.string().optional(),

    commit_sha: z.string().min(7).max(64).optional(),

    severity: z.enum(["critical", "high", "medium", "low", "info"]).nullish(),

    category: z.string().nullish(),

    file_path: z.string().optional(),

    line: z.number().optional(),

    probe: z.string().optional(),

    // fix-only fields: the fixer prompts the model with the full finding, and
    // needs a line range rather than the single `line` verify jobs carry.
    default_branch: z.string().optional(),
    title: z.string().optional(),
    description: z.string().nullish(),
    cwe_id: z.string().nullish(),
    owasp_category: z.string().nullish(),
    line_start: z.number().nullish(),
    line_end: z.number().nullish(),

    // scan-only fields.
    full_name: z.string().optional(),
    language: z.string().nullish(),
  })
  .superRefine((job, ctx) => {
    const require = (fields, kindLabel) => {
      for (const field of fields) {
        if (!job[field]) {
          ctx.addIssue({
            code: "custom",
            path: [field],
            message: `required for ${kindLabel} jobs`,
          });
        }
      }
    };

    if (job.kind === "verify") {
      require(["probe", "scan_id", "commit_sha", "vulnerability_id", "severity"], "verify");
    } else if (job.kind === "fix") {
      require(["file_path", "title", "default_branch", "vulnerability_id"], "fix");
    } else {
      require(["scan_id", "default_branch", "repo_token"], "scan");
    }
  });

app.post("/api/jobs", async (req, reply) => {
  const parsed = JobSchema.safeParse(req.body);
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });
  const { id, ...rest } = parsed.data;
  const job = { id: id ?? randomUUID(), created_at: Date.now(), ...rest };
  await redis.lpush("jobs:pending", JSON.stringify(job));
  await redis.hset(`job:${job.id}`, {
    status: "queued",
    kind: job.kind,
    created_at: job.created_at,
  });
  return reply.code(202).send({ job_id: job.id, status: "queued" });
});

app.get("/api/jobs/:id", async (req, reply) => {
  const data = await redis.hgetall(`job:${req.params.id}`);
  if (!data || Object.keys(data).length === 0) return reply.code(404).send({ error: "not_found" });
  return data;
});

const port = Number(process.env.PORT ?? 8080);
app.listen({ host: "0.0.0.0", port }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
