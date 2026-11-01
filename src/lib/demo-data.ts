/**
 * Static fixtures for the public /demo experience.
 *
 * ISOLATION: this module is the demo's ONLY data source. It imports nothing —
 * no Supabase client, no server functions, no fetch. Everything below is a
 * literal. The demo route must never import from lib/*.functions.ts,
 * integrations/supabase/*, or anything that can reach the network, so a
 * visitor exploring the demo cannot read or write real data even in principle.
 */

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** Relative so the demo always looks freshly scanned rather than dated. */
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

export type DemoSeverity = "critical" | "high" | "medium" | "low";
export type DemoVerification =
  "confirmed" | "not_exploitable" | "failed" | "pending" | "unverified";
export type DemoFixStatus = "none" | "pending" | "pr_created" | "failed";

export type DemoVulnerability = {
  id: string;
  title: string;
  severity: DemoSeverity;
  status: "open" | "in_progress" | "fixed" | "false_positive";
  category: string;
  cwe_id: string;
  owasp_category: string;
  cvss_score: number;
  file_path: string;
  line_start: number;
  line_end: number;
  description: string;
  ai_analysis: string;
  remediation_steps: string[];
  snippet: string;
  suggested_fix: string;
  verification_status: DemoVerification;
  verification_evidence?: string;
  detected_at: string;
  repository: string;
};

export const DEMO_REPOSITORIES = [
  {
    id: "repo-commerce",
    full_name: "acme-corp/acme-commerce",
    name: "acme-commerce",
    owner: "acme-corp",
    default_branch: "main",
    language: "TypeScript",
    is_private: true,
    status: "vulnerable" as const,
    security_score: 42,
    scan_mode: "weekly" as const,
    files_scanned: 1247,
    last_scan_at: ago(18 * MIN),
  },
  {
    id: "repo-payments",
    full_name: "acme-corp/acme-payments",
    name: "acme-payments",
    owner: "acme-corp",
    default_branch: "main",
    language: "Go",
    is_private: true,
    status: "secure" as const,
    security_score: 88,
    scan_mode: "weekly" as const,
    files_scanned: 412,
    last_scan_at: ago(2 * DAY),
  },
  {
    id: "repo-mobile",
    full_name: "acme-corp/acme-mobile-api",
    name: "acme-mobile-api",
    owner: "acme-corp",
    default_branch: "develop",
    language: "Python",
    is_private: false,
    status: "never_scanned" as const,
    security_score: null,
    scan_mode: "manual" as const,
    files_scanned: 0,
    last_scan_at: null,
  },
];

export const DEMO_REPO = DEMO_REPOSITORIES[0];

/** 18 findings: 2 critical, 5 high, 7 medium, 4 low. */
export const DEMO_VULNERABILITIES: DemoVulnerability[] = [
  {
    id: "v-001",
    title: "SQL injection in order lookup endpoint",
    severity: "critical",
    status: "open",
    category: "Injection",
    cwe_id: "CWE-89",
    owasp_category: "A03:2021 Injection",
    cvss_score: 9.8,
    file_path: "src/api/orders/[id].ts",
    line_start: 88,
    line_end: 92,
    description:
      "The order lookup handler interpolates the `id` route parameter directly into a SQL string. An unauthenticated caller can terminate the literal and append arbitrary SQL, reading or modifying any table the database user can reach — including `customers` and `payment_methods`.",
    ai_analysis:
      "Taint analysis traced `req.query.id` from the HTTP boundary into `db.query()` with no sanitisation, parameterisation or type coercion along the path. Because the endpoint is reachable before the session middleware runs, no authentication is required to exploit it. This is the highest-impact finding in the repository.",
    remediation_steps: [
      "Replace string interpolation with a parameterised query using placeholders.",
      "Add an input guard rejecting any `id` that is not a positive integer.",
      "Move the route behind the authentication middleware.",
      "Audit database logs for anomalous queries against `orders` and `customers`.",
    ],
    snippet: `export async function GET(req: Request, { params }: Ctx) {
  const { id } = params;

  // Interpolated straight into SQL — no parameterisation.
  const rows = await db.query(
    \`SELECT * FROM orders WHERE id = '\${id}' LIMIT 1\`
  );

  return Response.json(rows[0] ?? null);
}`,
    suggested_fix: `export async function GET(req: Request, { params }: Ctx) {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return new Response("Invalid order id", { status: 400 });
  }

  // Parameterised: the driver escapes the value, never the query shape.
  const rows = await db.query(
    "SELECT * FROM orders WHERE id = $1 LIMIT 1",
    [id]
  );

  return Response.json(rows[0] ?? null);
}`,
    verification_status: "confirmed",
    verification_evidence:
      "CodeQL dataflow confirmed a tainted path: req.query.id → template literal → db.query sink. 1 result in js/sql-injection.",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-002",
    title: "Hardcoded AWS credentials committed to source",
    severity: "critical",
    status: "open",
    category: "Secrets Exposure",
    cwe_id: "CWE-798",
    owasp_category: "A07:2021 Identification and Authentication Failures",
    cvss_score: 9.1,
    file_path: ".env.production",
    line_start: 12,
    line_end: 13,
    description:
      "A live AWS access key pair is committed in `.env.production`. Any secret in version control must be treated as compromised — it is exposed to every fork, clone and CI cache, and deleting the file does not remove it from history.",
    ai_analysis:
      "Detected by the deterministic secret scanner, which runs before the AI pass precisely so a committed credential is never missed. The key prefix matches the AWS long-lived access key format. The surrounding variables suggest production S3 and SES access.",
    remediation_steps: [
      "Revoke the key pair in the AWS IAM console immediately — before anything else.",
      "Move the values to a secret manager and load them at runtime.",
      "Add `.env.production` to `.gitignore` and commit a `.env.example` with placeholders.",
      "Purge the secret from git history with `git filter-repo`, then force-push.",
      "Review CloudTrail for use of the key prior to revocation.",
    ],
    snippet: `NODE_ENV=production
DATABASE_URL=postgres://acme:hunter2@db.internal:5432/commerce

AWS_ACCESS_KEY_ID=AKIA4XMPL7QWERTY9ZXC
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

S3_BUCKET=acme-commerce-invoices`,
    suggested_fix: `NODE_ENV=production

# Loaded at runtime from the secret manager — never committed.
# Required variables (see docs/deploy.md):
#   DATABASE_URL
#   AWS_ACCESS_KEY_ID
#   AWS_SECRET_ACCESS_KEY

S3_BUCKET=acme-commerce-invoices`,
    verification_status: "confirmed",
    verification_evidence: "trufflehog3 matched a live AWS key pair at HEAD in .env.production.",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-003",
    title: "Stored XSS in product review renderer",
    severity: "high",
    status: "open",
    category: "Cross-Site Scripting",
    cwe_id: "CWE-79",
    owasp_category: "A03:2021 Injection",
    cvss_score: 8.2,
    file_path: "src/components/ReviewList.tsx",
    line_start: 64,
    line_end: 66,
    description:
      "Customer review bodies are rendered with `dangerouslySetInnerHTML` without sanitisation. A review containing a script tag executes for every visitor who views the product page, enabling session theft.",
    ai_analysis:
      "The review body originates from user input, is persisted verbatim, and is injected as raw HTML on render — a classic stored XSS chain. Impact is amplified because the product page is public and the session cookie lacks HttpOnly (see the related cookie finding).",
    remediation_steps: [
      "Render the review as text instead of HTML.",
      "If formatting is required, sanitise with DOMPurify and allow-list tags.",
      "Set a Content-Security-Policy that blocks inline scripts.",
    ],
    snippet: `{reviews.map((review) => (
  <article key={review.id} className="review">
    <h4>{review.author}</h4>
    <div dangerouslySetInnerHTML={{ __html: review.body }} />
  </article>
))}`,
    suggested_fix: `{reviews.map((review) => (
  <article key={review.id} className="review">
    <h4>{review.author}</h4>
    {/* Rendered as text — React escapes it automatically. */}
    <p className="whitespace-pre-wrap">{review.body}</p>
  </article>
))}`,
    verification_status: "confirmed",
    verification_evidence:
      "CodeQL js/xss: 1 result — review.body flows to dangerouslySetInnerHTML.",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-004",
    title: "Server-side request forgery in image proxy",
    severity: "high",
    status: "open",
    category: "SSRF",
    cwe_id: "CWE-918",
    owasp_category: "A10:2021 Server-Side Request Forgery",
    cvss_score: 8.6,
    file_path: "src/api/image-proxy.ts",
    line_start: 31,
    line_end: 34,
    description:
      "The image proxy fetches any URL supplied in the `src` parameter. An attacker can point it at internal addresses such as the cloud metadata endpoint and read the response through the proxy.",
    ai_analysis:
      "No allow-list, scheme check or private-range filter is applied before the outbound fetch. On a cloud host this reaches 169.254.169.254, which typically exposes instance credentials.",
    remediation_steps: [
      "Allow-list the specific image hosts the application actually serves.",
      "Reject non-https schemes and any address resolving into a private range.",
      "Run the proxy egress through a network policy that blocks link-local addresses.",
    ],
    snippet: `export async function GET(req: Request) {
  const src = new URL(req.url).searchParams.get("src")!;

  // Any URL the caller supplies is fetched verbatim.
  const upstream = await fetch(src);
  return new Response(upstream.body, {
    headers: { "content-type": upstream.headers.get("content-type")! },
  });
}`,
    suggested_fix: `const ALLOWED_HOSTS = new Set([
  "images.acme-commerce.com",
  "cdn.acme-commerce.com",
]);

export async function GET(req: Request) {
  const src = new URL(req.url).searchParams.get("src") ?? "";
  let target: URL;
  try {
    target = new URL(src);
  } catch {
    return new Response("Invalid src", { status: 400 });
  }

  if (target.protocol !== "https:" || !ALLOWED_HOSTS.has(target.hostname)) {
    return new Response("Host not allowed", { status: 403 });
  }

  const upstream = await fetch(target);
  return new Response(upstream.body, {
    headers: { "content-type": upstream.headers.get("content-type")! },
  });
}`,
    verification_status: "confirmed",
    verification_evidence: "CodeQL js/request-forgery: tainted URL reaches fetch() sink.",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-005",
    title: "Broken access control on admin order export",
    severity: "high",
    status: "in_progress",
    category: "Broken Access Control",
    cwe_id: "CWE-284",
    owasp_category: "A01:2021 Broken Access Control",
    cvss_score: 8.1,
    file_path: "src/api/admin/orders.ts",
    line_start: 22,
    line_end: 25,
    description:
      "The admin order export checks that a session exists but never checks the caller's role. Any authenticated customer can export the full order table, including other customers' addresses.",
    ai_analysis:
      "Authentication and authorisation are conflated here: `getSession()` proves who the caller is, not what they may do. Every other admin route in this repository calls `requireRole('admin')`, so this endpoint is the outlier rather than the pattern.",
    remediation_steps: [
      "Add the `requireRole('admin')` guard used by the sibling admin routes.",
      "Add a regression test asserting a customer session receives 403.",
      "Review access logs for exports by non-admin sessions.",
    ],
    snippet: `export async function GET(req: Request) {
  const session = await getSession(req);
  if (!session) return new Response("Unauthorized", { status: 401 });

  // Authenticated — but never checked for the admin role.
  const orders = await db.orders.findMany();
  return Response.json(orders);
}`,
    suggested_fix: `export async function GET(req: Request) {
  const session = await getSession(req);
  if (!session) return new Response("Unauthorized", { status: 401 });
  if (!requireRole(session, "admin")) {
    return new Response("Forbidden", { status: 403 });
  }

  const orders = await db.orders.findMany();
  return Response.json(orders);
}`,
    verification_status: "confirmed",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-006",
    title: "Insecure deserialization of session payload",
    severity: "high",
    status: "open",
    category: "Deserialization",
    cwe_id: "CWE-502",
    owasp_category: "A08:2021 Software and Data Integrity Failures",
    cvss_score: 7.9,
    file_path: "src/lib/session.ts",
    line_start: 47,
    line_end: 49,
    description:
      "Session cookies are decoded with `node-serialize`, which evaluates embedded function expressions. A forged cookie can achieve remote code execution on the server.",
    ai_analysis:
      "The cookie is not signed, so its contents are fully attacker-controlled, and `node-serialize.unserialize` is known to execute `$$ND_FUNC$$` payloads. The combination turns a cookie into an RCE primitive.",
    remediation_steps: [
      "Replace `node-serialize` with `JSON.parse`.",
      "Sign session cookies with an HMAC and verify before parsing.",
      "Rotate the session secret and invalidate existing sessions.",
    ],
    snippet: `import { unserialize } from "node-serialize";

export function readSession(cookie: string) {
  const raw = Buffer.from(cookie, "base64").toString("utf8");
  return unserialize(raw); // executes embedded functions
}`,
    suggested_fix: `import { createHmac, timingSafeEqual } from "node:crypto";

export function readSession(cookie: string) {
  const [payload, sig] = cookie.split(".");
  const expected = createHmac("sha256", process.env.SESSION_SECRET!)
    .update(payload)
    .digest("base64url");

  const a = Buffer.from(sig ?? "");
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}`,
    verification_status: "not_exploitable",
    verification_evidence:
      "CodeQL analysed the path but could not prove reachability from an untrusted source in this build — the cookie parser is behind a feature flag that is currently disabled. Review manually before dismissing.",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-007",
    title: "Vulnerable dependency: lodash 4.17.11 (prototype pollution)",
    severity: "high",
    status: "open",
    category: "Vulnerable Dependency",
    cwe_id: "CWE-1321",
    owasp_category: "A06:2021 Vulnerable and Outdated Components",
    cvss_score: 7.5,
    file_path: "package.json",
    line_start: 34,
    line_end: 34,
    description:
      "lodash 4.17.11 is affected by CVE-2019-10744, a prototype pollution flaw in `defaultsDeep` that can alter `Object.prototype` and lead to privilege escalation or denial of service.",
    ai_analysis:
      "The application calls `_.defaultsDeep` when merging user-supplied checkout options, which is exactly the affected code path. Upgrading is low-risk: the fix landed in a patch release with no breaking API changes.",
    remediation_steps: [
      "Upgrade lodash to 4.17.21 or later.",
      "Re-run the dependency audit to confirm no transitive pin holds the old version.",
      "Prefer structured cloning over deep-merging attacker-controlled objects.",
    ],
    snippet: `"dependencies": {
  "express": "^4.18.2",
  "lodash": "4.17.11",
  "pg": "^8.11.3"
}`,
    suggested_fix: `"dependencies": {
  "express": "^4.18.2",
  "lodash": "^4.17.21",
  "pg": "^8.11.3"
}`,
    verification_status: "confirmed",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-008",
    title: "Missing rate limiting on login endpoint",
    severity: "medium",
    status: "open",
    category: "Authentication",
    cwe_id: "CWE-307",
    owasp_category: "A07:2021 Identification and Authentication Failures",
    cvss_score: 6.5,
    file_path: "src/api/auth/login.ts",
    line_start: 19,
    line_end: 21,
    description:
      "The login route accepts unlimited attempts per IP and per account, allowing credential stuffing and brute-force attacks to run unimpeded.",
    ai_analysis:
      "No throttling middleware wraps this handler and no failed-attempt counter is persisted. Combined with the SHA-1 password hashing finding, an offline crack of a leaked table would be trivial to weaponise online.",
    remediation_steps: [
      "Apply a per-IP and per-account rate limit with exponential backoff.",
      "Lock accounts temporarily after repeated failures and notify the owner.",
      "Add CAPTCHA or proof-of-work after the first few failures.",
    ],
    snippet: `router.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await findUser(email);
  // No attempt counter, no throttle.
  if (!user || !verify(password, user.hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  return res.json({ token: issueToken(user) });
});`,
    suggested_fix: `const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => \`\${req.ip}:\${req.body.email ?? ""}\`,
  standardHeaders: true,
});

router.post("/api/auth/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await findUser(email);
  if (!user || !verify(password, user.hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  return res.json({ token: issueToken(user) });
});`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-009",
    title: "Weak password hashing using SHA-1",
    severity: "medium",
    status: "open",
    category: "Cryptography",
    cwe_id: "CWE-916",
    owasp_category: "A02:2021 Cryptographic Failures",
    cvss_score: 6.8,
    file_path: "src/lib/auth/hash.ts",
    line_start: 12,
    line_end: 14,
    description:
      "Passwords are hashed with a single unsalted SHA-1 pass. SHA-1 is fast by design, so a leaked table can be cracked at billions of guesses per second on commodity GPUs.",
    ai_analysis:
      "Password storage needs a deliberately slow, salted KDF. The absence of a per-user salt also means identical passwords produce identical hashes, exposing reuse across accounts.",
    remediation_steps: [
      "Switch to Argon2id (or bcrypt with cost ≥ 12).",
      "Re-hash each password transparently on next successful login.",
      "Force a reset for accounts that do not log in within the migration window.",
    ],
    snippet: `import { createHash } from "node:crypto";

export function hashPassword(password: string) {
  return createHash("sha1").update(password).digest("hex");
}`,
    suggested_fix: `import argon2 from "argon2";

export function hashPassword(password: string) {
  return argon2.hash(password, { type: argon2.argon2id });
}

export function verifyPassword(hash: string, password: string) {
  return argon2.verify(hash, password);
}`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-010",
    title: "Open redirect in checkout return URL",
    severity: "medium",
    status: "open",
    category: "Open Redirect",
    cwe_id: "CWE-601",
    owasp_category: "A01:2021 Broken Access Control",
    cvss_score: 6.1,
    file_path: "src/api/checkout/return.ts",
    line_start: 27,
    line_end: 28,
    description:
      "After payment the user is redirected to whatever URL the `next` parameter contains, letting an attacker send shoppers to a lookalike site while the link still originates from the real domain.",
    ai_analysis:
      "The parameter is not validated against an allow-list or constrained to a relative path, which is the standard phishing primitive for open redirects.",
    remediation_steps: [
      "Accept only relative paths, rejecting anything containing a scheme or host.",
      "Or resolve the target against an allow-list of known routes.",
    ],
    snippet: `const next = url.searchParams.get("next") ?? "/";
return Response.redirect(next, 302);`,
    suggested_fix: `const next = url.searchParams.get("next") ?? "/";
// Relative, single-slash paths only — blocks //evil.com and https://evil.com
const safe = /^\\/(?!\\/)[\\w\\-./?=&%]*$/.test(next) ? next : "/";
return Response.redirect(new URL(safe, url.origin), 302);`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-011",
    title: "Missing CSRF protection on profile update",
    severity: "medium",
    status: "open",
    category: "CSRF",
    cwe_id: "CWE-352",
    owasp_category: "A01:2021 Broken Access Control",
    cvss_score: 6.5,
    file_path: "src/api/profile/update.ts",
    line_start: 15,
    line_end: 17,
    description:
      "The profile update accepts cookie-authenticated POSTs with no CSRF token, so a third-party page can change a logged-in customer's email address and then trigger a password reset.",
    ai_analysis:
      "The session cookie is sent on cross-site POSTs because SameSite is unset (see the cookie flags finding), which is what makes this exploitable rather than theoretical.",
    remediation_steps: [
      "Require a per-session CSRF token on all state-changing requests.",
      "Set `SameSite=Lax` (or `Strict`) on the session cookie.",
      "Re-authenticate the user before allowing an email change.",
    ],
    snippet: `router.post("/api/profile/update", async (req, res) => {
  const session = await getSession(req);
  await db.users.update(session.userId, req.body);
  res.json({ ok: true });
});`,
    suggested_fix: `router.post("/api/profile/update", verifyCsrf, async (req, res) => {
  const session = await getSession(req);
  await db.users.update(session.userId, req.body);
  res.json({ ok: true });
});`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-012",
    title: "Sensitive data written to application logs",
    severity: "medium",
    status: "open",
    category: "Information Disclosure",
    cwe_id: "CWE-532",
    owasp_category: "A09:2021 Security Logging and Monitoring Failures",
    cvss_score: 5.3,
    file_path: "src/lib/logger.ts",
    line_start: 58,
    line_end: 60,
    description:
      "Full request bodies are logged on error, so passwords and card details reach the log aggregator in plaintext and inherit its much broader access list.",
    ai_analysis:
      "Log retention typically far exceeds the lifetime of the credential, and log platforms are usually readable by the whole engineering organisation — turning a transient secret into a durable one.",
    remediation_steps: [
      "Redact known-sensitive keys before serialising.",
      "Log a correlation id instead of the payload.",
      "Purge historical logs containing captured credentials.",
    ],
    snippet: `logger.error("request failed", {
  url: req.url,
  body: req.body, // includes password / card fields
});`,
    suggested_fix: `const REDACT = new Set(["password", "token", "card", "cvv", "ssn"]);
const safeBody = Object.fromEntries(
  Object.entries(req.body ?? {}).map(([k, v]) =>
    REDACT.has(k.toLowerCase()) ? [k, "[redacted]"] : [k, v],
  ),
);

logger.error("request failed", { url: req.url, body: safeBody });`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-013",
    title: "Session cookie missing Secure and HttpOnly flags",
    severity: "medium",
    status: "open",
    category: "Session Management",
    cwe_id: "CWE-614",
    owasp_category: "A05:2021 Security Misconfiguration",
    cvss_score: 5.4,
    file_path: "src/lib/session.ts",
    line_start: 81,
    line_end: 84,
    description:
      "The session cookie is set without `HttpOnly`, `Secure` or `SameSite`, so it is readable by JavaScript, transmittable over plaintext HTTP, and attached to cross-site requests.",
    ai_analysis:
      "This finding is a force multiplier: it is what makes the stored XSS finding session-stealing rather than merely defacing, and what makes the missing CSRF token exploitable.",
    remediation_steps: [
      "Set `HttpOnly`, `Secure` and `SameSite=Lax` on the session cookie.",
      "Scope the cookie to the narrowest workable path and domain.",
    ],
    snippet: `res.setHeader("Set-Cookie", \`sid=\${id}; Path=/; Max-Age=604800\`);`,
    suggested_fix: `res.setHeader(
  "Set-Cookie",
  \`sid=\${id}; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax\`,
);`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-014",
    title: "Stack traces exposed in production error responses",
    severity: "medium",
    status: "open",
    category: "Information Disclosure",
    cwe_id: "CWE-209",
    owasp_category: "A05:2021 Security Misconfiguration",
    cvss_score: 5.0,
    file_path: "src/api/_middleware.ts",
    line_start: 41,
    line_end: 43,
    description:
      "Unhandled errors return the raw stack trace to the client, disclosing absolute file paths, dependency versions and internal hostnames that assist further attacks.",
    ai_analysis:
      "The handler does not branch on environment, so development-grade diagnostics ship to production users. Individually low impact, but it materially shortens reconnaissance.",
    remediation_steps: [
      "Return a generic message and a correlation id in production.",
      "Log the full trace server-side only.",
    ],
    snippet: `app.use((err, req, res, _next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});`,
    suggested_fix: `app.use((err, req, res, _next) => {
  const ref = crypto.randomUUID();
  logger.error("unhandled", { ref, err });
  res.status(500).json({ error: "Internal server error", ref });
});`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-015",
    title: "Missing Content-Security-Policy header",
    severity: "low",
    status: "open",
    category: "Security Headers",
    cwe_id: "CWE-693",
    owasp_category: "A05:2021 Security Misconfiguration",
    cvss_score: 3.7,
    file_path: "next.config.js",
    line_start: 18,
    line_end: 20,
    description:
      "No Content-Security-Policy is configured, so the browser has no defence-in-depth against injected scripts.",
    ai_analysis:
      "On its own this is minor, but a CSP would have blunted the stored XSS finding by refusing inline script execution. Worth fixing alongside it.",
    remediation_steps: [
      "Add a CSP starting in report-only mode.",
      "Tighten to `script-src 'self'` once violations are resolved.",
    ],
    snippet: `async headers() {
  return [{ source: "/(.*)", headers: [
    { key: "X-Content-Type-Options", value: "nosniff" },
  ]}];
}`,
    suggested_fix: `async headers() {
  return [{ source: "/(.*)", headers: [
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Content-Security-Policy",
      value: "default-src 'self'; script-src 'self'; object-src 'none'" },
  ]}];
}`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-016",
    title: "Outdated TLS configuration permits TLS 1.0",
    severity: "low",
    status: "open",
    category: "Cryptography",
    cwe_id: "CWE-326",
    owasp_category: "A02:2021 Cryptographic Failures",
    cvss_score: 3.1,
    file_path: "infra/nginx.conf",
    line_start: 24,
    line_end: 24,
    description:
      "The edge proxy still negotiates TLS 1.0 and 1.1, both deprecated and disallowed by PCI DSS for cardholder environments.",
    ai_analysis:
      "Given this repository processes payments, the compliance implication is likely more pressing than the exploitability.",
    remediation_steps: [
      "Restrict to TLS 1.2 and 1.3.",
      "Re-run an SSL Labs scan to confirm the grade.",
    ],
    snippet: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;`,
    suggested_fix: `ssl_protocols TLSv1.2 TLSv1.3;`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-017",
    title: "Directory listing enabled on /static",
    severity: "low",
    status: "open",
    category: "Security Misconfiguration",
    cwe_id: "CWE-548",
    owasp_category: "A05:2021 Security Misconfiguration",
    cvss_score: 3.5,
    file_path: "infra/nginx.conf",
    line_start: 52,
    line_end: 52,
    description:
      "`autoindex on` exposes a browsable file listing under /static, revealing asset names, backup files and build artefacts.",
    ai_analysis:
      "Directory listings routinely expose stale files such as `.bak` or `.zip` archives that were never meant to be reachable.",
    remediation_steps: [
      "Set `autoindex off`.",
      "Audit the directory for files that should not be published.",
    ],
    snippet: `location /static/ {
  autoindex on;
}`,
    suggested_fix: `location /static/ {
  autoindex off;
}`,
    verification_status: "unverified",
    detected_at: ago(18 * MIN),
    repository: "acme-corp/acme-commerce",
  },
  {
    id: "v-018",
    title: "Missing X-Frame-Options / frame-ancestors",
    severity: "low",
    status: "fixed",
    category: "Security Headers",
    cwe_id: "CWE-1021",
    owasp_category: "A05:2021 Security Misconfiguration",
    cvss_score: 3.1,
    file_path: "next.config.js",
    line_start: 22,
    line_end: 22,
    description:
      "No framing protection was set, leaving the checkout page open to clickjacking overlays.",
    ai_analysis:
      "Resolved in the previous scan cycle by adding a DENY policy. Retained here to show how fixed findings are tracked over time.",
    remediation_steps: ["Keep `frame-ancestors 'none'` in the CSP once it ships."],
    snippet: `// No framing header configured`,
    suggested_fix: `{ key: "X-Frame-Options", value: "DENY" }`,
    verification_status: "not_exploitable",
    detected_at: ago(9 * DAY),
    repository: "acme-corp/acme-commerce",
  },
];

export const DEMO_SEVERITY_COUNTS = {
  critical: DEMO_VULNERABILITIES.filter((v) => v.severity === "critical").length,
  high: DEMO_VULNERABILITIES.filter((v) => v.severity === "high").length,
  medium: DEMO_VULNERABILITIES.filter((v) => v.severity === "medium").length,
  low: DEMO_VULNERABILITIES.filter((v) => v.severity === "low").length,
};

export type DemoScan = {
  id: string;
  repository: string;
  status: "completed" | "running" | "failed";
  trigger: "manual" | "scheduled";
  profile: string;
  branch: string;
  commit_sha: string;
  progress: number;
  duration_seconds: number | null;
  security_score: number | null;
  counts: { critical: number; high: number; medium: number; low: number };
  started_at: string;
  files_scanned: number;
  logs: Array<{ stage: string; level: "info" | "warn" | "error"; message: string; at: string }>;
};

export const DEMO_SCANS: DemoScan[] = [
  {
    id: "scan-1041",
    repository: "acme-corp/acme-commerce",
    status: "completed",
    trigger: "scheduled",
    profile: "standard",
    branch: "main",
    commit_sha: "9f2c41e",
    progress: 100,
    duration_seconds: 214,
    security_score: 42,
    counts: DEMO_SEVERITY_COUNTS,
    started_at: ago(18 * MIN),
    files_scanned: 1247,
    logs: [
      {
        stage: "init",
        level: "info",
        message: "Weekly auto-scan of acme-corp/acme-commerce",
        at: ago(22 * MIN),
      },
      { stage: "fetch", level: "info", message: "Resolving default branch…", at: ago(22 * MIN) },
      { stage: "fetch", level: "info", message: "Enumerating repository tree…", at: ago(21 * MIN) },
      {
        stage: "select",
        level: "info",
        message: "Selected 18 of 1,247 files for AI analysis",
        at: ago(21 * MIN),
      },
      {
        stage: "downloading",
        level: "info",
        message: "Downloading file contents…",
        at: ago(21 * MIN),
      },
      {
        stage: "secrets",
        level: "warn",
        message: "Detected 1 hardcoded secret / exposed credential.",
        at: ago(20 * MIN),
      },
      {
        stage: "analyzing",
        level: "info",
        message: "Running AI security analysis…",
        at: ago(20 * MIN),
      },
      {
        stage: "persisting",
        level: "info",
        message: "Analysis returned 18 finding(s). Saving…",
        at: ago(19 * MIN),
      },
      {
        stage: "verify",
        level: "info",
        message: "Submitted 7 high/critical finding(s) to the sandbox",
        at: ago(19 * MIN),
      },
      {
        stage: "done",
        level: "info",
        message: "Scan complete — score 42, 18 finding(s)",
        at: ago(18 * MIN),
      },
    ],
  },
  {
    id: "scan-1038",
    repository: "acme-corp/acme-payments",
    status: "completed",
    trigger: "scheduled",
    profile: "standard",
    branch: "main",
    commit_sha: "3ab7d90",
    progress: 100,
    duration_seconds: 96,
    security_score: 88,
    counts: { critical: 0, high: 0, medium: 2, low: 1 },
    started_at: ago(2 * DAY),
    files_scanned: 412,
    logs: [
      {
        stage: "init",
        level: "info",
        message: "Weekly auto-scan of acme-corp/acme-payments",
        at: ago(2 * DAY),
      },
      {
        stage: "analyzing",
        level: "info",
        message: "Running AI security analysis…",
        at: ago(2 * DAY),
      },
      {
        stage: "done",
        level: "info",
        message: "Scan complete — score 88, 3 finding(s)",
        at: ago(2 * DAY),
      },
    ],
  },
  {
    id: "scan-1024",
    repository: "acme-corp/acme-commerce",
    status: "completed",
    trigger: "manual",
    profile: "deep",
    branch: "main",
    commit_sha: "5d1a8bc",
    progress: 100,
    duration_seconds: 268,
    security_score: 38,
    counts: { critical: 3, high: 5, medium: 7, low: 5 },
    started_at: ago(9 * DAY),
    files_scanned: 1203,
    logs: [
      {
        stage: "init",
        level: "info",
        message: "Queued scan of acme-corp/acme-commerce",
        at: ago(9 * DAY),
      },
      {
        stage: "done",
        level: "info",
        message: "Scan complete — score 38, 20 finding(s)",
        at: ago(9 * DAY),
      },
    ],
  },
];

/** Canned assistant replies, matched on keywords. No model is ever called. */
export const DEMO_ASSISTANT_SUGGESTIONS = [
  "Are my repos secure?",
  "Show my critical vulnerabilities",
  "How do I fix SQL injection?",
  "What is CWE-798?",
];

const ASSISTANT_REPLIES: Array<{ match: RegExp; reply: string }> = [
  {
    match: /secure|posture|overall|summary|status/i,
    reply: `**acme-corp/acme-commerce is at risk.** Security score **42/100**, last scanned 18 minutes ago.

- **2 critical** — SQL injection in the order lookup, and a live AWS key pair committed to \`.env.production\`
- **5 high** — stored XSS, SSRF, broken access control, insecure deserialization, a vulnerable lodash version
- **7 medium**, **4 low**

\`acme-payments\` looks healthy at **88/100**. \`acme-mobile-api\` has never been scanned — it is *not yet assessed*, which is not the same as secure.

Start with the two criticals: both are sandbox-**confirmed**, meaning the exploit path was reproduced rather than guessed.`,
  },
  {
    match: /critical|worst|urgent|priorit/i,
    reply: `Two confirmed critical findings, both in \`acme-commerce\`:

1. **SQL injection in order lookup** — \`src/api/orders/[id].ts:88\` (CWE-89, CVSS 9.8). The route parameter is interpolated into a SQL string and the endpoint sits *before* auth middleware, so it is unauthenticated.
2. **Hardcoded AWS credentials** — \`.env.production:12\` (CWE-798, CVSS 9.1). Revoke the key pair first; removing the file does not remove it from git history.

Both were reproduced in the sandbox, so these are not speculative.`,
  },
  {
    match: /sql|injection|89/i,
    reply: `Parameterise the query — never build SQL with string interpolation.

\`\`\`ts
// Vulnerable
const rows = await db.query(
  \`SELECT * FROM orders WHERE id = '\${id}'\`
);

// Fixed — the driver escapes the value, never the query shape
const rows = await db.query(
  "SELECT * FROM orders WHERE id = $1 LIMIT 1",
  [id],
);
\`\`\`

Also add an input guard (\`Number.isInteger(id)\`) and move the route behind your auth middleware. Use **Fix with AI** on that finding to generate the patch as a pull request.`,
  },
  {
    match: /798|secret|credential|aws|key/i,
    reply: `**CWE-798 — Use of Hard-coded Credentials.** A secret embedded in source is exposed to everyone with repository access, every fork and clone, and every CI cache.

For the \`.env.production\` finding, in order:

1. **Revoke** the AWS key pair in IAM — before anything else.
2. Load the values from a secret manager at runtime.
3. Gitignore the file and commit a \`.env.example\` with placeholders.
4. Purge it from history (\`git filter-repo\`) and force-push.
5. Check CloudTrail for use of the key before revocation.

Deleting the file alone is not remediation — the value stays in history.`,
  },
  {
    match: /xss|script/i,
    reply: `The stored XSS is in \`src/components/ReviewList.tsx:64\` — review bodies are passed to \`dangerouslySetInnerHTML\` unsanitised.

Render as text and let React escape it:

\`\`\`tsx
<p className="whitespace-pre-wrap">{review.body}</p>
\`\`\`

Worth noting: this is more severe here because the session cookie lacks \`HttpOnly\` (a separate medium finding), so injected script can read it. Fixing the cookie flags reduces the blast radius even before the XSS is patched.`,
  },
  {
    match: /fix|patch|pull request|pr\b/i,
    reply: `Open any finding and use **Fix with AI**. PentestAI reads the file at the current branch tip, asks a model to patch just that vulnerability, and opens a **pull request** — never a direct commit to your default branch.

The patch is deliberately labelled *AI-generated and unverified*: it has not been compiled, tested or re-scanned. Review it like any other untrusted patch.`,
  },
  {
    match: /verif|sandbox|confirm|exploitab/i,
    reply: `Every high and critical finding is re-run inside an isolated container before you see a verdict:

- **Confirmed** — the exploit path was reproduced. Evidence is attached.
- **Not exploitable** — analysed and unreachable in this build.
- **Failed** — the tooling itself errored. Inconclusive, *not* a clean bill of health.

In this demo, 5 findings are confirmed and 2 came back not-exploitable. That distinction is the point of the product: pattern matching tells you a line looks like a SQL query, dataflow analysis tells you whether user input actually reaches it.`,
  },
];

export function demoAssistantReply(question: string): string {
  const hit = ASSISTANT_REPLIES.find((r) => r.match.test(question));
  if (hit) return hit.reply;
  return `I can only answer from this demo's sample data, so I don't have anything on that.

Try asking about the **security posture**, the **critical findings**, **how to fix SQL injection**, or **how sandbox verification works**. In the real product this same assistant answers from your own repositories, scans and findings.`;
}
