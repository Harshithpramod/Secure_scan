import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import {
  aiRetry,
  analyzeFiles,
  isDailyQuotaError,
  parseRetryDelayMs,
  isSecretBearing,
  pickScannable,
  scanForSecrets,
  secretHitsToFindings,
  penalizeScore,
  sanitizeFindings,
  MAX_FILES,
} from "./scan.js";

describe("isSecretBearing", () => {
  it.each([
    [".env", true],
    [".env.production", true],
    ["config/.env.local", true],
    [".envrc", true],
    ["secrets.json", true],
    ["credentials.yaml", true],
    ["server.pem", true],
    ["id_rsa.key", true],
    ["src/index.ts", false],
    ["environment.ts", false], // must not match merely because it starts with "env"
    ["readme.md", false],
  ])("%s -> %s", (path, expected) => {
    expect(isSecretBearing(path)).toBe(expected);
  });
});

describe("pickScannable", () => {
  const f = (path, size = 100) => ({ path, size, sha: "x" });

  it("excludes vendored, generated and lock files", () => {
    const picked = pickScannable([
      f("node_modules/left-pad/index.js"),
      f("dist/bundle.js"),
      f("build/out.js"),
      f("vendor/lib.js"),
      f("app.min.js"),
      f("package-lock.json"),
      f("yarn.lock"),
      f("src/real.ts"),
    ]).map((x) => x.path);
    expect(picked).toEqual(["src/real.ts"]);
  });

  it("excludes files above the per-file byte cap", () => {
    expect(pickScannable([f("src/huge.ts", 30_001)])).toHaveLength(0);
    expect(pickScannable([f("src/ok.ts", 29_999)])).toHaveLength(1);
  });

  it("ranks secret-bearing files ahead of ordinary source", () => {
    const picked = pickScannable([f("src/util.ts"), f("src/index.ts"), f(".env")]);
    expect(picked[0].path).toBe(".env");
  });

  it("ranks auth-ish paths ahead of unremarkable ones", () => {
    const picked = pickScannable([f("src/util.ts"), f("src/auth/login.ts")]).map((x) => x.path);
    expect(picked.indexOf("src/auth/login.ts")).toBeLessThan(picked.indexOf("src/util.ts"));
  });

  it("caps the file count", () => {
    const many = Array.from({ length: 50 }, (_, i) => f(`src/f${i}.ts`));
    expect(pickScannable(many)).toHaveLength(MAX_FILES);
  });

  it("respects the total byte budget", () => {
    // 20 files x 20_000 bytes = 400k, over the 250k total budget.
    const many = Array.from({ length: 20 }, (_, i) => f(`src/f${i}.ts`, 20_000));
    const total = pickScannable(many).reduce((sum, x) => sum + x.size, 0);
    expect(total).toBeLessThanOrEqual(250_000);
  });

  it("includes extensionless Dockerfiles", () => {
    expect(pickScannable([f("Dockerfile")]).map((x) => x.path)).toEqual(["Dockerfile"]);
  });
});

describe("scanForSecrets", () => {
  const scan = (path, content) => scanForSecrets([{ path, content }]);

  it("detects an AWS access key id", () => {
    const hits = scan("src/aws.ts", 'const k = "AKIAIOSFODNN7EXAMPLE";');
    expect(hits.map((h) => h.kind)).toContain("AWS Access Key ID");
  });

  it("detects a GitHub token", () => {
    const hits = scan("src/gh.ts", `const t = "ghp_${"a".repeat(36)}";`);
    expect(hits.map((h) => h.kind)).toContain("GitHub Token");
  });

  it("detects a private key block", () => {
    const hits = scan("key.pem", "-----BEGIN RSA PRIVATE KEY-----");
    expect(hits.map((h) => h.kind)).toContain("Private Key Block");
  });

  it("reports an accurate 1-based line number", () => {
    const hits = scan(
      "src/a.ts",
      ["// line 1", "// line 2", 'const k = "AKIAIOSFODNN7EXAMPLE";'].join("\n"),
    );
    expect(hits[0].line).toBe(3);
  });

  it("never echoes the full secret back", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const hits = scan("src/a.ts", `const k = "${secret}";`);
    expect(hits[0].match).not.toBe(secret);
    expect(hits[0].match.length).toBeLessThan(secret.length);
  });

  it("skips comment lines", () => {
    expect(scan("src/a.ts", '# const k = "AKIAIOSFODNN7EXAMPLE";')).toHaveLength(0);
  });

  it("flags real-looking values in a .env file", () => {
    const hits = scan(".env", "DATABASE_PASSWORD=hunter2istoolong");
    expect(hits.some((h) => h.kind.includes("Exposed .env variable"))).toBe(true);
  });

  it("ignores obvious .env placeholders", () => {
    for (const value of ["your_api_key", "changeme", "xxx", "example", "<replace>"]) {
      expect(scan(".env", `API_KEY=${value}`)).toHaveLength(0);
    }
  });

  it("ignores short .env values", () => {
    expect(scan(".env", "API_KEY=abc")).toHaveLength(0);
  });

  it("does not treat non-sensitive .env keys as secrets", () => {
    expect(scan(".env", "NODE_ENV=production")).toHaveLength(0);
  });

  it("deduplicates identical file+line+kind hits", () => {
    const content = 'const k = "AKIAIOSFODNN7EXAMPLE";';
    const hits = scanForSecrets([
      { path: "a.ts", content },
      { path: "a.ts", content },
    ]);
    expect(hits).toHaveLength(1);
  });

  // Regex state leaking between lines is the classic /g flag bug: without
  // resetting lastIndex, every other match silently disappears.
  it("finds a secret on every matching line, not every other one", () => {
    const line = 'const k = "AKIAIOSFODNN7EXAMPLE";';
    const hits = scanForSecrets([
      { path: "a.ts", content: line },
      { path: "b.ts", content: line },
      { path: "c.ts", content: line },
    ]);
    expect(hits).toHaveLength(3);
  });
});

describe("secretHitsToFindings", () => {
  const hit = { file_path: "src/a.ts", line: 4, kind: "GitHub Token", match: "ghp_abc…" };

  it("rates a committed .env as critical and other files as high", () => {
    const [envFinding] = secretHitsToFindings([{ ...hit, file_path: ".env" }], []);
    const [srcFinding] = secretHitsToFindings([hit], []);
    expect(envFinding.severity).toBe("critical");
    expect(srcFinding.severity).toBe("high");
  });

  it("does not duplicate a finding the model already reported at that file and line", () => {
    const ai = [{ file_path: "src/a.ts", line_start: 4 }];
    expect(secretHitsToFindings([hit], ai)).toHaveLength(0);
  });

  it("keeps a hit the model reported at a different line", () => {
    const ai = [{ file_path: "src/a.ts", line_start: 99 }];
    expect(secretHitsToFindings([hit], ai)).toHaveLength(1);
  });

  it("attributes the finding to the secret scanner", () => {
    const findings = sanitizeFindings(secretHitsToFindings([hit], []));
    expect(findings[0].detected_by_agents).toEqual(["secret-scanner"]);
  });
});

describe("penalizeScore", () => {
  it("leaves the score alone when no secrets were found", () => {
    expect(penalizeScore(90, 0)).toBe(90);
  });

  it("caps the score once any secret is found", () => {
    expect(penalizeScore(95, 1)).toBe(30);
  });

  it("never raises a score that was already lower", () => {
    expect(penalizeScore(5, 3)).toBe(5);
  });

  it("floors the penalty so many secrets cannot drive the score negative", () => {
    expect(penalizeScore(100, 50)).toBe(15);
  });
});

describe("sanitizeFindings", () => {
  const valid = {
    title: "SQL injection",
    severity: "high",
    category: "Injection",
    cwe_id: "CWE-89",
    owasp_category: "A03",
    cvss_score: 8.1,
    file_path: "src/db.ts",
    line_start: 1,
    line_end: 2,
    description: "d",
    remediation_steps: ["a"],
    ai_analysis: "x",
  };

  // The DB enum has no "info" value, and one bad row fails the whole insert
  // batch — which used to fail the entire scan.
  it("drops severities the database enum does not accept", () => {
    const out = sanitizeFindings([
      valid,
      { ...valid, severity: "info" },
      { ...valid, severity: "" },
    ]);
    expect(out).toHaveLength(1);
  });

  it("drops entries with no title", () => {
    expect(sanitizeFindings([{ ...valid, title: undefined }])).toHaveLength(0);
  });

  it("nulls a CVSS score outside 0-10 instead of rejecting the finding", () => {
    expect(sanitizeFindings([{ ...valid, cvss_score: 42 }])[0].cvss_score).toBeNull();
    expect(sanitizeFindings([{ ...valid, cvss_score: -1 }])[0].cvss_score).toBeNull();
    expect(sanitizeFindings([valid])[0].cvss_score).toBe(8.1);
  });

  it("coerces non-integer line numbers to null", () => {
    expect(sanitizeFindings([{ ...valid, line_start: "3" }])[0].line_start).toBeNull();
  });

  it("truncates oversized text so one finding cannot blow up the callback body", () => {
    const out = sanitizeFindings([{ ...valid, description: "x".repeat(10_000) }]);
    expect(out[0].description.length).toBeLessThanOrEqual(4001);
  });

  it("caps the number of findings", () => {
    const many = Array.from({ length: 500 }, () => valid);
    expect(sanitizeFindings(many).length).toBeLessThanOrEqual(100);
  });

  it("defaults remediation_steps to an array when the model omits it", () => {
    expect(
      sanitizeFindings([{ ...valid, remediation_steps: "not an array" }])[0].remediation_steps,
    ).toEqual([]);
  });
});

describe("analyzeFiles — transient AI errors", () => {
  const ok = (findings) =>
    new Response(
      JSON.stringify({
        choices: [
          { message: { content: JSON.stringify({ findings, security_score: 80, summary: "s" }) } },
        ],
      }),
      { status: 200 },
    );
  const err = (status) => new Response("{}", { status });
  const files = [{ path: "a.js", content: "const x = 1;" }];
  const opts = { fullName: "o/r", language: "JavaScript" };
  let saved;

  beforeEach(() => {
    saved = [...aiRetry.delaysMs];
    aiRetry.delaysMs = [1, 1];
  });
  afterEach(() => {
    aiRetry.delaysMs = saved;
    vi.unstubAllGlobals();
  });

  it("retries a 503 and succeeds", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(err(503)).mockResolvedValueOnce(ok([]));
    vi.stubGlobal("fetch", fetch);
    const r = await analyzeFiles("k", "m", files, opts);
    expect(r.findings).toEqual([]);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("gives up after the configured retries", async () => {
    const fetch = vi.fn().mockImplementation(async () => err(503));
    vi.stubGlobal("fetch", fetch);
    await expect(analyzeFiles("k", "m", files, opts)).rejects.toThrow("AI gateway error 503");
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("does not retry a non-transient error", async () => {
    const fetch = vi.fn().mockImplementation(async () => err(400));
    vi.stubGlobal("fetch", fetch);
    await expect(analyzeFiles("k", "m", files, opts)).rejects.toThrow("AI gateway error 400");
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe("parseRetryDelayMs", () => {
  it("reads Gemini's RetryInfo delay", () => {
    const body = JSON.stringify({
      error: {
        code: 429,
        details: [{ "@type": "type.googleapis.com/google.rpc.RetryInfo", retryDelay: "37s" }],
      },
    });
    expect(parseRetryDelayMs(body)).toBe(37000);
    expect(parseRetryDelayMs('{"retryDelay": "2.5s"}')).toBe(2500);
  });

  it("returns null when there is no hint", () => {
    expect(parseRetryDelayMs("{}")).toBeNull();
    expect(parseRetryDelayMs(undefined)).toBeNull();
  });

  it("is honoured by the retry loop", async () => {
    const saved = [...aiRetry.delaysMs];
    aiRetry.delaysMs = [60000]; // would time the test out if the hint were ignored
    const ok = new Response(
      JSON.stringify({
        choices: [
          {
            message: { content: JSON.stringify({ findings: [], security_score: 90, summary: "" }) },
          },
        ],
      }),
      { status: 200 },
    );
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(new Response('{"retryDelay": "0s"}', { status: 429 }))
      .mockResolvedValueOnce(ok);
    vi.stubGlobal("fetch", fetch);
    try {
      await analyzeFiles("k", "m", [{ path: "a.js", content: "x" }], { fullName: "o/r" });
      expect(fetch).toHaveBeenCalledTimes(2);
    } finally {
      aiRetry.delaysMs = saved;
      vi.unstubAllGlobals();
    }
  });
});

describe("daily quota", () => {
  // Shape copied from a real 429 returned for this project's key.
  const dailyBody = JSON.stringify({
    error: {
      code: 429,
      status: "RESOURCE_EXHAUSTED",
      details: [
        {
          "@type": "type.googleapis.com/google.rpc.QuotaFailure",
          violations: [
            { quotaId: "GenerateRequestsPerDayPerProjectPerModel-FreeTier", quotaValue: "20" },
          ],
        },
        { "@type": "type.googleapis.com/google.rpc.RetryInfo", retryDelay: "38s" },
      ],
    },
  });
  const minuteBody = JSON.stringify({
    error: {
      details: [
        { violations: [{ quotaId: "GenerateRequestsPerMinutePerProjectPerModel-FreeTier" }] },
      ],
    },
  });

  it("tells a daily quota apart from a per-minute one", () => {
    expect(isDailyQuotaError(dailyBody)).toBe(true);
    expect(isDailyQuotaError(minuteBody)).toBe(false);
    expect(isDailyQuotaError("{}")).toBe(false);
  });

  it("fails immediately on a daily quota instead of waiting out a useless retryDelay", async () => {
    const fetch = vi.fn().mockImplementation(async () => new Response(dailyBody, { status: 429 }));
    vi.stubGlobal("fetch", fetch);
    try {
      const started = Date.now();
      await expect(
        analyzeFiles("k", "gemini-2.5-flash", [{ path: "a.js", content: "x" }], {
          fullName: "o/r",
        }),
      ).rejects.toThrow(/daily quota for gemini-2\.5-flash is used up \(20 requests\/day/);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(Date.now() - started).toBeLessThan(1000);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
