// AI helper (server-only). Do not import from the browser.
// Gemini's OpenAI-compatible endpoint, so the request/response shape stays
// portable to any other OpenAI-style provider.

const GEMINI_GATEWAY_URL =
  "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";

const DEFAULT_MODEL = "gemini-2.5-flash";

export type ChatMessage = {
  role: "system" | "user" | "assistant";
  content: string;
};

export async function callAI<T = unknown>(opts: {
  model?: string;
  messages: ChatMessage[];
  jsonSchema?: {
    name: string;
    schema: Record<string, unknown>;
  };
  temperature?: number;
}): Promise<T | string> {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    throw new Error("No AI key configured — set GEMINI_API_KEY.");
  }

  // Callers may still pass OpenRouter-style "google/gemini-…" ids; the Gemini
  // API wants the bare model name.
  const model = (opts.model ?? DEFAULT_MODEL).replace(/^google\//, "");

  const body: Record<string, unknown> = {
    model,
    messages: opts.messages,
    temperature: opts.temperature ?? 0.2,
  };

  if (opts.jsonSchema) {
    body.response_format = {
      type: "json_schema",
      json_schema: {
        name: opts.jsonSchema.name,
        strict: true,
        schema: opts.jsonSchema.schema,
      },
    };
  }

  const res = await fetch(GEMINI_GATEWAY_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const txt = await res.text();
    if (res.status === 429) throw new Error("AI rate limit exceeded — please retry shortly.");
    throw new Error(`AI gateway error ${res.status}: ${txt.slice(0, 300)}`);
  }

  const json = (await res.json()) as {
    choices: Array<{ message: { content: string } }>;
  };
  const content = json.choices?.[0]?.message?.content ?? "";
  if (opts.jsonSchema) {
    try {
      return JSON.parse(content) as T;
    } catch {
      // Some models wrap JSON in code fences — strip and retry.
      const stripped = content
        .replace(/^```(?:json)?/i, "")
        .replace(/```$/, "")
        .trim();
      return JSON.parse(stripped) as T;
    }
  }
  return content;
}
