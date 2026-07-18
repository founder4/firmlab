/**
 * LLM provider abstraction — the optional, flag-gated bridge to a model. DeepSeek-first (the parent project's
 * orientation), with OpenAI-compatible and Anthropic providers behind one `complete()` call.
 *
 * Deliberately dependency-free: raw `fetch` against each provider's HTTP API, no SDK — consistent with
 * @firmlab/core's zero-dep ethos, and it keeps the whole agent layer behind a single env flag. With
 * FIRMLAB_AGENT unset, loadLlmConfig() returns null and nothing here ever touches the network.
 *
 * The request builders and response parsers are pure (no I/O) so they unit-test without hitting a provider;
 * complete() is the thin fetch wrapper over them.
 */

export type LlmProvider = 'deepseek' | 'openai' | 'anthropic';

export interface LlmConfig {
  provider: LlmProvider;
  apiKey: string;
  baseUrl: string;
  model: string;
  maxTokens: number;
}

export interface LlmResult {
  text: string;
  model: string;
  provider: LlmProvider;
  inputTokens?: number;
  outputTokens?: number;
}

/** Per-provider defaults. DeepSeek is the default provider (v4-flash: general-purpose, 1M context). */
const PROVIDER_DEFAULTS: Record<LlmProvider, { baseUrl: string; model: string; keyEnv: string }> = {
  deepseek: { baseUrl: 'https://api.deepseek.com', model: 'deepseek-v4-flash', keyEnv: 'DEEPSEEK_API_KEY' },
  openai: { baseUrl: 'https://api.openai.com/v1', model: '', keyEnv: 'OPENAI_API_KEY' },
  anthropic: { baseUrl: 'https://api.anthropic.com', model: 'claude-opus-4-8', keyEnv: 'ANTHROPIC_API_KEY' },
};

/**
 * Resolve the LLM config from the environment, or null when the agent layer is off. Gated by FIRMLAB_AGENT so
 * the deterministic workbench stays local-only, no-network, no-cost by default. Returns null (not an error) when
 * the flag is unset or no API key is available — callers treat null as "copilot disabled".
 */
export function loadLlmConfig(env: NodeJS.ProcessEnv = process.env): LlmConfig | null {
  if (env.FIRMLAB_AGENT !== '1') return null;
  const provider = (env.FIRMLAB_LLM_PROVIDER ?? 'deepseek') as LlmProvider;
  if (!PROVIDER_DEFAULTS[provider]) return null;
  const defaults = PROVIDER_DEFAULTS[provider];
  const apiKey = env.FIRMLAB_LLM_API_KEY ?? env[defaults.keyEnv] ?? '';
  if (!apiKey) return null;
  const model = env.FIRMLAB_LLM_MODEL ?? defaults.model;
  if (!model) return null; // e.g. openai with no model configured
  return {
    provider,
    apiKey,
    baseUrl: env.FIRMLAB_LLM_BASE_URL ?? defaults.baseUrl,
    model,
    maxTokens: Number(env.FIRMLAB_LLM_MAX_TOKENS ?? 4096),
  };
}

export interface HttpRequest {
  url: string;
  headers: Record<string, string>;
  body: string;
}

// === OpenAI-compatible adapter (DeepSeek, OpenAI, any /chat/completions server) ===

export function buildChatCompletionsRequest(cfg: LlmConfig, system: string, user: string): HttpRequest {
  return {
    url: `${cfg.baseUrl.replace(/\/$/, '')}/chat/completions`,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.apiKey}` },
    body: JSON.stringify({
      model: cfg.model,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
      temperature: 0.2, // low, for stable analysis (DeepSeek default is 1; range 0–2)
      max_tokens: cfg.maxTokens,
    }),
  };
}

/** Parse an OpenAI-style chat-completions response. `reasoning_content` (DeepSeek thinking) is ignored — we
 * take only the final answer, never the chain of thought. */
export function parseChatCompletionsResponse(json: unknown): {
  text: string;
  inputTokens?: number;
  outputTokens?: number;
} {
  const j = json as {
    choices?: { message?: { content?: string } }[];
    usage?: { prompt_tokens?: number; completion_tokens?: number };
  };
  const text = j.choices?.[0]?.message?.content ?? '';
  const out: { text: string; inputTokens?: number; outputTokens?: number } = { text };
  if (typeof j.usage?.prompt_tokens === 'number') out.inputTokens = j.usage.prompt_tokens;
  if (typeof j.usage?.completion_tokens === 'number') out.outputTokens = j.usage.completion_tokens;
  return out;
}

// === Anthropic Messages API adapter ===

export function buildAnthropicRequest(cfg: LlmConfig, system: string, user: string): HttpRequest {
  return {
    url: `${cfg.baseUrl.replace(/\/$/, '')}/v1/messages`,
    headers: {
      'content-type': 'application/json',
      'x-api-key': cfg.apiKey,
      'anthropic-version': '2023-06-01',
    },
    // No `temperature`: the current Claude models (Opus 4.x etc.) reject sampling params with a 400.
    body: JSON.stringify({
      model: cfg.model,
      max_tokens: cfg.maxTokens,
      system,
      messages: [{ role: 'user', content: user }],
    }),
  };
}

export function parseAnthropicResponse(json: unknown): { text: string; inputTokens?: number; outputTokens?: number } {
  const j = json as {
    content?: { type?: string; text?: string }[];
    usage?: { input_tokens?: number; output_tokens?: number };
  };
  const text = (j.content ?? [])
    .filter((b) => b.type === 'text')
    .map((b) => b.text ?? '')
    .join('');
  const out: { text: string; inputTokens?: number; outputTokens?: number } = { text };
  if (typeof j.usage?.input_tokens === 'number') out.inputTokens = j.usage.input_tokens;
  if (typeof j.usage?.output_tokens === 'number') out.outputTokens = j.usage.output_tokens;
  return out;
}

/** Dispatch to the right adapter, POST it, and return the parsed completion. Throws on a non-2xx response. */
export async function complete(system: string, user: string, cfg: LlmConfig): Promise<LlmResult> {
  const isAnthropic = cfg.provider === 'anthropic';
  const req = isAnthropic ? buildAnthropicRequest(cfg, system, user) : buildChatCompletionsRequest(cfg, system, user);
  const res = await fetch(req.url, { method: 'POST', headers: req.headers, body: req.body });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`LLM provider ${cfg.provider} returned ${res.status}: ${detail.slice(0, 300)}`);
  }
  const json = await res.json();
  const parsed = isAnthropic ? parseAnthropicResponse(json) : parseChatCompletionsResponse(json);
  const result: LlmResult = { text: parsed.text, model: cfg.model, provider: cfg.provider };
  if (parsed.inputTokens !== undefined) result.inputTokens = parsed.inputTokens;
  if (parsed.outputTokens !== undefined) result.outputTokens = parsed.outputTokens;
  return result;
}
