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
import { effectiveEnv } from './flags.js';

export type LlmProvider = 'deepseek' | 'openai' | 'anthropic';
export type LlmThinking = 'enabled' | 'disabled';
export type LlmReasoningEffort = 'high' | 'max';

export interface LlmConfig {
  provider: LlmProvider;
  apiKey: string;
  baseUrl: string;
  model: string;
  maxTokens: number;
  /** DeepSeek V4 thinking controls. Other providers ignore these adapter-specific fields. */
  thinking: LlmThinking;
  reasoningEffort: LlmReasoningEffort;
}

export interface LlmResult {
  text: string;
  model: string;
  provider: LlmProvider;
  inputTokens?: number;
  outputTokens?: number;
  reasoningTokens?: number;
  /** True when a structured DeepSeek call needed the bounded non-thinking recovery attempt. */
  fallbackUsed?: boolean;
}

/** A provider answered and consumed tokens, but its final text could not be used by a structured node. */
export class LlmOutputError extends Error {
  override readonly name = 'LlmOutputError';

  constructor(
    message: string,
    readonly result: LlmResult,
  ) {
    super(message);
  }
}

/** Per-provider defaults. DeepSeek is the default provider (v4-flash: general-purpose, 1M context). */
export const PROVIDER_DEFAULTS: Record<LlmProvider, { baseUrl: string; model: string; keyEnv: string }> = {
  deepseek: { baseUrl: 'https://api.deepseek.com', model: 'deepseek-v4-flash', keyEnv: 'DEEPSEEK_API_KEY' },
  openai: { baseUrl: 'https://api.openai.com/v1', model: '', keyEnv: 'OPENAI_API_KEY' },
  anthropic: { baseUrl: 'https://api.anthropic.com', model: 'claude-opus-4-8', keyEnv: 'ANTHROPIC_API_KEY' },
};

/**
 * Resolve the LLM config from the environment, or null when the agent layer is off. Gated by FIRMLAB_AGENT so
 * the deterministic workbench stays local-only, no-network, no-cost by default. Returns null (not an error) when
 * the flag is unset or no API key is available — callers treat null as "copilot disabled".
 */
export function loadLlmConfig(env: NodeJS.ProcessEnv = effectiveEnv()): LlmConfig | null {
  if (env.FIRMLAB_AGENT !== '1') return null;
  const provider = (env.FIRMLAB_LLM_PROVIDER ?? 'deepseek') as LlmProvider;
  if (!PROVIDER_DEFAULTS[provider]) return null;
  const defaults = PROVIDER_DEFAULTS[provider];
  const apiKey = env.FIRMLAB_LLM_API_KEY ?? env[defaults.keyEnv] ?? '';
  if (!apiKey) return null;
  const model = env.FIRMLAB_LLM_MODEL ?? defaults.model;
  if (!model) return null; // e.g. openai with no model configured
  const thinking: LlmThinking = env.FIRMLAB_LLM_THINKING === 'disabled' ? 'disabled' : 'enabled';
  const reasoningEffort: LlmReasoningEffort = env.FIRMLAB_LLM_REASONING_EFFORT === 'max' ? 'max' : 'high';
  return {
    provider,
    apiKey,
    baseUrl: env.FIRMLAB_LLM_BASE_URL ?? defaults.baseUrl,
    model,
    maxTokens: Number(env.FIRMLAB_LLM_MAX_TOKENS ?? 4096),
    thinking,
    reasoningEffort,
  };
}

export interface HttpRequest {
  url: string;
  headers: Record<string, string>;
  body: string;
}

// === OpenAI-compatible adapter (DeepSeek, OpenAI, any /chat/completions server) ===

export function buildChatCompletionsRequest(
  cfg: LlmConfig,
  system: string,
  user: string,
  format: 'text' | 'json' = 'text',
  thinkingOverride?: LlmThinking,
): HttpRequest {
  const body: Record<string, unknown> = {
    model: cfg.model,
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    max_tokens: cfg.maxTokens,
  };
  if (format === 'json') body.response_format = { type: 'json_object' };
  if (cfg.provider === 'deepseek') {
    const thinking = thinkingOverride ?? cfg.thinking;
    body.thinking = { type: thinking };
    if (thinking === 'enabled') body.reasoning_effort = cfg.reasoningEffort;
    else body.temperature = 0.2;
  } else if (format === 'text') {
    body.temperature = 0.2;
  }
  return {
    url: `${cfg.baseUrl.replace(/\/$/, '')}/chat/completions`,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.apiKey}` },
    body: JSON.stringify(body),
  };
}

/** Parse an OpenAI-style chat-completions response. `reasoning_content` (DeepSeek thinking) is ignored — we
 * take only the final answer, never the chain of thought. */
export function parseChatCompletionsResponse(json: unknown): {
  text: string;
  inputTokens?: number;
  outputTokens?: number;
  reasoningTokens?: number;
} {
  const j = json as {
    choices?: { message?: { content?: string } }[];
    usage?: {
      prompt_tokens?: number;
      completion_tokens?: number;
      completion_tokens_details?: { reasoning_tokens?: number };
    };
  };
  const text = j.choices?.[0]?.message?.content ?? '';
  const out: { text: string; inputTokens?: number; outputTokens?: number; reasoningTokens?: number } = { text };
  if (typeof j.usage?.prompt_tokens === 'number') out.inputTokens = j.usage.prompt_tokens;
  if (typeof j.usage?.completion_tokens === 'number') out.outputTokens = j.usage.completion_tokens;
  if (typeof j.usage?.completion_tokens_details?.reasoning_tokens === 'number') {
    out.reasoningTokens = j.usage.completion_tokens_details.reasoning_tokens;
  }
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
async function dispatchCompletion(
  system: string,
  user: string,
  cfg: LlmConfig,
  format: 'text' | 'json',
  thinkingOverride?: LlmThinking,
): Promise<LlmResult> {
  const isAnthropic = cfg.provider === 'anthropic';
  const req = isAnthropic
    ? buildAnthropicRequest(cfg, system, user)
    : buildChatCompletionsRequest(cfg, system, user, format, thinkingOverride);
  const res = await fetch(req.url, { method: 'POST', headers: req.headers, body: req.body });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`LLM provider ${cfg.provider} returned ${res.status}: ${detail.slice(0, 300)}`);
  }
  const json = await res.json();
  const parsed: { text: string; inputTokens?: number; outputTokens?: number; reasoningTokens?: number } = isAnthropic
    ? parseAnthropicResponse(json)
    : parseChatCompletionsResponse(json);
  const result: LlmResult = { text: parsed.text, model: cfg.model, provider: cfg.provider };
  if (parsed.inputTokens !== undefined) result.inputTokens = parsed.inputTokens;
  if (parsed.outputTokens !== undefined) result.outputTokens = parsed.outputTokens;
  if (parsed.reasoningTokens !== undefined) {
    result.reasoningTokens = parsed.reasoningTokens;
  }
  return result;
}

export async function complete(system: string, user: string, cfg: LlmConfig): Promise<LlmResult> {
  return dispatchCompletion(system, user, cfg, 'text');
}

function containsJsonObject(text: string): boolean {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end < start) return false;
  try {
    const value = JSON.parse(text.slice(start, end + 1));
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  } catch {
    return false;
  }
}

function sumOptional(a: number | undefined, b: number | undefined): number | undefined {
  return a === undefined && b === undefined ? undefined : (a ?? 0) + (b ?? 0);
}

/**
 * Structured decision call: provider-enforced JSON where supported. DeepSeek gets the configured thinking mode
 * first. If that paid request returns an empty/truncated non-object, retry exactly once without thinking — a
 * bounded recovery for provider JSON-mode edge cases. Usage from BOTH calls is returned so the governor never
 * turns the recovery into invisible spend.
 */
export async function completeJson(system: string, user: string, cfg: LlmConfig): Promise<LlmResult> {
  const first = await dispatchCompletion(system, user, cfg, 'json');
  if (cfg.provider !== 'deepseek' || cfg.thinking !== 'enabled' || containsJsonObject(first.text)) return first;

  const recovery = await dispatchCompletion(system, user, cfg, 'json', 'disabled');
  const combined: LlmResult = { ...recovery, fallbackUsed: true };
  const inputTokens = sumOptional(first.inputTokens, recovery.inputTokens);
  const outputTokens = sumOptional(first.outputTokens, recovery.outputTokens);
  const reasoningTokens = sumOptional(first.reasoningTokens, recovery.reasoningTokens);
  if (inputTokens !== undefined) combined.inputTokens = inputTokens;
  if (outputTokens !== undefined) combined.outputTokens = outputTokens;
  if (reasoningTokens !== undefined) combined.reasoningTokens = reasoningTokens;
  return combined;
}

/** Preserve provider usage when schema parsing fails so the governor never reports a paid turn as free. */
export function parseLlmOutput<T>(result: LlmResult, parse: (text: string) => T): T {
  try {
    return parse(result.text);
  } catch (err) {
    throw new LlmOutputError(err instanceof Error ? err.message : String(err), result);
  }
}
