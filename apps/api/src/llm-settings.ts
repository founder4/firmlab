/**
 * The model provider, configurable by the operator instead of only by a compose file.
 *
 * `loadLlmConfig` has always read four environment variables, so choosing DeepSeek over Anthropic meant editing a
 * YAML file on the host and recreating the container. This moves that decision into Settings, on the same
 * store-backed override mechanism the lane flags use — and it inherits that mechanism's discipline: every field
 * reports whether the ENVIRONMENT or an OVERRIDE won, because an operator who set `FIRMLAB_LLM_MODEL` in compose
 * and sees a different model in the UI deserves to be told why rather than left to guess.
 *
 * **The API key is not like the other three, and this file treats it differently in three ways.**
 *
 *  1. **It is never returned.** `describeLlm` reports only whether a key is present and the last four characters,
 *     which is enough to tell two keys apart and not enough to use one. A settings endpoint that echoed the key
 *     back would turn one authenticated reader into a credential exfiltration path.
 *  2. **Storing it widens who can spend money.** It used to require shell access to the host; it now requires
 *     reaching the workbench UI. That is a real change and the interface says so, because this key is billed and
 *     — on the agent and research lanes — receives prompts built from firmware the operator may not own.
 *  3. **It can be cleared back to the environment.** A key pinned by hand to the same value the env holds is a
 *     different state from one following the env, and only one of them survives a later compose change.
 *
 * **The reason an incomplete config is stated rather than silently off.** `loadLlmConfig` returns `null` — the
 * copilot simply does not appear — when the flag is off, when there is no key, or when the provider has no
 * default model and none was set. That last case is a trap: choosing `openai` in a dropdown and getting no
 * copilot, with nothing on screen saying a model id is still required, is a gap reading as a decision. So
 * `describeLlm` computes `ready` and, when false, the sentence naming what is missing.
 *
 * Pure and store-free: `settings.ts` binds it, and vitest cannot resolve `node:sqlite`.
 */
import { type LlmProvider, PROVIDER_DEFAULTS } from './llm.js';

/**
 * The four keys a runtime setting may write. Deliberately a fixed list, exactly as `TOGGLEABLE_FLAGS` is: a
 * settings table that could hold any environment variable would turn a UI with one authenticated user into
 * arbitrary process configuration.
 */
export const LLM_SETTING_KEYS = [
  'FIRMLAB_LLM_PROVIDER',
  'FIRMLAB_LLM_MODEL',
  'FIRMLAB_LLM_BASE_URL',
  'FIRMLAB_LLM_API_KEY',
] as const;

export type LlmSettingKey = (typeof LLM_SETTING_KEYS)[number];

const KEY_SET: ReadonlySet<string> = new Set<string>(LLM_SETTING_KEYS);

/** Is this a key a runtime setting is allowed to write? Takes any string — the caller's input is a request body. */
export function isLlmSettingKey(name: string): name is LlmSettingKey {
  return KEY_SET.has(name);
}

export const LLM_PROVIDERS: readonly LlmProvider[] = ['deepseek', 'openai', 'anthropic'];

/** Where a value came from. Same vocabulary as `FlagSource`, for the same reason. */
export type LlmFieldSource = 'override' | 'environment' | 'default';

export interface LlmFieldState {
  value: string;
  source: LlmFieldSource;
}

export interface LlmSettingsState {
  provider: LlmFieldState;
  model: LlmFieldState;
  baseUrl: LlmFieldState;
  /** The key, described and never disclosed. */
  apiKey: {
    /** Whether ANY key is available — from the override or from the environment. */
    present: boolean;
    source: LlmFieldSource;
    /** Last four characters, enough to tell two keys apart and useless as a credential. Empty when absent. */
    tail: string;
    /**
     * The environment variable this provider reads when no override is set (`DEEPSEEK_API_KEY`,
     * `ANTHROPIC_API_KEY`…). Named so an operator can put the key in `.env` instead, which is still the safer
     * place for it.
     */
    envVar: string;
  };
  /** True when `loadLlmConfig` would return a config rather than null. */
  ready: boolean;
  /** Empty when ready; otherwise what is missing, in words, rather than a silently absent copilot. */
  reason: string;
  /** Known provider ids, so the UI never invents one. Not translated: they are identifiers. */
  providers: readonly LlmProvider[];
  /** The default model for each provider, so choosing one can pre-fill it. Empty string = the provider has none. */
  defaultModels: Record<string, string>;
}

const tailOf = (key: string): string => (key.length <= 4 ? '' : key.slice(-4));

/**
 * Pure: what the model configuration is, where each part of it came from, and whether it will actually work.
 *
 * The environment is passed in rather than read, so a test can ask what a half-configured deployment reports —
 * which is the case this function mostly exists for.
 */
export function describeLlm(
  env: NodeJS.ProcessEnv,
  overrides: Record<string, string>,
  agentEnabled: boolean,
): LlmSettingsState {
  const pick = (key: LlmSettingKey, fallback: string): LlmFieldState => {
    if (overrides[key] !== undefined) return { value: overrides[key], source: 'override' };
    const fromEnv = env[key];
    if (fromEnv !== undefined && fromEnv !== '') return { value: fromEnv, source: 'environment' };
    return { value: fallback, source: 'default' };
  };

  const provider = pick('FIRMLAB_LLM_PROVIDER', 'deepseek');
  const known = LLM_PROVIDERS.includes(provider.value as LlmProvider);
  const defaults = PROVIDER_DEFAULTS[provider.value as LlmProvider] ?? PROVIDER_DEFAULTS.deepseek;

  const model = pick('FIRMLAB_LLM_MODEL', defaults.model);
  const baseUrl = pick('FIRMLAB_LLM_BASE_URL', defaults.baseUrl);

  const overrideKey = overrides.FIRMLAB_LLM_API_KEY ?? '';
  const envKey = env.FIRMLAB_LLM_API_KEY ?? env[defaults.keyEnv] ?? '';
  const apiKey = overrideKey || envKey;

  const reason = !agentEnabled
    ? 'FIRMLAB_AGENT is off, so no model is contacted whatever is configured here. Turn the lane on above.'
    : !known
      ? `"${provider.value}" is not a provider this build knows (${LLM_PROVIDERS.join(', ')}), so the layer stays off.`
      : !apiKey
        ? `No API key. Set one here, or put it in ${defaults.keyEnv} where the deployment reads its secrets.`
        : !model.value
          ? `The ${provider.value} provider has no default model, so a model id has to be set explicitly — without one the copilot stays off with nothing on screen to say why.`
          : '';

  return {
    provider,
    model,
    baseUrl,
    apiKey: {
      present: Boolean(apiKey),
      source: overrideKey ? 'override' : envKey ? 'environment' : 'default',
      tail: tailOf(apiKey),
      envVar: defaults.keyEnv,
    },
    ready: reason === '',
    reason,
    providers: LLM_PROVIDERS,
    defaultModels: Object.fromEntries(LLM_PROVIDERS.map((p) => [p, PROVIDER_DEFAULTS[p].model])),
  };
}

/**
 * Pure: is this a value the setting may hold?
 *
 * Only two of the four can be checked at all. A model id is provider-specific and changes faster than any list
 * here could — validating it against a hardcoded set would reject a model released last week, which is worse than
 * letting the provider return its own error. A key is opaque by construction.
 */
export function validateLlmSetting(key: LlmSettingKey, value: string): { ok: true } | { ok: false; error: string } {
  if (key === 'FIRMLAB_LLM_PROVIDER') {
    return LLM_PROVIDERS.includes(value as LlmProvider)
      ? { ok: true }
      : { ok: false, error: `Unknown provider "${value}". This build supports: ${LLM_PROVIDERS.join(', ')}.` };
  }
  if (key === 'FIRMLAB_LLM_BASE_URL') {
    return /^https?:\/\/[^\s]+$/i.test(value)
      ? { ok: true }
      : { ok: false, error: 'The base URL has to be an http(s) URL — this is where prompts are sent.' };
  }
  // A model id and a key are taken as given: the provider is the authority on both, and a stale allow-list here
  // would reject a model that shipped last week.
  return value.trim() ? { ok: true } : { ok: false, error: 'An empty value is not a setting — clear it instead.' };
}
