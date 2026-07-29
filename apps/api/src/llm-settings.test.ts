import { describe, expect, it } from 'vitest';
import { LLM_PROVIDERS, describeLlm, isLlmSettingKey, validateLlmSetting } from './llm-settings.js';

/**
 * Three properties carry this feature, and each one is a way it could quietly do harm.
 *
 *  1. **The API key never comes back out.** Not on read, not on write, not by accident through a field that
 *     happens to hold it.
 *  2. **A half-configured provider says what is missing.** `loadLlmConfig` returns null for four different
 *     reasons and the copilot simply does not appear; choosing `openai` in a dropdown and getting silence is a
 *     gap reading as a decision.
 *  3. **Every field says whether the environment or the override won**, so a compose file and this screen can
 *     never disagree without saying so.
 */

const state = (env: NodeJS.ProcessEnv = {}, overrides: Record<string, string> = {}, agent = true) =>
  describeLlm(env, overrides, agent);

describe('describeLlm — the key is described, never disclosed', () => {
  it('reports presence and a four-character tail, and the key appears nowhere else', () => {
    const s = state({}, { FIRMLAB_LLM_API_KEY: 'sk-supersecret-abcd' });
    expect(s.apiKey.present).toBe(true);
    expect(s.apiKey.tail).toBe('abcd');
    // The whole serialized state is searched, not just the field: a leak through some other field is the failure
    // this test exists for.
    expect(JSON.stringify(s)).not.toContain('supersecret');
  });

  it('does not pretend a short key is a tail', () => {
    // Four characters or fewer IS the whole key, so echoing it as a "tail" would disclose it.
    expect(state({}, { FIRMLAB_LLM_API_KEY: 'abcd' }).apiKey.tail).toBe('');
  });

  it('finds a key in the provider’s own environment variable and names where it looked', () => {
    const s = state({ DEEPSEEK_API_KEY: 'env-key-1234' });
    expect(s.apiKey).toMatchObject({ present: true, source: 'environment', tail: '1234', envVar: 'DEEPSEEK_API_KEY' });
  });

  it('names the RIGHT environment variable per provider', () => {
    expect(state({}, { FIRMLAB_LLM_PROVIDER: 'anthropic' }).apiKey.envVar).toBe('ANTHROPIC_API_KEY');
    expect(state({}, { FIRMLAB_LLM_PROVIDER: 'openai' }).apiKey.envVar).toBe('OPENAI_API_KEY');
  });
});

describe('describeLlm — a half-configured provider says what is missing', () => {
  it('says the lane is off rather than blaming the model config', () => {
    const s = state({ DEEPSEEK_API_KEY: 'k'.repeat(10) }, {}, false);
    expect(s.ready).toBe(false);
    expect(s.reason).toMatch(/FIRMLAB_AGENT is off/);
  });

  it('names the missing key AND where to put it instead of here', () => {
    const s = state({});
    expect(s.ready).toBe(false);
    expect(s.reason).toMatch(/No API key/);
    expect(s.reason).toContain('DEEPSEEK_API_KEY');
  });

  /** The trap: openai has no default model, so a dropdown choice alone turns the copilot off silently. */
  it('says a model id is still required for a provider with no default', () => {
    const s = state({ OPENAI_API_KEY: 'k'.repeat(10) }, { FIRMLAB_LLM_PROVIDER: 'openai' });
    expect(s.ready).toBe(false);
    expect(s.reason).toMatch(/no default model/);
    expect(s.reason).toMatch(/nothing on screen to say why/);
  });

  it('is ready once that model is supplied', () => {
    const s = state({ OPENAI_API_KEY: 'k'.repeat(10) }, { FIRMLAB_LLM_PROVIDER: 'openai', FIRMLAB_LLM_MODEL: 'gpt-x' });
    expect(s.ready).toBe(true);
    expect(s.reason).toBe('');
  });

  it('refuses a provider this build does not know, instead of falling through to a default', () => {
    const s = state({ DEEPSEEK_API_KEY: 'k'.repeat(10) }, { FIRMLAB_LLM_PROVIDER: 'mistral' });
    expect(s.ready).toBe(false);
    expect(s.reason).toMatch(/not a provider this build knows/);
  });
});

describe('describeLlm — every field says who won', () => {
  it('reports the environment when only compose set it', () => {
    expect(state({ FIRMLAB_LLM_MODEL: 'from-compose' }).model).toEqual({
      value: 'from-compose',
      source: 'environment',
    });
  });

  it('reports the override, and the value it overrode is not what shows', () => {
    // The whole reason the source is reported: an operator who set this in compose and sees something else here
    // has to be told which one is in force.
    expect(state({ FIRMLAB_LLM_MODEL: 'from-compose' }, { FIRMLAB_LLM_MODEL: 'from-ui' }).model).toEqual({
      value: 'from-ui',
      source: 'override',
    });
  });

  it('reports the provider default when neither set it', () => {
    expect(state({}).model).toEqual({ value: 'deepseek-v4-flash', source: 'default' });
    expect(state({}).baseUrl.source).toBe('default');
  });

  it('offers the per-provider default models, so choosing one can pre-fill it', () => {
    const s = state({});
    expect(s.providers).toEqual(LLM_PROVIDERS);
    expect(s.defaultModels.deepseek).toBe('deepseek-v4-flash');
    // openai's is empty ON PURPOSE, and that emptiness is what `reason` explains above.
    expect(s.defaultModels.openai).toBe('');
  });
});

describe('the allow-list and the validators', () => {
  it('admits the four settable keys and nothing else', () => {
    for (const k of ['FIRMLAB_LLM_PROVIDER', 'FIRMLAB_LLM_MODEL', 'FIRMLAB_LLM_BASE_URL', 'FIRMLAB_LLM_API_KEY']) {
      expect(isLlmSettingKey(k)).toBe(true);
    }
    // A settings table that could hold any environment variable would be arbitrary process configuration.
    expect(isLlmSettingKey('FIRMLAB_DATA_DIR')).toBe(false);
    expect(isLlmSettingKey('PATH')).toBe(false);
  });

  it('rejects an unknown provider by name', () => {
    const r = validateLlmSetting('FIRMLAB_LLM_PROVIDER', 'mistral');
    expect(r.ok).toBe(false);
  });

  it('requires the base URL to be an http(s) URL — it is where prompts are sent', () => {
    expect(validateLlmSetting('FIRMLAB_LLM_BASE_URL', 'https://api.example.com/v1').ok).toBe(true);
    expect(validateLlmSetting('FIRMLAB_LLM_BASE_URL', 'file:///etc/passwd').ok).toBe(false);
    expect(validateLlmSetting('FIRMLAB_LLM_BASE_URL', 'api.example.com').ok).toBe(false);
  });

  it('takes a model id as given, because the provider is the authority and a list here would go stale', () => {
    expect(validateLlmSetting('FIRMLAB_LLM_MODEL', 'a-model-released-last-week').ok).toBe(true);
  });

  it('refuses an empty value rather than storing a blank that reads as configured', () => {
    expect(validateLlmSetting('FIRMLAB_LLM_MODEL', '   ').ok).toBe(false);
  });
});
