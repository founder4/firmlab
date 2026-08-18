import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  type LlmConfig,
  LlmOutputError,
  buildAnthropicRequest,
  buildChatCompletionsRequest,
  completeJson,
  loadLlmConfig,
  parseAnthropicResponse,
  parseChatCompletionsResponse,
  parseLlmOutput,
} from './llm.js';

const deepseek: LlmConfig = {
  provider: 'deepseek',
  apiKey: 'sk-x',
  baseUrl: 'https://api.deepseek.com',
  model: 'deepseek-v4-flash',
  maxTokens: 2048,
  thinking: 'enabled',
  reasoningEffort: 'max',
};

afterEach(() => vi.unstubAllGlobals());

describe('loadLlmConfig', () => {
  it('returns null when the agent flag is off (local-only default)', () => {
    expect(loadLlmConfig({})).toBeNull();
    expect(loadLlmConfig({ FIRMLAB_LLM_API_KEY: 'k' })).toBeNull();
  });

  it('defaults to DeepSeek v4-flash when the flag + a key are set', () => {
    const cfg = loadLlmConfig({ FIRMLAB_AGENT: '1', DEEPSEEK_API_KEY: 'sk-1' });
    expect(cfg).toMatchObject({
      provider: 'deepseek',
      model: 'deepseek-v4-flash',
      baseUrl: 'https://api.deepseek.com',
      thinking: 'enabled',
      reasoningEffort: 'high',
    });
  });

  it('accepts explicit DeepSeek thinking and effort controls', () => {
    expect(
      loadLlmConfig({
        FIRMLAB_AGENT: '1',
        DEEPSEEK_API_KEY: 'sk-1',
        FIRMLAB_LLM_THINKING: 'enabled',
        FIRMLAB_LLM_REASONING_EFFORT: 'max',
      }),
    ).toMatchObject({ thinking: 'enabled', reasoningEffort: 'max' });
  });

  it('returns null when the flag is set but no key is available', () => {
    expect(loadLlmConfig({ FIRMLAB_AGENT: '1' })).toBeNull();
  });

  it('honors provider/model/base overrides and the generic key', () => {
    const cfg = loadLlmConfig({
      FIRMLAB_AGENT: '1',
      FIRMLAB_LLM_PROVIDER: 'anthropic',
      FIRMLAB_LLM_API_KEY: 'sk-a',
      FIRMLAB_LLM_MODEL: 'claude-opus-4-8',
    });
    expect(cfg).toMatchObject({
      provider: 'anthropic',
      model: 'claude-opus-4-8',
      baseUrl: 'https://api.anthropic.com',
    });
  });

  it('openai requires an explicit model (no safe default)', () => {
    expect(loadLlmConfig({ FIRMLAB_AGENT: '1', FIRMLAB_LLM_PROVIDER: 'openai', OPENAI_API_KEY: 'k' })).toBeNull();
    const cfg = loadLlmConfig({
      FIRMLAB_AGENT: '1',
      FIRMLAB_LLM_PROVIDER: 'openai',
      OPENAI_API_KEY: 'k',
      FIRMLAB_LLM_MODEL: 'gpt-x',
    });
    expect(cfg?.model).toBe('gpt-x');
  });
});

describe('buildChatCompletionsRequest (DeepSeek/OpenAI)', () => {
  it('posts to /chat/completions with a Bearer key and system+user messages', () => {
    const req = buildChatCompletionsRequest(deepseek, 'SYS', 'USER');
    expect(req.url).toBe('https://api.deepseek.com/chat/completions');
    expect(req.headers.authorization).toBe('Bearer sk-x');
    const body = JSON.parse(req.body);
    expect(body.model).toBe('deepseek-v4-flash');
    expect(body.messages).toEqual([
      { role: 'system', content: 'SYS' },
      { role: 'user', content: 'USER' },
    ]);
    expect(body.thinking).toEqual({ type: 'enabled' });
    expect(body.reasoning_effort).toBe('max');
    expect(body.temperature).toBeUndefined();
    expect(body.max_tokens).toBe(2048);
  });

  it('uses max-effort thinking plus provider-enforced JSON for a DeepSeek decision node', () => {
    const body = JSON.parse(buildChatCompletionsRequest(deepseek, 'Return JSON', 'Decide', 'json').body);
    expect(body.response_format).toEqual({ type: 'json_object' });
    expect(body.thinking).toEqual({ type: 'enabled' });
    expect(body.reasoning_effort).toBe('max');
    expect(body.temperature).toBeUndefined();
  });
});

describe('parseChatCompletionsResponse', () => {
  it('takes the message content and usage, ignoring reasoning_content', () => {
    const out = parseChatCompletionsResponse({
      choices: [{ message: { content: 'answer', reasoning_content: 'chain of thought' } }],
      usage: { prompt_tokens: 10, completion_tokens: 5, completion_tokens_details: { reasoning_tokens: 3 } },
    });
    expect(out).toEqual({ text: 'answer', inputTokens: 10, outputTokens: 5, reasoningTokens: 3 });
  });

  it('preserves usage when a structured response cannot be parsed', () => {
    const result = {
      text: '',
      model: 'deepseek-v4-pro',
      provider: 'deepseek' as const,
      inputTokens: 10,
      outputTokens: 5,
    };
    try {
      parseLlmOutput(result, JSON.parse);
      throw new Error('expected parse failure');
    } catch (err) {
      expect(err).toBeInstanceOf(LlmOutputError);
      expect((err as LlmOutputError).result).toBe(result);
    }
  });
});

describe('completeJson', () => {
  it('retries one malformed thinking response without thinking and accounts for both paid calls', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{ message: { content: '', reasoning_content: 'private reasoning' } }],
          usage: {
            prompt_tokens: 100,
            completion_tokens: 50,
            completion_tokens_details: { reasoning_tokens: 48 },
          },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{ message: { content: '{"decision":"safe"}' } }],
          usage: { prompt_tokens: 100, completion_tokens: 7 },
        }),
      });
    vi.stubGlobal('fetch', fetchMock);

    const result = await completeJson('Return JSON', 'Decide', deepseek);

    expect(result).toMatchObject({
      text: '{"decision":"safe"}',
      inputTokens: 200,
      outputTokens: 57,
      reasoningTokens: 48,
      fallbackUsed: true,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const firstBody = JSON.parse(fetchMock.mock.calls[0]?.[1]?.body as string);
    const retryBody = JSON.parse(fetchMock.mock.calls[1]?.[1]?.body as string);
    expect(firstBody).toMatchObject({ thinking: { type: 'enabled' }, reasoning_effort: 'max' });
    expect(retryBody).toMatchObject({ thinking: { type: 'disabled' }, temperature: 0.2 });
    expect(retryBody.reasoning_effort).toBeUndefined();
  });
});

describe('buildAnthropicRequest', () => {
  it('posts to /v1/messages with x-api-key, no temperature (4.x rejects it)', () => {
    const cfg: LlmConfig = {
      ...deepseek,
      provider: 'anthropic',
      baseUrl: 'https://api.anthropic.com',
      model: 'claude-opus-4-8',
    };
    const req = buildAnthropicRequest(cfg, 'SYS', 'USER');
    expect(req.url).toBe('https://api.anthropic.com/v1/messages');
    expect(req.headers['x-api-key']).toBe('sk-x');
    expect(req.headers['anthropic-version']).toBe('2023-06-01');
    const body = JSON.parse(req.body);
    expect(body.system).toBe('SYS');
    expect(body.messages).toEqual([{ role: 'user', content: 'USER' }]);
    expect(body.temperature).toBeUndefined();
  });
});

describe('parseAnthropicResponse', () => {
  it('joins text blocks and reads usage', () => {
    const out = parseAnthropicResponse({
      content: [
        { type: 'text', text: 'hello ' },
        { type: 'text', text: 'world' },
        { type: 'thinking', text: 'x' },
      ],
      usage: { input_tokens: 3, output_tokens: 7 },
    });
    expect(out).toEqual({ text: 'hello world', inputTokens: 3, outputTokens: 7 });
  });
});
