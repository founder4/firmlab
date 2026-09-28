import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getImage: vi.fn(),
  listJobs: vi.fn(),
  loadLlmConfig: vi.fn(),
  runOpacidad: vi.fn(),
  startJob: vi.fn(),
}));

vi.mock('../store.js', () => ({
  getImage: mocks.getImage,
  listFindings: vi.fn(() => []),
  listImages: vi.fn(() => []),
  listJobs: mocks.listJobs,
}));
vi.mock('../llm.js', () => ({ loadLlmConfig: mocks.loadLlmConfig }));
vi.mock('../opacidad.js', () => ({ runOpacidad: mocks.runOpacidad }));
vi.mock('../providers/jobs.js', () => ({ startJob: mocks.startJob }));

import { opacidadRoutes, parseOpacidadRequest } from './opacidad.js';

type QueuedWork = (handle: { id: string; log: (line: string) => void }) => Promise<unknown>;

const LLM = { provider: 'deepseek', model: 'deepseek-flash', apiKey: 'k', baseUrl: 'http://127.0.0.1:1' };

describe('parseOpacidadRequest', () => {
  it.each([undefined, null, {}, { narrative: 'auto' }])('reads %j as auto', (body) => {
    expect(parseOpacidadRequest(body)).toEqual({ narrative: 'auto' });
  });

  it('accepts an explicit deterministic narrative', () => {
    expect(parseOpacidadRequest({ narrative: 'deterministic' })).toEqual({ narrative: 'deterministic' });
  });

  it.each([
    [{ narrative: 'llm' }, /auto" or "deterministic/],
    [{ narrative: true }, /auto" or "deterministic/],
    [{ narative: 'deterministic' }, /Unknown field\(s\): narative/],
    [[], /JSON object/],
    ['deterministic', /JSON object/],
  ])('refuses %j instead of reading it as auto', (body, error) => {
    const parsed = parseOpacidadRequest(body);
    expect(parsed).toHaveProperty('error');
    expect((parsed as { error: string }).error).toMatch(error);
  });
});

describe('POST /images/:id/opacidad', () => {
  let queuedWork: QueuedWork | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    queuedWork = undefined;
    mocks.getImage.mockReturnValue({ id: 'image-1', path: '/data/images/image-1/fw.bin', identityJson: '{}' });
    mocks.listJobs.mockReturnValue([]);
    mocks.loadLlmConfig.mockReturnValue(LLM);
    mocks.runOpacidad.mockResolvedValue({ steps: [], findings: { total: 0 } });
    mocks.startJob.mockImplementation((_imageId, _kind, _params, work: QueuedWork) => {
      queuedWork = work;
      return 'opacidad-job';
    });
  });

  async function post(payload?: unknown) {
    const app = Fastify();
    await app.register(opacidadRoutes, { prefix: '/api' });
    const response = await app.inject({
      method: 'POST',
      url: '/api/images/image-1/opacidad',
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
    await app.close();
    return response;
  }

  async function runQueued(): Promise<string[]> {
    const lines: string[] = [];
    await queuedWork?.({ id: 'opacidad-job', log: (line) => lines.push(line) });
    return lines;
  }

  it('keeps the configured LLM by default (no body, and an empty one)', async () => {
    for (const payload of [undefined, {}]) {
      vi.clearAllMocks();
      mocks.startJob.mockImplementation((_i, _k, _p, work: QueuedWork) => {
        queuedWork = work;
        return 'opacidad-job';
      });
      const response = await post(payload);
      expect(response.statusCode).toBe(202);
      expect(mocks.startJob).toHaveBeenCalledWith(
        'image-1',
        'opacidad',
        { narrative: 'deepseek', narrativeMode: 'auto' },
        expect.any(Function),
      );
      await runQueued();
      expect(mocks.runOpacidad).toHaveBeenCalledWith('image-1', '/data/images/image-1/fw.bin', expect.anything(), LLM);
    }
  });

  it('stays deterministic by default when no LLM is configured', async () => {
    mocks.loadLlmConfig.mockReturnValue(null);
    const response = await post({});
    expect(response.statusCode).toBe(202);
    expect(mocks.startJob.mock.calls[0]?.[2]).toEqual({ narrative: 'deterministic', narrativeMode: 'auto' });
    await runQueued();
    expect(mocks.runOpacidad.mock.calls[0]?.[3]).toBeNull();
  });

  it('withholds a configured LLM when the deterministic narrative is requested, and records why', async () => {
    const response = await post({ narrative: 'deterministic' });
    expect(response.statusCode).toBe(202);
    expect(mocks.loadLlmConfig).not.toHaveBeenCalled();
    expect(mocks.startJob.mock.calls[0]?.[2]).toEqual({ narrative: 'deterministic', narrativeMode: 'deterministic' });
    const lines = await runQueued();
    expect(mocks.runOpacidad.mock.calls[0]?.[3]).toBeNull();
    expect(lines.some((line) => /Narrative mode: deterministic \(requested explicitly\)/.test(line))).toBe(true);
  });

  it('rejects an invalid narrative without starting a job', async () => {
    const response = await post({ narrative: 'gpt' });
    expect(response.statusCode).toBe(400);
    expect(response.json().error).toMatch(/auto" or "deterministic/);
    expect(mocks.startJob).not.toHaveBeenCalled();
  });
});
