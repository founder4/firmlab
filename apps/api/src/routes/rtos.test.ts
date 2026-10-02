import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getImage: vi.fn(),
  listJobs: vi.fn(),
  startJob: vi.fn(),
  syncFindings: vi.fn(),
  runRenodeRamCapture: vi.fn(),
  runRtosElfSymbols: vi.fn(),
  runRtosAnalysis: vi.fn(),
}));

vi.mock('../store.js', () => ({ getImage: mocks.getImage, listJobs: mocks.listJobs }));
vi.mock('../providers/jobs.js', () => ({ startJob: mocks.startJob }));
vi.mock('../findings.js', () => ({ syncFindings: mocks.syncFindings }));
vi.mock('../providers/renode-ram.js', () => ({ runRenodeRamCapture: mocks.runRenodeRamCapture }));
vi.mock('../providers/rtos-elf-symbols.js', () => ({ runRtosElfSymbols: mocks.runRtosElfSymbols }));
vi.mock('../providers/rtos.js', () => ({ runRtosAnalysis: mocks.runRtosAnalysis }));

import type { RtosTaskSnapshotResult } from '../providers/rtos-tasks.js';
import { rtosRoutes } from './rtos.js';

type QueuedWork = (handle: { id: string; log: (line: string) => void }) => Promise<unknown>;

const BASE = 0x2000_0000;
const SENTINEL = BASE + 8;
const ITEM = BASE + 0x20;

/** One-item little-endian 32-bit ready list at BASE, pxCurrentTCB at BASE + 0x40. `next` overrides the item's pxNext. */
function snapshotB64(opts: { next?: number; length?: number } = {}): string {
  const dv = new DataView(new ArrayBuffer(0x60));
  dv.setUint32(SENTINEL - BASE + 4, ITEM, true);
  dv.setUint32(ITEM - BASE + 4, opts.next ?? SENTINEL, true);
  dv.setUint32(ITEM - BASE + 12, 0x2000_1000, true);
  dv.setUint32(0x40, 0x2000_1000, true);
  return Buffer.from(new Uint8Array(dv.buffer).slice(0, opts.length ?? 0x60)).toString('base64');
}

const memory = (bytesBase64: string) => ({ base: BASE, endian: 'little', pointerWidth: 4, bytesBase64 });
const SYMBOLS = { pxCurrentTCB: BASE + 0x40, readyLists: [{ priority: 1, address: BASE }] };

describe('RTOS task snapshot route', () => {
  let queuedWork: QueuedWork | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    queuedWork = undefined;
    mocks.getImage.mockReturnValue({ id: 'image-1', path: '/images/fw.bin' });
    mocks.listJobs.mockReturnValue([]);
    mocks.startJob.mockImplementation((_imageId, _kind, _params, work: QueuedWork) => {
      queuedWork = work;
      return 'rtos-tasks-job';
    });
  });

  async function post(payload: Record<string, unknown>) {
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });
    const response = await app.inject({ method: 'POST', url: '/api/images/image-1/rtos/tasks', payload });
    await app.close();
    return response;
  }

  async function runQueued(): Promise<RtosTaskSnapshotResult> {
    if (!queuedWork) throw new Error('no job was queued');
    return (await queuedWork({ id: 'rtos-tasks-job', log: () => undefined })) as RtosTaskSnapshotResult;
  }

  it('returns 404 for an unknown image without creating a job', async () => {
    mocks.getImage.mockReturnValue(undefined);
    const response = await post({ memory: memory(snapshotB64()), symbols: SYMBOLS });
    expect(response.statusCode).toBe(404);
    expect(mocks.startJob).not.toHaveBeenCalled();
  });

  it('refuses an undeclared layout with 400 before any parse or job', async () => {
    const response = await post({ memory: { base: BASE, bytesBase64: snapshotB64() }, symbols: SYMBOLS });
    expect(response.statusCode).toBe(400);
    expect(response.json().details.join('\n')).toMatch(/endian[\s\S]*pointerWidth/);
    expect(mocks.startJob).not.toHaveBeenCalled();
  });

  it('queues a valid list and persists a complete, lead-only result with bytes attempted/completed', async () => {
    const response = await post({ memory: memory(snapshotB64()), symbols: SYMBOLS });
    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ jobId: 'rtos-tasks-job' });
    expect(mocks.startJob).toHaveBeenCalledWith(
      'image-1',
      'rtos-tasks',
      { base: BASE, endian: 'little', pointerWidth: 4, bytes: 0x60 },
      expect.any(Function),
    );
    const result = await runQueued();
    expect(result).toMatchObject({ coverage: 'complete', proofState: 'needs_runtime_reproduction' });
    expect(result.totals).toEqual({ nodesAttempted: 1, nodesCompleted: 1, bytesAttempted: 32, bytesCompleted: 32 });
    expect(mocks.syncFindings).not.toHaveBeenCalled();
  });

  it('persists missing_symbol as coverage none', async () => {
    await post({ memory: memory(snapshotB64()), symbols: {} });
    const result = await runQueued();
    expect(result.coverage).toBe('none');
    expect(result.currentTask.coverage).toBe('missing_symbol');
    expect(result.readyLists[0]?.coverage).toBe('missing_symbol');
  });

  it('persists a truncated record as truncated with fewer bytes completed than attempted', async () => {
    await post({ memory: memory(snapshotB64({ length: 0x28 })), symbols: { readyLists: SYMBOLS.readyLists } });
    const result = await runQueued();
    expect(result.readyLists[0]).toMatchObject({ coverage: 'truncated', attempted: 1, completed: 0 });
    expect(result.totals).toMatchObject({ bytesAttempted: 28, bytesCompleted: 8 });
  });

  it('persists a pointer outside the snapshot as out_of_range and partial coverage', async () => {
    await post({ memory: memory(snapshotB64({ next: 0x3000_0000 })), symbols: SYMBOLS });
    const result = await runQueued();
    expect(result.coverage).toBe('partial');
    expect(result.readyLists[0]).toMatchObject({ coverage: 'out_of_range', attempted: 2, completed: 1 });
    expect(result.totals).toMatchObject({ bytesAttempted: 52, bytesCompleted: 32 });
  });

  it('serves the newest completed snapshot result', async () => {
    mocks.listJobs.mockReturnValue([
      { kind: 'rtos', status: 'done', resultJson: '{"isCortexM":true}' },
      { kind: 'rtos-tasks', status: 'done', resultJson: '{"coverage":"partial"}' },
      { kind: 'rtos-tasks', status: 'done', resultJson: '{"coverage":"complete"}' },
    ]);
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });
    const response = await app.inject({ method: 'GET', url: '/api/images/image-1/rtos/tasks' });
    await app.close();
    expect(response.json()).toEqual({ result: { coverage: 'partial' } });
  });
});

describe('RTOS RAM capture route', () => {
  let queuedWork: QueuedWork | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    queuedWork = undefined;
    mocks.getImage.mockReturnValue({
      id: 'image-1',
      path: '/images/fw.elf',
      identityJson: '{"class":"rtos"}',
      analysisJson: '{"arch":"arm"}',
    });
    mocks.listJobs.mockReturnValue([]);
    mocks.startJob.mockImplementation((_imageId, _kind, _params, work: QueuedWork) => {
      queuedWork = work;
      return 'ram-capture-job';
    });
    mocks.runRenodeRamCapture.mockResolvedValue({
      available: true,
      ran: true,
      captured: true,
      reason: 'Captured 20480 bytes from sram',
      proofState: 'needs_runtime_reproduction',
      platform: 'cpus/stm32l072.repl',
      region: { name: 'sram', base: 0x20000000, size: 0x5000 },
      bytesBase64: 'AAAA',
      bytes: 'AAAA',
      bytesCaptured: 20480,
      seconds: 2,
      secondsRun: 2,
    });
  });

  async function post(payload?: Record<string, unknown>) {
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });
    const response = await app.inject({
      method: 'POST',
      url: '/api/images/image-1/rtos/ram-capture',
      ...(payload !== undefined ? { payload } : {}),
    });
    await app.close();
    return response;
  }

  it('returns 404 for an unknown image without creating a job', async () => {
    mocks.getImage.mockReturnValue(undefined);
    const response = await post({});
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: 'Image not found' });
    expect(mocks.startJob).not.toHaveBeenCalled();
  });

  it('rejects invalid seconds with 400', async () => {
    for (const invalid of [0, 31, -1, 2.5]) {
      const response = await post({ seconds: invalid });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: 'Invalid seconds: must be an integer between 1 and 30' });
      expect(mocks.startJob).not.toHaveBeenCalled();
    }
  });

  it('queues a ram capture job with default parameters and logs the reason', async () => {
    const logSpy = vi.fn();
    const response = await post({});
    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ jobId: 'ram-capture-job' });
    expect(mocks.startJob).toHaveBeenCalledWith(
      'image-1',
      'rtos-ram-capture',
      { seconds: undefined, platform: undefined },
      expect.any(Function),
    );

    expect(queuedWork).toBeDefined();
    if (!queuedWork) throw new Error('no job queued');
    const result = await queuedWork({ id: 'ram-capture-job', log: logSpy });
    expect(mocks.runRenodeRamCapture).toHaveBeenCalledWith('/images/fw.elf', {
      platform: undefined,
      seconds: undefined,
      identityJson: '{"class":"rtos"}',
      analysisJson: '{"arch":"arm"}',
    });
    expect(logSpy).toHaveBeenCalledWith('Captured 20480 bytes from sram');
    expect(result).toMatchObject({ captured: true, bytesCaptured: 20480 });
  });

  it('passes explicit seconds and platform to startJob and runner', async () => {
    const response = await post({ seconds: 5, platform: '/custom/platform.repl' });
    expect(response.statusCode).toBe(202);
    expect(mocks.startJob).toHaveBeenCalledWith(
      'image-1',
      'rtos-ram-capture',
      { seconds: 5, platform: '/custom/platform.repl' },
      expect.any(Function),
    );

    expect(queuedWork).toBeDefined();
    if (!queuedWork) throw new Error('no job queued');
    await queuedWork({ id: 'ram-capture-job', log: () => undefined });
    expect(mocks.runRenodeRamCapture).toHaveBeenCalledWith('/images/fw.elf', {
      platform: '/custom/platform.repl',
      seconds: 5,
      identityJson: '{"class":"rtos"}',
      analysisJson: '{"arch":"arm"}',
    });
  });

  it('serves the newest completed ram-capture result or null', async () => {
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });

    mocks.listJobs.mockReturnValue([]);
    const emptyRes = await app.inject({ method: 'GET', url: '/api/images/image-1/rtos/ram-capture' });
    expect(emptyRes.json()).toEqual({ result: null });

    mocks.listJobs.mockReturnValue([
      { kind: 'rtos-ram-capture', status: 'done', resultJson: '{"captured":true,"bytesCaptured":20480}' },
      { kind: 'rtos-ram-capture', status: 'running', resultJson: null },
    ]);
    const doneRes = await app.inject({ method: 'GET', url: '/api/images/image-1/rtos/ram-capture' });
    expect(doneRes.json()).toEqual({ result: { captured: true, bytesCaptured: 20480 } });

    await app.close();
  });
});

describe('RTOS ELF symbols route', () => {
  let queuedWork: QueuedWork | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    queuedWork = undefined;
    mocks.getImage.mockReturnValue({ id: 'image-1', path: '/images/fw.elf' });
    mocks.listJobs.mockReturnValue([]);
    mocks.startJob.mockImplementation((_imageId, _kind, _params, work: QueuedWork) => {
      queuedWork = work;
      return 'elf-symbols-job';
    });
    mocks.runRtosElfSymbols.mockReturnValue({
      available: true,
      verdict: 'symbols-read',
      summary: 'Read symbols from ELF',
      symbols: [],
      prefill: {},
    });
  });

  it('returns 404 for an unknown image without creating a job', async () => {
    mocks.getImage.mockReturnValue(undefined);
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });
    const response = await app.inject({ method: 'POST', url: '/api/images/image-1/rtos/elf-symbols' });
    await app.close();
    expect(response.statusCode).toBe(404);
    expect(mocks.startJob).not.toHaveBeenCalled();
  });

  it('queues an elf-symbols job and logs summary', async () => {
    const logSpy = vi.fn();
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });
    const response = await app.inject({ method: 'POST', url: '/api/images/image-1/rtos/elf-symbols' });
    await app.close();
    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ jobId: 'elf-symbols-job' });
    expect(mocks.startJob).toHaveBeenCalledWith('image-1', 'rtos-elf-symbols', {}, expect.any(Function));

    expect(queuedWork).toBeDefined();
    if (!queuedWork) throw new Error('no job queued');
    const result = await queuedWork({ id: 'elf-symbols-job', log: logSpy });
    expect(mocks.runRtosElfSymbols).toHaveBeenCalledWith('/images/fw.elf');
    expect(logSpy).toHaveBeenCalledWith('Read symbols from ELF');
    expect(result).toMatchObject({ verdict: 'symbols-read' });
  });

  it('serves the newest completed elf-symbols result or null', async () => {
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });

    mocks.listJobs.mockReturnValue([]);
    const emptyRes = await app.inject({ method: 'GET', url: '/api/images/image-1/rtos/elf-symbols' });
    expect(emptyRes.json()).toEqual({ result: null });

    mocks.listJobs.mockReturnValue([
      { kind: 'rtos-elf-symbols', status: 'done', resultJson: '{"verdict":"symbols-read"}' },
    ]);
    const doneRes = await app.inject({ method: 'GET', url: '/api/images/image-1/rtos/elf-symbols' });
    expect(doneRes.json()).toEqual({ result: { verdict: 'symbols-read' } });

    await app.close();
  });
});

describe('RTOS base analysis route', () => {
  let queuedWork: QueuedWork | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    queuedWork = undefined;
    mocks.getImage.mockReturnValue({ id: 'image-1', path: '/images/fw.bin' });
    mocks.listJobs.mockReturnValue([]);
    mocks.startJob.mockImplementation((_imageId, _kind, _params, work: QueuedWork) => {
      queuedWork = work;
      return 'rtos-job';
    });
    mocks.runRtosAnalysis.mockReturnValue({
      isCortexM: true,
      findings: [{ id: 'f1', type: 'cortex-m-vector-table' }],
    });
  });

  it('returns 404 for an unknown image without creating a job', async () => {
    mocks.getImage.mockReturnValue(undefined);
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });
    const response = await app.inject({ method: 'POST', url: '/api/images/image-1/rtos' });
    await app.close();
    expect(response.statusCode).toBe(404);
    expect(mocks.startJob).not.toHaveBeenCalled();
  });

  it('queues an rtos analysis job and syncs findings', async () => {
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });
    const response = await app.inject({ method: 'POST', url: '/api/images/image-1/rtos' });
    await app.close();
    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ jobId: 'rtos-job' });
    expect(mocks.startJob).toHaveBeenCalledWith('image-1', 'rtos', {}, expect.any(Function));

    expect(queuedWork).toBeDefined();
    if (!queuedWork) throw new Error('no job queued');
    const result = await queuedWork({ id: 'rtos-job', log: () => undefined });
    expect(mocks.runRtosAnalysis).toHaveBeenCalledWith('/images/fw.bin');
    expect(mocks.syncFindings).toHaveBeenCalledWith('image-1', 'rtos', [{ id: 'f1', type: 'cortex-m-vector-table' }]);
    expect(result).toMatchObject({ isCortexM: true });
  });

  it('serves the newest completed rtos result or null', async () => {
    const app = Fastify();
    await app.register(rtosRoutes, { prefix: '/api' });

    mocks.listJobs.mockReturnValue([]);
    const emptyRes = await app.inject({ method: 'GET', url: '/api/images/image-1/rtos' });
    expect(emptyRes.json()).toEqual({ result: null });

    mocks.listJobs.mockReturnValue([{ kind: 'rtos', status: 'done', resultJson: '{"isCortexM":true}' }]);
    const doneRes = await app.inject({ method: 'GET', url: '/api/images/image-1/rtos' });
    expect(doneRes.json()).toEqual({ result: { isCortexM: true } });

    await app.close();
  });
});
