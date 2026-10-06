/**
 * The probe classifier, tested on the three shapes it must tell apart. The fixtures below are hand-built error
 * objects, which is exactly how `parseGdbOutput` was once wrong — written from the same assumption as the code.
 * `scripts/probe-shapes.mjs` therefore drives REAL `execFile` failures through this same function: these tests pin
 * the contract, that script proves the shapes are the ones Node actually throws.
 */
import { describe, expect, it } from 'vitest';
import { RENODE_REFUSING_PROXY } from './providers/renode-offline.js';
import { OFFLINE_ANCHORE_ENV, TOOL_IDS, classifyProbeFailure, probeEnv, toolSpec } from './tools.js';

describe('classifyProbeFailure', () => {
  // Three facts one `available: false` used to cover. Getting `timeout` wrong is the expensive one: it sends every
  // provider needing that tool to `blocked_by_platform`, which reads as "this deployment cannot", not "it was slow".
  it('calls a binary that is not on PATH missing', () => {
    expect(classifyProbeFailure(Object.assign(new Error('spawn ghidra ENOENT'), { code: 'ENOENT' }))).toBe('missing');
  });

  it('calls a probe Node killed on its timeout a timeout, not a missing tool', () => {
    // This is the shape `execFile` produces on `timeout`: it kills the child, so `killed` is set and `code` is not.
    expect(classifyProbeFailure(Object.assign(new Error('timeout'), { killed: true, signal: 'SIGTERM' }))).toBe(
      'timeout',
    );
    expect(classifyProbeFailure({ signal: 'SIGKILL' })).toBe('timeout');
  });

  it('calls a non-zero exit an error — the tool is there and refused', () => {
    expect(classifyProbeFailure(Object.assign(new Error('exit 1'), { code: 1, killed: false }))).toBe('error');
  });

  // Conservative on a shape it does not know: `error` claims the tool is present, `missing` would claim it is not,
  // and inventing an absence is the one answer that costs a capability the deployment actually has.
  it('falls back to error rather than inventing an absence', () => {
    expect(classifyProbeFailure(new Error('something else'))).toBe('error');
    expect(classifyProbeFailure(null)).toBe('error');
    expect(classifyProbeFailure(undefined)).toBe('error');
  });
});

describe('probeEnv', () => {
  const base = { PATH: '/usr/bin', HTTPS_PROXY: 'http://corp:3128', NO_PROXY: '*', no_proxy: '.antmicro.com' };

  // The boot runs were already offline; the probe was the one renode invocation that inherited the operator's
  // proxies, bypass list included. Read through the real table, so dropping the hook from the spec fails here.
  it('runs the renode probe under the same offline env as its boot runs', () => {
    const spec = toolSpec('renode');
    expect(spec?.probeEnv).toBeDefined();
    const env = probeEnv(spec ?? {}, base);
    expect(env.HTTPS_PROXY).toBe(RENODE_REFUSING_PROXY);
    expect(env.https_proxy).toBe(RENODE_REFUSING_PROXY);
    expect(env.NO_PROXY).toBeUndefined();
    expect(env.no_proxy).toBeUndefined();
    for (const [k, v] of Object.entries(OFFLINE_ANCHORE_ENV)) expect(env[k]).toBe(v);
    expect(env.PATH).toBe('/usr/bin');
  });

  it('keeps every other probe on the shared anchore baseline, proxies untouched', () => {
    for (const id of TOOL_IDS.filter((t) => t !== 'renode')) {
      const env = probeEnv(toolSpec(id) ?? {}, base);
      for (const [k, v] of Object.entries(OFFLINE_ANCHORE_ENV)) expect(env[k]).toBe(v);
      expect(env.HTTPS_PROXY).toBe('http://corp:3128');
      expect(env.NO_PROXY).toBe('*');
    }
  });

  it('does not mutate the environment it is given', () => {
    const copy = { ...base };
    probeEnv(toolSpec('renode') ?? {}, copy);
    expect(copy).toEqual(base);
  });
});
