/**
 * The numbers in these fixtures are the corpus's, not invented: `NetUSB.ko` really does recover 340 functions
 * with 228 entry points and 17 functions calling `__kmalloc`, and the WR940N's libraries really do come back
 * with a graph of zero functions.
 */
import { describe, expect, it } from 'vitest';
import {
  type ExportReachResult,
  KERNEL_SINKS,
  USERLAND_SINKS,
  buildExportReachFindings,
  sinkSeverity,
  sinksFor,
  summarise,
} from './exportreach.js';

const base = (o: Partial<ExportReachResult> = {}): ExportReachResult => ({
  available: true,
  reason: '',
  arch: 'MIPS32',
  functionsRecovered: 340,
  entryPoints: 228,
  sinks: [],
  findings: [],
  ...o,
});

describe('sink vocabulary', () => {
  it('asks a kernel module kernel questions and a library userland ones', () => {
    // A `.ko` never calls system(3) and a `.so` never calls __kmalloc; asking the wrong set costs nothing but
    // makes the result read as though the question applied.
    expect(sinksFor('lib/modules/2.6.31/nas/NetUSB.ko')).toBe(KERNEL_SINKS);
    expect(sinksFor('usr/lib/liblvhsr.so')).toBe(USERLAND_SINKS);
    expect(sinksFor('lib/modules/2.6.31/nas/NetUSB.ko')).toContain('__kmalloc');
    expect(sinksFor('usr/lib/liblvhsr.so')).toContain('system');
  });

  it('ranks a command-exec sink above an unbounded copy above a plain allocation', () => {
    expect(sinkSeverity('system')).toBe('high');
    expect(sinkSeverity('strcpy')).toBe('medium');
    expect(sinkSeverity('__kmalloc')).toBe('low');
  });
});

describe('findings', () => {
  it('files a reachable sink as a lead, and says why it is weaker than symbolic reachability', () => {
    const r = base({
      sinks: [
        {
          sink: '__kmalloc',
          outcome: 'reachable',
          holders: 17,
          reachableFrom: 37,
          entryPointsNamed: ['KTCP_stop', 'run_init_sbus', 'dumpUsbAllDesc'],
          namedTruncated: 0,
        },
      ],
    });
    const f = buildExportReachFindings('lib/modules/2.6.31/nas/NetUSB.ko', r);
    expect(f).toHaveLength(1);
    const row = f[0];
    expect(row?.proofState).toBe('needs_runtime_reproduction');
    expect(row?.kind).toBe('export-reachable-sink');
    // The distinction from `symreach` has to be IN the row, not only in a doc comment.
    expect(row?.rationale).toContain('branch conditions along the path can be satisfied');
    expect(row?.rationale).toContain('37 of this kernel module');
    expect(row?.evidence?.reachableFromEntryPoints).toBe(37);
  });

  it('files ONE row per sink, never one per entry point', () => {
    // Forty exports all reaching strcpy is one fact about the library.
    const r = base({
      sinks: [
        {
          sink: 'strcpy',
          outcome: 'reachable',
          holders: 3,
          reachableFrom: 40,
          entryPointsNamed: Array.from({ length: 40 }, (_, i) => `fn_${i}`),
          namedTruncated: 0,
        },
      ],
    });
    expect(buildExportReachFindings('usr/lib/x.so', r)).toHaveLength(1);
  });

  it('reports an empty graph as blocked, never as a clean object', () => {
    // The WR940N's 64 libraries all land here. Silent, they would look exactly like libraries that were
    // analysed and found clean.
    const f = buildExportReachFindings(
      'lib/libuClibc-0.9.30.so',
      base({ outcome: 'no_functions_recovered', functionsRecovered: 0, entryPoints: 0 }),
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.proofState).toBe('blocked_by_platform');
    expect(f[0]?.rationale).toContain('NOT a statement that the object is free of reachable sinks');
  });

  it('writes no row for a sink that was not reached, and no row for an absent one', () => {
    const f = buildExportReachFindings(
      'usr/lib/x.so',
      base({
        sinks: [
          { sink: 'system', outcome: 'not_reached', holders: 2, reachableFrom: 0 },
          { sink: 'strcpy', outcome: 'absent', holders: 0 },
        ],
      }),
    );
    expect(f).toHaveLength(0);
  });
});

describe('summarise', () => {
  it('says a sink not reached is not a sink that cannot be reached', () => {
    const s = summarise('usr/lib/x.so', {
      available: true,
      functionsRecovered: 761,
      entryPoints: 12,
      sinks: [
        { sink: 'memcpy', outcome: 'reachable', holders: 1, reachableFrom: 1 },
        { sink: 'system', outcome: 'not_reached', holders: 1, reachableFrom: 0 },
        { sink: 'strcpy', outcome: 'absent' },
      ],
    });
    expect(s).toContain('761 function(s) recovered');
    expect(s).toContain('1 sink(s) reachable');
    expect(s).toContain('indirect calls are unresolved');
  });

  it('calls an empty graph a failure to analyse in the summary too', () => {
    const s = summarise('lib/libuClibc-0.9.30.so', {
      available: true,
      outcome: 'no_functions_recovered',
      functionsRecovered: 0,
      sinks: [],
    });
    expect(s).toContain('failure to analyse, not a clean result');
  });
});
