import { describe, expect, it } from 'vitest';
import type { BinAssessment } from './binvuln.js';
import type { JobHandle } from './jobs.js';
import {
  type LibraryReach,
  type LibrarySinkResult,
  MAX_ENTRY_POINTS,
  MAX_SINKS,
  buildLibraryFindings,
  buildLibrarySpec,
  buildReachFindings,
  buildSpec,
  classifyReachTarget,
  manualSource,
  noEntryPoints,
  nothingToAsk,
  parseLibraryReachOutput,
  parseReachOutput,
  pickSinks,
  runSymReach,
  summariseLibraryReach,
  unavailable,
  validateSinkNames,
} from './symreach.js';

/** The runner only ever calls `log` on its handle, and these cases return before it does. */
const silentHandle = { log: () => {} } as unknown as JobHandle;

describe('pickSinks — which questions are worth asking', () => {
  it('keeps only real unbounded-copy imports and orders them by directness', () => {
    const { asked } = pickSinks(['sprintf', 'gets', 'malloc', 'strcpy']);
    expect(asked).toEqual(['gets', 'strcpy', 'sprintf']); // malloc is not an unbounded-copy sink
  });

  it('caps the asked set and reports what was dropped rather than discarding it silently', () => {
    const { asked, dropped } = pickSinks(['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf']);
    expect(asked).toHaveLength(MAX_SINKS);
    expect(dropped).toEqual(['vsprintf', 'scanf']);
  });

  it('asks nothing when the binary imports no unbounded-copy function', () => {
    expect(pickSinks(['memcpy', 'snprintf']).asked).toEqual([]);
  });

  /**
   * Why W9's command-exec specs MUST carry `policy: 'as-given'`, pinned here because the first wiring of them did
   * not and the failure was silent-shaped. Under the default policy a command-exec sink set survives as NOTHING,
   * `runSymReach` returns `unavailable('no sink to ask about')`, and that composes a `blocked_by_platform` row
   * reading *"the deployment could not answer it"*. Measured: the WR940N's `usr/bin/httpd` came back blocked from
   * an autonomous scan minutes after the manual route proved `system` reachable in that same binary in 11 s.
   */
  it('deletes an entire command-exec question under the DEFAULT policy, which is why the caller must say', () => {
    expect(pickSinks(['system', 'popen', 'execve']).asked).toEqual([]);
    expect(pickSinks(['system', 'popen', 'execve'], 'as-given').asked).toEqual(['system', 'popen', 'execve']);
  });

  // The autonomous path is settling a W5 candidate, so it filters. The manual route is an operator asking a
  // question of their own — "is system reachable in this CGI?" is the same question, and refusing it would be the
  // prober protecting its own framing rather than answering.
  it('keeps an operator’s own sink names verbatim under the as-given policy', () => {
    const { asked } = pickSinks(['system', 'memcpy', 'doSystem'], 'as-given');
    expect(asked).toEqual(['system', 'memcpy', 'doSystem']);
  });

  it('still spends the budget on the sharpest sink first in a mixed manual list', () => {
    expect(pickSinks(['memcpy', 'gets', 'system'], 'as-given').asked).toEqual(['gets', 'memcpy', 'system']);
  });

  it('dedupes a repeated manual sink instead of asking the same question twice', () => {
    expect(pickSinks(['system', 'system', ' system '], 'as-given').asked).toEqual(['system']);
  });
});

describe('validateSinkNames — a typo is reported, never silently answered as a smaller question', () => {
  it('separates symbol names from things that are not', () => {
    const { valid, rejected } = validateSinkNames(['strcpy', 'os.execute', '', '  system ', 'rm -rf']);
    expect(valid).toEqual(['strcpy', 'system']);
    expect(rejected).toEqual(['os.execute', 'rm -rf']);
  });
});

describe('manualSource — a second question must not delete the first answer', () => {
  // Caught in in-container validation on the real DVRF_v03: `system` proven reachable in usr/sbin/generate_pin
  // disappeared from the ledger when a later probe on the same binary asked about `sprintf` instead, because
  // findings sync by source and the source was the binary alone.
  it('keys a manual probe by the question, so different sinks accumulate', () => {
    expect(manualSource('usr/sbin/generate_pin', ['system'])).not.toBe(
      manualSource('usr/sbin/generate_pin', ['sprintf']),
    );
  });

  it('re-asking the same question re-syncs rather than duplicating, whatever the order', () => {
    expect(manualSource('bin/x', ['strcpy', 'system'])).toBe(manualSource('bin/x', ['system', 'strcpy']));
  });

  it('keeps the bare per-binary key when sinks are derived — that is the question W9 asks', () => {
    expect(manualSource('bin/x', [])).toBe('symreach:bin/x');
  });
});

describe('buildSpec', () => {
  it('carries the absolute binary, the sinks and the budgets', () => {
    const spec = buildSpec('/rootfs/bin/httpd', ['strcpy'], 30);
    expect(spec.binary).toBe('/rootfs/bin/httpd');
    expect(spec.sinks).toEqual(['strcpy']);
    expect(spec.budgetSeconds).toBe(30);
    expect(spec.maxSteps).toBeGreaterThan(0);
    expect(spec.maxActive).toBeGreaterThan(0);
  });
});

describe('parseReachOutput', () => {
  it('normalizes a successful probe run', () => {
    const p = parseReachOutput({
      ok: true,
      arch: 'MIPS32',
      entry: '0x400610',
      results: [
        {
          sink: 'strcpy',
          outcome: 'reached',
          addresses: ['0x4008a0'],
          steps: 12,
          pruned: false,
          errors: 0,
          argv1: 'AAAA',
          path: ['0x400700', '0x4008a0'],
        },
      ],
    });
    expect(p.ok).toBe(true);
    expect(p.arch).toBe('MIPS32');
    expect(p.sinks[0]?.outcome).toBe('reached');
    expect(p.sinks[0]?.argv1).toBe('AAAA');
    expect(p.sinks[0]?.path).toEqual(['0x400700', '0x4008a0']);
  });

  it('reports a probe failure rather than an empty success', () => {
    expect(parseReachOutput({ ok: false, error: 'angr not importable' })).toMatchObject({
      ok: false,
      error: 'angr not importable',
    });
    expect(parseReachOutput(null).ok).toBe(false);
  });

  it('treats an unrecognised outcome as inconclusive, never as a clean sink', () => {
    const p = parseReachOutput({ ok: true, results: [{ sink: 'gets', outcome: 'weird' }] });
    expect(p.sinks[0]?.outcome).toBe('not_reached_in_budget');
    expect(p.sinks[0]?.reason).toContain('unrecognised');
  });
});

describe('buildReachFindings — the honesty contract', () => {
  it('a reached sink is static_confirmed and phrased as reachability, not exploitability', () => {
    const drafts = buildReachFindings('bin/pwn', [
      {
        sink: 'strcpy',
        outcome: 'reached',
        addresses: ['0x4008a0'],
        steps: 9,
        pruned: false,
        errors: 0,
        argv1: 'AAAA',
      },
    ]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('sink-reachable');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(drafts[0]?.evidence?.concreteInput).toContain('AAAA');
    expect(drafts[0]?.rationale).toContain('not exploitability');
  });

  it('an exhausted budget stays needs_runtime_reproduction and is never called unreachable', () => {
    const drafts = buildReachFindings('bin/pwn', [
      {
        sink: 'gets',
        outcome: 'not_reached_in_budget',
        addresses: ['0x400900'],
        steps: 400,
        pruned: true,
        errors: 0,
        reason: 'step budget (400 steps) reached',
      },
    ]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('sink-reachability-inconclusive');
    expect(drafts[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(drafts[0]?.rationale).toContain('NOT evidence they are unreachable');
    expect(drafts[0]?.evidence?.statesPruned).toBe(true);
  });

  it('attributes angr-internal crashes to the tool, not to the firmware', () => {
    // angr 9.2's sscanf SimProcedure raises a raw TypeError on a symbolic position. Those are paths never walked,
    // and the report must say so rather than let a reader infer the binary is quiet.
    const drafts = buildReachFindings('usr/sbin/bpalogin', [
      {
        sink: 'strcpy',
        outcome: 'not_reached_in_budget',
        addresses: ['0x5000c0'],
        steps: 40,
        pruned: false,
        errors: 13,
        reason: 'angr-internal errors dominated the search (13)',
      },
    ]);
    expect(drafts[0]?.title).not.toContain('budget ran out');
    expect(drafts[0]?.evidence?.toolErrors).toBe(13);
    expect(drafts[0]?.rationale).toContain('lost to angr-internal errors');
    expect(drafts[0]?.proofState).toBe('needs_runtime_reproduction');
  });

  it('a sink whose symbol is absent produces no claim at all', () => {
    const drafts = buildReachFindings('bin/pwn', [
      {
        sink: 'gets',
        outcome: 'absent',
        addresses: [],
        steps: 0,
        pruned: false,
        errors: 0,
        reason: 'no PLT/symbol address',
      },
    ]);
    expect(drafts).toEqual([]);
  });

  it('mixes a confirmed reachability with an inconclusive note in one run', () => {
    const drafts = buildReachFindings('bin/pwn', [
      { sink: 'strcpy', outcome: 'reached', addresses: ['0x1'], steps: 5, pruned: false, errors: 0 },
      { sink: 'gets', outcome: 'not_reached_in_budget', addresses: ['0x2'], steps: 400, pruned: false, errors: 0 },
    ]);
    expect(drafts.map((d) => d.kind)).toEqual(['sink-reachable', 'sink-reachability-inconclusive']);
  });
});

/**
 * The conflation `a20f2850` paid for, pinned at the constructor.
 *
 * That commit fixed the CALLER — W9 now says `as-given` for a command-exec question — and left the provider still
 * willing to blame the deployment for anything at all that went wrong. `blocked_by_platform` means *"the question
 * was asked and this deployment could not answer it"*, and a row saying that is read as a real limit: it is
 * counted by coverage, composed into the narrative, and outlives the caller that produced it. A malformed request
 * is not that, and `dynprobe-run.ts` had already drawn the same line one provider earlier.
 */
describe('unavailable — a caller error must not be reported as a capability limit', () => {
  it('writes NO finding when the question could not be posed', () => {
    const r = unavailable('usr/bin/httpd', "the 'unsafe-copy' policy kept none of the 3 name(s) requested", 'request');
    expect(r.available).toBe(false);
    expect(r.blockedBy).toBe('request');
    // The whole fix: nothing reaches the ledger. The reason still travels on the result.
    expect(r.findings).toEqual([]);
    expect(r.reason).toContain('unsafe-copy');
  });

  it('still records a genuine platform limit, because absence of a tool is not absence of a problem', () => {
    const r = unavailable('usr/bin/httpd', 'angr not installed in this deployment');
    expect(r.blockedBy).toBe('platform');
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]?.kind).toBe('sink-reachability-blocked');
    expect(r.findings[0]?.proofState).toBe('blocked_by_platform');
    expect(r.findings[0]?.rationale).toContain('missing capability');
  });

  it('separates a broken attempt from a missing capability, since only one is worth retrying', () => {
    const r = unavailable('usr/bin/httpd', 'angr probe produced no output', 'harness');
    expect(r.blockedBy).toBe('harness');
    // Both keep `blocked_by_platform` — the vocabulary has no third state and inventing one here would be worse.
    expect(r.findings[0]?.proofState).toBe('blocked_by_platform');
    expect(r.findings[0]?.rationale).toContain('retry may');
  });

  it('refuses a run with no rootfs as a request defect, not as something this deployment cannot do', async () => {
    const r = await runSymReach(null, 'usr/bin/httpd', ['strcpy'], silentHandle);
    expect(r.blockedBy).toBe('request');
    expect(r.findings).toEqual([]);
  });
});

describe('nothingToAsk — a binary with no unbounded-copy symbol is ANSWERED, not blocked', () => {
  const assess = (over: Partial<BinAssessment> = {}): BinAssessment => ({
    path: 'usr/sbin/tiny',
    size: 4096,
    runnable: true,
    unsafeCopy: [],
    cmdExec: [],
    hasCanary: true,
    symbolSource: 'dynsym',
    ...over,
  });

  it('is a bounded negative about the bytes, and says what it does not cover', () => {
    const r = nothingToAsk('usr/sbin/tiny', assess());
    expect(r.available).toBe(true);
    expect(r.asked).toEqual([]);
    const d = r.findings[0];
    expect(d?.kind).toBe('sink-reachability-not-applicable');
    expect(d?.proofState).toBe('static_confirmed');
    // The claim is about symbols, and the row has to say so itself — an inlined copy leaves nothing to read.
    expect(d?.rationale).toContain('does NOT say the binary contains no unbounded copy');
    expect(d?.rationale).toContain('inlined');
  });

  it('names the weaker evidence when there was no symbol table to read', () => {
    const r = nothingToAsk('usr/sbin/tiny', assess({ symbolSource: 'strings' }));
    expect(r.reason).toContain('printable-string superset');
    expect(r.findings[0]?.evidence).toMatchObject({ symbolSource: 'strings' });
  });

  it('points at the sinks the binary DOES name, so the answer is not read as "uninteresting"', () => {
    const r = nothingToAsk('usr/sbin/tiny', assess({ cmdExec: ['system', 'popen'] }));
    expect(r.findings[0]?.rationale).toContain('system, popen');
  });
});

/* ---------------------------------------------------------------------------------------------------------- *
 * The library rung. Three things are pinned here: that a shared object is asked from its EXPORTS instead of from
 * an entry point it does not have, that the weaker claim that produces is never dressed up as the stronger one,
 * and that an executable comes out of every path unchanged.
 * ---------------------------------------------------------------------------------------------------------- */

/** Minimal ELF32 with a chosen e_type, program headers and dynamic tags — the shape `binvuln` is tested on too. */
const elf = (type: number, phTypes: number[], dynTags: number[] = [], little = true): Uint8Array => {
  const PH_OFF = 0x40;
  const PH_ENT = 32;
  const DYN_OFF = PH_OFF + PH_ENT * Math.max(1, phTypes.length);
  const dynSize = (dynTags.length + 1) * 8;
  const buf = Buffer.alloc(DYN_OFF + dynSize);
  const u16 = little ? buf.writeUInt16LE.bind(buf) : buf.writeUInt16BE.bind(buf);
  const u32 = little ? buf.writeUInt32LE.bind(buf) : buf.writeUInt32BE.bind(buf);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 1, little ? 1 : 2], 0);
  u16(type, 0x10);
  u32(PH_OFF, 0x1c);
  u16(PH_ENT, 0x2a);
  u16(phTypes.length, 0x2c);
  phTypes.forEach((t, i) => {
    const ph = PH_OFF + i * PH_ENT;
    u32(t, ph);
    if (t === 2) {
      u32(DYN_OFF, ph + 0x04);
      u32(dynSize, ph + 0x10);
    }
  });
  dynTags.forEach((tag, i) => u32(tag, DYN_OFF + i * 8));
  return buf;
};

const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PT_INTERP = 3;
const DT_NEEDED = 1;
const DT_SONAME = 14;

describe('classifyReachTarget — which question this object can even be asked', () => {
  it('leaves an executable on the entry-point rung', () => {
    expect(classifyReachTarget(elf(2, [PT_LOAD]))).toBe('executable');
  });

  it('routes an ET_DYN with a SONAME to the library rung, interpreter or not', () => {
    // The corpus shape that forced this: uClibc builds libc WITH an interpreter so it can print its banner.
    expect(classifyReachTarget(elf(3, [PT_LOAD, PT_INTERP, PT_DYNAMIC], [DT_SONAME]))).toBe('library');
    expect(classifyReachTarget(elf(3, [PT_LOAD, PT_DYNAMIC], [DT_NEEDED], false))).toBe('library');
  });

  it('leaves a PIE on the entry-point rung — ET_DYN, an interpreter, and no link-time name of its own', () => {
    expect(classifyReachTarget(elf(3, [PT_LOAD, PT_INTERP, PT_DYNAMIC], [DT_NEEDED, 5]))).toBe('executable');
  });

  /**
   * `isRunnableElf` answers `false` for a file it cannot PARSE, so deferring the whole decision to it would route
   * every truncated executable into a rung that asks a library's question about it. e_type is read first for
   * exactly this, and a `.ko` (ET_REL) stays where it was — the `exportreach` route owns that target.
   */
  it('never routes a non-ET_DYN object to the library rung, however broken its headers are', () => {
    const truncated = elf(2, [PT_LOAD]);
    truncated.set([0xff, 0xff], 0x2c); // e_phnum lies: nothing below the header can be parsed
    expect(classifyReachTarget(truncated)).toBe('executable');
    expect(classifyReachTarget(elf(1, [PT_LOAD]))).toBe('executable'); // ET_REL — a .ko
  });

  it('reports something that is not an ELF as such, rather than guessing a rung', () => {
    expect(classifyReachTarget(Buffer.alloc(128, 0x41))).toBe('not-elf');
    expect(classifyReachTarget(Buffer.alloc(8, 0x7f))).toBe('not-elf');
  });
});

describe('buildLibrarySpec — the same prover, told where to start', () => {
  it('asks the probe for the export-start mode and bounds how many exports it may start from', () => {
    const spec = buildLibrarySpec('/rootfs/lib/libfoo.so', ['strcpy'], 120);
    expect(spec.mode).toBe('library');
    expect(spec.maxEntryPoints).toBe(MAX_ENTRY_POINTS);
    expect(spec.budgetSeconds).toBe(120);
    expect(spec.sinks).toEqual(['strcpy']);
  });

  it('leaves the executable spec exactly as it was — no mode, no export cap', () => {
    const spec = buildSpec('/rootfs/usr/bin/httpd', ['strcpy'], 120);
    expect(spec).not.toHaveProperty('mode');
    expect(spec).not.toHaveProperty('maxEntryPoints');
  });
});

describe('parseLibraryReachOutput', () => {
  it('normalizes a run, keeping the export accounting beside each outcome', () => {
    const parsed = parseLibraryReachOutput({
      ok: true,
      arch: 'MIPS32',
      mode: 'library',
      entryPointsTotal: 118,
      entryPointsConsidered: 16,
      maxEntryPoints: 16,
      entryPointSource: 'dynsym-export',
      entryPointsNamed: ['pwd_read', 'pwd_write'],
      results: [
        {
          sink: 'strcpy',
          outcome: 'reached',
          addresses: ['0x400a10'],
          reachedFrom: 'pwd_read',
          entryPointsAttempted: 2,
          entryPointsCompleted: 1,
          steps: 61,
          pruned: false,
          errors: 0,
          path: ['0x400900', '0x400a10'],
        },
      ],
    });
    expect(parsed.ok).toBe(true);
    expect(parsed.arch).toBe('MIPS32');
    expect(parsed.library?.entryPointsTotal).toBe(118);
    expect(parsed.library?.entryPointsConsidered).toBe(16);
    expect(parsed.library?.entryPointSource).toBe('dynsym-export');
    expect(parsed.library?.sinks[0]?.reachedFrom).toBe('pwd_read');
    expect(parsed.library?.sinks[0]?.entryPointsAttempted).toBe(2);
  });

  it('treats an unrecognised outcome as inconclusive, never as a clean sink', () => {
    const parsed = parseLibraryReachOutput({ ok: true, entryPointsTotal: 3, results: [{ sink: 'gets', outcome: '' }] });
    expect(parsed.library?.sinks[0]?.outcome).toBe('not_reached_in_budget');
    expect(parsed.library?.sinks[0]?.reason).toContain('inconclusive');
  });

  it('reads a missing export count as zero, which is the blocked path and not an answered one', () => {
    const parsed = parseLibraryReachOutput({ ok: true, results: [] });
    expect(parsed.library?.entryPointsTotal).toBe(0);
  });

  it('reports a probe failure rather than an empty success', () => {
    expect(parseLibraryReachOutput({ ok: false, error: 'could not load the object' }).ok).toBe(false);
    expect(parseLibraryReachOutput('not json').ok).toBe(false);
  });
});

describe('buildLibraryFindings — a path from an export is a lead, not a proof of reachability from input', () => {
  const sink = (over: Partial<LibrarySinkResult> = {}): LibrarySinkResult => ({
    sink: 'strcpy',
    outcome: 'reached',
    addresses: ['0x400a10'],
    entryPointsAttempted: 2,
    entryPointsCompleted: 1,
    steps: 61,
    pruned: false,
    errors: 0,
    ...over,
  });
  const lib = (sinks: LibrarySinkResult[], over: Partial<LibraryReach> = {}): LibraryReach => ({
    entryPointsTotal: 118,
    entryPointsConsidered: 16,
    maxEntryPoints: 16,
    budgetSeconds: 90,
    sinks,
    ...over,
  });

  /**
   * The line the whole rung turns on. An export's arguments are unconstrained, so a satisfiable path from one is
   * strictly weaker than a path from program input — `static_confirmed` here would claim reachability nobody
   * proved, and the `exportreach` lane's control-flow row would then look like the same fact twice.
   */
  it('files a reached sink as needs_runtime_reproduction and says why it is not confirmed', () => {
    const drafts = buildLibraryFindings('lib/libfoo.so', lib([sink({ reachedFrom: 'pwd_read' })]));
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('library-sink-reachable');
    expect(drafts[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(drafts[0]?.evidenceChannel).toBe('symbolic_execution');
    expect(drafts[0]?.title).toContain('pwd_read');
    expect(drafts[0]?.rationale).toMatch(/UNCONSTRAINED/);
    expect(drafts[0]?.rationale).toMatch(/stronger than a control-flow route/);
  });

  it('ranks a command-exec sink above an unbounded copy, the axis that does move', () => {
    const exec = buildLibraryFindings('lib/libfoo.so', lib([sink({ sink: 'system', reachedFrom: 'do_cmd' })]));
    expect(exec[0]?.severity).toBe('high');
    expect(buildLibraryFindings('lib/libfoo.so', lib([sink()]))[0]?.severity).toBe('medium');
  });

  it('never calls an unreached sink unreachable, and names both bounds it ran into', () => {
    const drafts = buildLibraryFindings(
      'lib/libfoo.so',
      lib([
        sink({ outcome: 'not_reached_in_budget', entryPointsAttempted: 4, entryPointsCompleted: 1, errors: 2 }),
        sink({ sink: 'gets', outcome: 'skipped', entryPointsAttempted: 0, entryPointsCompleted: 0, reason: 'budget' }),
      ]),
    );
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('library-sink-reachability-inconclusive');
    expect(drafts[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(drafts[0]?.rationale).toMatch(/None of that is evidence the sinks are unreachable/);
    // Attempted vs completed, and the exports never started from at all: the silence has to be readable.
    const ev = drafts[0]?.evidence as Record<string, number>;
    expect(ev.entryPointSearchesAttempted).toBe(4);
    expect(ev.entryPointSearchesCompleted).toBe(1);
    expect(ev.entryPointsNotConsidered).toBe(102);
    expect(ev.toolErrors).toBe(2);
    expect(drafts[0]?.rationale).toContain('102');
  });

  it('says nothing at all about a sink the object does not import', () => {
    expect(buildLibraryFindings('lib/libfoo.so', lib([sink({ outcome: 'absent' })]))).toEqual([]);
  });

  it('mixes one reached lead with the note for the rest, in one run', () => {
    const drafts = buildLibraryFindings(
      'lib/libfoo.so',
      lib([sink({ reachedFrom: 'pwd_read' }), sink({ sink: 'sprintf', outcome: 'not_reached_in_budget' })]),
    );
    expect(drafts.map((d) => d.kind)).toEqual(['library-sink-reachable', 'library-sink-reachability-inconclusive']);
    // The rung never reaches the entry-point rung's proof state, whatever it found.
    expect(drafts.some((d) => d.proofState === 'static_confirmed')).toBe(false);
  });
});

describe('summariseLibraryReach — the export cap is a bound, so it is in the sentence', () => {
  it('names the exports considered, the ones never started from, and what a miss does not mean', () => {
    const text = summariseLibraryReach('lib/libc.so.0', {
      entryPointsTotal: 1600,
      entryPointsConsidered: 16,
      maxEntryPoints: 16,
      budgetSeconds: 90,
      sinks: [
        {
          sink: 'strcpy',
          outcome: 'not_reached_in_budget',
          addresses: [],
          entryPointsAttempted: 16,
          entryPointsCompleted: 0,
          steps: 400,
          pruned: true,
          errors: 0,
        },
      ],
    });
    expect(text).toContain('16 of its 1600');
    expect(text).toContain('1584 were never started from');
    expect(text).toMatch(/inconclusive rather than unreachable/);
  });

  it('says so plainly when every export was considered', () => {
    const text = summariseLibraryReach('lib/libfoo.so', {
      entryPointsTotal: 9,
      entryPointsConsidered: 9,
      maxEntryPoints: 16,
      budgetSeconds: 90,
      sinks: [],
    });
    expect(text).toContain('all 9 of its exported entry point(s)');
  });
});

describe('noEntryPoints — nowhere to ask from is not a library with nothing in it', () => {
  it('blocks rather than answering, and writes the row that keeps the silence visible', () => {
    const r = noEntryPoints('lib/libstripped.so', {
      entryPointsTotal: 0,
      entryPointsConsidered: 0,
      maxEntryPoints: MAX_ENTRY_POINTS,
      budgetSeconds: 90,
      sinks: [],
    });
    expect(r.available).toBe(false);
    expect(r.blockedBy).toBe('platform');
    expect(r.mode).toBe('library');
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]?.proofState).toBe('blocked_by_platform');
    expect(r.reason).toMatch(/not a library free of reachable sinks/);
  });
});
