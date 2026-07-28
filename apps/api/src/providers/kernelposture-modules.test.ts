import { describe, expect, it } from 'vitest';
import { assessModuleProvenance, moduleProvenanceFindings, parseModinfo } from './kernelposture.js';

const mod = (file: string, modinfo: string) => ({ file, facts: parseModinfo(modinfo) });

const evidence = (versionDir: string, provenance: ReturnType<typeof assessModuleProvenance>, inspected: number) => ({
  versionDir,
  vermagic: null,
  moduleCount: inspected,
  signedCount: 0,
  inspectedCount: inspected,
  provenance,
});

describe('parseModinfo', () => {
  it('reads intree, licence and name out of real .modinfo bytes', () => {
    // The shape a .modinfo section actually has, taken from the GL.iNet BE3600's own ath_pktlog.ko.
    // Fields in a real .modinfo section are NUL-separated, not space-separated. The first fixture here used
    // spaces and hid a real defect: the licence regex ran to the next unprintable byte, so it swallowed
    // `vermagic=...` too — and it would have truncated nothing, which is why only realistic bytes caught it.
    const NUL = '\u0000';
    expect(
      parseModinfo(`name=ath_pktlog${NUL}license=Proprietary${NUL}vermagic=5.4.213 SMP preempt aarch64${NUL}`),
    ).toEqual({ license: 'Proprietary', name: 'ath_pktlog' });
    expect(parseModinfo(`intree=Y${NUL}name=nf_nat${NUL}license=GPL${NUL}`)).toEqual({
      intree: true,
      license: 'GPL',
      name: 'nf_nat',
    });
    // A licence containing a space must survive whole — stopping at whitespace would have split this one.
    expect(parseModinfo(`license=Dual BSD/GPL${NUL}name=a${NUL}`).license).toBe('Dual BSD/GPL');
  });

  it('says nothing rather than guessing when the module is stripped of modinfo', () => {
    expect(parseModinfo('no keys here at all')).toEqual({});
  });
});

describe('assessModuleProvenance', () => {
  it('calls every module indeterminate when the build emits no intree tag at all', () => {
    // A 2.6.22-era build predates the tag. Deciding "all out-of-tree" there would be exactly the recall-based
    // claim this codebase refuses to make elsewhere; the rule calibrates from the set, not from a remembered
    // kernel version.
    const p = assessModuleProvenance([mod('ipt_REJECT', 'license=GPL\u0000'), mod('ath', 'license=GPL\u0000')]);
    expect(p.tagUnused).toBe(true);
    expect(p.indeterminate).toBe(2);
    expect(p.outOfTree).toBe(0);
    expect(p.inTree).toBe(0);
  });

  it('separates in-tree from out-of-tree once the tag IS in use', () => {
    const p = assessModuleProvenance([
      mod('nf_nat', 'intree=Y\u0000license=GPL\u0000name=nf_nat\u0000'),
      mod('ecm', 'license=GPL\u0000name=ecm\u0000'),
      mod('ath_pktlog', 'license=Proprietary\u0000name=ath_pktlog\u0000'),
    ]);
    expect(p.tagUnused).toBe(false);
    expect(p.inTree).toBe(1);
    expect(p.outOfTree).toBe(2);
    expect(p.outOfTreeNames).toEqual(['ecm', 'ath_pktlog']);
    expect(p.proprietary).toEqual(['ath_pktlog (Proprietary)']);
  });

  it('does not call a GPL-compatible licence proprietary', () => {
    const p = assessModuleProvenance([
      mod('a', 'intree=Y\u0000license=Dual BSD/GPL\u0000'),
      mod('b', 'intree=Y\u0000license=GPL v2\u0000'),
      mod('c', 'intree=Y\u0000license=MIT\u0000'),
    ]);
    expect(p.proprietary).toEqual([]);
  });
});

describe('moduleProvenanceFindings', () => {
  it('yields the honest non-answer when the tag is unused, not a zero that reads as a measurement', () => {
    const p = assessModuleProvenance([mod('ath', 'license=GPL\u0000')]);
    const f = moduleProvenanceFindings(evidence('2.6.22', p, 1));
    expect(f).toHaveLength(1);
    expect(f[0]?.proofState).toBe('blocked_by_platform');
    expect(f[0]?.rationale).toMatch(/NOTHING is decided either way/);
  });

  it('claims attack surface, never defects', () => {
    const p = assessModuleProvenance([
      mod('nf_nat', 'intree=Y\u0000license=GPL\u0000'),
      mod('ecm', 'license=GPL\u0000name=ecm\u0000'),
    ]);
    const f = moduleProvenanceFindings(evidence('5.4.213', p, 2));
    const oot = f.find((d) => d.kind === 'kernel-out-of-tree-modules');
    expect(oot?.proofState).toBe('static_confirmed');
    expect(oot?.rationale).toMatch(/nothing here opened a module and looked for a defect/i);
    expect(oot?.title).not.toMatch(/vulnerab/i);
  });

  it('says nothing at all when there is no module evidence to speak from', () => {
    expect(moduleProvenanceFindings(null)).toEqual([]);
  });
});
