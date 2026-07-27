import { describe, expect, it } from 'vitest';
import { buildFwHuntFindings, parseFwHuntOutput, ruleCategory } from './fwhunt.js';

// Verbatim from a real run against Debian's OVMF_CODE.fd, 108-rule corpus, inside the tools image.
const REAL_OUTPUT = `
Scanner result IntelAlderLakeLeak (variant: default) No threat detected
Scanner result BRLY-MsiLeakBootGuardKeys (variant: default) No threat detected
Scanner result BRLY-2022-009 (variant: default) No threat detected (S3Resume2Pei)
Scanner result BRLY-2021-010 (variant: variant1) No threat detected (NvmExpressDxe)
Scanner result BRLY-2021-010 (variant: variant2) No threat detected (NvmExpressDxe)
Scanner result CVE-2023-45230 (variant: variant1) No threat detected (Dhcp6Dxe)
`.trim();

describe('parseFwHuntOutput — against the analyzer’s real output shape', () => {
  it('reads rule, variant and module out of a clean run', () => {
    const { verdicts, unreadableLines } = parseFwHuntOutput(REAL_OUTPUT);
    expect(verdicts).toHaveLength(6);
    expect(unreadableLines).toBe(0);
    expect(verdicts.every((v) => !v.matched)).toBe(true);
    expect(verdicts[2]).toMatchObject({ rule: 'BRLY-2022-009', variant: 'default', module: 'S3Resume2Pei' });
    // The same rule reports once per variant; both must survive rather than collapsing into one.
    expect(verdicts.filter((v) => v.rule === 'BRLY-2021-010').map((v) => v.variant)).toEqual(['variant1', 'variant2']);
  });

  it('recognises the trigger line as a match', () => {
    const { verdicts } = parseFwHuntOutput(
      'Scanner result Lojax-SecDxe (variant: default) FwHunt rule has been triggered and threat detected!',
    );
    expect(verdicts[0]).toMatchObject({ rule: 'Lojax-SecDxe', matched: true });
  });

  it('survives the ANSI colour click emits on a terminal', () => {
    const colored = `Scanner result [32mBlackLotusBootkit[0m (variant: default) [31mFwHunt rule has been triggered and threat detected![0m`;
    expect(parseFwHuntOutput(colored).verdicts[0]).toMatchObject({ rule: 'BlackLotusBootkit', matched: true });
  });

  it('counts an unreadable verdict as unknown rather than folding it into "nothing matched"', () => {
    const { verdicts, unreadableLines } = parseFwHuntOutput(
      'Scanner result Weird (variant: default) something the parser has never seen',
    );
    expect(verdicts).toHaveLength(0);
    expect(unreadableLines).toBe(1);
  });

  it('ignores banner and progress noise entirely', () => {
    expect(parseFwHuntOutput('loading rules...\n[*] analyzing\n').verdicts).toHaveLength(0);
  });
});

describe('ruleCategory', () => {
  it('resolves the corpus category from the rule path', () => {
    expect(ruleCategory('Threats/BlackLotusBootkit.yml')).toBe('Threats');
    expect(ruleCategory('Vulnerabilities/BRLY-2021-010.yml')).toBe('Vulnerabilities');
    expect(ruleCategory('SomethingElse/x.yml')).toBeUndefined();
  });
});

describe('buildFwHuntFindings — the denominator matters more than the numerator', () => {
  it('never returns an empty result for a clean scan, and refuses to call it "no implant"', () => {
    const { verdicts } = parseFwHuntOutput(REAL_OUTPUT);
    const drafts = buildFwHuntFindings({ verdicts, rulesInCorpus: 108 });
    expect(drafts).toHaveLength(1);
    const note = drafts[0] as (typeof drafts)[number];
    expect(note.kind).toBe('uefi-fwhunt-coverage');
    expect(note.title).toContain('not "no implant"');
    // 5 distinct rules ran out of 108 — reporting "no matches" without that ratio would present a ~5%-coverage
    // scan as a clean bill of health.
    expect(note.evidence?.rulesRun).toBe(5);
    expect(note.evidence?.rulesNotApplicable).toBe(103);
    expect(note.rationale).toContain('never applied to this image');
    expect(note.rationale).toContain('unexamined by construction');
  });

  it('attributes a match to the rule, not to FirmLab, and grades it by corpus category', () => {
    const drafts = buildFwHuntFindings({
      verdicts: [{ rule: 'BlackLotusBootkit', variant: 'default', matched: true }],
      rulePaths: { BlackLotusBootkit: 'Threats/BlackLotusBootkit.yml' },
      rulesInCorpus: 108,
    });
    const hit = drafts[0] as (typeof drafts)[number];
    expect(hit.kind).toBe('uefi-fwhunt-match');
    expect(hit.severity).toBe('critical');
    expect(hit.proofState).toBe('static_confirmed');
    expect(hit.evidence?.category).toBe('Threats');
    expect(hit.rationale).toContain("The claim here is the RULE's, not FirmLab's");
  });

  it('grades a mitigation-hygiene rule below a live-threat rule', () => {
    const drafts = buildFwHuntFindings({
      verdicts: [{ rule: 'SomeMitigation', matched: true }],
      rulePaths: { SomeMitigation: 'MitigationFailures/SomeMitigation.yml' },
    });
    expect(drafts[0]?.severity).toBe('medium');
  });

  it('reports unparsed verdicts as unknown in the coverage note', () => {
    const drafts = buildFwHuntFindings({ verdicts: [{ rule: 'A', matched: false }], unreadableLines: 3 });
    const note = drafts[drafts.length - 1] as (typeof drafts)[number];
    expect(note.evidence?.unreadableLines).toBe(3);
    expect(note.rationale).toContain('unknown rather than negative');
  });
});
