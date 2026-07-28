import { describe, expect, it } from 'vitest';
import {
  type CarvedModule,
  type CorpusRule,
  type ModulePass,
  buildFwHuntFindings,
  classifyModulePrivilege,
  describeCarvedModule,
  parseFwHuntOutput,
  parseRuleMeta,
  rankModulesForScan,
  ruleCategory,
  selectModuleRules,
} from './fwhunt.js';

// Verbatim from a real `scan-firmware` run against the OVMF build shipped with this deployment's QEMU
// (edk2-x86_64-code.fd), 108-rule corpus, inside the tools image. 17 rules ran; they touched 6 of 125 modules.
const REAL_OUTPUT = `
Scanner result IntelAlderLakeLeak (variant: default) No threat detected
Scanner result BRLY-MsiLeakBootGuardKeys (variant: default) No threat detected
Scanner result BRLY-2022-009 (variant: default) No threat detected (S3Resume2Pei)
Scanner result BRLY-2021-010 (variant: variant1) No threat detected (NvmExpressDxe)
Scanner result BRLY-2021-010 (variant: variant2) No threat detected (NvmExpressDxe)
Scanner result CVE-2023-45230 (variant: variant1) No threat detected (Dhcp6Dxe)
`.trim();

// Verbatim from a real `scan-module` run against one carved module. Both interpolations carry the delimiters:
// the rule name has a space AND parentheses, the variant label has parentheses, and the trailer is the path we
// passed rather than a bare module name.
const REAL_MODULE_OUTPUT = `
Scanner result BlackLotusBootkit (variant: lightweight scan) No threat detected (mods/VariableRuntimeDxe-cbd2e4d5-7068-4ff5-b462-9822b4ad8d60.dxe)
Scanner result BRLY-2022-028 (RsbStuffingCheck) (variant: informational (the patch from EDK2 is missing)) FwHunt rule has been triggered and threat detected! (mods/VariableRuntimeDxe-cbd2e4d5-7068-4ff5-b462-9822b4ad8d60.dxe)
Scanner result BRLY-2022-028 (RsbStuffingCheck) (variant: vulnerability (RSB Stuffing before RSM skipped in SMI Entry code)) No threat detected (mods/VariableRuntimeDxe-cbd2e4d5-7068-4ff5-b462-9822b4ad8d60.dxe)
`.trim();

// The head of a real corpus rule — the one whose printed name is not its filename and whose variant labels are
// prose. Indentation is load-bearing: `parseRuleMeta` reads the `meta:` block by it.
const REAL_RULE_YAML = `RsbStuffingCheck:
  meta:
    author: Binarly (https://github.com/binarly-io/FwHunt)
    license: CC0-1.0
    name: BRLY-2022-028 (RsbStuffingCheck)
    namespace: MitigationFailures
    description: Check if StuffRsb used before RSM
    url: https://binarly.io/posts/FirmwareBleed
    volume guids:
      - a3ff0ef5-0c28-42f5-b544-8c7de1e80014
      - 7a9354d9-0468-444a-81ce-0bf617d890df
  variants:
    informational (the patch from EDK2 is missing):
      hex_strings:
        not-any:
          - f3900faee8eb..48ffc875..4881c4........0faa
`;

function carved(name: string): CarvedModule {
  return { path: `/tmp/mods/${name}.dxe`, name };
}

/** A rule as the corpus reader hands it over: `name` and `path` carry the module label. */
function rule(name: string, rulePath = `Threats/${name}.yml`): CorpusRule {
  return { path: rulePath, name, volumeGuids: 0 };
}

/**
 * A rule that names a module only in its prose. `CVE-2023-45230` is the real one: it says `Dhcp6Dxe` in its
 * description and in neither its `meta.name` nor its filename.
 */
function describedRule(name: string, description: string): CorpusRule {
  return { path: `Vulnerabilities/${name}.yml`, name, description, volumeGuids: 0 };
}

function modulePassFixture(over: Partial<ModulePass> = {}): ModulePass {
  return {
    ran: true,
    reason: '',
    verdicts: [],
    unreadableLines: 0,
    modulesCarved: 125,
    modulesScanned: [carved('SecMain'), carved('BdsDxe')],
    modulesSkipped: [],
    modulesFailed: [],
    skipReason: '',
    rulesOffered: 102,
    rulesExcluded: [],
    scopedRuleNames: [],
    deepDirsSkipped: 0,
    ...over,
  };
}

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
    // Written as escapes, not literal ESC bytes: the fixture has to survive being copied through tooling that
    // eats control characters, and a fixture that silently loses them tests the wrong thing.
    const g = '\u001b[32m';
    const r = '\u001b[31m';
    const off = '\u001b[0m';
    const colored = `Scanner result ${g}BlackLotusBootkit${off} (variant: default) ${r}FwHunt rule has been triggered and threat detected!${off}`;
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

  // The line the previous regex dropped. Its rule is the only one that TRIGGERED on real OVMF bytes, so treating
  // it as unparseable meant the scanner's single positive never reached the ledger.
  it('reads a rule name and a variant label that both contain parentheses', () => {
    const { verdicts, unreadableLines } = parseFwHuntOutput(REAL_MODULE_OUTPUT);
    expect(unreadableLines).toBe(0);
    expect(verdicts).toHaveLength(3);
    expect(verdicts[1]).toMatchObject({
      rule: 'BRLY-2022-028 (RsbStuffingCheck)',
      variant: 'informational (the patch from EDK2 is missing)',
      matched: true,
    });
    expect(verdicts[2]?.variant).toBe('vulnerability (RSB Stuffing before RSM skipped in SMI Entry code)');
  });

  it('keeps the path scan-module echoes back as the module trailer', () => {
    const { verdicts } = parseFwHuntOutput(REAL_MODULE_OUTPUT);
    expect(verdicts[0]?.module).toBe('mods/VariableRuntimeDxe-cbd2e4d5-7068-4ff5-b462-9822b4ad8d60.dxe');
  });

  it('treats an unterminated variant group as unknown instead of guessing where it ends', () => {
    const { verdicts, unreadableLines } = parseFwHuntOutput('Scanner result X (variant: never closed');
    expect(verdicts).toHaveLength(0);
    expect(unreadableLines).toBe(1);
  });
});

describe('ruleCategory', () => {
  it('resolves the corpus category from the rule path', () => {
    expect(ruleCategory('Threats/BlackLotusBootkit.yml')).toBe('Threats');
    expect(ruleCategory('Vulnerabilities/BRLY-2021-010.yml')).toBe('Vulnerabilities');
    expect(ruleCategory('SomethingElse/x.yml')).toBeUndefined();
  });
});

describe('parseRuleMeta — the four fields that decide what a rule may be asked to do, or is about', () => {
  it('reads the printed name, which is not the filename', () => {
    expect(parseRuleMeta(REAL_RULE_YAML).name).toBe('BRLY-2022-028 (RsbStuffingCheck)');
  });

  it('reads the description — the field that carries a module label when the name does not', () => {
    expect(parseRuleMeta(REAL_RULE_YAML).description).toBe('Check if StuffRsb used before RSM');
    expect(parseRuleMeta('R:\n  meta:\n    name: X\n').description).toBeUndefined();
  });

  it('counts the volume GUIDs the author scoped the rule to', () => {
    expect(parseRuleMeta(REAL_RULE_YAML).volumeGuids).toBe(2);
  });

  it('reads a target when the rule declares one, and leaves it absent when it does not', () => {
    expect(parseRuleMeta(REAL_RULE_YAML).target).toBeUndefined();
    expect(parseRuleMeta('R:\n  meta:\n    name: X\n    target: firmware\n').target).toBe('firmware');
  });

  it('stops at the end of the meta block, so variant keys cannot be mistaken for meta', () => {
    // `variants:` sits at the same indent as `meta:` and its children carry prose containing colons.
    expect(parseRuleMeta(REAL_RULE_YAML).target).toBeUndefined();
    expect(parseRuleMeta('R:\n  variants:\n    v:\n      name: not-meta\n').name).toBeUndefined();
  });

  it('returns an empty read rather than throwing on a file with no meta block', () => {
    expect(parseRuleMeta('nonsense')).toEqual({ volumeGuids: 0 });
  });
});

describe('selectModuleRules — a rule no pass can offer is a hole, not a pass', () => {
  const corpus: CorpusRule[] = [
    { path: 'Threats/A.yml', name: 'A', volumeGuids: 1 },
    { path: 'Threats/B.yml', name: 'B', target: 'module', volumeGuids: 0 },
    { path: 'SupplyChain/C.yml', name: 'C', target: 'firmware', volumeGuids: 0 },
    { path: 'Threats/D.yml', name: 'D', target: 'bootloader', volumeGuids: 0 },
  ];

  it('offers module rules and refuses firmware/bootloader rules', () => {
    const { rules } = selectModuleRules(corpus);
    expect(rules.map((r) => r.name)).toEqual(['A', 'B']);
  });

  it('returns the refused rules with the target that disqualified them, instead of dropping them', () => {
    const { excluded } = selectModuleRules(corpus);
    expect(excluded).toEqual([
      { rule: 'C', target: 'firmware' },
      { rule: 'D', target: 'bootloader' },
    ]);
  });
});

describe('describeCarvedModule — two carvers, two layouts, one label', () => {
  it('reads the analyzer’s own flat `<Name>-<guid><ext>` output', () => {
    expect(describeCarvedModule('/t/mods/VariableRuntimeDxe-cbd2e4d5-7068-4ff5-b462-9822b4ad8d60.dxe')).toEqual({
      path: '/t/mods/VariableRuntimeDxe-cbd2e4d5-7068-4ff5-b462-9822b4ad8d60.dxe',
      name: 'VariableRuntimeDxe',
      guid: 'cbd2e4d5-7068-4ff5-b462-9822b4ad8d60',
    });
  });

  it('reads chipsec’s nested `<Name>.efi` under a GUID-named directory', () => {
    const p = '/t/img.fd.dir/FV/00_x.dir/04_52c05b14-0b98-496c-bc3b-04b50211d680.FV_PEI_CORE.dir/PeiCore.efi';
    expect(describeCarvedModule(p)).toEqual({ path: p, name: 'PeiCore', guid: '52c05b14-0b98-496c-bc3b-04b50211d680' });
  });

  it('still labels a file that follows neither convention, rather than dropping it', () => {
    expect(describeCarvedModule('/t/blob.bin')).toEqual({ path: '/t/blob.bin', name: 'blob' });
  });
});

describe('classifyModulePrivilege — read off the carve, most privileged signal wins', () => {
  it('reads the FFS type chipsec stamps into the directory name', () => {
    const p = '/t/img.fd.dir/FV/00_x.dir/04_52c05b14-0b98-496c-bc3b-04b50211d680.FV_PEI_CORE.dir/PeiCore.efi';
    expect(classifyModulePrivilege({ path: p, name: 'PeiCore' })).toBe('boot-core');
  });

  it('classifies from the carve directory alone when the module’s own name says nothing', () => {
    expect(classifyModulePrivilege({ path: '/t/img.fd.dir/01_abc.FV_SMM.dir/Foo.efi', name: 'Foo' })).toBe('smm');
  });

  it('reads the extension the analyzer’s own extract appends', () => {
    expect(classifyModulePrivilege({ path: '/t/mods/CpuIo2Smm-cbd2e4d5.smm', name: 'CpuIo2Smm' })).toBe('smm');
  });

  it('takes the MOST privileged signal when the extension and the name disagree', () => {
    // The extension says "a DXE driver"; the name says "the SEC phase entry point". Under-ranking this one costs
    // the earliest code in the image its only look, so the name wins.
    expect(classifyModulePrivilege({ path: '/t/mods/SecMain-cbd2e4d5.dxe', name: 'SecMain' })).toBe('boot-core');
  });

  it('separates a runtime driver from an ordinary one, and a PEIM from both', () => {
    expect(classifyModulePrivilege(carved('VariableRuntimeDxe'))).toBe('runtime-dxe');
    expect(classifyModulePrivilege(carved('NvmExpressDxe'))).toBe('dxe-driver');
    expect(classifyModulePrivilege(carved('S3Resume2Pei'))).toBe('peim');
    expect(classifyModulePrivilege({ path: '/t/mods/Shell.efi', name: 'Shell' })).toBe('application');
  });

  it('admits it could not read a tier rather than promoting the module to one', () => {
    expect(classifyModulePrivilege({ path: '/t/blob.bin', name: 'blob' })).toBe('unclassified');
  });
});

describe('rankModulesForScan — coverage debt, not carve order', () => {
  const modules = [carved('Zeta'), carved('Alpha'), carved('NvmExpressDxe'), carved('Beta')];

  it('puts modules the whole-image pass never reached first — those had zero rules run', () => {
    const { selected } = rankModulesForScan({ modules, coveredByImageScan: ['NvmExpressDxe'], cap: 4 });
    expect(selected.map((m) => m.name)).toEqual(['Alpha', 'Beta', 'Zeta', 'NvmExpressDxe']);
  });

  it('is stable, so two runs over the same image scan the same modules', () => {
    const a = rankModulesForScan({ modules, coveredByImageScan: [], cap: 2 });
    const b = rankModulesForScan({ modules: [...modules].reverse(), coveredByImageScan: [], cap: 2 });
    expect(a.selected.map((m) => m.name)).toEqual(b.selected.map((m) => m.name));
  });

  it('hands back what the cap dropped instead of silently shortening the list', () => {
    const { selected, skipped } = rankModulesForScan({ modules, coveredByImageScan: [], cap: 2 });
    expect(selected).toHaveLength(2);
    expect(skipped.map((m) => m.name)).toEqual(['NvmExpressDxe', 'Zeta']);
  });

  it('a cap of zero scans nothing and reports every module as skipped', () => {
    const { selected, skipped } = rankModulesForScan({ modules, coveredByImageScan: [], cap: 0 });
    expect(selected).toEqual([]);
    expect(skipped).toHaveLength(4);
  });

  it('matches the image pass’s module label even when it echoed a path', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('Alpha'), carved('NvmExpressDxe')],
      coveredByImageScan: ['mods/NvmExpressDxe-cbd2e4d5.dxe', 'NvmExpressDxe'],
      cap: 1,
    });
    expect(selected[0]?.name).toBe('Alpha');
  });

  it('scans everything and drops nothing when the cap exceeds the carve', () => {
    const { selected, skipped } = rankModulesForScan({ modules, coveredByImageScan: [], cap: 99 });
    expect(selected).toHaveLength(4);
    expect(skipped).toEqual([]);
  });
});

describe('rankModulesForScan — the corpus names some of these modules, and that is worth a slot', () => {
  it('puts a module a rule was written about ahead of one no rule mentions', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('Alpha'), carved('SecDxe')],
      coveredByImageScan: [],
      cap: 1,
      rules: [rule('LojaxSecDxe')],
    });
    // Alphabetically Alpha wins; the corpus is why it does not.
    expect(selected[0]?.name).toBe('SecDxe');
  });

  it('reads the rule FILENAME too, because five rules print a name that is not their filename', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('Alpha'), carved('NvmExpressDxe')],
      coveredByImageScan: [],
      cap: 1,
      rules: [rule('BRLY-2021-010', 'Vulnerabilities/NvmExpressDxeOverflow.yml')],
    });
    expect(selected[0]?.name).toBe('NvmExpressDxe');
  });

  it('ranks a module more rules name ahead of one fewer name, and both ahead of an unnamed module', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('Alpha'), carved('DxeCore'), carved('SecDxe')],
      coveredByImageScan: [],
      cap: 3,
      rules: [rule('LojaxSecDxe'), rule('SecDxeImplant'), rule('CosmicStrandDxeCore')],
    });
    // DxeCore is the more privileged module and still loses to the one two rules were written about.
    expect(selected.map((m) => m.name)).toEqual(['SecDxe', 'DxeCore', 'Alpha']);
  });

  it('does not test a label too short to mean anything, so `Core` does not match half the corpus', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('Alpha'), carved('Core')],
      coveredByImageScan: [],
      cap: 1,
      rules: [rule('PiSmmCoreDoor')],
    });
    expect(selected[0]?.name).toBe('Alpha');
  });

  it('counts a rule that names the module only in its prose — CVE-2023-45230 and Dhcp6Dxe', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('PiSmmCore'), carved('Dhcp6Dxe')],
      coveredByImageScan: [],
      cap: 1,
      rules: [
        describedRule('CVE-2023-45230', 'Buffer overflow in the DHCPv6 client (Dhcp6Dxe) parsing a long server ID'),
      ],
    });
    // PiSmmCore is the more privileged module and wins on privilege alone; the corpus having written something
    // about Dhcp6Dxe — in the one field that was not being read — is what takes the slot off it.
    expect(selected[0]?.name).toBe('Dhcp6Dxe');
  });

  it('weights a description mention at half a name mention, so prose never outranks an identifier', () => {
    // Two unclassified modules, so privilege cannot decide and the alphabetical break points AGAINST the module
    // the rule is named for — the mention score is the only thing that can reorder them.
    const modules = [carved('Alpha'), carved('Bravo')];
    const named = rule('BravoImplant');
    const describes = (id: string): CorpusRule => describedRule(id, 'the bug is reached through Alpha');

    // 2 (a name mention) against 1 (a description mention): the named module wins, against the alphabetical break.
    const one = rankModulesForScan({ modules, coveredByImageScan: [], cap: 2, rules: [named, describes('BRLY-1')] });
    expect(one.selected.map((m) => m.name)).toEqual(['Bravo', 'Alpha']);

    // 2 against 2: two rules describing a module tie with one rule named after it, and the tie falls through.
    const two = rankModulesForScan({
      modules,
      coveredByImageScan: [],
      cap: 2,
      rules: [named, describes('BRLY-1'), describes('BRLY-2')],
    });
    expect(two.selected.map((m) => m.name)).toEqual(['Alpha', 'Bravo']);
  });

  it('counts one rule once however often it says the label — attention, not verbosity', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('Alpha'), carved('Bravo')],
      coveredByImageScan: [],
      cap: 2,
      rules: [
        { path: 'Threats/BravoImplant.yml', name: 'BravoImplant', description: 'an implant in Bravo', volumeGuids: 0 },
        describedRule('BRLY-1', 'the bug is reached through Alpha'),
        describedRule('BRLY-2', 'a second rule about Alpha'),
      ],
    });
    // Bravo scores the name weight (2), not name + description (3), so Alpha's two descriptions tie it and the
    // alphabetical break decides. A 3 here would put Bravo first.
    expect(selected.map((m) => m.name)).toEqual(['Alpha', 'Bravo']);
  });

  it('applies the short-label rule to prose too, which is where a short label hits most easily', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('Alpha'), carved('Core')],
      coveredByImageScan: [],
      cap: 1,
      rules: [describedRule('BRLY-3', 'the DXE dispatcher is patched before Core hands control over')],
    });
    expect(selected[0]?.name).toBe('Alpha');
  });

  it('still puts a module the image pass already reached last, however well the corpus knows it', () => {
    const { selected, skipped } = rankModulesForScan({
      modules: [carved('Alpha'), carved('PiSmmCore')],
      coveredByImageScan: ['PiSmmCore'],
      cap: 1,
      rules: [rule('PiSmmCoreImplant')],
    });
    expect(selected.map((m) => m.name)).toEqual(['Alpha']);
    expect(skipped.map((m) => m.name)).toEqual(['PiSmmCore']);
  });
});

describe('rankModulesForScan — privilege decides when the corpus names nothing', () => {
  it('spends its slots on SMM and the dispatch cores before ordinary drivers and applications', () => {
    const { selected } = rankModulesForScan({
      modules: [
        carved('AaaDxe'),
        { path: '/tmp/mods/ShellApp.efi', name: 'ShellApp' },
        carved('PiSmmCore'),
        carved('PeiCore'),
      ],
      coveredByImageScan: [],
      cap: 4,
    });
    expect(selected.map((m) => m.name)).toEqual(['PiSmmCore', 'PeiCore', 'AaaDxe', 'ShellApp']);
  });

  it('prefers a driver that stays mapped at OS runtime over one that does not', () => {
    const { selected } = rankModulesForScan({
      modules: [carved('AlphaDxe'), carved('VariableRuntimeDxe')],
      coveredByImageScan: [],
      cap: 1,
    });
    expect(selected[0]?.name).toBe('VariableRuntimeDxe');
  });

  it('breaks a tie between two modules sharing a label by path, never by carve order', () => {
    // The same driver in two firmware volumes is the case where a name tiebreak silently hands the decision back
    // to the directory walk. Reversing the input must not change what gets scanned.
    const one = { path: '/t/vol1/PeiCore.efi', name: 'PeiCore' };
    const two = { path: '/t/vol2/PeiCore.efi', name: 'PeiCore' };
    const a = rankModulesForScan({ modules: [one, two], coveredByImageScan: [], cap: 1 });
    const b = rankModulesForScan({ modules: [two, one], coveredByImageScan: [], cap: 1 });
    expect(a.selected[0]?.path).toBe('/t/vol1/PeiCore.efi');
    expect(b.selected[0]?.path).toBe('/t/vol1/PeiCore.efi');
  });

  it('is deterministic across an input permutation once the corpus is in play', () => {
    const modules = [carved('ZetaDxe'), carved('PiSmmCore'), carved('SecDxe'), carved('Beta')];
    const rules = [rule('LojaxSecDxe'), rule('BRLY-2021-010', 'Vulnerabilities/ZetaDxeOverflow.yml')];
    const a = rankModulesForScan({ modules, coveredByImageScan: [], cap: 3, rules });
    const b = rankModulesForScan({ modules: [...modules].reverse(), coveredByImageScan: [], cap: 3, rules });
    expect(a.selected.map((m) => m.name)).toEqual(b.selected.map((m) => m.name));
    expect(a.skipped.map((m) => m.name)).toEqual(b.skipped.map((m) => m.name));
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
    expect(note.title).toContain('5/108 rule(s) ran');
    // 5 distinct rules ran out of 108 — reporting "no matches" without that ratio would present a ~5%-coverage
    // scan as a clean bill of health.
    expect(note.evidence?.rulesRun).toBe(5);
    expect(note.evidence?.rulesNotApplicable).toBe(103);
    expect(note.rationale).toContain('examined nothing');
    expect(note.rationale).toContain('unexamined by construction');
  });

  it('says the per-module pass was never attempted rather than letting its absence read as coverage', () => {
    const { verdicts } = parseFwHuntOutput(REAL_OUTPUT);
    const note = buildFwHuntFindings({ verdicts, rulesInCorpus: 108 })[0] as { evidence?: Record<string, unknown> };
    expect(note.evidence?.modulePass).toBe('not attempted');
  });

  it('names the reason when the pass was attempted and did not run', () => {
    const { verdicts } = parseFwHuntOutput(REAL_OUTPUT);
    const pass = modulePassFixture({ ran: false, reason: 'the per-module cap is 0 (FIRMLAB_FWHUNT_MODULE_CAP)' });
    const drafts = buildFwHuntFindings({ verdicts, rulesInCorpus: 108, modulePass: pass });
    const note = drafts[drafts.length - 1] as (typeof drafts)[number];
    expect(note.evidence?.modulePass).toBe('did not run');
    expect(note.rationale).toContain('FIRMLAB_FWHUNT_MODULE_CAP');
    // A pass that did not run contributes no rules, so the union must not quietly grow.
    expect(note.evidence?.rulesRun).toBe(5);
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

describe('buildFwHuntFindings — folding the per-module pass in', () => {
  const imageVerdicts = parseFwHuntOutput(REAL_OUTPUT).verdicts;

  it('counts the union of both passes as the rules that examined these bytes', () => {
    const pass = modulePassFixture({
      verdicts: [
        { rule: 'Lojax-SecDxe', matched: false, module: 'SecMain' },
        { rule: 'CosmicStrand', matched: false, module: 'SecMain' },
        // A rule the whole-image pass already ran must not be double-counted.
        { rule: 'BRLY-2021-010', matched: false, module: 'SecMain' },
      ],
    });
    const drafts = buildFwHuntFindings({ verdicts: imageVerdicts, rulesInCorpus: 108, modulePass: pass });
    const note = drafts[drafts.length - 1] as (typeof drafts)[number];
    expect(note.evidence?.rulesRunWholeImage).toBe(5);
    expect(note.evidence?.rulesRun).toBe(7);
    expect(note.evidence?.rulesNotApplicable).toBe(101);
    expect(note.rationale).toContain('lifting the rules that examined something from 5 to 7');
  });

  it('groups a rule that fired on many modules into one finding rather than flooding the ledger', () => {
    const pass = modulePassFixture({
      modulesScanned: [carved('SecMain'), carved('BdsDxe'), carved('CpuDxe')],
      verdicts: [
        { rule: 'BRLY-2022-028 (RsbStuffingCheck)', variant: 'informational', matched: true, module: 'SecMain' },
        { rule: 'BRLY-2022-028 (RsbStuffingCheck)', variant: 'informational', matched: true, module: 'BdsDxe' },
        { rule: 'BRLY-2022-028 (RsbStuffingCheck)', variant: 'informational', matched: true, module: 'CpuDxe' },
      ],
    });
    const drafts = buildFwHuntFindings({ verdicts: imageVerdicts, rulesInCorpus: 108, modulePass: pass });
    const hits = drafts.filter((d) => d.kind === 'uefi-fwhunt-module-match');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence?.modulesMatched).toBe(3);
    expect(hits[0]?.evidence?.modules).toEqual(['SecMain', 'BdsDxe', 'CpuDxe']);
    expect(hits[0]?.title).toContain('matched 3 carved EFI module(s)');
  });

  it('keeps a rule’s variants apart, because they assert different things', () => {
    const pass = modulePassFixture({
      verdicts: [
        { rule: 'R', variant: 'informational', matched: true, module: 'SecMain' },
        { rule: 'R', variant: 'vulnerability', matched: true, module: 'SecMain' },
      ],
    });
    const drafts = buildFwHuntFindings({ verdicts: imageVerdicts, modulePass: pass });
    expect(drafts.filter((d) => d.kind === 'uefi-fwhunt-module-match')).toHaveLength(2);
  });

  it('grades a match found outside the rule’s declared volume scope one step lower, and says why', () => {
    const verdict = { rule: 'BlackLotusBootkit', variant: 'default', matched: true, module: 'SecMain' };
    const build = (pass: ModulePass) =>
      buildFwHuntFindings({
        verdicts: [],
        rulePaths: { BlackLotusBootkit: 'Threats/BlackLotusBootkit.yml' },
        modulePass: pass,
      })[0] as NonNullable<ReturnType<typeof buildFwHuntFindings>[number]>;
    const scoped = build(modulePassFixture({ verdicts: [verdict], scopedRuleNames: ['BlackLotusBootkit'] }));
    const unscoped = build(modulePassFixture({ verdicts: [verdict] }));
    expect(unscoped.severity).toBe('critical');
    expect(scoped.severity).toBe('high');
    expect(scoped.evidence?.ranOutsideDeclaredVolumeScope).toBe(true);
    expect(scoped.rationale).toContain('the author never intended it against these modules');
  });

  it('names the module list cap instead of silently shortening it', () => {
    const many = Array.from({ length: 20 }, (_, i) => ({ rule: 'R', matched: true, module: `Mod${i}` }));
    const drafts = buildFwHuntFindings({ verdicts: [], modulePass: modulePassFixture({ verdicts: many }) });
    const hit = drafts[0] as (typeof drafts)[number];
    expect((hit.evidence?.modules as string[]).length).toBe(12);
    expect(hit.evidence?.modulesNotListed).toBe(8);
    expect(hit.evidence?.modulesMatched).toBe(20);
  });

  it('states every module the bounds dropped, and that failures are unknown rather than clean', () => {
    const pass = modulePassFixture({
      modulesSkipped: [carved('A'), carved('B')],
      modulesFailed: [carved('C')],
      skipReason: 'a cap of 12 module(s), taken in order of coverage debt rather than carve order',
      rulesExcluded: [{ rule: 'IntelAlderLakeLeak', target: 'firmware' }],
      scopedRuleNames: ['BRLY-2021-010'],
      deepDirsSkipped: 1,
    });
    const drafts = buildFwHuntFindings({ verdicts: imageVerdicts, rulesInCorpus: 108, modulePass: pass });
    const note = drafts[drafts.length - 1] as (typeof drafts)[number];
    expect(note.evidence?.modulesSkipped).toBe(2);
    expect(note.evidence?.modulesFailed).toBe(1);
    expect(note.evidence?.carveDirsTooDeepToWalk).toBe(1);
    expect(note.rationale).toContain('2 module(s) were never scanned');
    expect(note.rationale).toContain('coverage debt');
    expect(note.rationale).toContain('unknown, not clean');
    expect(note.rationale).toContain('target: firmware');
    expect(note.rationale).toContain('graded one step lower');
    expect(note.rationale).toContain('too deeply nested');
  });

  it('folds module matches into the headline count so the title cannot read as clean', () => {
    const pass = modulePassFixture({ verdicts: [{ rule: 'R', matched: true, module: 'SecMain' }] });
    const drafts = buildFwHuntFindings({ verdicts: imageVerdicts, rulesInCorpus: 108, modulePass: pass });
    const note = drafts[drafts.length - 1] as (typeof drafts)[number];
    expect(note.title).toContain('1 rule match(es)');
    // The headline must never state the rule fraction without the module fraction beside it.
    expect(note.title).toContain('over 2/125 carved module(s)');
    expect(note.evidence?.rulesMatched).toBe(1);
  });
});
