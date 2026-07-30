/**
 * The pure half of the YARA rootfs scan.
 *
 * Deliberately never requires the real `yara` binary — that is this repo's rule, and it is also the only way the
 * degradation paths can be exercised at all: the interesting states here are the ones where nothing scanned, and a
 * test that needed the tool could not tell "yara is missing" apart from "the test host is missing yara".
 *
 * What is being protected, in order of how badly it would ship:
 *   1. The four empty states stay four. `no_corpus`, `corpus_empty`, `no_rules_applied` and a scan that ran and
 *      matched nothing are four different answers, and every one of them has an empty `matches` array.
 *   2. The denominator explains itself. N of M, with the private rules and the uncompilable files named.
 *   3. A clean scan says it is bounded by the corpus rather than reading as a verdict.
 *   4. The cap ranks. A scan list that is the prefix of a directory walk is a set that is an artifact of layout.
 *   5. A match is attributed to its rule and never restated as FirmLab's own claim about the firmware.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const toolState = vi.hoisted(() => ({ present: true }));
vi.mock('../tools.js', () => ({
  isToolAvailable: vi.fn(async () => toolState.present),
}));

import {
  type CorpusSummary,
  type RuleFile,
  type ScanSummary,
  type ScanTarget,
  blockedResult,
  buildYaraFindings,
  classifyCompileFailure,
  classifyContent,
  classifyLocation,
  describeCoverage,
  describeRuleDenominator,
  loadRuleCorpus,
  maskYaraSource,
  parseCompileDiagnostics,
  parseRuleDeclarations,
  parseScanErrors,
  parseYaraMatchLine,
  parseYaraOutput,
  rankScanTargets,
  runYaraScan,
  severityForMatch,
  summarizeCorpus,
  yaraCorpusSources,
  yaraFileCap,
} from './yarascan.js';

const handle = { id: 'test', log: (): void => {} };

const tmpdirs: string[] = [];
function tmp(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'yarascan-test-'));
  tmpdirs.push(d);
  return d;
}
afterEach(() => {
  toolState.present = true;
  while (tmpdirs.length) fs.rmSync(tmpdirs.pop() as string, { recursive: true, force: true });
});

// -----------------------------------------------------------------------------------------------------------------
// Parsing what yara said
// -----------------------------------------------------------------------------------------------------------------

describe('parseYaraMatchLine', () => {
  it('reads namespace, rule, tags and path out of a `-e -g` line', () => {
    const m = parseYaraMatchLine('r3_malware_linux_yar:Backdoor_Generic [linux,backdoor] /rootfs/usr/sbin/telnetd');
    expect(m).toEqual({
      namespace: 'r3_malware_linux_yar',
      rule: 'Backdoor_Generic',
      tags: ['linux', 'backdoor'],
      path: '/rootfs/usr/sbin/telnetd',
    });
  });

  it('keeps a path that contains spaces — the field is unquoted and the path is whatever is left', () => {
    const m = parseYaraMatchLine('r0_x:Foo [] /rootfs/usr/share/My Vendor App/run.sh');
    expect(m?.path).toBe('/rootfs/usr/share/My Vendor App/run.sh');
    expect(m?.tags).toEqual([]);
  });

  it('does not stop the meta group at a `]` that lives inside a quoted value', () => {
    const m = parseYaraMatchLine('r0_x:Foo [] [description="drops a file in [tmp]",score=70] /rootfs/tmp/a');
    expect(m?.path).toBe('/rootfs/tmp/a');
    expect(m?.rule).toBe('Foo');
  });

  it('reads a line with no namespace at all', () => {
    expect(parseYaraMatchLine('Mirai_Loader /rootfs/bin/dvrHelper')).toEqual({
      rule: 'Mirai_Loader',
      tags: [],
      path: '/rootfs/bin/dvrHelper',
    });
  });

  it('refuses a line it cannot read rather than inventing a rule out of it', () => {
    expect(parseYaraMatchLine('')).toBeNull();
    expect(parseYaraMatchLine('scanning...')).toBeNull();
    expect(parseYaraMatchLine('r0_x:Foo [unclosed /rootfs/a')).toBeNull();
    expect(parseYaraMatchLine('r0_x:9NotAnIdentifier /rootfs/a')).toBeNull();
  });
});

describe('parseYaraOutput', () => {
  it('groups a rule that fired on many files into one claim, with the files sorted', () => {
    const { groups } = parseYaraOutput(
      [
        'r1_web:Webshell_PHP [webshell] /rootfs/www/b.php',
        'r1_web:Webshell_PHP [webshell] /rootfs/www/a.php',
        'r2_bot:Mirai_Strings [] /rootfs/bin/dvrHelper',
        '',
      ].join('\n'),
    );
    expect(groups).toHaveLength(2);
    expect(groups[0]).toMatchObject({ rule: 'Mirai_Strings', files: ['/rootfs/bin/dvrHelper'] });
    expect(groups[1]).toMatchObject({
      rule: 'Webshell_PHP',
      namespace: 'r1_web',
      tags: ['webshell'],
      files: ['/rootfs/www/a.php', '/rootfs/www/b.php'],
    });
  });

  it('counts a line it could not read instead of folding it into "nothing matched"', () => {
    const { groups, unreadableLines } = parseYaraOutput('r0_x:Foo [] /rootfs/a\nyara: something went sideways\n');
    expect(groups).toHaveLength(1);
    // The noise line has no bracket group and no leading identifier shape it can be read as.
    expect(unreadableLines).toBe(1);
  });
});

describe('the compiler and scanner diagnostics', () => {
  it('reads yara compile errors and warnings off stderr, keeping the file they were about', () => {
    const diags = parseCompileDiagnostics(
      [
        '/rules/apt/lojax.yar(12): error: undefined identifier "pe"',
        '/rules/generic/packer.yar(3): warning: $a is slowing down scanning',
        'not a diagnostic at all',
      ].join('\n'),
    );
    expect(diags).toEqual([
      { file: '/rules/apt/lojax.yar', line: 12, level: 'error', message: 'undefined identifier "pe"' },
      { file: '/rules/generic/packer.yar', line: 3, level: 'warning', message: '$a is slowing down scanning' },
    ]);
  });

  /**
   * These four strings are CAPTURED from YARA 4.2.3 (`yara --version`, Debian 4.2.3-4/arm64) running against real
   * firmware bytes, not written from `cli/yara.c`. That distinction is the whole point of this block: the parser
   * above was authored from the source's print order and got the shape below wrong for a year.
   *
   * `error: rule "X" in f.yar(1): msg` is the COMMON shape — every broken or slow rule in an operator's corpus
   * produces it — and `parseCompileDiagnostics` returned `[]` for it, so the per-file attribution was lost on
   * exactly the failures that happen, and the module's own "warnings are kept" promise was not delivered.
   */
  it('reads the RULE-scoped shape too, which is the one a real yara actually prints', () => {
    const diags = parseCompileDiagnostics(
      [
        // Captured: `yara ns0:bad.yar empty.probe`, rc=1
        'error: rule "Broken" in bad.yar(1): undefined string "$nope"',
        // Captured: `yara ns0:w1.yar empty.probe`, rc=0 — a warning does NOT fail the compile
        'warning: rule "Slow" in w1.yar(1): string "$a" may slow down scanning',
        // Captured: `yara ns0:mod.yar empty.probe`, rc=1 — the file-scoped shape, which already worked
        'mod.yar(1): error: unknown module "string"',
      ].join('\n'),
    );
    // In stderr order: the parser reports what yara said, in the order it said it, so a reader comparing the two
    // sees the same sequence.
    expect(diags).toEqual([
      { file: 'bad.yar', line: 1, level: 'error', message: 'undefined string "$nope"', rule: 'Broken' },
      {
        file: 'w1.yar',
        line: 1,
        level: 'warning',
        message: 'string "$a" may slow down scanning',
        rule: 'Slow',
      },
      { file: 'mod.yar', line: 1, level: 'error', message: 'unknown module "string"' },
    ]);
  });

  /**
   * A file-scoped diagnostic has no rule because there IS no rule yet — the import failed before one was read. That
   * is not the same as a rule whose name could not be parsed, and the field being absent rather than `''` is what
   * keeps the two apart.
   */
  it('omits the rule for a file-scoped diagnostic, rather than reporting an empty one', () => {
    const [fileScoped] = parseCompileDiagnostics('mod.yar(1): error: unknown module "string"');
    expect(fileScoped).not.toHaveProperty('rule');
    const [ruleScoped] = parseCompileDiagnostics('error: rule "R" in f.yar(2): undefined string "$x"');
    expect(ruleScoped?.rule).toBe('R');
  });

  it('still classifies an unrecognised SHAPE, because the message is read independently of the layout', () => {
    // What an unknown shape costs is the file and line, never the fact that something failed.
    expect(parseCompileDiagnostics('yara: something entirely new')).toEqual([]);
    expect(classifyCompileFailure('something entirely new')).toBe('other');
  });

  it('classifies a failure by what an operator would have to do about it', () => {
    expect(classifyCompileFailure('can\'t open include file "./common.yar"')).toBe('missing-module');
    // MEASURED 2026-07-30 on yara 4.2.3-4/arm64: Debian ships cuckoo, so this exact message does NOT arise here.
    // Kept because an operator's own build may lack a module, and `string` is one no build has:
    expect(classifyCompileFailure('unknown module "string"')).toBe('missing-module');
    expect(classifyCompileFailure('undefined identifier "pe"')).toBe('undefined-identifier');
    expect(classifyCompileFailure('syntax error, unexpected _IDENTIFIER_')).toBe('syntax');
    expect(classifyCompileFailure('something nobody has seen before')).toBe('other');
  });

  it('reads the files yara was pointed at and could not open — tried and unknown, never clean', () => {
    expect(parseScanErrors('error scanning /rootfs/proc/self/mem: could not open file\nok')).toEqual([
      { path: '/rootfs/proc/self/mem', message: 'could not open file' },
    ]);
  });
});

// -----------------------------------------------------------------------------------------------------------------
// Reading the corpus — where the denominator comes from
// -----------------------------------------------------------------------------------------------------------------

describe('maskYaraSource', () => {
  it('blanks comments and string bodies while leaving offsets and line breaks alone', () => {
    const src = 'rule A { /* rule B */ strings: $a = "rule C" condition: $a }';
    const masked = maskYaraSource(src);
    expect(masked).toHaveLength(src.length);
    expect(masked).toContain('rule A');
    expect(masked).not.toContain('rule B');
    expect(masked).not.toContain('rule C');
  });
});

describe('parseRuleDeclarations', () => {
  const src = [
    'import "pe"',
    'import "elf"',
    '',
    '// rule NotARule — this one is a comment',
    'private rule Helper_Strings',
    '{',
    '  strings:',
    '    $s = "rule Decoy"',
    '  condition:',
    '    $s',
    '}',
    '',
    'rule Implant_Marker : linux implant',
    '{',
    '  meta:',
    '    author = "Someone Else"',
    '    reference = "https://example.invalid/report"',
    '    severity = "critical"',
    '  strings:',
    '    $re = /busybox{2,4}/',
    '  condition:',
    '    Helper_Strings and $re',
    '}',
    '',
    'global rule Everything { condition: true }',
  ].join('\n');

  it('counts rules where they are DECLARED, with their modifiers and tags', () => {
    const { rules, imports } = parseRuleDeclarations(src);
    expect(rules.map((r) => r.name)).toEqual(['Helper_Strings', 'Implant_Marker', 'Everything']);
    expect(rules[0]?.isPrivate).toBe(true);
    expect(rules[1]?.tags).toEqual(['linux', 'implant']);
    expect(rules[2]?.isGlobal).toBe(true);
    expect(imports).toEqual(['pe', 'elf']);
  });

  it('never mistakes a commented-out or quoted `rule` for a declaration', () => {
    const { rules } = parseRuleDeclarations(src);
    expect(rules.map((r) => r.name)).not.toContain('NotARule');
    expect(rules.map((r) => r.name)).not.toContain('Decoy');
  });

  it('reads the meta block, because that is the attribution a match is reported through', () => {
    const { rules } = parseRuleDeclarations(src);
    expect(rules[1]?.meta).toEqual({
      author: 'Someone Else',
      reference: 'https://example.invalid/report',
      severity: 'critical',
    });
  });
});

describe('loadRuleCorpus', () => {
  it('reads .yar/.yara and counts what the extension filter refused, rather than silently ignoring it', () => {
    const dir = tmp();
    fs.mkdirSync(path.join(dir, 'apt'));
    fs.writeFileSync(path.join(dir, 'apt', 'a.yar'), 'rule A { condition: true }');
    fs.writeFileSync(path.join(dir, 'b.yara'), 'private rule B { condition: true }\nrule C { condition: true }');
    fs.writeFileSync(path.join(dir, 'README.md'), 'these are the rules');
    fs.writeFileSync(path.join(dir, 'compiled.yarc'), 'binary');

    const { files, missingSources, filesSkippedByFilter } = loadRuleCorpus([dir]);
    expect(files.map((f) => f.relPath).sort()).toEqual(['apt/a.yar', 'b.yara']);
    expect(filesSkippedByFilter).toBe(2);
    expect(missingSources).toEqual([]);
    // Namespaces are unique per file, which is what lets a match name the file it came from.
    expect(new Set(files.map((f) => f.namespace)).size).toBe(2);
  });

  it('reports a configured path that is not on disk as a wiring mistake, not as an empty corpus', () => {
    const { files, missingSources } = loadRuleCorpus(['/nonexistent/rules']);
    expect(files).toEqual([]);
    expect(missingSources).toEqual(['/nonexistent/rules']);
  });
});

describe('yaraCorpusSources — the built-in corpus is empty on purpose', () => {
  it('is empty when nothing is configured: FirmLab authors no signatures', () => {
    expect(yaraCorpusSources({})).toEqual([]);
    expect(yaraCorpusSources({ FIRMLAB_YARA_RULES: '   ' })).toEqual([]);
  });

  it('splits the operator value on the platform path delimiter', () => {
    const value = ['/opt/rules-a', '/opt/rules-b/one.yar'].join(path.delimiter);
    expect(yaraCorpusSources({ FIRMLAB_YARA_RULES: value })).toEqual(['/opt/rules-a', '/opt/rules-b/one.yar']);
  });

  it('falls back to the default cap rather than to "no cap" when the env value is nonsense', () => {
    expect(yaraFileCap({ FIRMLAB_YARA_FILE_CAP: 'lots' })).toBe(20000);
    expect(yaraFileCap({ FIRMLAB_YARA_FILE_CAP: '0' })).toBe(0);
  });
});

// -----------------------------------------------------------------------------------------------------------------
// The denominator
// -----------------------------------------------------------------------------------------------------------------

function ruleFile(namespace: string, rules: Array<{ name: string; isPrivate?: boolean }>): RuleFile {
  return {
    path: `/rules/${namespace}.yar`,
    corpus: '/rules',
    relPath: `${namespace}.yar`,
    namespace,
    rules: rules.map((r) => ({
      name: r.name,
      isPrivate: r.isPrivate ?? false,
      isGlobal: false,
      tags: [],
      meta: {},
    })),
    imports: [],
    unreadable: false,
  };
}

describe('summarizeCorpus — N of M, and where the difference went', () => {
  const files = [
    ruleFile('a', [{ name: 'A1' }, { name: 'A2' }, { name: 'A_helper', isPrivate: true }]),
    ruleFile('b', [{ name: 'B1' }, { name: 'B2' }]),
  ];

  it('counts every declared rule, and applies neither the private ones nor the ones in a rejected file', () => {
    const summary = summarizeCorpus({
      files,
      sources: ['/rules'],
      rejected: [
        {
          path: '/rules/b.yar',
          corpus: '/rules',
          namespace: 'b',
          rulesLost: 2,
          reason: 'missing-module',
          message: 'unknown module "cuckoo"',
        },
      ],
    });
    expect(summary.rulesDeclared).toBe(5);
    expect(summary.rulesPrivate).toBe(1);
    // A1 and A2 only: the private helper cannot report, and b.yar never compiled.
    expect(summary.rulesApplied).toBe(2);
    expect(summary.filesCompiled).toBe(1);
  });

  it('says why the missing rules are missing, naming private rules and the compile failures separately', () => {
    const summary = summarizeCorpus({
      files,
      sources: ['/rules'],
      rejected: [
        {
          path: '/rules/b.yar',
          corpus: '/rules',
          namespace: 'b',
          rulesLost: 2,
          reason: 'missing-module',
          message: 'unknown module "cuckoo"',
        },
      ],
    });
    const sentence = describeRuleDenominator(summary);
    expect(sentence).toContain('2 of the 5 rules declared in the corpus were applied');
    expect(sentence).toContain('the other 3 examined nothing');
    expect(sentence).toContain('1 declared `private`');
    expect(sentence).toContain('2 in 1 rule file this yara build refused to compile');
    expect(sentence).toContain('1×missing-module');
  });

  it('does not append an explanation when there is nothing to explain', () => {
    const summary = summarizeCorpus({ files: [ruleFile('a', [{ name: 'A1' }])], sources: ['/rules'] });
    expect(describeRuleDenominator(summary)).toBe('1 of the 1 rule declared in the corpus was applied to these bytes.');
  });
});

// -----------------------------------------------------------------------------------------------------------------
// A clean scan is not "no implant"
// -----------------------------------------------------------------------------------------------------------------

const CLEAN_CORPUS: CorpusSummary = summarizeCorpus({
  files: [ruleFile('a', [{ name: 'A1' }, { name: 'A2' }])],
  sources: ['/opt/yara-rules'],
});

const CLEAN_SCAN: ScanSummary = {
  root: '/data/extract/img/rootfs',
  filesFound: 1890,
  filesListed: 1204,
  filesScanned: 1204,
  filesTooLarge: 6,
  filesOverCap: 680,
  filesUnrepresentable: 0,
  filesFailed: [],
  bytesListed: 12345678,
  maxFileBytes: 64 * 1024 * 1024,
  fileCap: 1204,
  skipReason: 'a cap of 1204 file(s), taken in order of what the first bytes say the file IS',
  dirsUnreadable: 0,
  deepDirsSkipped: 0,
};

describe('the clean-scan sentence', () => {
  it('states both denominators and refuses to let zero matches read as a verdict', () => {
    const s = describeCoverage(CLEAN_CORPUS, CLEAN_SCAN, 0);
    expect(s).toContain('0 rules matched.');
    expect(s).toContain('2 of the 2 rules declared in the corpus were applied to these bytes.');
    expect(s).toContain('1204 of the 1890 regular files under /data/extract/img/rootfs were scanned');
    expect(s).toContain('a rule that does not exist cannot match');
    expect(s).toContain('never that this rootfs carries no implant, webshell, Mirai variant or backdoor account');
    expect(s).toContain('FirmLab authors no signatures');
    expect(s).toContain('/opt/yara-rules');
  });

  it('titles a clean scan with the fraction and the caveat, never with "clean"', () => {
    const [coverage] = buildYaraFindings({ matches: [], corpus: CLEAN_CORPUS, scan: CLEAN_SCAN });
    expect(coverage?.kind).toBe('yara-coverage');
    expect(coverage?.title).toBe(
      'YARA: no rule matched — 2/2 rule(s) applied over 1204/1890 file(s), which is not "no implant"',
    );
    expect(coverage?.title).not.toMatch(/clean|no implant was|secure/i);
    expect(coverage?.severity).toBe('info');
  });

  it('emits the coverage note even when nothing matched — an empty result must not be an empty list', () => {
    const drafts = buildYaraFindings({ matches: [], corpus: CLEAN_CORPUS, scan: CLEAN_SCAN });
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.rationale).toContain('bounded by the corpus that ran');
  });

  it('names the files yara could not read as unknown rather than letting them count as scanned', () => {
    const scan: ScanSummary = { ...CLEAN_SCAN, filesScanned: 1202, filesFailed: ['/rootfs/a', '/rootfs/b'] };
    expect(describeCoverage(CLEAN_CORPUS, scan, 0)).toContain(
      '2 were handed to yara and it could not read them, so those are unknown, not clean',
    );
  });
});

// -----------------------------------------------------------------------------------------------------------------
// A match belongs to the rule that made it
// -----------------------------------------------------------------------------------------------------------------

describe("buildYaraFindings — the match is the rule's claim", () => {
  const drafts = buildYaraFindings({
    matches: [
      {
        rule: 'Linux_Mirai_Variant',
        namespace: 'r7_malware_mirai_yar',
        corpus: '/opt/yara-rules',
        ruleFile: 'malware/mirai.yar',
        tags: ['linux', 'botnet'],
        meta: { author: 'Someone Else', reference: 'https://example.invalid/mirai' },
        files: ['/rootfs/bin/dvrHelper', '/rootfs/usr/bin/busybox'],
      },
    ],
    corpus: CLEAN_CORPUS,
    scan: CLEAN_SCAN,
  });
  const match = drafts[0];

  it('names the rule and the corpus it came from, and does not assert the family as established', () => {
    expect(match?.title).toBe(
      "YARA rule 'Linux_Mirai_Variant' matched 2 files (rule from /opt/yara-rules · malware/mirai.yar)",
    );
    // The rule's name may say Mirai; the title must not say this firmware IS Mirai.
    expect(match?.title).not.toMatch(/this firmware (is|contains)/i);
    expect(match?.rationale).toContain('belongs to the rule and its author, not to FirmLab');
    expect(match?.rationale).toContain("author's label, not an established identification");
  });

  it('grades the byte-level fact and nothing more', () => {
    expect(match?.proofState).toBe('static_confirmed');
    expect(match?.evidence).toMatchObject({
      rule: 'Linux_Mirai_Variant',
      corpus: '/opt/yara-rules',
      ruleFile: 'malware/mirai.yar',
      tags: ['linux', 'botnet'],
      filesMatched: 2,
      severityFrom: 'firmlab-placement',
    });
  });

  it('still emits the coverage note beside a match, so the numerator never travels without its denominator', () => {
    expect(drafts.map((d) => d.kind)).toEqual(['yara-rule-match', 'yara-coverage']);
    expect(drafts[1]?.title).toContain('1 rule matched — 2/2 rule(s) applied');
  });
});

describe('severityForMatch', () => {
  it("uses the rule author's own severity when the rule declares one on this ledger's ladder", () => {
    expect(severityForMatch({ severity: 'Critical' })).toEqual({ severity: 'critical', source: 'rule-meta' });
  });

  it('files an ungraded rule at high as a PLACEMENT, and says so rather than pretending to have judged it', () => {
    expect(severityForMatch({})).toEqual({ severity: 'high', source: 'firmlab-placement' });
    expect(severityForMatch({ severity: 'catastrophic' })).toEqual({
      severity: 'high',
      source: 'firmlab-placement',
    });
  });
});

// -----------------------------------------------------------------------------------------------------------------
// The cap ranks
// -----------------------------------------------------------------------------------------------------------------

describe('rankScanTargets', () => {
  function target(relPath: string, content: ScanTarget['content']): ScanTarget {
    return {
      path: `/rootfs/${relPath}`,
      relPath,
      size: 1024,
      content,
      location: classifyLocation(relPath),
    };
  }

  it('spends the cap on code and on where code is planted, not on whatever the walk produced first', () => {
    // Deliberately adversarial order: exactly the shape a LIFO walk of usr/ before bin/ produces.
    const targets = [
      target('usr/share/doc/z1.txt', 'other'),
      target('usr/share/doc/z2.txt', 'other'),
      target('usr/share/doc/z3.txt', 'other'),
      target('etc/init.d/rcS', 'script'),
      target('bin/dvrHelper', 'elf'),
      target('www/cgi-bin/upload.cgi', 'script'),
    ];
    const { selected, skipped } = rankScanTargets({ targets, cap: 3 });
    expect(selected.map((t) => t.relPath).sort()).toEqual([
      'bin/dvrHelper',
      'etc/init.d/rcS',
      'www/cgi-bin/upload.cgi',
    ]);
    expect(skipped).toHaveLength(3);
    expect(skipped.every((t) => t.relPath.startsWith('usr/share/doc/'))).toBe(true);
  });

  it('is a function of the rootfs alone — the same files in a different walk order rank identically', () => {
    const relPaths = ['usr/share/doc/a.txt', 'etc/init.d/rcS', 'bin/dvrHelper', 'lib/libc.so'];
    const build = (order: string[]): string[] =>
      rankScanTargets({
        targets: order.map((p) => target(p, p.endsWith('.txt') ? 'other' : p.endsWith('rcS') ? 'script' : 'elf')),
        cap: 2,
      }).selected.map((t) => t.relPath);
    expect(build(relPaths)).toEqual(build([...relPaths].reverse()));
  });

  it('drops nothing when the cap is 0, which is what "no cap" has to mean', () => {
    const targets = [target('bin/a', 'elf'), target('bin/b', 'elf')];
    expect(rankScanTargets({ targets, cap: 0 }).skipped).toEqual([]);
  });

  it('reads content off the bytes and location off the tree, and never confuses the two', () => {
    expect(classifyContent(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))).toBe('elf');
    expect(classifyContent(Buffer.from('#!/b'))).toBe('script');
    expect(classifyContent(Buffer.from('MZ\0\0', 'binary'))).toBe('other');
    expect(classifyLocation('etc/init.d/rcS')).toBe('startup');
    expect(classifyLocation('www/cgi-bin/x.cgi')).toBe('web-root');
    expect(classifyLocation('usr/sbin/httpd')).toBe('executable-path');
    expect(classifyLocation('usr/lib/libz.so')).toBe('library-path');
    expect(classifyLocation('usr/share/doc/readme')).toBe('other');
  });
});

// -----------------------------------------------------------------------------------------------------------------
// The empty states, which are the whole point
// -----------------------------------------------------------------------------------------------------------------

describe('the states where nothing was scanned stay distinguishable', () => {
  it('gives each cause its own title, state and remedy — five empty lists, five different answers', () => {
    const states = [
      blockedResult('tool_absent', 'yara is not installed in this deployment'),
      blockedResult('no_corpus', 'no rule corpus is configured'),
      blockedResult('corpus_empty', 'the configured corpus declares no rules'),
      blockedResult('no_rules_applied', 'none of the corpus could be compiled'),
      blockedResult('no_target', 'there is nothing to scan'),
    ];
    expect(new Set(states.map((s) => s.findings[0]?.title)).size).toBe(5);
    expect(new Set(states.map((s) => s.state)).size).toBe(5);
    for (const s of states) {
      expect(s.available).toBe(false);
      expect(s.matches).toEqual([]);
      expect(s.scan).toBeNull();
      expect(s.findings[0]?.proofState).toBe('blocked_by_platform');
      expect(s.findings[0]?.rationale).toContain('NOT "no implant was found": nothing looked');
    }
  });

  it('never lets a blocked scan and a clean scan produce the same finding', () => {
    const blocked = blockedResult('no_corpus', 'no rule corpus is configured').findings[0];
    const [clean] = buildYaraFindings({ matches: [], corpus: CLEAN_CORPUS, scan: CLEAN_SCAN });
    expect(blocked?.kind).not.toBe(clean?.kind);
    expect(blocked?.proofState).toBe('blocked_by_platform');
    expect(clean?.proofState).toBe('static_confirmed');
  });
});

describe('runYaraScan degrades honestly, without ever needing the real binary', () => {
  it('reports the absent tool as an absent ANSWER, and never touches the corpus', async () => {
    toolState.present = false;
    const r = await runYaraScan('/nonexistent/rootfs', handle, { env: { FIRMLAB_YARA_RULES: '/opt/rules' } });
    expect(r.state).toBe('tool_absent');
    expect(r.reason).toContain('yara is not installed');
    expect(r.corpus.sources).toEqual(['/opt/rules']);
    expect(r.corpus.rulesDeclared).toBe(0);
    expect(r.findings[0]?.proofState).toBe('blocked_by_platform');
  });

  it('keeps "nobody supplied rules" apart from "rules ran and matched nothing"', async () => {
    const r = await runYaraScan('/nonexistent/rootfs', handle, { env: {} });
    expect(r.state).toBe('no_corpus');
    expect(r.reason).toContain('FirmLab ships no built-in signatures');
    // The distinguishing property: this is not a scan with zero matches, and its finding says so.
    expect(r.scan).toBeNull();
    expect(r.findings[0]?.title).toContain('no corpus is configured');
  });

  it('separates a corpus that is not there from a corpus that holds no rules', async () => {
    const missing = await runYaraScan('/nonexistent/rootfs', handle, {
      env: { FIRMLAB_YARA_RULES: '/nonexistent/rules' },
    });
    expect(missing.state).toBe('corpus_empty');
    expect(missing.reason).toContain('do not exist');

    const dir = tmp();
    fs.writeFileSync(path.join(dir, 'notes.txt'), 'no rules here');
    const empty = await runYaraScan('/nonexistent/rootfs', handle, { env: { FIRMLAB_YARA_RULES: dir } });
    expect(empty.state).toBe('corpus_empty');
    expect(empty.reason).toContain('skipped by the .yar/.yara filter');
    expect(empty.reason).not.toContain('do not exist');
  });

  it('says there is nothing to scan when the corpus is real and the rootfs is not', async () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, 'a.yar'), 'rule A { condition: true }');
    const r = await runYaraScan('/nonexistent/rootfs', handle, { env: { FIRMLAB_YARA_RULES: dir } });
    expect(r.state).toBe('no_target');
    expect(r.corpus.rulesDeclared).toBe(1);
    expect(r.corpus.rulesApplied).toBe(1);
  });
});
