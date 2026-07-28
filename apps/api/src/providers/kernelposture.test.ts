import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { afterAll, describe, expect, it } from 'vitest';
import {
  type KernelBlobFacts,
  MODULE_SIG_TRAILER,
  type ModuleEvidence,
  type PostureEvidence,
  ageSeverity,
  assessPosture,
  compareVersion,
  extractPrintable,
  kernelAge,
  parseConfigVersion,
  parseKernelBanner,
  parseKernelConfig,
  parseKernelVersion,
  parseVermagic,
  postureFindings,
  readKernelBlobFacts,
  runKernelPosture,
  selectKernelBlobs,
} from './kernelposture.js';

/**
 * Every banner below was read out of the deployed corpus with `strings`, not written from the format as remembered —
 * the fixtures and the code must not share an assumption (CLAUDE.md's standing lesson).
 */
const BANNERS = {
  wr940n:
    'Linux version 2.6.31-gdb94342-dirty (tplink@3c80e22a1de8) (gcc version 4.3.3 (GCC) ) #1 Thu May 28 10:36:36 CST 2026',
  wdr3600:
    'Linux version 2.6.31--LSDK-9.2.0_U6.616 (root@liaozhiming) (gcc version 4.3.3 (GCC) ) #1 Mon May 18 19:48:32 CST 2015',
  imou: 'Linux version 4.9.84 (jenkins@105ca6eedc05) (gcc version 4.9.4 (Buildroot 2017.08-gc7bbae9-dirty) ) #6 PREEMPT Fri Dec 22 15:59:10 CST 2023',
  tenda:
    'Linux version 4.4.282 (caogongcheng@ubt) (gcc version 5.5.0 (Buildroot 2018.02.7_V1.0.04-g78fae67) ) #1 Thu Oct 17 15:51:45 CST 2024',
  dvrf: 'Linux version 2.6.22 (root@localhost.localdomain) (gcc version 4.2.3) #4 Wed Mar 9 02:05:36 CST 2016',
  /** Inside `usr/sbin/tailscaled` in the GL.iNet BE3600 rootfs — a Go binary's own embedded reference banner. */
  tailscaledDecoy: 'Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016',
} as const;

/** A fixed instant so the age arithmetic is deterministic: 2026-07-28. */
const NOW = Date.parse('2026-07-28T00:00:00Z');

describe('parseKernelBanner', () => {
  it('decodes the WR940N banner (local version, toolchain, build number and date)', () => {
    const b = parseKernelBanner(BANNERS.wr940n);
    expect(b?.version).toBe('2.6.31-gdb94342-dirty');
    expect(b?.numeric).toMatchObject({ major: 2, minor: 6, patch: 31, series: '2.6' });
    expect(b?.builder).toBe('tplink@3c80e22a1de8');
    expect(b?.toolchain).toBe('gcc version 4.3.3');
    expect(b?.buildNumber).toBe(1);
    expect(b?.buildYear).toBe(2026);
  });

  it('survives the WDR3600 double-dash local version', () => {
    const b = parseKernelBanner(BANNERS.wdr3600);
    expect(b?.version).toBe('2.6.31--LSDK-9.2.0_U6.616');
    expect(b?.numeric.patch).toBe(31);
    expect(b?.buildYear).toBe(2015);
  });

  it('handles a PREEMPT flag between the build number and the date (IMOU)', () => {
    const b = parseKernelBanner(BANNERS.imou);
    expect(b?.numeric).toMatchObject({ major: 4, minor: 9, patch: 84 });
    expect(b?.buildNumber).toBe(6);
    expect(b?.buildDate).toContain('Dec 22');
    expect(b?.buildYear).toBe(2023);
  });

  it('handles a single-parenthesis toolchain (DVRF)', () => {
    const b = parseKernelBanner(BANNERS.dvrf);
    expect(b?.numeric).toMatchObject({ major: 2, minor: 6, patch: 22 });
    expect(b?.toolchain).toBe('gcc version 4.2.3');
  });

  it('parses the tailscaled decoy fine — it is excluded by WHERE it may be read, not by the parser', () => {
    const b = parseKernelBanner(BANNERS.tailscaledDecoy);
    expect(b?.version).toBe('4.4.0');
    expect(b?.builder).toBeUndefined();
  });

  it('refuses a banner with no dotted version, and text with no banner', () => {
    expect(parseKernelBanner('Linux version unknown (nobody@nowhere)')).toBeNull();
    expect(parseKernelBanner('squashfs-root/bin/busybox')).toBeNull();
  });

  it('stops the raw banner at the first control byte so a neighbouring string cannot bleed in', () => {
    const b = parseKernelBanner(`${BANNERS.dvrf}\nSOME_OTHER_KERNEL_STRING`);
    expect(b?.raw).toBe(BANNERS.dvrf);
    expect(b?.raw).not.toContain('SOME_OTHER_KERNEL_STRING');
  });
});

describe('parseKernelVersion / compareVersion', () => {
  it('treats a missing patch as 0 and exposes the maintenance series', () => {
    expect(parseKernelVersion('3.14')).toMatchObject({ major: 3, minor: 14, patch: 0, series: '3.14' });
  });

  it('orders across all three components', () => {
    const v = parseKernelVersion('2.6.22') as NonNullable<ReturnType<typeof parseKernelVersion>>;
    expect(compareVersion(v, [2, 6, 26])).toBe(-1);
    expect(compareVersion(v, [2, 6, 22])).toBe(0);
    expect(compareVersion(v, [2, 4])).toBe(1);
    expect(compareVersion(v, [3, 14])).toBe(-1);
  });
});

describe('parseVermagic', () => {
  it('reads the real vermagic strings from both ends of the corpus', () => {
    expect(parseVermagic('vermagic=5.4.213 SMP preempt mod_unload aarch64')).toBe('5.4.213');
    expect(parseVermagic('vermagic=2.6.31-gdb94342-dirty mod_unload MIPS32_R2 32BIT ')).toBe('2.6.31-gdb94342-dirty');
    expect(parseVermagic('__mod_vermagic5')).toBeNull();
  });
});

describe('parseKernelConfig / parseConfigVersion', () => {
  const CONFIG = [
    '#',
    '# Automatically generated file; DO NOT EDIT.',
    '# Linux/mips 5.4.213 Kernel Configuration',
    '#',
    'CONFIG_STRICT_DEVMEM=y',
    '# CONFIG_DEVKMEM is not set',
    'CONFIG_LOCALVERSION=""',
  ].join('\n');

  it('reads a set option, an explicitly unset one, and the header version', () => {
    const cfg = parseKernelConfig(CONFIG);
    expect(cfg.CONFIG_STRICT_DEVMEM).toBe('y');
    expect(cfg.CONFIG_DEVKMEM).toBe('n');
    expect(parseConfigVersion(CONFIG)).toBe('5.4.213');
  });

  it('reads the older `# Linux kernel version:` header spelling', () => {
    expect(parseConfigVersion('#\n# Linux kernel version: 2.6.31\n#\nCONFIG_MIPS=y\n')).toBe('2.6.31');
  });
});

// === Blob facts — the anchor rule that stops a manufactured negative ===

/** Build a kernel-ish string table the way `drivers/char/mem.c` lays it out in a real blob. */
function blobStrings(opts: { kmem: boolean; siblings: boolean; extra?: string[] }): {
  tokens: Set<string>;
  text: string;
} {
  const parts = ['Kernel panic - not syncing: %s', 'swapper', 'unable to get major %d for memory devs'];
  if (opts.kmem) parts.push('kmem');
  if (opts.siblings) parts.push('null', 'full', 'urandom');
  parts.push(...(opts.extra ?? []));
  const tokens = new Set<string>();
  for (const p of parts) {
    tokens.add(p);
    for (const w of p.split(/\s+/)) if (w.length >= 3) tokens.add(w);
  }
  return { tokens, text: parts.join('\n') };
}

describe('readKernelBlobFacts', () => {
  it('anchors on the mem devlist only when the siblings of kmem are visible', () => {
    const anchored = blobStrings({ kmem: true, siblings: true });
    expect(readKernelBlobFacts('/blob', anchored.tokens, anchored.text)).toMatchObject({
      readable: true,
      memDevlistAnchored: true,
      hasKmemEntry: true,
    });

    // No siblings → we may have been looking at a still-compressed blob; `kmem` absent proves nothing.
    const unanchored = blobStrings({ kmem: false, siblings: false });
    expect(readKernelBlobFacts('/blob', unanchored.tokens, unanchored.text).memDevlistAnchored).toBe(false);
  });

  it('reports a blob with no universal kernel strings as not readable', () => {
    const { tokens, text } = extractPrintable(Buffer.from('random padding, not a kernel at all'));
    expect(readKernelBlobFacts('/blob', tokens, text).readable).toBe(false);
  });

  it('records loose CONFIG_ tokens without letting them mean anything', () => {
    // Exactly the IMOU case: the only CONFIG_ token in that 4.9.84 kernel comes from a printk.
    const { tokens, text } = blobStrings({
      kmem: false,
      siblings: true,
      extra: ['initcall_blacklist requires CONFIG_KALLSYMS'],
    });
    const facts = readKernelBlobFacts('/blob', tokens, text);
    expect(facts.looseConfigTokens).toContain('CONFIG_KALLSYMS');
    // …and it must not turn into an answer anywhere. Nothing in the marker set reads looseConfigTokens.
    expect(facts.hasStackProtector).toBe(false);
    expect(facts.hasModuleSigParam).toBe(false);
  });
});

// === The three-state assessment ===

function evidence(over: Partial<PostureEvidence> = {}): PostureEvidence {
  return {
    version: parseKernelVersion('2.6.31'),
    config: null,
    configPath: null,
    blob: null,
    modules: null,
    sysctl: {},
    sysctlPath: null,
    ...over,
  };
}

function factsFrom(opts: Parameters<typeof blobStrings>[0], at = '/extract/20400'): KernelBlobFacts {
  const { tokens, text } = blobStrings(opts);
  return readKernelBlobFacts(at, tokens, text);
}

function answer(ev: PostureEvidence, id: string) {
  const a = assessPosture(ev).find((x) => x.id === id);
  if (!a) throw new Error(`no answer for ${id}`);
  return a;
}

describe('assessPosture — the version gate runs before any marker', () => {
  it('reports KASLR on a 2.6.31 kernel as undetermined/option-postdates-kernel, never "off"', () => {
    const a = answer(evidence({ blob: factsFrom({ kmem: true, siblings: true }) }), 'kaslr');
    expect(a.verdict).toBe('unknown');
    expect(a.reason).toBe('option-postdates-kernel');
    expect(a.bad).toBe(false);
    expect(a.detail).toContain('3.14');
  });

  it('reports module signing on 2.6.31 as postdating the kernel, even with an unsigned module set present', () => {
    const modules: ModuleEvidence = {
      versionDir: '2.6.31',
      vermagic: '2.6.31-gdb94342-dirty',
      moduleCount: 40,
      signedCount: 0,
      inspectedCount: 40,
    };
    const a = answer(evidence({ modules }), 'module-sig');
    expect(a.verdict).toBe('unknown');
    expect(a.reason).toBe('option-postdates-kernel');
  });

  it('reports an option upstream removed before this kernel as undetermined/option-removed-upstream', () => {
    const a = answer(evidence({ version: parseKernelVersion('6.6.30') }), 'devkmem');
    expect(a.verdict).toBe('unknown');
    expect(a.reason).toBe('option-removed-upstream');
  });

  /**
   * The regression this file exists for. `/dev/kmem` predates `CONFIG_DEVKMEM` (2.6.26), so gating the DEVICE on the
   * SWITCH's introduction reported the DVRF's 2.6.22 kernel — which demonstrably ships a `kmem` device entry — as
   * "the option does not exist here". That is the three-state logic collapsing in the dangerous direction: an honest
   * -sounding "undetermined" hiding a confirmed exposure.
   */
  it('still reports /dev/kmem on a 2.6.22 kernel that predates the CONFIG_DEVKMEM switch', () => {
    const a = answer(
      evidence({ version: parseKernelVersion('2.6.22'), blob: factsFrom({ kmem: true, siblings: true }) }),
      'devkmem',
    );
    expect(a.verdict).toBe('on');
    expect(a.bad).toBe(true);
    expect(a.source).toBe('kernel-blob');
    expect(a.detail).toContain('cannot be disabled');
  });
});

describe('assessPosture — an absence only counts when an anchor proves the right place was in view', () => {
  it('calls /dev/kmem off when the device table is visible and carries no kmem entry (the 4.9.84 case)', () => {
    const a = answer(
      evidence({ version: parseKernelVersion('4.9.84'), blob: factsFrom({ kmem: false, siblings: true }) }),
      'devkmem',
    );
    expect(a.verdict).toBe('off');
    expect(a.bad).toBe(false);
    expect(a.source).toBe('kernel-blob');
  });

  it('leaves /dev/kmem undetermined when the device table was never in view', () => {
    const a = answer(evidence({ blob: factsFrom({ kmem: false, siblings: false }) }), 'devkmem');
    expect(a.verdict).toBe('unknown');
    expect(a.reason).toBe('no-kernel-config-shipped');
  });

  it('distinguishes no blob, an unreadable blob and a readable blob with nothing to say', () => {
    expect(answer(evidence(), 'strict-devmem').reason).toBe('no-kernel-blob');

    const junk = extractPrintable(Buffer.from('padding padding padding'));
    const unreadable = readKernelBlobFacts('/extract/1A4', junk.tokens, junk.text);
    expect(answer(evidence({ blob: unreadable }), 'strict-devmem').reason).toBe('kernel-blob-not-readable');

    expect(answer(evidence({ blob: factsFrom({ kmem: true, siblings: true }) }), 'strict-devmem').reason).toBe(
      'no-kernel-config-shipped',
    );
  });
});

describe('assessPosture — a shipped config outranks everything and is the only source that may say "off" by absence', () => {
  it('reads an explicit `is not set` line', () => {
    const config = parseKernelConfig('CONFIG_MIPS=y\n# CONFIG_STRICT_DEVMEM is not set\n');
    const a = answer(
      evidence({ version: parseKernelVersion('4.9.84'), config, configPath: 'proc/config.gz' }),
      'strict-devmem',
    );
    expect(a.verdict).toBe('off');
    expect(a.source).toBe('kernel-config');
    expect(a.detail).toContain('is not set');
  });

  it('treats absence from an exhaustive config as off, and says why it is entitled to', () => {
    const config = parseKernelConfig('CONFIG_MIPS=y\n');
    const a = answer(
      evidence({ version: parseKernelVersion('4.9.84'), config, configPath: 'proc/config.gz' }),
      'strict-devmem',
    );
    expect(a.verdict).toBe('off');
    expect(a.detail).toContain('would appear as');
  });

  it('accepts the older Kconfig spelling of an option through the alias table', () => {
    const config = parseKernelConfig('CONFIG_CC_STACKPROTECTOR=y\n');
    const a = answer(
      evidence({ version: parseKernelVersion('3.10.14'), config, configPath: '.config' }),
      'stackprotector',
    );
    expect(a.verdict).toBe('on');
    expect(a.detail).toContain('CONFIG_CC_STACKPROTECTOR');
  });

  it('beats a blob marker that would have said otherwise', () => {
    const config = parseKernelConfig('# CONFIG_DEVKMEM is not set\n');
    const a = answer(
      evidence({
        version: parseKernelVersion('4.9.84'),
        config,
        configPath: 'proc/config.gz',
        blob: factsFrom({ kmem: true, siblings: true }),
      }),
      'devkmem',
    );
    expect(a.verdict).toBe('off');
    expect(a.source).toBe('kernel-config');
  });
});

describe('assessPosture — the shipped module set answers signing without any kernel blob', () => {
  const modules = (signedCount: number, inspectedCount = 375): ModuleEvidence => ({
    versionDir: '5.4.213',
    vermagic: '5.4.213',
    moduleCount: inspectedCount,
    signedCount,
    inspectedCount,
  });

  it('calls signing off when no shipped module carries the trailer (the BE3600 case)', () => {
    const a = answer(evidence({ version: parseKernelVersion('5.4.213'), modules: modules(0) }), 'module-sig');
    expect(a.verdict).toBe('off');
    expect(a.bad).toBe(true);
    expect(a.source).toBe('shipped-modules');
    expect(a.detail).toContain(MODULE_SIG_TRAILER);
  });

  it('calls signing on when some module is signed', () => {
    const a = answer(evidence({ version: parseKernelVersion('5.4.213'), modules: modules(12) }), 'module-sig');
    expect(a.verdict).toBe('on');
    expect(a.bad).toBe(false);
  });

  it('says nothing at all when no module was inspected', () => {
    const a = answer(
      evidence({ version: parseKernelVersion('5.4.213'), modules: { ...modules(0), inspectedCount: 0 } }),
      'module-sig',
    );
    expect(a.verdict).toBe('unknown');
  });
});

describe('assessPosture — the sysctl knobs come from the rootfs, not from the sysctl name existing', () => {
  it('reads an explicit kptr_restrict assignment', () => {
    const a = answer(
      evidence({
        version: parseKernelVersion('5.4.213'),
        sysctl: { 'kernel.kptr_restrict': '2' },
        sysctlPath: 'etc/sysctl.d/10-default.conf',
      }),
      'kptr-restrict',
    );
    expect(a.verdict).toBe('on');
    expect(a.source).toBe('rootfs-sysctl');
  });

  it('does not infer a value from the sysctl merely existing in the kernel', () => {
    const blob = factsFrom({ kmem: false, siblings: true, extra: ['kptr_restrict', 'dmesg_restrict'] });
    const a = answer(evidence({ version: parseKernelVersion('5.4.213'), blob }), 'kptr-restrict');
    expect(a.verdict).toBe('unknown');
  });
});

// === Age ===

describe('kernelAge / ageSeverity', () => {
  it('measures a 2.6 kernel from the curated series date and flags it pre-modern', () => {
    const v = parseKernelVersion('2.6.31') as NonNullable<ReturnType<typeof parseKernelVersion>>;
    const age = kernelAge(v, NOW, 2026);
    expect(age).toMatchObject({ series: '2.6', seriesReleased: '2003-12', preModern: true });
    expect(age?.years).toBe(22);
    // The banner's own build stamp against the series release — a 2.6 line still being built 23 years later.
    expect(age?.yearsOldAtBuild).toBe(23);
    expect(ageSeverity(age as NonNullable<typeof age>)).toBe('critical');
  });

  it('measures a 5.4 kernel as mid-aged rather than pre-modern', () => {
    const v = parseKernelVersion('5.4.213') as NonNullable<ReturnType<typeof parseKernelVersion>>;
    const age = kernelAge(v, NOW);
    expect(age).toMatchObject({ series: '5.4', seriesReleased: '2019-11', preModern: false, years: 6 });
    expect(ageSeverity(age as NonNullable<typeof age>)).toBe('medium');
  });

  it('falls back to the major line for an uncurated series, and refuses to guess a future major', () => {
    const v = parseKernelVersion('4.7.3') as NonNullable<ReturnType<typeof parseKernelVersion>>;
    expect(kernelAge(v, NOW)?.seriesReleased).toBe('2015-04');
    const alien = parseKernelVersion('99.1.0') as NonNullable<ReturnType<typeof parseKernelVersion>>;
    expect(kernelAge(alien, NOW)).toBeNull();
  });
});

// === Findings ===

function shell(over: Partial<Parameters<typeof postureFindings>[0]> = {}): Parameters<typeof postureFindings>[0] {
  return {
    available: true,
    located: true,
    version: '2.6.31',
    versionSource: 'kernel-banner',
    versionConflicts: [],
    banner: null,
    bannerPath: null,
    configPath: null,
    rootfsPath: null,
    rootfsDiscovered: false,
    blob: null,
    modules: null,
    age: null,
    answers: [],
    searched: [],
    bounds: [],
    reason: '',
    ...over,
  };
}

describe('postureFindings', () => {
  it('turns a kernel it could not find into blocked_by_platform carrying what it looked for — never an empty list', () => {
    const drafts = postureFindings(shell({ located: false, version: null, searched: ['the raw image x.bin'] }));
    expect(drafts).toHaveLength(1);
    expect(drafts[0]).toMatchObject({ kind: 'kernel-not-located', proofState: 'blocked_by_platform' });
    expect((drafts[0]?.evidence as { searched: string[] }).searched).toContain('the raw image x.bin');
  });

  it('always records the questions it could not answer, so a short list never reads as "clean"', () => {
    const answers = assessPosture(evidence());
    const drafts = postureFindings(shell({ answers }));
    const undetermined = drafts.find((d) => d.kind === 'kernel-posture-undetermined');
    expect(undetermined?.proofState).toBe('blocked_by_platform');
    expect(undetermined?.severity).toBe('info');
    expect(undetermined?.title).toContain(`of ${answers.length}`);
    expect(undetermined?.rationale).toContain('not a passing answer');
  });

  it('raises /dev/kmem at HIGH / static_confirmed with a title that reads correctly for an inverted question', () => {
    const answers = assessPosture(evidence({ blob: factsFrom({ kmem: true, siblings: true }) }));
    const drafts = postureFindings(shell({ answers }));
    const kmem = drafts.find((d) => d.kind === 'kernel-devkmem');
    expect(kmem?.severity).toBe('high');
    expect(kmem?.proofState).toBe('static_confirmed');
    expect(kmem?.title).toContain('/dev/kmem is compiled in');
  });

  it('never raises a finding for a question that came back undetermined', () => {
    const answers = assessPosture(evidence());
    const drafts = postureFindings(shell({ answers }));
    expect(drafts.some((d) => d.kind === 'kernel-kaslr')).toBe(false);
  });

  it('states the age without naming a CVE', () => {
    const v = parseKernelVersion('2.6.31') as NonNullable<ReturnType<typeof parseKernelVersion>>;
    const age = kernelAge(v, NOW, 2026);
    const drafts = postureFindings(shell({ age }));
    const ageDraft = drafts.find((d) => d.kind === 'kernel-age');
    expect(ageDraft?.severity).toBe('critical');
    expect(ageDraft?.proofState).toBe('static_confirmed');
    expect(ageDraft?.rationale).toContain('not this one');
    expect(ageDraft?.rationale).not.toMatch(/CVE-\d/);
  });

  it('reports a version disagreement rather than resolving it', () => {
    const drafts = postureFindings(
      shell({
        versionConflicts: [{ a: '5.4.213', aSource: 'lib-modules-dir', b: '4.4.0', bSource: 'kernel-banner' }],
      }),
    );
    const conflict = drafts.find((d) => d.kind === 'kernel-version-conflict');
    expect(conflict?.title).toContain('5.4.213 vs 4.4.0');
    expect(conflict?.rationale).toContain('reported rather than resolved');
  });
});

// === Bounds ===

describe('selectKernelBlobs', () => {
  const sizes: Record<string, number> = {
    '/x/20400': 2_496_348,
    '/x/20400.7z': 3_931_648,
    '/x/4254': 114_032,
    '/x/100200.squashfs': 2_989_066,
    '/x/530FE': 2_650_112,
    '/x/piggy': 1_000_000,
  };

  it('keeps decompressed, extension-less blobs in the size band and drops the compressed siblings', () => {
    const { chosen } = selectKernelBlobs(Object.keys(sizes), (p) => sizes[p] ?? 0);
    expect(chosen).toEqual(['/x/530FE', '/x/20400', '/x/piggy']);
    // The 114 KB fragment is under the band; the .7z / .squashfs siblings are containers, never a kernel.
    expect(chosen).not.toContain('/x/4254');
    expect(chosen).not.toContain('/x/20400.7z');
  });

  it('orders largest-first and reports what the cap dropped, so the set is not a directory-order artefact', () => {
    const many = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`/x/${i}`, 300_000 + i]));
    const { chosen, dropped } = selectKernelBlobs(Object.keys(many), (p) => many[p] ?? 0);
    expect(chosen).toHaveLength(12);
    expect(chosen[0]).toBe('/x/19');
    expect(dropped).toBe(8);
  });
});

describe('extractPrintable', () => {
  it('splits NUL-separated runs into exact tokens and a searchable text', () => {
    const NUL = '\u0000';
    const { tokens, text } = extractPrintable(Buffer.from(`kmem${NUL}null${NUL}Kernel panic - not syncing`, 'latin1'));
    expect(tokens.has('kmem')).toBe(true);
    expect(tokens.has('null')).toBe(true);
    // The phrase survives for substring markers, and its words become tokens too.
    expect(text).toContain('Kernel panic');
    expect(tokens.has('syncing')).toBe(true);
  });
});

// === The runner, end to end ===

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-kernelposture-'));
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

/** A blob shaped like a real decompressed kernel: NUL-separated strings, banner included. */
function writeKernelBlob(at: string, banner: string, extra: string[]): void {
  const NUL = '\u0000';
  const body = ['Kernel panic - not syncing: %s', 'swapper', banner, ...extra].join(NUL);
  // Pad past the 256 KiB candidate floor with NULs, the way the tail of a real kernel image reads.
  fs.writeFileSync(at, Buffer.concat([Buffer.from(body, 'latin1'), Buffer.alloc(300 * 1024)]));
}

describe('runKernelPosture', () => {
  it('reads the banner out of a carved blob and never out of a rootfs binary that merely mentions one', () => {
    const root = path.join(tmp, 'be3600');
    const extract = path.join(root, 'extract');
    const rootfs = path.join(root, 'rootfs');
    fs.mkdirSync(extract, { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'usr/sbin'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'lib/modules/5.4.213'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'etc/sysctl.d'), { recursive: true });

    // The decoy: a Go binary carrying its own reference banner, exactly as tailscaled does in the real rootfs.
    fs.writeFileSync(path.join(rootfs, 'usr/sbin/tailscaled'), Buffer.alloc(400 * 1024, 0x41));
    fs.appendFileSync(path.join(rootfs, 'usr/sbin/tailscaled'), BANNERS.tailscaledDecoy);

    // An unsigned module set, which is what really answers module signing here.
    fs.writeFileSync(
      path.join(rootfs, 'lib/modules/5.4.213/act_gact.ko'),
      Buffer.from('\u0000vermagic=5.4.213 SMP preempt mod_unload aarch64\u0000', 'latin1'),
    );
    fs.writeFileSync(path.join(rootfs, 'etc/sysctl.d/10-default.conf'), 'kernel.kptr_restrict = 1\n');

    writeKernelBlob(
      path.join(extract, '1A4'),
      'Linux version 5.4.213 (gl@build) (gcc version 9.3.0) #1 Mon Jan 6 00:00:00 UTC 2025',
      ['null', 'full', 'urandom', 'module.sig_enforce'],
    );
    const image = path.join(root, 'fw.bin');
    fs.writeFileSync(image, Buffer.alloc(1024));

    const r = runKernelPosture(image, rootfs, extract, NOW);
    expect(r.located).toBe(true);
    expect(r.version).toBe('5.4.213');
    expect(r.versionSource).toBe('kernel-banner');
    // The decoy version must appear nowhere — not as the answer and not as a reported conflict.
    expect(r.versionConflicts).toHaveLength(0);
    expect(JSON.stringify(r)).not.toContain('4.4.0');

    expect(r.modules).toMatchObject({ versionDir: '5.4.213', vermagic: '5.4.213', signedCount: 0 });
    const sig = r.answers.find((a) => a.id === 'module-sig');
    expect(sig).toMatchObject({ verdict: 'off', source: 'shipped-modules' });
    const kmem = r.answers.find((a) => a.id === 'devkmem');
    expect(kmem).toMatchObject({ verdict: 'off', source: 'kernel-blob' });
    const kptr = r.answers.find((a) => a.id === 'kptr-restrict');
    expect(kptr).toMatchObject({ verdict: 'on', source: 'rootfs-sysctl' });
    expect(r.findings.some((f) => f.kind === 'kernel-posture-undetermined')).toBe(true);
  });

  /**
   * The regression the deployed corpus exposed. The GL.iNet BE3600's extracted rootfs lives INSIDE the extraction
   * output directory (`<outputDir>/carve/rootfs`), and `usr/sbin/tailscaled` there is a 30 MB extension-less Go
   * binary carrying its own `Linux version 4.4.0 …` string. The test above builds the rootfs BESIDE the extraction
   * directory, which is not what the extractor does — so it agreed with the code instead of checking it, and the
   * provider's first run against real bytes reported the decoy's 4.4.0 as the kernel of a 5.4.213 device.
   */
  it('never reads a banner out of a rootfs binary, even when the rootfs sits inside the extraction output', () => {
    const at = path.join(tmp, 'be3600-real-layout');
    const extract = path.join(at, 'extract');
    const rootfs = path.join(extract, 'carve/rootfs');
    fs.mkdirSync(path.join(rootfs, 'usr/sbin'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'bin'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'sbin'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'lib/modules/5.4.213'), { recursive: true });

    // Sized past the candidate floor and carrying a kernel anchor, so only the pruning rule can keep it out.
    fs.writeFileSync(path.join(rootfs, 'usr/sbin/tailscaled'), Buffer.alloc(400 * 1024, 0x41));
    fs.appendFileSync(path.join(rootfs, 'usr/sbin/tailscaled'), `Kernel panic ${BANNERS.tailscaledDecoy}`);
    fs.writeFileSync(
      path.join(rootfs, 'lib/modules/5.4.213/act_gact.ko'),
      Buffer.from('\u0000vermagic=5.4.213 SMP preempt mod_unload aarch64\u0000', 'latin1'),
    );
    writeKernelBlob(
      path.join(extract, '1A4'),
      'Linux version 5.4.213 (gl@build) (gcc version 9.3.0) #1 Mon Jan 6 00:00:00 UTC 2025',
      ['null', 'full', 'urandom', 'module.sig_enforce'],
    );
    const image = path.join(at, 'fw.bin');
    fs.writeFileSync(image, Buffer.alloc(1024));

    const r = runKernelPosture(image, rootfs, extract, NOW);
    expect(r.version).toBe('5.4.213');
    expect(r.bannerPath).toBe(path.join(extract, '1A4'));
    expect(JSON.stringify(r)).not.toContain('4.4.0');
    expect(JSON.stringify(r)).not.toContain('tailscaled');
  });

  /**
   * The BE3600's stored extraction really does record `rootfsPath: null` while `carve/rootfs` sits on disk. Without
   * the discovery step the device comes back "no kernel located"; with it, the shipped module set still answers both
   * the version and module signing — and the result says where that tree came from.
   */
  it('recognises an extracted filesystem root when the caller had no rootfs to give, and says that it did', () => {
    const at = path.join(tmp, 'be3600-discovered');
    const extract = path.join(at, 'extract');
    const rootfs = path.join(extract, 'carve/rootfs');
    fs.mkdirSync(path.join(rootfs, 'usr/sbin'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'bin'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'etc'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'lib/modules/5.4.213'), { recursive: true });
    fs.writeFileSync(path.join(rootfs, 'usr/sbin/tailscaled'), Buffer.alloc(400 * 1024, 0x41));
    fs.appendFileSync(path.join(rootfs, 'usr/sbin/tailscaled'), `Kernel panic ${BANNERS.tailscaledDecoy}`);
    fs.writeFileSync(
      path.join(rootfs, 'lib/modules/5.4.213/act_gact.ko'),
      Buffer.from('\u0000vermagic=5.4.213 SMP preempt mod_unload aarch64\u0000', 'latin1'),
    );
    const image = path.join(at, 'fw.bin');
    fs.writeFileSync(image, Buffer.alloc(1024));

    const r = runKernelPosture(image, null, extract, NOW);
    expect(r.located).toBe(true);
    expect(r.rootfsDiscovered).toBe(true);
    expect(r.rootfsPath).toBe(rootfs);
    expect(r.version).toBe('5.4.213');
    expect(r.versionSource).toBe('module-vermagic');
    expect(r.searched.some((s) => s.includes('recognised in the extraction output'))).toBe(true);
    expect(JSON.stringify(r)).not.toContain('4.4.0');
    // No kernel image at all → every marker-backed question is undetermined, and says which reason applies.
    expect(r.answers.find((a) => a.id === 'devkmem')).toMatchObject({ verdict: 'unknown', reason: 'no-kernel-blob' });
    expect(r.answers.find((a) => a.id === 'module-sig')).toMatchObject({ verdict: 'off', source: 'shipped-modules' });
  });

  it('falls back to the raw image, and still answers when there is no rootfs at all', () => {
    const root = path.join(tmp, 'raw-only');
    fs.mkdirSync(root, { recursive: true });
    const image = path.join(root, 'fw.bin');
    writeKernelBlob(image, BANNERS.dvrf, ['kmem', 'null', 'full', 'urandom']);

    const r = runKernelPosture(image, null, null, NOW);
    expect(r.located).toBe(true);
    expect(r.version).toBe('2.6.22');
    expect(r.age).toMatchObject({ preModern: true });
    expect(r.findings.find((f) => f.kind === 'kernel-devkmem')?.severity).toBe('high');
    expect(r.searched.some((s) => s.includes('no rootfs was available'))).toBe(true);
  });

  it('says it found nothing, and what it looked for, rather than returning a clean result', () => {
    const root = path.join(tmp, 'nothing');
    fs.mkdirSync(root, { recursive: true });
    const image = path.join(root, 'blob.bin');
    fs.writeFileSync(image, Buffer.alloc(64 * 1024, 0x5a));

    const r = runKernelPosture(image, null, null, NOW);
    expect(r.located).toBe(false);
    expect(r.answers).toHaveLength(0);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ kind: 'kernel-not-located', proofState: 'blocked_by_platform' });
    expect(r.reason).toContain('not a clean result');
  });

  it('prefers a shipped kernel config over every inferred source and records where it came from', () => {
    const root = path.join(tmp, 'with-config');
    const rootfs = path.join(root, 'rootfs');
    fs.mkdirSync(path.join(rootfs, 'proc'), { recursive: true });
    const cfg = [
      '# Automatically generated file; DO NOT EDIT.',
      '# Linux/arm 4.9.84 Kernel Configuration',
      'CONFIG_DEVKMEM=y',
      '# CONFIG_STRICT_DEVMEM is not set',
      '',
    ].join('\n');
    fs.writeFileSync(path.join(rootfs, 'proc/config.gz'), zlib.gzipSync(Buffer.from(cfg)));
    const image = path.join(root, 'fw.bin');
    fs.writeFileSync(image, Buffer.alloc(1024));

    const r = runKernelPosture(image, rootfs, null, NOW);
    expect(r.configPath).toBe('proc/config.gz');
    expect(r.version).toBe('4.9.84');
    expect(r.versionSource).toBe('kernel-config');
    expect(r.answers.find((a) => a.id === 'devkmem')).toMatchObject({ verdict: 'on', source: 'kernel-config' });
    expect(r.answers.find((a) => a.id === 'strict-devmem')).toMatchObject({ verdict: 'off', source: 'kernel-config' });
  });
});
