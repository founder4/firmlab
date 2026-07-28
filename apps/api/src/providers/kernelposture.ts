/**
 * Kernel posture — the security properties of the kernel that every other analysis in this workbench runs *on top of*.
 *
 * The binary-hardening lane measures NX/canary/PIC per userland ELF and the component lane matches userland versions
 * to CVEs; neither has ever looked at the kernel underneath them. A firmware shipping Linux 2.6.31 with `/dev/kmem`
 * compiled in and an unsigned module set is a durable, fully static, honest finding, and it is the layer that decides
 * whether any userland mitigation means anything at all.
 *
 * WHAT THIS REFUSES TO CLAIM — this provider's failure mode is manufacturing a negative, so most of its shape exists
 * to stop that:
 *
 *  - **The absence of a `CONFIG_` string is not the absence of the feature.** Measured across the corpus, a
 *    `CONFIG_*` token scan of a decompressed kernel is worthless as an oracle: the 2.6.22/2.6.31 vendor kernels
 *    carry ZERO uppercase `CONFIG_` tokens, and the two 4.x kernels carry three between them — of which
 *    `CONFIG_KALLSYMS` occurs only inside the printk `"initcall_blacklist requires CONFIG_KALLSYMS"`. A token
 *    lifted out of a diagnostic message is not a setting. Loose tokens are therefore recorded as an observation and
 *    are NEVER consulted by `assessPosture`; see `LOOSE_CONFIG_TOKENS_ARE_NOT_EVIDENCE`. What a kernel really
 *    carries is symbol names and printk fragments, and those are what the marker set is built from.
 *  - **An answer only becomes `off` when an anchor proves we were looking in the right place.** `/dev/kmem` is
 *    decided from the `drivers/char/mem.c` device-name table, and only when its siblings (`null`, `full`,
 *    `urandom`, …) are visible in the same blob — that is what turns "we did not see `kmem`" into "`kmem` is not in
 *    the table". Without the anchor the answer stays undetermined, because a string scan of a blob that is still
 *    compressed reads whatever happened to survive.
 *  - **An option that postdates the kernel is not an option that is off.** KASLR did not exist in 2.6.31; reporting
 *    "KASLR disabled" there is a category error. Those answers come back undetermined with the reason
 *    `option-postdates-kernel`, and the version gate runs BEFORE any marker is consulted. The mirror of that trap is
 *    just as real and cost this file a rewrite: `/dev/kmem` predates the `CONFIG_DEVKMEM` switch that turns it off,
 *    so gating the *device* on the *option's* introduction (2.6.26) would have reported the DVRF's 2.6.22 kernel —
 *    which demonstrably ships `kmem` — as "the option does not exist here", hiding a worse fact behind an honest
 *    -sounding one. `since` is therefore the version the FEATURE exists from, and `notConfigurableBefore` records
 *    separately that there was no way to turn it off.
 *  - **Where the answer came from travels with it.** A shipped `.config` and a string in a blob are different
 *    evidentiary standards, exactly as `sbom` and `compcve` findings are labelled by source.
 *  - **No exploitability, no CVE ids.** "This version is inside the affected range of X" is `compcve`/`sbom` work.
 *    The claim here is the posture that is literally in the bytes, plus the age arithmetic that follows from the
 *    version number alone.
 *  - **A kernel that could not be located is `blocked_by_platform`**, carrying what was looked for — never an empty
 *    findings list, which would read as "the kernel is fine".
 *
 * The banner is deliberately NOT searched for across rootfs files. `usr/sbin/tailscaled` in the GL.iNet BE3600
 * rootfs contains the literal string `Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016`, and
 * `usr/share/ucode/fw4.uc` contains a regex that matches banners — a naive rootfs grep reports a 4.4.0 kernel for a
 * device whose modules say 5.4.213. Banners are taken from carved/decompressed blobs, the raw image and `/boot`
 * only; the rootfs contributes its version through `lib/modules/<version>/` and `.ko` vermagic, which cannot be
 * confused with a mention inside a Go binary. When two sources disagree anyway, the disagreement is reported rather
 * than resolved.
 *
 * That rule was true when written and false in practice, which is the trap this codebase has paid for twice
 * already. The first run against the deployed corpus reported the BE3600 as kernel **4.4.0, source
 * `kernel-banner`, path `…/carve/rootfs/usr/sbin/tailscaled`** — because the extracted rootfs lives INSIDE the
 * extraction output directory the blob search enumerates, and a 30 MB extension-less Go binary is indistinguishable
 * from a decompressed kernel by name and size alone. The unit test had put the rootfs beside the extraction
 * directory instead of inside it, so it agreed with the code rather than checking it. `walkExtraction` now prunes
 * every extracted filesystem root out of the blob candidates, recognising them by the same marker directories
 * `extract.ts` uses, and hands them back so a caller that had no rootfs still gets its module set read.
 *
 * Everything that decides anything is pure and exported (banner/vermagic/config parsing, the version gate, the
 * assessment, the findings). The runner only walks directories and reads bounded prefixes.
 */
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import type { FindingSeverity } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';

/**
 * Named so the rule is greppable from outside this file: loose `CONFIG_*` tokens recovered from a kernel blob are
 * surfaced as an observation and never consulted by `assessPosture`. Validated on real bytes — see the module doc.
 */
export const LOOSE_CONFIG_TOKENS_ARE_NOT_EVIDENCE = true;

// === Version ===

/** A kernel version reduced to the three numbers the version gate compares on, plus the raw token it came from. */
export interface KernelVersion {
  major: number;
  minor: number;
  patch: number;
  /** `major.minor` — the maintenance series, which is what decides whether upstream still touches this code. */
  series: string;
  /** The full token as it appeared, local version and all (`2.6.31-gdb94342-dirty`). */
  raw: string;
}

/** Pure: read a `2.6.31-gdb94342-dirty` / `5.4.213` / `2.6.31--LSDK-9.2.0_U6.616` token into comparable numbers. */
export function parseKernelVersion(token: string): KernelVersion | null {
  const m = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(token.trim());
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = m[3] === undefined ? 0 : Number(m[3]);
  return { major, minor, patch, series: `${major}.${minor}`, raw: token.trim() };
}

/** A `[major, minor, patch?]` bound the version gate compares against. */
export type VersionBound = readonly [number, number, number?];

/** Pure: -1 / 0 / 1 comparing a kernel version against a `[major, minor, patch?]` bound. */
export function compareVersion(v: KernelVersion, to: VersionBound): number {
  const pairs: Array<[number, number]> = [
    [v.major, to[0]],
    [v.minor, to[1]],
    [v.patch, to[2] ?? 0],
  ];
  for (const [a, b] of pairs) {
    if (a !== b) return a < b ? -1 : 1;
  }
  return 0;
}

/** Render a bound the way an operator reads it (`2.6.26`, `3.14`). */
function boundText(b: VersionBound): string {
  return b[2] === undefined ? `${b[0]}.${b[1]}` : `${b[0]}.${b[1]}.${b[2]}`;
}

// === The banner ===

/** A decoded `Linux version …` banner. Every field is optional except the version — vendors truncate differently. */
export interface KernelBanner {
  /** The version token exactly as the banner spells it, local version included. */
  version: string;
  numeric: KernelVersion;
  /** `user@host` of the machine that built it. */
  builder?: string;
  /** `gcc version 4.3.3` / `clang version …` — the toolchain dates the build as much as the version does. */
  toolchain?: string;
  /** The `#N` build counter. */
  buildNumber?: number;
  /** The build date as the banner spells it (`Thu May 28 10:36:36 CST 2026`). */
  buildDate?: string;
  /** The build year, parsed out of `buildDate` — the only part the age arithmetic uses. */
  buildYear?: number;
  raw: string;
}

const BANNER_ANCHOR = 'Linux version ';
const DAY = '(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)';
const BANNER_DATE_RE = new RegExp(`(${DAY}\\s+\\w{3}\\s+\\d{1,2}\\s+[\\d:]{4,8}(?:\\s+[A-Z]{2,5})?\\s+(\\d{4}))`);

/**
 * Pure: decode a kernel banner out of a chunk of text. Anchors on `Linux version ` followed by a DOTTED version —
 * that requirement is what stops `"Linux version unknown"`-style strings from becoming a result. Returns null when
 * no banner is present.
 *
 * Validated against every banner shape in the corpus, which differ more than the format suggests:
 *   `Linux version 2.6.31-gdb94342-dirty (tplink@…) (gcc version 4.3.3 (GCC) ) #1 Thu May 28 10:36:36 CST 2026`
 *   `Linux version 2.6.31--LSDK-9.2.0_U6.616 (root@liaozhiming) (gcc version 4.3.3 (GCC) ) #1 Mon May 18 … 2015`
 *   `Linux version 4.9.84 (jenkins@…) (gcc version 4.9.4 (Buildroot 2017.08-gc7bbae9-dirty) ) #6 PREEMPT Fri … 2023`
 *   `Linux version 2.6.22 (root@localhost.localdomain) (gcc version 4.2.3) #4 Wed Mar 9 02:05:36 CST 2016`
 *   `Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016`   ← no parens at all (a Go binary's embedded copy)
 * The last one parses fine; it is excluded by WHERE a banner may be read from, not by the parser.
 */
export function parseKernelBanner(text: string): KernelBanner | null {
  const at = text.indexOf(BANNER_ANCHOR);
  if (at < 0) return null;
  const window = text.slice(at, at + 320);
  const vm = /^Linux version (\d+\.\d+(?:\.\d+)?\S*)/.exec(window);
  if (!vm?.[1]) return null;
  const versionToken = vm[1];
  const numeric = parseKernelVersion(versionToken);
  if (!numeric) return null;

  const tail = window.slice(vm[0].length);
  // Cut the raw banner at the first control character so a neighbouring string in the blob cannot bleed into it.
  // Scanned by char code rather than by a regex character class: a control-character class is exactly the shape
  // CLAUDE.md warns about, and biome refuses it outright — for good reason, since the literal-byte version of
  // that same class is what put a NUL into this file's first draft.
  let ctrl = -1;
  for (let i = 0; i < window.length; i++) {
    if (window.charCodeAt(i) < 0x20) {
      ctrl = i;
      break;
    }
  }
  const raw = (ctrl < 0 ? window : window.slice(0, ctrl)).trim();

  const banner: KernelBanner = { version: versionToken, numeric, raw };

  const bm = /^\s*\(([^()]{1,120})\)/.exec(tail);
  if (bm?.[1]) banner.builder = bm[1].trim();

  const tm = /((?:gcc|clang|GCC|Clang)\s+version\s+[^()]{1,80})/.exec(tail);
  if (tm?.[1]) banner.toolchain = tm[1].trim();

  const nm = /#(\d+)/.exec(tail);
  if (nm?.[1]) banner.buildNumber = Number(nm[1]);

  const dm = BANNER_DATE_RE.exec(tail);
  if (dm?.[1] && dm[2]) {
    banner.buildDate = dm[1].trim();
    banner.buildYear = Number(dm[2]);
  }
  return banner;
}

/** Pure: read the version out of a module's `vermagic=` (`vermagic=5.4.213 SMP preempt mod_unload aarch64`). */
export function parseVermagic(text: string): string | null {
  return /vermagic=(\d+\.\d+(?:\.\d+)?\S*)/.exec(text)?.[1] ?? null;
}

// === A shipped kernel configuration — the authoritative source ===

/**
 * Pure: parse a kernel `.config` (the text inside `/proc/config.gz`, `/boot/config-*`, a shipped `.config`, or an
 * IKCONFIG segment). `CONFIG_X=y`/`=m`/`="str"` become the value; `# CONFIG_X is not set` becomes `n`, which is the
 * line that makes a config authoritative — it is the only source in this provider that states a negative directly
 * rather than by inference.
 */
export function parseKernelConfig(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const unset = /^#\s*(CONFIG_[A-Z0-9_]+)\s+is not set\s*$/.exec(line);
    if (unset?.[1]) {
      out[unset[1]] = 'n';
      continue;
    }
    const set = /^(CONFIG_[A-Z0-9_]+)=(.*)$/.exec(line);
    if (set?.[1]) out[set[1]] = (set[2] ?? '').trim();
  }
  return out;
}

/** Does this text read as a kernel `.config`, rather than some other file that happens to be called `config`? */
export function looksLikeKernelConfig(text: string): boolean {
  return /^#\s*Automatically generated/m.test(text) || /^CONFIG_[A-Z0-9_]+=/m.test(text);
}

/**
 * Pure: the kernel version out of a generated `.config`'s header comment — kconfig writes either
 * `# Linux/mips 2.6.31 Kernel Configuration` or `# Linux kernel version: 2.6.31`. There is no `CONFIG_` symbol
 * carrying the version, so the comment is the only place a config states it.
 */
export function parseConfigVersion(text: string): string | null {
  const head = text.slice(0, 2048);
  return (
    /^#\s*Linux(?:\/\S+)?\s+(\d+\.\d+(?:\.\d+)?\S*)\s+Kernel Configuration/m.exec(head)?.[1] ??
    /^#\s*Linux kernel version:\s*(\d+\.\d+(?:\.\d+)?\S*)/m.exec(head)?.[1] ??
    null
  );
}

// === What a decompressed kernel blob actually tells us ===

/**
 * The markers this provider trusts, each confirmed present-or-absent across the corpus rather than assumed. They are
 * symbol names and printk fragments, not `CONFIG_` tokens, because those are what a kernel really carries.
 */
export interface KernelBlobFacts {
  /** Where the blob was read from. */
  path: string;
  /**
   * The blob's `.rodata` is readable — proven by universal kernel strings (`Kernel panic`, …). Without this the blob
   * is still compressed or is not a kernel, and no absence in it may be read as an `off`.
   */
  readable: boolean;
  /** The `drivers/char/mem.c` device-name table is visible (≥2 of its non-`kmem` entries) — the `/dev/kmem` anchor. */
  memDevlistAnchored: boolean;
  /** `kmem` present as a standalone entry in that table → `/dev/kmem` is compiled in. */
  hasKmemEntry: boolean;
  /** `__stack_chk_fail`/`__stack_chk_guard` → the kernel itself was built with the stack protector. */
  hasStackProtector: boolean;
  /** The `module.sig_enforce` boot parameter exists → `CONFIG_MODULE_SIG` is compiled in. */
  hasModuleSigParam: boolean;
  /** `kptr_restrict` / `dmesg_restrict` exist as sysctls in this kernel. */
  hasKptrRestrictSysctl: boolean;
  hasDmesgRestrictSysctl: boolean;
  /** A KASLR boot parameter (`nokaslr`) is recognised. */
  hasKaslrParam: boolean;
  /** The read-only-data write-protect printk exists → `CONFIG_STRICT_KERNEL_RWX`/`DEBUG_RODATA` compiled in. */
  hasRodataWriteProtect: boolean;
  /** The `/dev/mem` range-check diagnostic → `CONFIG_STRICT_DEVMEM` compiled in. */
  hasStrictDevmemDiag: boolean;
  /** An embedded IKCONFIG segment is present (`CONFIG_IKCONFIG` → the kernel carries its own gzipped `.config`). */
  ikconfigPresent: boolean;
  /** Loose `CONFIG_*` tokens. Recorded for the operator; never consulted — see the module doc. */
  looseConfigTokens: string[];
}

/** Sibling entries of `kmem` in `drivers/char/mem.c`'s device list — the anchor set. */
const MEM_DEVLIST_SIBLINGS = ['null', 'zero', 'full', 'random', 'urandom', 'kmsg', 'port'];
/** Strings a real, decompressed Linux kernel always carries. Two of these prove the blob's `.rodata` is readable. */
const KERNEL_ANCHORS = ['Kernel panic', 'Linux version ', 'swapper', 'Freeing unused', 'Out of memory'];

/**
 * Pure: derive the trusted markers from a blob's printable strings.
 *
 * `tokens` is the set of NUL/whitespace-delimited printable runs (needed for the exact-match device-table entries —
 * `kmem` must be its own entry, not a substring of some `vmalloc_kmem`), and `text` is the same runs joined, for the
 * phrase markers. The split matters: the entire value of the `/dev/kmem` signal is that it is an exact table entry.
 */
export function readKernelBlobFacts(blobPath: string, tokens: ReadonlySet<string>, text: string): KernelBlobFacts {
  const anchors = KERNEL_ANCHORS.filter((a) => text.includes(a)).length;
  const siblings = MEM_DEVLIST_SIBLINGS.filter((s) => tokens.has(s)).length;
  const loose = [...new Set(text.match(/CONFIG_[A-Z0-9_]{2,48}/g) ?? [])].sort();
  return {
    path: blobPath,
    readable: anchors >= 2,
    memDevlistAnchored: siblings >= 2,
    hasKmemEntry: tokens.has('kmem'),
    hasStackProtector: tokens.has('__stack_chk_fail') || tokens.has('__stack_chk_guard'),
    hasModuleSigParam: text.includes('module.sig_enforce') || tokens.has('sig_enforce'),
    hasKptrRestrictSysctl: tokens.has('kptr_restrict'),
    hasDmesgRestrictSysctl: tokens.has('dmesg_restrict'),
    hasKaslrParam: tokens.has('nokaslr'),
    hasRodataWriteProtect: text.includes('Write protecting') || tokens.has('mark_rodata_ro'),
    hasStrictDevmemDiag: text.includes('tried to access /dev/mem') || tokens.has('devmem_is_allowed'),
    ikconfigPresent: text.includes('IKCFG_ST'),
    looseConfigTokens: loose.slice(0, 40),
  };
}

// === The shipped module set ===

/** What the `.ko` files in the rootfs say — a source that survives a kernel blob nobody could decompress. */
export interface ModuleEvidence {
  /** The version directory name under `lib/modules/`. */
  versionDir: string | null;
  /** A version read out of a module's `vermagic=` — the strongest version evidence a rootfs alone can give. */
  vermagic: string | null;
  moduleCount: number;
  /** How many of the inspected modules carried the `~Module signature appended~` trailer. */
  signedCount: number;
  /** How many were actually opened (the sampling bound). */
  inspectedCount: number;
  /** Where the inspected modules came from. Optional forever — absent on every result stored before this pass. */
  provenance?: ModuleProvenance;
}

/** What one `.ko`'s `.modinfo` says about where it came from. All optional: a stripped module says nothing. */
export interface ModinfoFacts {
  /** `intree=Y` — set by the kernel build system for a module built inside the kernel tree. */
  intree?: boolean;
  license?: string;
  name?: string;
}

/**
 * Pure: read the `.modinfo` key=value pairs out of a module's bytes. They are NUL-separated ASCII in a dedicated
 * section, so the printable-string scan finds them without a section-header walk — which matters, because OpenWrt
 * strips section headers and every module on the corpus's richest image reports `e_shoff == 0`.
 */
export function parseModinfo(text: string): ModinfoFacts {
  const out: ModinfoFacts = {};
  const intree = readModinfoValue(text, 'intree');
  if (intree !== null) out.intree = intree === 'Y' || intree === 'y';
  const license = readModinfoValue(text, 'license');
  if (license) out.license = license;
  const name = readModinfoValue(text, 'name');
  if (name) out.name = name;
  return out;
}

/**
 * Read one `key=value` record out of a `.modinfo` blob, stopping at the NUL that ends it.
 *
 * Deliberately not a regular expression. The value legitimately contains spaces (`Dual BSD/GPL`, `GPL v2`), so a
 * whitespace-terminated match truncates the licence that matters most; and the correct terminator is a control
 * character, which a regex cannot carry here without tripping `noControlCharactersInRegex` — a rule worth obeying
 * rather than suppressing, since scanning for a NUL by hand is both clearer and closer to what the format is:
 * NUL-separated records, not prose to pattern-match over.
 */
function readModinfoValue(text: string, key: string, maxLen = 64): string | null {
  const needle = `${key}=`;
  let from = 0;
  while (from < text.length) {
    const at = text.indexOf(needle, from);
    if (at === -1) return null;
    // A record starts at the beginning of the blob or just after a NUL; anything else is a coincidental substring
    // inside another string (`filename=`, `parmtype=`), which must not be mistaken for the key.
    const prev = at === 0 ? 0 : text.charCodeAt(at - 1);
    if (at !== 0 && prev !== 0) {
      from = at + needle.length;
      continue;
    }
    const start = at + needle.length;
    let end = start;
    while (end < text.length && end - start < maxLen && text.charCodeAt(end) !== 0) end++;
    return text.slice(start, end).trim();
  }
  return null;
}

/** Where the shipped modules came from, and whether that question could be answered at all. */
export interface ModuleProvenance {
  inTree: number;
  outOfTree: number;
  /** Modules carrying no `intree=` tag in a build that uses the tag elsewhere is out-of-tree; see below. */
  indeterminate: number;
  /** True when NO inspected module carried an `intree=` tag, so the build does not use it and nothing is decided. */
  tagUnused: boolean;
  /** Names of out-of-tree modules, bounded, so the finding can quote rather than assert. */
  outOfTreeNames: string[];
  /** Modules declaring a non-GPL-compatible licence — these taint the kernel. */
  proprietary: string[];
}

/**
 * Pure: decide module provenance from the SET, never from a remembered kernel version.
 *
 * `intree=Y` is written by the kernel build system, so its absence is meaningful — but only in a build that emits
 * the tag at all. The tag postdates the oldest kernels in this corpus (DVRF ships 2.6.22), and hard-coding the
 * version it arrived in would be exactly the recall-based claim `component-cve.ts` refuses to make about CVE
 * ranges. So the rule calibrates itself: if NOT ONE inspected module carries `intree=`, this build does not use
 * the tag and the question is unanswerable here — every module is `indeterminate` and `tagUnused` says why. Only
 * when the tag IS in use does its absence on a given module mean that module was built outside the tree.
 */
export function assessModuleProvenance(mods: ReadonlyArray<{ file: string; facts: ModinfoFacts }>): ModuleProvenance {
  const tagUnused = !mods.some((m) => m.facts.intree !== undefined);
  const outOfTreeNames: string[] = [];
  const proprietary: string[] = [];
  let inTree = 0;
  let outOfTree = 0;
  let indeterminate = 0;
  for (const m of mods) {
    const label = m.facts.name ?? m.file;
    if (tagUnused) indeterminate++;
    else if (m.facts.intree === true) inTree++;
    else {
      outOfTree++;
      if (outOfTreeNames.length < 24) outOfTreeNames.push(label);
    }
    // A GPL-incompatible licence taints the kernel and is a fact about the string, not a judgement about the code.
    const lic = m.facts.license ?? '';
    if (lic && !/GPL|MIT|BSD|Dual/i.test(lic) && proprietary.length < 24) proprietary.push(`${label} (${lic})`);
  }
  return { inTree, outOfTree, indeterminate, tagUnused, outOfTreeNames, proprietary };
}

/** The trailer `scripts/sign-file` appends to a signed module. Its absence from EVERY module is the useful signal. */
export const MODULE_SIG_TRAILER = '~Module signature appended~';

// === The posture questions ===

export type PostureVerdict = 'on' | 'off' | 'unknown';

/** Why an answer is undetermined. Never collapsed into a bare "no" — that is the whole point of this provider. */
export type UndeterminedReason =
  | 'no-kernel-config-shipped'
  | 'option-postdates-kernel'
  | 'option-removed-upstream'
  | 'no-kernel-blob'
  | 'kernel-blob-not-readable'
  | 'no-marker-evidence'
  | 'kernel-version-unknown';

/** Which standard of evidence produced an answer — a shipped config and a string in a blob are not the same claim. */
export type PostureSource = 'kernel-config' | 'kernel-blob' | 'shipped-modules' | 'rootfs-sysctl';

export interface PostureAnswer {
  id: string;
  /** The upstream Kconfig symbol (or sysctl) the question is about. */
  option: string;
  question: string;
  verdict: PostureVerdict;
  /** Present exactly when `verdict === 'unknown'`. */
  reason?: UndeterminedReason;
  /** Present exactly when `verdict !== 'unknown'`. */
  source?: PostureSource;
  /** The sentence an operator reads: what was found, or what was looked for and why it did not settle it. */
  detail: string;
  /** True when this answer is the dangerous one. */
  bad: boolean;
  /** The title the finding gets when `bad` — written per question so an inverted question still reads correctly. */
  badTitle: string;
  severity: FindingSeverity;
}

interface QuestionSpec {
  id: string;
  option: string;
  question: string;
  /**
   * The version from which the FEATURE this question is about exists at all. Below it the question is unanswerable
   * by construction and the gate returns `option-postdates-kernel`. Note this is the feature, not the Kconfig
   * switch — see `notConfigurableBefore`.
   */
  since: VersionBound;
  /**
   * When the feature predates the switch that turns it off, the version at which it became configurable. Used only
   * to explain the answer: below it, the feature is present and there was no way to disable it.
   */
  notConfigurableBefore?: VersionBound;
  /** The version at which upstream deleted the option, when it did. */
  removedIn?: VersionBound;
  /** Which verdict is the dangerous one. Most questions are `off`; `/dev/kmem` is `on`. */
  badVerdict: 'on' | 'off';
  badTitle: string;
  severity: FindingSeverity;
}

/**
 * The posture questions, each with the kernel version from which the property exists at all. The `since` values are
 * the earliest upstream architecture to get the feature — deliberately the LOWEST bound, so the gate only ever
 * suppresses an answer it is certain is a category error (a MIPS 2.6.31 has no KASLR under any reading; an ARM 4.2
 * might not either, but that is an arch question this provider does not pretend to settle).
 */
const QUESTIONS: readonly QuestionSpec[] = [
  {
    id: 'kaslr',
    option: 'CONFIG_RANDOMIZE_BASE',
    question: 'Is the kernel image loaded at a randomized base address (KASLR)?',
    since: [3, 14],
    badVerdict: 'off',
    badTitle: 'Kernel base address is not randomized (no KASLR)',
    severity: 'medium',
  },
  {
    id: 'strict-devmem',
    option: 'CONFIG_STRICT_DEVMEM',
    question: 'Does /dev/mem refuse access to kernel RAM?',
    since: [2, 6, 26],
    badVerdict: 'off',
    badTitle: '/dev/mem exposes kernel RAM (CONFIG_STRICT_DEVMEM off)',
    severity: 'high',
  },
  {
    id: 'io-strict-devmem',
    option: 'CONFIG_IO_STRICT_DEVMEM',
    question: 'Does /dev/mem also refuse in-use MMIO regions?',
    since: [4, 6],
    badVerdict: 'off',
    badTitle: '/dev/mem exposes in-use MMIO regions (CONFIG_IO_STRICT_DEVMEM off)',
    severity: 'medium',
  },
  {
    id: 'devkmem',
    option: 'CONFIG_DEVKMEM',
    question: 'Is /dev/kmem — a direct window onto kernel virtual memory — compiled in?',
    // The DEVICE, not the switch. /dev/kmem long predates CONFIG_DEVKMEM (2.6.26), which is what made it optional;
    // gating on 2.6.26 would report the DVRF's 2.6.22 kernel — which demonstrably ships `kmem` — as "the option does
    // not exist here", which is true of the switch and dangerously false of the device.
    since: [2, 0],
    notConfigurableBefore: [2, 6, 26],
    removedIn: [5, 13],
    badVerdict: 'on',
    badTitle: '/dev/kmem is compiled in — kernel virtual memory is readable and writable from userland',
    severity: 'high',
  },
  {
    id: 'module-sig',
    option: 'CONFIG_MODULE_SIG',
    question: 'Does the kernel verify a signature before loading a module?',
    since: [3, 7],
    badVerdict: 'off',
    badTitle: 'Kernel modules are not signature-verified',
    severity: 'medium',
  },
  {
    id: 'stackprotector',
    option: 'CONFIG_STACKPROTECTOR',
    question: 'Was the kernel itself built with a stack protector?',
    since: [2, 6, 30],
    badVerdict: 'off',
    badTitle: 'Kernel built without a stack protector',
    severity: 'medium',
  },
  {
    id: 'strict-rwx',
    option: 'CONFIG_STRICT_KERNEL_RWX',
    question: 'Is kernel text/rodata mapped read-only (W^X)?',
    since: [2, 6, 8],
    badVerdict: 'off',
    badTitle: 'Kernel text/rodata is not write-protected (no CONFIG_STRICT_KERNEL_RWX/DEBUG_RODATA)',
    severity: 'medium',
  },
  {
    id: 'kptr-restrict',
    option: 'kernel.kptr_restrict',
    question: 'Are kernel pointers hidden from unprivileged userland?',
    since: [2, 6, 38],
    badVerdict: 'off',
    badTitle: 'Kernel pointers are exposed to unprivileged userland (kptr_restrict = 0)',
    severity: 'low',
  },
  {
    id: 'dmesg-restrict',
    option: 'kernel.dmesg_restrict',
    question: 'Is the kernel log withheld from unprivileged userland?',
    since: [2, 6, 37],
    badVerdict: 'off',
    badTitle: 'The kernel log is readable by unprivileged userland (dmesg_restrict = 0)',
    severity: 'low',
  },
];

/** Every input the assessment is allowed to look at. Nothing else reaches a verdict. */
export interface PostureEvidence {
  version: KernelVersion | null;
  /** A parsed, shipped kernel configuration — authoritative when present. */
  config: Record<string, string> | null;
  /** Where that config came from, for the finding's evidence. */
  configPath: string | null;
  blob: KernelBlobFacts | null;
  modules: ModuleEvidence | null;
  /** `kernel.*` assignments read from the rootfs sysctl files. */
  sysctl: Record<string, string>;
  sysctlPath: string | null;
}

/** Additional Kconfig spellings a shipped config may use for the same property. */
const CONFIG_ALIASES: Readonly<Record<string, readonly string[]>> = {
  CONFIG_STACKPROTECTOR: [
    'CONFIG_CC_STACKPROTECTOR',
    'CONFIG_STACKPROTECTOR_STRONG',
    'CONFIG_CC_STACKPROTECTOR_STRONG',
  ],
  CONFIG_STRICT_KERNEL_RWX: ['CONFIG_DEBUG_RODATA', 'CONFIG_DEBUG_SET_MODULE_RONX'],
  CONFIG_MODULE_SIG: ['CONFIG_MODULE_SIG_ALL', 'CONFIG_MODULE_SIG_FORCE'],
};

function undetermined(q: QuestionSpec, reason: UndeterminedReason, detail: string): PostureAnswer {
  return {
    id: q.id,
    option: q.option,
    question: q.question,
    verdict: 'unknown',
    reason,
    detail,
    bad: false,
    badTitle: q.badTitle,
    severity: q.severity,
  };
}

function determined(q: QuestionSpec, verdict: 'on' | 'off', source: PostureSource, detail: string): PostureAnswer {
  return {
    id: q.id,
    option: q.option,
    question: q.question,
    verdict,
    source,
    detail,
    bad: verdict === q.badVerdict,
    badTitle: q.badTitle,
    severity: q.severity,
  };
}

/** Answer one question from a shipped config, if a config was shipped. */
function answerFromConfig(q: QuestionSpec, ev: PostureEvidence): PostureAnswer | null {
  const cfg = ev.config;
  if (!cfg) return null;
  const names = [q.option, ...(CONFIG_ALIASES[q.option] ?? [])];
  for (const name of names) {
    const value = cfg[name];
    if (value === undefined) continue;
    if (value === 'n') {
      return determined(q, 'off', 'kernel-config', `The shipped kernel config records \`# ${name} is not set\`.`);
    }
    return determined(q, 'on', 'kernel-config', `The shipped kernel config records \`${name}=${value}\`.`);
  }
  // A generated .config spells an enabled option out as `=y`; if none of the spellings appears at all, the protection
  // is not compiled in — whether because it was unset or because its dependencies were unmet does not change the
  // posture. This is the ONLY place this provider turns an absence into an `off`, and it is entitled to, because the
  // artefact it is reading is exhaustive by construction, unlike a string scan.
  return determined(
    q,
    'off',
    'kernel-config',
    `None of ${names.join(', ')} appears in the shipped kernel config; an enabled option would appear as \`=y\`.`,
  );
}

/** Answer one question from the trusted blob markers. Returns null when the blob has nothing to say about it. */
function answerFromBlob(q: QuestionSpec, blob: KernelBlobFacts): PostureAnswer | null {
  switch (q.id) {
    case 'devkmem': {
      // The one question a blob can answer NEGATIVELY, because the anchor proves the right table was in view.
      if (!blob.memDevlistAnchored) return null;
      return blob.hasKmemEntry
        ? determined(
            q,
            'on',
            'kernel-blob',
            'The kernel’s character-device table lists a `kmem` entry, so /dev/kmem is compiled in.',
          )
        : determined(
            q,
            'off',
            'kernel-blob',
            'The kernel’s character-device table is visible in the blob and carries no `kmem` entry.',
          );
    }
    case 'stackprotector':
      return blob.hasStackProtector
        ? determined(q, 'on', 'kernel-blob', 'The kernel blob references `__stack_chk_fail`/`__stack_chk_guard`.')
        : null;
    case 'module-sig':
      return blob.hasModuleSigParam
        ? determined(
            q,
            'on',
            'kernel-blob',
            'The kernel exposes the `module.sig_enforce` boot parameter, so CONFIG_MODULE_SIG is compiled in. ' +
              'Whether enforcement is actually ON is a separate question this blob does not answer.',
          )
        : null;
    case 'strict-rwx':
      return blob.hasRodataWriteProtect
        ? determined(q, 'on', 'kernel-blob', 'The kernel carries its read-only-data write-protect diagnostic.')
        : null;
    case 'strict-devmem':
      return blob.hasStrictDevmemDiag
        ? determined(q, 'on', 'kernel-blob', 'The kernel carries the /dev/mem range-check diagnostic.')
        : null;
    case 'kaslr':
      return blob.hasKaslrParam
        ? determined(q, 'on', 'kernel-blob', 'The kernel recognises the `nokaslr` boot parameter.')
        : null;
    default:
      return null;
  }
}

/** Answer the two sysctl questions from the rootfs's own sysctl files, when they set the knob explicitly. */
function answerFromSysctl(q: QuestionSpec, ev: PostureEvidence): PostureAnswer | null {
  if (q.id !== 'kptr-restrict' && q.id !== 'dmesg-restrict') return null;
  const value = ev.sysctl[q.option];
  if (value === undefined) return null;
  return determined(
    q,
    value.trim() === '0' ? 'off' : 'on',
    'rootfs-sysctl',
    `${ev.sysctlPath ?? 'A rootfs sysctl file'} sets \`${q.option} = ${value.trim()}\`.`,
  );
}

/**
 * Answer module signing from the shipped module set. This is the strongest thing a rootfs alone can say, and it is
 * available even when the kernel image was never decompressed: a kernel enforcing signatures could not load its own
 * modules, so a module set with no signature trailer anywhere means enforcement is not in force for that set.
 */
function answerFromModules(q: QuestionSpec, mods: ModuleEvidence): PostureAnswer | null {
  if (q.id !== 'module-sig' || mods.inspectedCount === 0) return null;
  if (mods.signedCount > 0) {
    return determined(
      q,
      'on',
      'shipped-modules',
      `${mods.signedCount} of ${mods.inspectedCount} inspected modules carry an appended signature.`,
    );
  }
  return determined(
    q,
    'off',
    'shipped-modules',
    `None of the ${mods.inspectedCount} inspected module(s) carries a \`${MODULE_SIG_TRAILER}\` trailer. A kernel enforcing signatures could not load its own module set, so enforcement is not in force here.`,
  );
}

/**
 * Pure: answer every posture question from the evidence, three states throughout.
 *
 * Order is the point. The version gate runs FIRST, so an option that did not exist yet can never be reported as
 * "disabled". Then a shipped config (authoritative), the module set, the trusted blob markers, the rootfs sysctls.
 * When nothing settles it the answer is `unknown` carrying the reason that actually applies — distinguishing
 * "nobody shipped a config" from "the blob never decompressed" from "the blob was readable and simply carries no
 * marker either way", because those three need three different responses.
 */
export function assessPosture(ev: PostureEvidence): PostureAnswer[] {
  return QUESTIONS.map((q) => {
    if (!ev.version) {
      return undetermined(
        q,
        'kernel-version-unknown',
        'No kernel version was recovered, so it is not even known whether this option exists in this kernel.',
      );
    }
    if (compareVersion(ev.version, q.since) < 0) {
      return undetermined(
        q,
        'option-postdates-kernel',
        `${q.option} was introduced upstream in ${boundText(q.since)}; this kernel is ${ev.version.raw}. The option does not exist here, which is not the same as it being disabled.`,
      );
    }
    if (q.removedIn && compareVersion(ev.version, q.removedIn) >= 0) {
      return undetermined(
        q,
        'option-removed-upstream',
        `${q.option} was removed upstream in ${boundText(q.removedIn)}; this kernel is ${ev.version.raw}, so the option no longer exists.`,
      );
    }

    const answer =
      answerFromConfig(q, ev) ??
      (ev.modules ? answerFromModules(q, ev.modules) : null) ??
      (ev.blob?.readable ? answerFromBlob(q, ev.blob) : null) ??
      answerFromSysctl(q, ev);

    if (answer) {
      // A feature that predates its own off-switch cannot have been turned off — say so rather than leaving the
      // operator to wonder why an ancient kernel "has it enabled".
      if (q.notConfigurableBefore && compareVersion(ev.version, q.notConfigurableBefore) < 0) {
        return {
          ...answer,
          detail: `${answer.detail} ${q.option} only became a switch in ${boundText(q.notConfigurableBefore)}; in ${ev.version.raw} the feature is unconditional and cannot be disabled.`,
        };
      }
      return answer;
    }

    if (!ev.blob) {
      return undetermined(
        q,
        'no-kernel-blob',
        'No kernel image was located to read markers from, and no kernel config was shipped. The version is known ' +
          'from the rootfs; the posture is not.',
      );
    }
    if (!ev.blob.readable) {
      return undetermined(
        q,
        'kernel-blob-not-readable',
        `The candidate kernel blob (${ev.blob.path}) does not read as a decompressed kernel — its strings carry none of the markers every kernel has, so nothing absent from it may be read as a disabled option.`,
      );
    }
    if (!ev.config) {
      return undetermined(
        q,
        'no-kernel-config-shipped',
        `No kernel config was shipped, and the decompressed kernel carries no marker that settles ${q.option} either way. A missing string is not a missing feature.`,
      );
    }
    return undetermined(q, 'no-marker-evidence', `Nothing in the available evidence settles ${q.option}.`);
  });
}

// === Age ===

/**
 * Curated first-release dates for the kernel series that actually turn up in firmware, hand-checked against
 * kernel.org's release history and kept at SERIES level on purpose. A per-patch table would be recall dressed up as
 * data, and the age argument does not need one: the series is what decides whether upstream still touches this code.
 * A series that is not listed falls back to its major line, and a major that is not listed yields NO age claim at
 * all rather than a guess.
 */
export const SERIES_RELEASED: Readonly<Record<string, string>> = {
  '2.4': '2001-01',
  '2.6': '2003-12',
  '3.0': '2011-07',
  '3.2': '2012-01',
  '3.4': '2012-05',
  '3.10': '2013-06',
  '3.14': '2014-03',
  '3.18': '2014-12',
  '4.1': '2015-06',
  '4.4': '2016-01',
  '4.9': '2016-12',
  '4.14': '2017-11',
  '4.19': '2018-10',
  '5.4': '2019-11',
  '5.10': '2020-12',
  '5.15': '2021-10',
  '6.1': '2022-12',
  '6.6': '2023-10',
  '6.12': '2024-11',
};

/** Fallback when the exact series is not curated — the major line's own first release. */
const MAJOR_RELEASED: Readonly<Record<string, string>> = {
  '2': '2001-01',
  '3': '2011-07',
  '4': '2015-04',
  '5': '2019-03',
  '6': '2022-10',
};

export interface KernelAge {
  series: string;
  /** `YYYY-MM` the series first shipped, from the curated table. */
  seriesReleased: string;
  /** Whole years between that date and the reference instant. */
  years: number;
  /** True when the series predates 3.0 — those lines receive no upstream maintenance of any kind. */
  preModern: boolean;
  /** Years between the series' release and the build date stamped in the banner, when there is one. */
  yearsOldAtBuild?: number;
}

/**
 * Pure: how old this kernel is, measured from the curated series-release date to `nowMs`. Deterministic given its
 * inputs — the runner supplies the clock, so the unit test does not depend on one. Returns null when neither the
 * series nor its major line is curated, because a made-up date is worse than no age claim.
 */
export function kernelAge(version: KernelVersion, nowMs: number, buildYear?: number): KernelAge | null {
  const released = SERIES_RELEASED[version.series] ?? MAJOR_RELEASED[String(version.major)];
  if (!released) return null;
  const releasedMs = Date.parse(`${released}-01T00:00:00Z`);
  if (Number.isNaN(releasedMs)) return null;
  const age: KernelAge = {
    series: version.series,
    seriesReleased: released,
    years: Math.max(0, Math.floor((nowMs - releasedMs) / (365.25 * 24 * 3600 * 1000))),
    preModern: version.major < 3,
  };
  if (buildYear !== undefined) {
    const gap = buildYear - Number(released.slice(0, 4));
    if (gap >= 0) age.yearsOldAtBuild = gap;
  }
  return age;
}

/** Pure: the severity the age alone justifies. Pre-3.0 is never below `high` — that line is simply unmaintained. */
export function ageSeverity(age: KernelAge): FindingSeverity {
  if (age.preModern) return age.years >= 15 ? 'critical' : 'high';
  if (age.years >= 10) return 'high';
  if (age.years >= 6) return 'medium';
  if (age.years >= 3) return 'low';
  return 'info';
}

// === Result + findings ===

/** Where the version came from — different sources, different confidence, so the result says which. */
export type VersionSource = 'kernel-config' | 'kernel-banner' | 'module-vermagic' | 'lib-modules-dir';

/** A version disagreement between two sources. Reported, never silently resolved. */
export interface VersionConflict {
  a: string;
  aSource: VersionSource;
  b: string;
  bSource: VersionSource;
}

export interface KernelPostureResult {
  available: boolean;
  /** False when no kernel could be located at all — the `blocked_by_platform` case. */
  located: boolean;
  version: string | null;
  versionSource: VersionSource | null;
  versionConflicts: VersionConflict[];
  banner: KernelBanner | null;
  /** The file the banner was read out of, so the operator can go and look at it. */
  bannerPath: string | null;
  configPath: string | null;
  /** The filesystem tree the module set / config / sysctls were read from, when there was one. */
  rootfsPath: string | null;
  /** True when that tree was recognised inside the extraction output rather than supplied by the caller. */
  rootfsDiscovered: boolean;
  blob: KernelBlobFacts | null;
  modules: ModuleEvidence | null;
  age: KernelAge | null;
  answers: PostureAnswer[];
  findings: FindingDraft[];
  /** What was searched, in order — this is what a `located: false` result owes the operator. */
  searched: string[];
  /** What a bound dropped, and by which rule. Empty when nothing was dropped. */
  bounds: string[];
  reason: string;
}

const UNDETERMINED_LABEL: Readonly<Record<UndeterminedReason, string>> = {
  'no-kernel-config-shipped': 'no kernel config shipped and no marker in the kernel image',
  'option-postdates-kernel': 'the option postdates this kernel',
  'option-removed-upstream': 'the option was removed upstream before this kernel',
  'no-kernel-blob': 'no kernel image was located to read',
  'kernel-blob-not-readable': 'the kernel image was never decompressed',
  'no-marker-evidence': 'no evidence either way',
  'kernel-version-unknown': 'the kernel version itself is unknown',
};

/**
 * Pure: compose the honest findings. Four shapes, and the last is the one that keeps this provider truthful:
 *   1. A kernel that could not be located → `blocked_by_platform` with the list of places searched, and nothing else.
 *   2. The AGE of the kernel — `static_confirmed`, because the version is literally in the bytes. No CVE claim.
 *   3. One finding per posture question whose answer came back dangerous, at that question's severity.
 *   4. ONE finding recording the questions that could NOT be answered, at `blocked_by_platform`. Without it, a
 *      firmware where nothing could be determined would produce a short list that reads as "the kernel is fine".
 */
/**
 * Pure: what the shipped module set's provenance is worth saying.
 *
 * The claim is about SURFACE, not defects. An out-of-tree module is code running with full kernel privilege that
 * the kernel's own review and patch process never covered: when an upstream bug is fixed, these do not receive
 * the fix, and no distribution security team tracks them. That is a fact worth a finding. "68 vulnerable modules"
 * would not be — nothing here opened one and looked.
 *
 * A build that does not emit `intree=` at all yields no finding rather than a zero, because a zero would be a
 * measurement and this is the absence of one.
 */
export function moduleProvenanceFindings(mods: ModuleEvidence | null): FindingDraft[] {
  const p = mods?.provenance;
  if (!p) return [];
  const drafts: FindingDraft[] = [];
  if (p.tagUnused) {
    drafts.push({
      kind: 'kernel-module-provenance-unknown',
      title: `Module provenance is not determinable: none of the ${mods?.inspectedCount ?? 0} inspected modules carries an intree tag`,
      severity: 'info',
      proofState: 'blocked_by_platform',
      evidence: { inspected: mods?.inspectedCount, moduleCount: mods?.moduleCount },
      rationale:
        'The kernel build system writes `intree=Y` into a module built inside the kernel tree, so its absence ' +
        'normally means the module was built outside it. This build emits the tag on no module at all, so the ' +
        'tag is not in use here and NOTHING is decided either way — this is the question being unanswerable, not ' +
        'an answer that every module is in-tree.',
    });
    return drafts;
  }
  if (p.outOfTree > 0) {
    drafts.push({
      kind: 'kernel-out-of-tree-modules',
      title: `${p.outOfTree} of ${p.inTree + p.outOfTree} kernel modules are built out of tree`,
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { outOfTree: p.outOfTree, inTree: p.inTree, names: p.outOfTreeNames },
      rationale:
        'These modules declare no `intree=Y`, so they were built outside the kernel source tree. They run with ' +
        'full kernel privilege while sitting outside the process that reviews and patches the kernel: an upstream ' +
        'fix does not reach them, and no distribution security team tracks them. This is a statement about ' +
        'ATTACK SURFACE and about who maintains it — nothing here opened a module and looked for a defect.',
    });
  }
  if (p.proprietary.length > 0) {
    drafts.push({
      kind: 'kernel-proprietary-modules',
      title: `${p.proprietary.length} kernel module(s) declare a non-GPL licence and taint the kernel`,
      severity: 'low',
      proofState: 'static_confirmed',
      evidence: { modules: p.proprietary },
      rationale:
        "The `license=` string in each module's .modinfo is not GPL-compatible, so loading it sets the kernel " +
        'taint flag. Source is therefore unavailable for review, and an upstream maintainer will not debug a ' +
        'tainted kernel. A fact about the declared licence string, not about the code behind it.',
    });
  }
  return drafts;
}

export function postureFindings(result: Omit<KernelPostureResult, 'findings'>): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  drafts.push(...moduleProvenanceFindings(result.modules));

  if (!result.located) {
    drafts.push({
      kind: 'kernel-not-located',
      title: 'No Linux kernel could be located in this image',
      severity: 'info',
      proofState: 'blocked_by_platform',
      evidence: { searched: result.searched, bounds: result.bounds },
      rationale:
        'The kernel-posture questions were asked and could not be answered: no kernel banner, no kernel config and ' +
        'no module set were found in the raw image, the extraction output or the rootfs. This is a gap in coverage, ' +
        'not a statement that the kernel is sound.',
    });
    return drafts;
  }

  if (result.age && result.version) {
    const built = result.age.yearsOldAtBuild;
    drafts.push({
      kind: 'kernel-age',
      title: `Kernel ${result.version} — the ${result.age.series} series is ${result.age.years} years old`,
      severity: ageSeverity(result.age),
      proofState: 'static_confirmed',
      evidence: {
        version: result.version,
        versionSource: result.versionSource,
        series: result.age.series,
        seriesReleased: result.age.seriesReleased,
        years: result.age.years,
        ...(result.banner?.buildDate ? { buildDate: result.banner.buildDate } : {}),
        ...(result.banner?.toolchain ? { toolchain: result.banner.toolchain } : {}),
        ...(built === undefined ? {} : { yearsOldAtBuild: built }),
      },
      rationale: `The image runs Linux ${result.version}; the ${result.age.series} series first shipped ${result.age.seriesReleased}${result.age.preModern ? ', and no kernel before 3.0 receives upstream fixes of any kind' : ''}${
        built !== undefined && built >= 5
          ? `. The banner’s own build stamp is ${result.banner?.buildDate}, so a ${built}-year-old kernel line was still being built for this product`
          : ''
      }. This is the version arithmetic only — which specific CVEs apply is the SBOM/component lane’s claim, not this one.`,
    });
  }

  for (const a of result.answers) {
    if (!a.bad) continue;
    drafts.push({
      kind: `kernel-${a.id}`,
      title: a.badTitle,
      severity: a.severity,
      proofState: 'static_confirmed',
      evidence: { option: a.option, verdict: a.verdict, source: a.source, detail: a.detail, kernel: result.version },
      rationale: `${a.detail} Determined from ${a.source}; this is a property of the shipped kernel image, not a claim about a running device, and it is not an exploitability claim.`,
    });
  }

  const unknown = result.answers.filter((a) => a.verdict === 'unknown');
  if (unknown.length > 0) {
    const byReason: Record<string, string[]> = {};
    for (const a of unknown) {
      const key = a.reason ?? 'no-marker-evidence';
      byReason[key] ??= [];
      byReason[key]?.push(a.option);
    }
    const summary = Object.entries(byReason)
      .map(([r, opts]) => `${opts.join(', ')} — ${UNDETERMINED_LABEL[r as UndeterminedReason]}`)
      .join('; ');
    drafts.push({
      kind: 'kernel-posture-undetermined',
      title: `${unknown.length} of ${result.answers.length} kernel posture questions could not be answered`,
      severity: 'info',
      proofState: 'blocked_by_platform',
      evidence: {
        kernel: result.version,
        undetermined: unknown.map((a) => ({ option: a.option, reason: a.reason, detail: a.detail })),
        configPath: result.configPath,
        blob: result.blob?.path ?? null,
      },
      rationale: `${summary}. Each of these questions was asked and could not be settled from the bytes available. An unanswered question is not a passing answer: the absence of a CONFIG_ string is not the absence of the feature, and an option that postdates this kernel cannot be "disabled".`,
    });
  }

  if (result.versionConflicts.length > 0) {
    const c = result.versionConflicts[0] as VersionConflict;
    drafts.push({
      kind: 'kernel-version-conflict',
      title: `Kernel version sources disagree (${c.a} vs ${c.b})`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { conflicts: result.versionConflicts },
      rationale: `${c.aSource} says ${c.a} and ${c.bSource} says ${c.b}. Both readings are literally in the bytes; which one the device actually boots is not decidable statically, so the disagreement is reported rather than resolved.`,
    });
  }

  return drafts;
}

// === The runner (I/O only) ===

/** A kernel is never smaller than this, and a firmware kernel is never larger — the candidate-blob size band. */
const BLOB_MIN_BYTES = 256 * 1024;
const BLOB_MAX_BYTES = 64 * 1024 * 1024;
/** How many candidate blobs are opened. Ordered largest-first, and what the bound dropped is reported. */
const BLOB_CANDIDATE_CAP = 12;
/** How much of one blob is read. Comfortably above every firmware kernel measured (114 KiB … 5.6 MiB). */
const BLOB_READ_CAP = 24 * 1024 * 1024;
/** How many `.ko` files are opened for the signature check. Reported when it truncates. */
const MODULE_SAMPLE_CAP = 200;
/** Bound on the recursive walk of an extraction tree. */
const WALK_FILE_CAP = 4000;

function readBounded(p: string, cap: number): Uint8Array | null {
  try {
    const fd = fs.openSync(p, 'r');
    try {
      const len = Math.min(fs.fstatSync(fd).size, cap);
      const buf = Buffer.allocUnsafe(len);
      fs.readSync(fd, buf, 0, len, 0);
      return buf;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

/** Case-sensitive byte search for an ASCII needle — the cheap prefilter before the full string extraction. */
function containsAscii(buf: Uint8Array, needle: string): boolean {
  const n = needle.length;
  outer: for (let i = 0; i + n <= buf.length; i++) {
    for (let k = 0; k < n; k++) {
      if ((buf[i + k] as number) !== needle.charCodeAt(k)) continue outer;
    }
    return true;
  }
  return false;
}

/**
 * Extract printable runs from a byte buffer: the token set (exact-match entries such as the `kmem` device name) and
 * the same runs joined by newline (phrase search). Kept here rather than shelling out to `strings`, so the provider
 * has no tool dependency and the marker logic above stays pure over its inputs.
 */
export function extractPrintable(buf: Uint8Array, minRun = 3): { tokens: Set<string>; text: string } {
  const tokens = new Set<string>();
  const parts: string[] = [];
  let run: number[] = [];
  const flush = (): void => {
    if (run.length >= minRun) {
      const s = String.fromCharCode(...run);
      parts.push(s);
      tokens.add(s);
    }
    run = [];
  };
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] as number;
    if (b >= 0x20 && b <= 0x7e) {
      run.push(b);
      // Bound one run so a huge printable region cannot blow the argument list of String.fromCharCode.
      if (run.length >= 2048) flush();
    } else {
      flush();
    }
  }
  flush();
  // Whitespace-split the runs too: a device-table entry can share a run with the printk that precedes it.
  for (const p of parts) {
    if (p.includes(' ')) {
      for (const w of p.split(/\s+/)) if (w.length >= minRun) tokens.add(w);
    }
  }
  return { tokens, text: parts.join('\n') };
}

/** Recursively list files under `dir`, bounded. */
function walkFiles(dir: string, cap: number): string[] {
  return walkExtraction(dir, cap, false).files;
}

/**
 * The directory names that mark the root of an extracted Linux filesystem — the same marker set `extract.ts` uses to
 * recognise a rootfs, deliberately, so the two cannot drift apart.
 */
const FS_ROOT_MARKERS = ['bin', 'etc', 'sbin', 'lib'];

/** ≥2 markers is an extracted filesystem root: `squashfs-root`, `ubifs-root`, `carve/rootfs`, whatever it is called. */
function isFilesystemRoot(entries: readonly fs.Dirent[]): boolean {
  let n = 0;
  for (const e of entries) if (e.isDirectory() && FS_ROOT_MARKERS.includes(e.name)) n++;
  return n >= 2;
}

/**
 * Walk an extraction tree, optionally PRUNING every extracted filesystem root it meets and returning those roots
 * separately.
 *
 * The pruning is the fix for a defect real bytes exposed and the unit test did not. The module doc above promises
 * that a banner is never read out of a rootfs binary — but on the GL.iNet BE3600 the extracted rootfs lives at
 * `<outputDir>/carve/rootfs`, i.e. INSIDE the extraction output this walk enumerates. `usr/sbin/tailscaled` is a
 * 30 MB extension-less Go binary, so it sailed through the "decompressed blob" filter, and the provider reported
 * kernel 4.4.0 — the decoy banner inside tailscaled — for a device whose own modules say 5.4.213. The unit test
 * had placed the rootfs beside the extraction directory rather than inside it, so it agreed with the code instead
 * of checking it. Recognising the root by markers rather than by name means a differently-named carve directory
 * cannot reintroduce it.
 *
 * The pruned roots are useful in their own right: when the caller had no rootfs to give (the BE3600's stored
 * extraction recorded `rootfsPath: null`), a filesystem root discovered here is where the module set and the
 * shipped config are read from — and the result says that is where it came from.
 */
function walkExtraction(dir: string, cap: number, pruneFilesystemRoots: boolean): { files: string[]; roots: string[] } {
  const files: string[] = [];
  const roots: string[] = [];
  const stack = [dir];
  while (stack.length > 0 && files.length < cap) {
    const cur = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    if (pruneFilesystemRoots && cur !== dir && isFilesystemRoot(entries)) {
      roots.push(cur);
      continue;
    }
    for (const e of entries) {
      const p = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(p);
      else if (e.isFile()) {
        files.push(p);
        if (files.length >= cap) break;
      }
    }
  }
  // Shallowest first, then lexicographic — a deterministic order, never the filesystem's.
  roots.sort((a, b) => a.split(path.sep).length - b.split(path.sep).length || (a < b ? -1 : 1));
  return { files, roots };
}

/** The container extensions binwalk leaves beside its decompressed output — the compressed side is never a kernel. */
const CONTAINER_EXT = new Set([
  '.7z',
  '.xz',
  '.gz',
  '.zlib',
  '.lzma',
  '.lzo',
  '.zst',
  '.bz2',
  '.squashfs',
  '.jffs2',
  '.cramfs',
  '.ubi',
  '.ubifs',
  '.romfs',
  '.cpio',
  '.tar',
]);

/** Names that are a kernel even when they carry an extension. */
const KERNEL_NAME_RE = /^(?:piggy|vmlinux|vmlinuz|zImage|uImage|Image|bzImage|kernel)/i;

/**
 * Pure: the candidate kernel blobs in a file list. Decompressed binwalk output is named by offset with NO extension
 * (`20400`, `530FE`, `piggy`), which is the signal used here, plus the conventional kernel names. Ordered
 * largest-first — a deterministic rule rather than directory order, so the SET is not an artefact of the filesystem
 * layout; what the cap drops is returned so the result can say so.
 */
export function selectKernelBlobs(
  files: readonly string[],
  sizeOf: (p: string) => number,
): { chosen: string[]; dropped: number } {
  const scored = files
    .filter((f) => {
      const base = path.basename(f);
      const ext = path.extname(base).toLowerCase();
      if (CONTAINER_EXT.has(ext)) return false;
      return ext === '' || KERNEL_NAME_RE.test(base);
    })
    .map((f) => ({ f, size: sizeOf(f) }))
    .filter((x) => x.size >= BLOB_MIN_BYTES && x.size <= BLOB_MAX_BYTES)
    .sort((a, b) => b.size - a.size || (a.f < b.f ? -1 : 1));
  return {
    chosen: scored.slice(0, BLOB_CANDIDATE_CAP).map((x) => x.f),
    dropped: Math.max(0, scored.length - BLOB_CANDIDATE_CAP),
  };
}

/** Kernel-config file names worth opening, in the order they are trusted. */
const CONFIG_CANDIDATES = ['proc/config.gz', 'boot/config.gz', 'etc/config.gz', 'config.gz', '.config', 'boot/config'];

function tryReadConfig(rootfs: string): { text: string; at: string } | null {
  const decode = (buf: Uint8Array): string | null => {
    if (buf[0] === 0x1f && buf[1] === 0x8b) {
      try {
        return zlib.gunzipSync(Buffer.from(buf)).toString('utf8');
      } catch {
        return null;
      }
    }
    return Buffer.from(buf).toString('utf8');
  };
  for (const rel of CONFIG_CANDIDATES) {
    const buf = readBounded(path.join(rootfs, rel), 4 * 1024 * 1024);
    if (!buf || buf.length < 2) continue;
    const text = decode(buf);
    if (text && looksLikeKernelConfig(text)) return { text, at: rel };
  }
  // `boot/config-<version>` is named after the kernel, so it has to be listed rather than guessed.
  try {
    for (const name of fs.readdirSync(path.join(rootfs, 'boot'))) {
      if (!name.startsWith('config-')) continue;
      const buf = readBounded(path.join(rootfs, 'boot', name), 4 * 1024 * 1024);
      if (!buf) continue;
      const text = decode(buf);
      if (text && looksLikeKernelConfig(text)) return { text, at: `boot/${name}` };
    }
  } catch {
    /* no /boot — the common case in embedded firmware */
  }
  return null;
}

/** Read `kernel.*` assignments out of the rootfs sysctl files. */
function readSysctl(rootfs: string): { values: Record<string, string>; at: string | null } {
  const values: Record<string, string> = {};
  let at: string | null = null;
  const files: string[] = [path.join(rootfs, 'etc/sysctl.conf')];
  try {
    for (const n of fs.readdirSync(path.join(rootfs, 'etc/sysctl.d')).sort()) {
      files.push(path.join(rootfs, 'etc/sysctl.d', n));
    }
  } catch {
    /* no sysctl.d */
  }
  for (const f of files) {
    const buf = readBounded(f, 256 * 1024);
    if (!buf) continue;
    for (const line of Buffer.from(buf).toString('utf8').split('\n')) {
      const m = /^\s*(kernel\.[a-z_]+)\s*=\s*(\S+)/.exec(line);
      if (m?.[1] && m[2] !== undefined) {
        values[m[1]] = m[2];
        at ??= path.relative(rootfs, f);
      }
    }
  }
  return { values, at };
}

/** Inspect the shipped module set: its version directory, a `vermagic`, and how many carry a signature trailer. */
function readModules(rootfs: string): ModuleEvidence | null {
  const base = path.join(rootfs, 'lib/modules');
  let versionDirs: string[];
  try {
    versionDirs = fs
      .readdirSync(base, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^\d+\.\d+/.test(e.name))
      .map((e) => e.name)
      .sort();
  } catch {
    return null;
  }
  const versionDir = versionDirs[0];
  if (!versionDir) return null;
  const kos = walkFiles(path.join(base, versionDir), WALK_FILE_CAP)
    .filter((f) => f.endsWith('.ko'))
    .sort();
  let signedCount = 0;
  let vermagic: string | null = null;
  let inspectedCount = 0;
  const facts: { file: string; facts: ModinfoFacts }[] = [];
  for (const ko of kos.slice(0, MODULE_SAMPLE_CAP)) {
    const buf = readBounded(ko, 8 * 1024 * 1024);
    if (!buf) continue;
    inspectedCount++;
    const text = Buffer.from(buf).toString('latin1');
    if (text.includes(MODULE_SIG_TRAILER)) signedCount++;
    vermagic ??= parseVermagic(text);
    facts.push({ file: path.basename(ko, '.ko'), facts: parseModinfo(text) });
  }
  return {
    versionDir,
    vermagic,
    moduleCount: kos.length,
    signedCount,
    inspectedCount,
    provenance: assessModuleProvenance(facts),
  };
}

function statSize(p: string): number {
  try {
    return fs.statSync(p).size;
  } catch {
    return 0;
  }
}

/**
 * Locate the kernel and read its posture. Reads, in this order: a shipped kernel config in the rootfs, the shipped
 * module set, the candidate kernel blobs in the extraction tree and `/boot`, then the raw image itself. Honest
 * throughout — a kernel it cannot find is `located: false` carrying the list of places it looked, and every posture
 * answer travels with the standard of evidence that produced it.
 */
export function runKernelPosture(
  imagePath: string,
  rootfsPath: string | null,
  outputDir: string | null,
  nowMs: number = Date.now(),
): KernelPostureResult {
  const searched: string[] = [];
  const bounds: string[] = [];
  const conflicts: VersionConflict[] = [];

  // --- enumerate the extraction tree first: it decides BOTH the blob candidates and, when the caller had no
  // rootfs to give, which extracted filesystem the module set is read from. Filesystem roots are pruned out of
  // the blob candidates (see walkExtraction — this is the tailscaled defect).
  let blobFiles: string[] = [];
  let discoveredRoots: string[] = [];
  if (outputDir) {
    const walk = walkExtraction(outputDir, WALK_FILE_CAP, true);
    blobFiles = walk.files;
    discoveredRoots = walk.roots;
  }

  let rootfs = rootfsPath;
  let rootfsDiscovered = false;
  const firstRoot = discoveredRoots[0];
  if (!rootfs && firstRoot) {
    rootfs = firstRoot;
    rootfsDiscovered = true;
  }

  // --- the authoritative source, when a vendor left one behind ---
  let config: Record<string, string> | null = null;
  let configPath: string | null = null;
  let configVersion: string | null = null;
  let sysctl: Record<string, string> = {};
  let sysctlPath: string | null = null;
  let modules: ModuleEvidence | null = null;
  if (rootfsDiscovered) {
    searched.push(
      `no rootfs was supplied, so the extracted filesystem root ${rootfs} was recognised in the extraction output (${FS_ROOT_MARKERS.join('/')} markers) and used instead`,
    );
  }
  if (rootfs) {
    searched.push(`rootfs kernel config (${CONFIG_CANDIDATES.join(', ')}, boot/config-*)`);
    const cfg = tryReadConfig(rootfs);
    if (cfg) {
      config = parseKernelConfig(cfg.text);
      configPath = cfg.at;
      configVersion = parseConfigVersion(cfg.text);
    }
    searched.push('rootfs lib/modules/<version> (directory name, .ko vermagic, signature trailer)');
    modules = readModules(rootfs);
    if (modules && modules.moduleCount > modules.inspectedCount) {
      bounds.push(
        `${modules.moduleCount - modules.inspectedCount} of ${modules.moduleCount} modules were not opened (cap ${MODULE_SAMPLE_CAP}, path-sorted); the signature verdict covers the ${modules.inspectedCount} inspected.`,
      );
    }
    const sc = readSysctl(rootfs);
    sysctl = sc.values;
    sysctlPath = sc.at;
  } else {
    searched.push('no rootfs was available or discoverable, so no shipped kernel config or module set could be read');
  }

  // --- the banner, from blobs and the raw image only (never from an arbitrary rootfs file) ---
  const candidates: string[] = [];
  if (outputDir) {
    searched.push(
      `extraction output ${outputDir} (decompressed, extension-less blobs ≥ 256 KiB, largest first; ${discoveredRoots.length} extracted filesystem root(s) pruned out)`,
    );
    const sel = selectKernelBlobs(blobFiles, statSize);
    candidates.push(...sel.chosen);
    if (sel.dropped > 0) {
      bounds.push(
        `${sel.dropped} candidate blob(s) beyond the ${BLOB_CANDIDATE_CAP}-file cap were not opened; candidates are ordered largest-first, never by directory order.`,
      );
    }
  }
  if (rootfs) {
    // /boot is the ONE path inside a rootfs a banner may be read from — see the module doc on tailscaled.
    const bootFiles = walkFiles(path.join(rootfs, 'boot'), 64);
    if (bootFiles.length > 0) {
      searched.push('rootfs /boot (the only rootfs path a banner is accepted from)');
      candidates.push(...selectKernelBlobs(bootFiles, statSize).chosen);
    }
  }
  searched.push(`the raw image ${path.basename(imagePath)}`);
  candidates.push(imagePath);

  let banner: KernelBanner | null = null;
  let bannerPath: string | null = null;
  let blob: KernelBlobFacts | null = null;
  for (const cand of candidates) {
    const buf = readBounded(cand, BLOB_READ_CAP);
    if (!buf) continue;
    // Cheap prefilter: a blob with neither a banner nor the universal panic string is not worth extracting strings
    // from, and the raw images in the corpus are up to 111 MB.
    if (!containsAscii(buf, BANNER_ANCHOR) && !containsAscii(buf, 'Kernel panic')) continue;
    const { tokens, text } = extractPrintable(buf);
    const facts = readKernelBlobFacts(cand, tokens, text);
    const b = parseKernelBanner(text);
    if (b) {
      banner = b;
      bannerPath = cand;
      blob = facts;
      break;
    }
    // Keep the best readable non-banner blob: its markers are still worth something without a version banner.
    if (facts.readable && !blob) blob = facts;
  }

  // --- reconcile the version sources rather than silently preferring one ---
  const claims: Array<{ v: string; s: VersionSource }> = [];
  if (configVersion) claims.push({ v: configVersion, s: 'kernel-config' });
  if (banner) claims.push({ v: banner.version, s: 'kernel-banner' });
  if (modules?.vermagic) claims.push({ v: modules.vermagic, s: 'module-vermagic' });
  if (modules?.versionDir) claims.push({ v: modules.versionDir, s: 'lib-modules-dir' });

  let version: string | null = null;
  let versionSource: VersionSource | null = null;
  const head = claims[0];
  if (head) {
    version = head.v;
    versionSource = head.s;
    const headNum = parseKernelVersion(head.v);
    for (const c of claims.slice(1)) {
      const other = parseKernelVersion(c.v);
      if (!headNum || !other) continue;
      if (headNum.major !== other.major || headNum.minor !== other.minor || headNum.patch !== other.patch) {
        conflicts.push({ a: head.v, aSource: head.s, b: c.v, bSource: c.s });
      }
    }
  }

  const numeric = version ? parseKernelVersion(version) : null;
  const located = numeric !== null;
  const answers = located
    ? assessPosture({ version: numeric, config, configPath, blob, modules, sysctl, sysctlPath })
    : [];
  const age = numeric ? kernelAge(numeric, nowMs, banner?.buildYear) : null;
  const answered = answers.filter((a) => a.verdict !== 'unknown').length;

  const shell: Omit<KernelPostureResult, 'findings'> = {
    available: true,
    located,
    version,
    versionSource,
    versionConflicts: conflicts,
    banner,
    bannerPath,
    configPath,
    rootfsPath: rootfs,
    rootfsDiscovered,
    blob,
    modules,
    age,
    answers,
    searched,
    bounds,
    reason: located
      ? `Linux ${version} (from ${versionSource}; ${configPath ? `kernel config at ${configPath}` : 'no kernel config shipped'}). ${answered} of ${answers.length} posture questions answered from the bytes; ${answers.length - answered} could not be determined and each says why. An undetermined question is not a passing one.`
      : 'No Linux kernel was located. The posture questions were asked and could not be answered — a coverage gap, not a clean result.',
  };

  return { ...shell, findings: postureFindings(shell) };
}
