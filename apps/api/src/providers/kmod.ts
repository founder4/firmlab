/**
 * The kernel-module surface — what a rootfs's `.ko` files call, who wrote them, and where a length read off the
 * wire reaches an allocator.
 *
 * **Why this provider exists, in one measurement.** On the corpus's WDR3600 the workbench produced kernel
 * *posture* only: `kernel-age` critical, `/dev/kmem` compiled in, *"none of the 84 inspected modules carries an
 * intree tag"*, *"8 of 9 kernel posture questions could not be answered"*. Its sole mention of the module that
 * mattered was a count inside `component-map`. A blind agent with nothing but a shell went into the same bytes
 * and came back with **KCodes NetUSB 1.02.66 listening on TCP 20005**, with a byte-swapped attacker length
 * reaching `__kmalloc` in `SoftwareBus_dispatchNormalEPMsgOut` — and, in the other direction, *declined* the
 * obvious CVE-2015-3036 for an Apr-2015 NetUSB because `run_init_sbus` carries the vendor's own bounds check.
 * Eighty-four modules inspected for one tag, none disassembled. `binvuln` skips them by construction and says so
 * (`isRelocatableObject`: *"a different question … that deserves its own provider rather than a userland sweep's
 * vocabulary"*). This is that provider, and the vocabulary is the kernel's.
 *
 * **Three layers, and only the third one costs anything.**
 *
 * 1. *Identity*, from `.modinfo`. `license`, `author`, `depends` and every `description` record — which is where
 *    a vendor writes the product version. Measured: 628 `.ko` across the corpus's 5 rootfs images read in ~5 s.
 * 2. *The kernel API*, from the ELF symbol table. An `ET_REL` object's undefined symbols ARE the kernel functions
 *    the linker will bind, with no dynamic-loader indirection to guess through — a stronger signal than anything
 *    the userland sweep gets. `sock_create` + `kernel_accept` means this module answers the network **without a
 *    userland daemon in front of it**, which is the shape `servicemap` structurally cannot see.
 * 3. *The call site*, from radare2. Only for ranked modules, because it is the only part with a cost.
 *
 * **The ranking is provenance-first, and the corpus decided which provenance signal.** The obvious key is the
 * `intree` tag — and on the very image this provider exists for, **not one of the 84 modules carries it**. That
 * build predates the tag, so its absence decides nothing, exactly as `assessModuleProvenance` already worked out
 * for the posture questions; inheriting the tag as a rank key would have ordered the WDR3600 by a signal that is
 * uniformly absent there. The key that survives is the declared **licence**: `Proprietary` is 5 of 82 declared
 * licences on the WDR3600 and 3 of 374 on the GL.iNet, and crossing it with the socket API leaves `NetUSB.ko`
 * **alone** on its image. The `intree` key is still used — but only on an image where the tag is in use at all,
 * and `provenanceUsable` records which of the two decided the order.
 *
 * **What a row here may claim.** The imports are literally in the bytes, so "this module opens a kernel socket
 * and allocates from the kernel heap" is `static_confirmed`. What happens at the call site is NOT: a window of
 * disassembly shows what the instructions do, and a bounds check that lives in the caller, or forty instructions
 * further back, is invisible to it. So every call-site row is `needs_runtime_reproduction` and phrased as a
 * statement **about the window** — *"no comparison appears in the N instructions before the call"*, never "there
 * is no bounds check". The distinction is the entire reason this can report the NetUSB allocation and the
 * `run_init_sbus` check with the same mechanism, and be right about both.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingSeverity } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';
import { isRelocatableObject } from './binvuln.js';
import { readModinfoValues } from './kernelposture.js';

const execFileAsync = promisify(execFile);

// === Identity, from `.modinfo` ===

/** What a module's `.modinfo` records say about itself. All optional: a stripped module says nothing. */
export interface KmodIdentity {
  license?: string;
  author?: string;
  /** EVERY `description` record, in order — vendors use the second and third as a version/build stamp. */
  descriptions: string[];
  /** A declared `version=` record, which almost no vendor module carries. */
  version?: string;
  /**
   * A version-shaped token found in a `description` record. A CANDIDATE, kept separate from `version` because it
   * was inferred from prose rather than read from the field that means it — see `readVersionCandidate`.
   */
  versionCandidate?: { value: string; from: string };
  vermagic?: string;
  depends: string[];
  intree?: boolean;
  srcversion?: string;
}

/** Pure: read a module's identity out of the printable text of its bytes. */
export function readIdentity(text: string): KmodIdentity {
  const descriptions = readModinfoValues(text, 'description');
  const id: KmodIdentity = {
    descriptions,
    depends: readModinfoValues(text, 'depends')
      .flatMap((d) => d.split(','))
      .map((d) => d.trim())
      .filter((d) => d.length > 0),
  };
  const license = readModinfoValues(text, 'license')[0];
  if (license) id.license = license;
  const author = readModinfoValues(text, 'author')[0];
  if (author) id.author = author;
  const version = readModinfoValues(text, 'version')[0];
  if (version) id.version = version;
  const vermagic = readModinfoValues(text, 'vermagic')[0];
  if (vermagic) id.vermagic = vermagic;
  const srcversion = readModinfoValues(text, 'srcversion')[0];
  if (srcversion) id.srcversion = srcversion;
  const intree = readModinfoValues(text, 'intree')[0];
  if (intree !== undefined) id.intree = intree === 'Y' || intree === 'y';
  if (!version) {
    const candidate = readVersionCandidate(descriptions);
    if (candidate) id.versionCandidate = candidate;
  }
  return id;
}

/**
 * Pure: find a version-shaped token in the description records.
 *
 * Vendors do not fill in `version=`. KCodes writes `description=1.02.66 TL-WDR3600 v1 7437` as the third of five
 * description records, and that string is the difference between "a proprietary module" and a component that a
 * CVE range can be matched against. So the token is worth reaching for — and worth keeping in a field whose name
 * says it was inferred, because the same shape occurs in prose that is not a version at all.
 *
 * The pattern is deliberately strict: at least three dot-separated numeric components, anchored at a record or
 * word boundary. Two components (`2.6`) match kernel versions, dates and far too much English; three is where a
 * product version starts being more likely than a coincidence. The record it came from travels with it so a
 * reader can overrule the guess without opening the file.
 */
export function readVersionCandidate(descriptions: readonly string[]): { value: string; from: string } | undefined {
  for (const d of descriptions) {
    const m = /(?:^|[\s:=v])(\d+\.\d+\.\d+(?:\.\d+)?)(?:$|[\s,;)])/.exec(d);
    const value = m?.[1];
    if (value) return { value, from: d };
  }
  return undefined;
}

// === The kernel API, from the symbol table ===

export type KernelApiCategory =
  /** Opens, binds or accepts a KERNEL socket — reachable from the network with no userland daemon in front. */
  | 'socket'
  /** Registers a packet hook: sees traffic before any socket does. */
  | 'netfilter'
  /** Kernel-heap allocation. Interesting only in company — see `rankModules`. */
  | 'alloc'
  /** No length in the signature at all. */
  | 'unbounded-copy'
  /** Takes a length, so the question is where the length comes from. */
  | 'length-copy'
  /** The syscall edge. */
  | 'user-boundary'
  /** Spawns userland or manipulates credentials. */
  | 'privilege'
  /** Registers a handle userland can open. */
  | 'device';

/**
 * The kernel symbols this sweep recognises, grouped by what they let an attacker reach.
 *
 * Exact names, not patterns. An undefined symbol in an `ET_REL` object is the exact string the module loader will
 * resolve against the kernel's export table — there is no versioning suffix, no PLT and no `@GLIBC_2.14` to strip,
 * so a substring match would only add false positives. Where the kernel genuinely ships several spellings of one
 * primitive (`kmalloc` / `__kmalloc` / `kzalloc`) all of them are listed.
 *
 * `length-copy` is separated from `unbounded-copy` on purpose. Kernel `memcpy` takes a length, so it is not the
 * `strcpy`-shaped defect the userland sweep looks for; it matters here because the length is a runtime value and
 * the question this provider asks is where that value came from.
 */
export const KERNEL_API: Readonly<Record<KernelApiCategory, readonly string[]>> = {
  socket: [
    'sock_create',
    'sock_create_kern',
    'sock_create_lite',
    'kernel_bind',
    'kernel_listen',
    'kernel_accept',
    'kernel_connect',
    'kernel_recvmsg',
    'kernel_sendmsg',
    'sock_recvmsg',
    'sock_sendmsg',
    'sock_release',
    'netlink_kernel_create',
    'netlink_unicast',
    'netlink_broadcast',
  ],
  netfilter: ['nf_register_hook', 'nf_register_hooks', 'nf_register_net_hook', 'nf_register_net_hooks'],
  alloc: [
    '__kmalloc',
    'kmalloc',
    'kzalloc',
    '__kzalloc',
    'kmalloc_order',
    'kmalloc_order_trace',
    '__kmalloc_node',
    'kmem_cache_alloc',
    'kcalloc',
    'vmalloc',
    '__vmalloc',
    'vzalloc',
    '__get_free_pages',
    'alloc_pages',
    'dev_alloc_skb',
    '__alloc_skb',
    'alloc_skb',
  ],
  'unbounded-copy': ['strcpy', 'strcat', 'sprintf', 'vsprintf', 'scnprintf'],
  'length-copy': ['memcpy', 'memmove', '__memcpy', 'strncpy', 'strlcpy', 'strncat'],
  'user-boundary': [
    'copy_from_user',
    'copy_to_user',
    '_copy_from_user',
    '_copy_to_user',
    '__copy_from_user',
    '__copy_to_user',
    '__copy_from_user_inatomic',
    'strncpy_from_user',
  ],
  privilege: [
    'call_usermodehelper',
    'call_usermodehelper_setup',
    'call_usermodehelper_exec',
    'commit_creds',
    'prepare_kernel_cred',
    'kernel_thread',
    'kthread_create',
    'kthread_run',
    'daemonize',
  ],
  device: [
    'register_chrdev',
    '__register_chrdev',
    'misc_register',
    'proc_create',
    'proc_create_data',
    'create_proc_entry',
    'device_create',
    'cdev_add',
  ],
};

/** Which categories a module's imports fall into, and the exact symbols that put them there. */
export type KernelApiSurface = Readonly<Partial<Record<KernelApiCategory, readonly string[]>>>;

/** Pure: classify a module's undefined symbols against the kernel vocabulary. */
export function classifyKernelApi(imports: readonly string[]): KernelApiSurface {
  const seen = new Set(imports);
  const out: Partial<Record<KernelApiCategory, string[]>> = {};
  for (const [category, names] of Object.entries(KERNEL_API) as Array<[KernelApiCategory, readonly string[]]>) {
    const hit = names.filter((n) => seen.has(n));
    if (hit.length > 0) out[category] = hit;
  }
  return out;
}

// === Provenance and ranking ===

/** Which provenance signal this image can actually be ordered by. */
export interface ProvenanceUsability {
  /** At least one module carries `intree=`, so its absence on another module means something. */
  intreeTagInUse: boolean;
  /** At least one module declares a licence, so a non-GPL declaration is a signal rather than a silence. */
  licenceDeclared: boolean;
  /** The prose the ranking prints about itself — never omitted, because an unusable key is a real limit. */
  note: string;
}

/**
 * Pure: decide which provenance keys this image supports, from the SET rather than from a remembered kernel
 * version. Same calibration `assessModuleProvenance` applies to the posture questions, and for the same reason:
 * the `intree` tag postdates the oldest kernels in this corpus, and hard-coding the version it arrived in would
 * be the recall-based claim `component-cve.ts` refuses to make about CVE ranges.
 */
export function assessProvenanceUsability(ids: readonly KmodIdentity[]): ProvenanceUsability {
  const intreeTagInUse = ids.some((i) => i.intree !== undefined);
  const licenceDeclared = ids.some((i) => i.license !== undefined);
  const parts: string[] = [];
  parts.push(
    intreeTagInUse
      ? 'The intree tag is in use on this image, so a module lacking it was built outside the kernel tree.'
      : 'NOT ONE module on this image carries an intree tag, so this build does not emit it and the tag ' +
          'decides nothing here — its absence is not evidence that a module is out-of-tree.',
  );
  parts.push(
    licenceDeclared
      ? 'Declared licences are present, so a non-GPL declaration ranks a module up.'
      : 'No module declares a licence, so that key is unavailable too.',
  );
  return { intreeTagInUse, licenceDeclared, note: parts.join(' ') };
}

/** A GPL-compatible declaration. Anything else is vendor code the kernel community never reviewed. */
export function isGplCompatible(license: string | undefined): boolean {
  if (!license) return false;
  return /\b(GPL|LGPL|MIT|BSD|MPL)\b/i.test(license);
}

/** One module as the sweep sees it before any disassembly. */
export interface KmodRecord {
  /** Rootfs-relative path. */
  file: string;
  size: number;
  identity: KmodIdentity;
  api: KernelApiSurface;
  /** How many undefined symbols the object carries — the denominator behind `api`. */
  importCount: number;
}

/** Why a module was ranked where it was. Data, so a reader can disagree with the ordering rather than the row. */
export interface KmodRankKeys {
  /** Declares a licence that is not GPL/BSD/MIT-compatible. */
  nonGpl: boolean;
  /** Built outside the kernel tree — only ever true when `intreeTagInUse`. */
  outOfTree: boolean;
  /** Answers the network with no userland daemon in front of it. */
  socket: boolean;
  /** Allocates from the kernel heap AND copies — the pair the call-site pass can ask a question about. */
  allocAndCopy: boolean;
  /** Crosses the syscall edge. */
  userBoundary: boolean;
  score: number;
}

/**
 * Pure: score one module. The keys are ordered by how much they narrow the set, measured on the corpus rather
 * than assumed — `nonGpl` takes 84 modules to 5 on the WDR3600, and crossing it with `socket` leaves one.
 *
 * A score orders the disassembly budget. It does NOT claim anything: upstream GPL code has kernel bugs too, and
 * the busiest network module on any of these images is netfilter, which is as reviewed as kernel code gets.
 */
export function scoreModule(rec: KmodRecord, usable: ProvenanceUsability): KmodRankKeys {
  const nonGpl = usable.licenceDeclared && rec.identity.license !== undefined && !isGplCompatible(rec.identity.license);
  const outOfTree = usable.intreeTagInUse && rec.identity.intree !== true;
  const socket = rec.api.socket !== undefined;
  const allocAndCopy =
    rec.api.alloc !== undefined && (rec.api['length-copy'] !== undefined || rec.api['unbounded-copy'] !== undefined);
  const userBoundary = rec.api['user-boundary'] !== undefined;
  const score =
    (nonGpl ? 8 : 0) + (socket ? 4 : 0) + (outOfTree ? 2 : 0) + (allocAndCopy ? 2 : 0) + (userBoundary ? 1 : 0);
  return { nonGpl, outOfTree, socket, allocAndCopy, userBoundary, score };
}

/** A module with its rank keys attached. */
export interface RankedKmod extends KmodRecord {
  keys: KmodRankKeys;
}

/**
 * Pure: order the modules for the disassembly budget, highest score first.
 *
 * The tiebreak is the PATH, never arrival order. A filesystem walk returns modules in directory order, which
 * makes the selected set an artifact of how the vendor laid out `lib/modules` — the exact defect rule 4 exists
 * for, and one this codebase has already paid for twice in `binvuln`.
 */
export function rankModules(recs: readonly KmodRecord[], usable: ProvenanceUsability): RankedKmod[] {
  return recs
    .map((r) => ({ ...r, keys: scoreModule(r, usable) }))
    .sort((a, b) => b.keys.score - a.keys.score || a.file.localeCompare(b.file));
}

// === The call site ===

/**
 * Which argument register carries the SIZE, per sink. `null` means the sink takes no size worth chasing and is
 * examined for its presence alone.
 *
 * `__kmalloc(size, flags)` puts it first; `memcpy(dst, src, n)` and `copy_from_user(to, from, n)` put it third.
 * Getting this wrong does not produce a wrong answer so much as a useless one — the chase would follow a pointer
 * instead of a length — so the table is small and explicit rather than inferred.
 */
export const SINK_SIZE_ARG: Readonly<Record<string, number>> = {
  __kmalloc: 0,
  kmalloc: 0,
  kzalloc: 0,
  __kzalloc: 0,
  __kmalloc_node: 0,
  kmalloc_order: 0,
  kmem_cache_alloc: 1,
  kcalloc: 1,
  vmalloc: 0,
  __vmalloc: 0,
  vzalloc: 0,
  __get_free_pages: 1,
  dev_alloc_skb: 0,
  __alloc_skb: 0,
  alloc_skb: 0,
  memcpy: 2,
  memmove: 2,
  __memcpy: 2,
  strncpy: 2,
  strlcpy: 2,
  copy_from_user: 2,
  _copy_from_user: 2,
  __copy_from_user: 2,
  copy_to_user: 2,
  _copy_to_user: 2,
};

/** Argument registers by architecture, in order. */
const ARG_REGS: Readonly<Record<string, readonly string[]>> = {
  mips: ['a0', 'a1', 'a2', 'a3'],
  arm: ['r0', 'r1', 'r2', 'r3'],
  arm64: ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
  x86: ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
};

/**
 * Mnemonics that genuinely reverse byte order. `wsbh` is MIPS32R2's half-word swap, `rev`/`rev16`/`rev32` are
 * Arm's, `bswap` is x86's. A value that passes through one of these on its way to an allocation size arrived in
 * network byte order — which is to say from outside the machine.
 */
const BYTESWAP_STRONG = new Set(['wsbh', 'rev', 'rev16', 'rev32', 'bswap']);

/**
 * Rotates. On MIPS32R2 the 32-bit byte swap is the PAIR `wsbh` + `rotr …, 0x10`, so a rotate corroborates the
 * swap beside it — but a rotate alone is just a rotate, and counting it as a byte swap would inflate the severity
 * of any bit-twiddling code that happens to feed an allocator. Recorded, never sufficient on its own.
 */
const BYTESWAP_WEAK = new Set(['rotr', 'ror', 'rol', 'rotl']);

/** Mnemonics that compare a register against something — evidence a bound was TESTED. */
const COMPARE_MNEMONICS = new Set([
  'slti',
  'sltiu',
  'slt',
  'sltu',
  'cmp',
  'cmn',
  'tst',
  'teq',
  'beq',
  'bne',
  // The zero-compare spellings. MIPS emits `beqz`/`bnez` for the overwhelmingly common test-against-zero, so
  // omitting them leaves the most frequent comparison in the ISA unrecognised — which is both a missed check
  // and, worse, a branch mis-read as an instruction that DEFINES its first operand.
  'beqz',
  'bnez',
  'blt',
  'bgt',
  'bge',
  'ble',
  'bltu',
  'bgeu',
  'bltz',
  'bgez',
  'bgtz',
  'blez',
  'cbz',
  'cbnz',
  'tbz',
  'tbnz',
]);

/**
 * Instructions whose FIRST operand is a source, not a destination — so they must not be read as defining it.
 *
 * MIPS spells a store `sw rt, off(base)`, putting the register being *read* exactly where `lw` puts the one being
 * written; a parser that assumes operand 0 is always the destination will untrack a live register at every store
 * and re-track it at the wrong place. Branches are the same shape (`beqz v0, target` reads `v0`), which matters
 * more than it looks: the comparison test below only counts when it touches a register the chase is still
 * following, and mis-classifying a branch as a definition would end the chase right at the check it exists to
 * find.
 */
const NON_DEFINING = new Set([
  'sw',
  'sh',
  'sb',
  'sd',
  'swl',
  'swr',
  'sdl',
  'sdr',
  'sc',
  'str',
  'strb',
  'strh',
  'stur',
  'stp',
  'push',
  ...COMPARE_MNEMONICS,
]);

/** Call instructions. Crossing one backwards means the value may be the callee's return, not anything local. */
const CALL_MNEMONICS = new Set(['jal', 'jalr', 'bal', 'bl', 'blx', 'call', 'jalx']);

/** Pure: does this instruction write its first operand register? */
export function definesFirstOperand(mnemonic: string): boolean {
  return !NON_DEFINING.has(mnemonic) && !CALL_MNEMONICS.has(mnemonic);
}

/** One parsed disassembly line. */
export interface DisasmLine {
  addr: number;
  mnemonic: string;
  operands: string[];
}

/**
 * Pure: parse radare2's `pd` output into instructions.
 *
 * Tolerant by design — r2 decorates its listing with call-graph gutters (`|`, `:`, `,=<`), comments after `;`
 * and flag lines, and a strict parser would silently return nothing on a listing that shifted by one column.
 * A line that does not look like `0xADDR  HEXBYTES  MNEMONIC OPS` is skipped rather than guessed at.
 */
export function parseDisasm(out: string): DisasmLine[] {
  const lines: DisasmLine[] = [];
  for (const raw of out.split('\n')) {
    // The three fields together are the discriminator — an address, the instruction bytes, a mnemonic. The
    // address width is deliberately NOT used as one: every module in this corpus is based at 0x08000000 and
    // prints eight digits, and a stricter width silently drops the lines of any object based lower, which would
    // surface as "no evidence at this site" rather than as an error.
    const m = /0x([0-9a-f]{4,16})\s+[0-9a-f]{2,}\s+([a-z][a-z0-9._]*)\s*(.*)$/i.exec(raw);
    if (!m) continue;
    const addr = Number.parseInt(m[1] as string, 16);
    if (!Number.isFinite(addr)) continue;
    const mnemonic = (m[2] as string).toLowerCase();
    const rest = (m[3] as string).split(';')[0] ?? '';
    const operands = rest
      .split(',')
      .map((o) => o.trim())
      .filter((o) => o.length > 0);
    lines.push({ addr, mnemonic, operands });
  }
  return lines;
}

/** What the instructions before a sink reference show. Every field is about the WINDOW, never about the program. */
export interface CallSiteEvidence {
  /** A true byte-swap (`wsbh`/`rev`/`bswap`) wrote a value the size argument derives from. */
  byteSwapped: boolean;
  /** A rotate sat on the chain — the other half of the MIPS32R2 swap idiom, on its own not a swap. */
  rotated: boolean;
  /** A comparison touched a value the size argument derives from, while the chase was still following it. */
  compared: boolean;
  /** A constant added along the chain — the `+0x11` header adjustment that makes a wrap reachable. */
  addend: number | null;
  /** The registers the chase walked, in order. Data, so a reader can check the inference rather than trust it. */
  chain: string[];
  /** The chase crossed a call, so the value may be a return rather than anything computed in view. */
  crossedCall: boolean;
  /** The chase ran out of window still following a live register — the evidence below it is unread. */
  truncated: boolean;
}

/**
 * Pure: chase the size argument backwards through a window of instructions.
 *
 * **This is reaching-definition tracking, not a keyword scan over the window, and the difference is the whole
 * value of the result.** A register is followed only until the instruction that WRITES it; past that point the
 * same name holds a different value, and any comparison against it says nothing about the one that reached the
 * call. Scanning the window for `sltiu` instead would report a bound wherever the surrounding code happened to
 * compare anything — and that error runs in the dangerous direction, quietly downgrading a real lead by claiming
 * a check that is not on the path. On the real `SoftwareBus_dispatchNormalEPMsgOut` there is a `beqz v0` four
 * instructions above the allocation testing the PREVIOUS call's return value in the same register that later
 * carries the length, which is exactly the shape that would have produced a false exoneration.
 *
 * The chase is otherwise deliberately shallow — register-to-register moves and simple arithmetic — and it stops
 * at anything it does not understand rather than assuming the value passed through. Consequences, all of them
 * stated wherever a row is composed:
 *
 * - `compared: false` means *no comparison appeared in this window on this chain*. A bound enforced in the
 *   caller, or before the window opens, is invisible here. It is a reason to look, never a claim there is none —
 *   and `truncated`/`crossedCall` say when the window is the reason.
 * - `byteSwapped: true` is the strong direction: a value that passed through a byte-order reversal on its way to
 *   an allocation size arrived in network byte order, which is to say from outside.
 */
export function chaseSizeArgument(window: readonly DisasmLine[], sizeReg: string): CallSiteEvidence {
  const chain: string[] = [sizeReg];
  const tracked = new Set([sizeReg]);
  let byteSwapped = false;
  let rotated = false;
  let addend: number | null = null;
  let crossedCall = false;
  let defIndex = 0;

  // Pass 1, backwards from the call: find the definitions that REACH the size argument. A register is followed
  // only until the instruction that writes it; below that point the same name holds a different value.
  for (let i = window.length - 1; i >= 0 && tracked.size > 0; i--) {
    const ins = window[i];
    if (!ins) continue;
    if (COMPARE_MNEMONICS.has(ins.mnemonic)) continue;
    if (CALL_MNEMONICS.has(ins.mnemonic)) {
      crossedCall = true;
      continue;
    }
    if (!definesFirstOperand(ins.mnemonic)) continue;
    const dst = operandRegister(ins.operands[0]);
    if (!dst || !tracked.has(dst)) continue;
    defIndex = i;
    if (BYTESWAP_STRONG.has(ins.mnemonic)) byteSwapped = true;
    if (BYTESWAP_WEAK.has(ins.mnemonic)) rotated = true;
    if (addend === null && /^(add|sub|addi|addiu|subi|subu|addu)$/.test(ins.mnemonic)) {
      const imm = ins.operands[2] ?? ins.operands[1];
      if (imm && /^-?(0x[0-9a-f]+|\d+)$/i.test(imm)) {
        addend = Number.parseInt(imm, imm.toLowerCase().startsWith('0x') ? 16 : 10);
      }
    }
    tracked.delete(dst);
    for (const op of ins.operands.slice(1)) {
      const src = operandRegister(op);
      if (src && !tracked.has(src)) {
        tracked.add(src);
        if (!chain.includes(src)) chain.push(src);
      }
    }
  }

  return {
    byteSwapped,
    rotated,
    compared: findComparison(window, defIndex, chain),
    addend,
    chain,
    crossedCall,
    truncated: tracked.size > 0,
  };
}

/**
 * Pass 2, forwards from the definition: was the value TESTED anywhere on its way to the call?
 *
 * A backward chase alone answers the wrong question, and the corpus said so before this shipped. The bounds check
 * a compiler emits does not compare the value itself — it computes a temporary and compares THAT. On the real
 * `run_init_sbus` in `NetUSB.ko`, the vendor's own check reads `addiu v0, a2, -1` then `sltiu v0, v0, 0x3f`: the
 * length is in `a2`, and nothing ever compares `a2`. A backward chase from the size argument never visits `v0`,
 * because `v0` is derived FROM the tracked value rather than feeding into it — so the check that makes this
 * allocation safe would have been invisible, and the module would have carried a row saying no comparison
 * appears. That is the noisy direction rather than the dangerous one, but it is still wrong, and it would have
 * been wrong on the exact function a reviewer used to DECLINE a CVE on this module.
 *
 * So the forward pass starts JUST AFTER the definition the backward chase reached and propagates: a register
 * defined from a live one joins the live set, a register defined from anything else leaves it, and a comparison
 * touching a live register is the check. Starting after the definition rather than at the top of the window is
 * what keeps an unrelated earlier use of the same register name out of the answer — on the real allocation site
 * there is a `beqz v0` testing a previous call's return four instructions above the reload, and it sits before
 * this index precisely so it cannot be counted.
 *
 * **Starting AT the definition instead of after it silently disables the whole pass**, which is how this was
 * first written: the defining instruction is a load whose source is a memory reference, so the propagation rule
 * reads it as "defined from something not live" and drops the tracked register on the very first iteration. The
 * live set is empty from then on and no comparison can ever match. It failed loudly on the `run_init_sbus`
 * fixture; against a hand-written fixture that started one instruction later it would have passed.
 */
function findComparison(window: readonly DisasmLine[], defIndex: number, chain: readonly string[]): boolean {
  const live = new Set(chain);
  for (let i = defIndex + 1; i < window.length; i++) {
    const ins = window[i];
    if (!ins) continue;
    if (COMPARE_MNEMONICS.has(ins.mnemonic)) {
      for (const op of ins.operands) {
        const r = operandRegister(op);
        if (r && live.has(r)) return true;
      }
      continue;
    }
    if (CALL_MNEMONICS.has(ins.mnemonic)) continue;
    if (!definesFirstOperand(ins.mnemonic)) continue;
    const dst = operandRegister(ins.operands[0]);
    if (!dst) continue;
    const fromLive = ins.operands.slice(1).some((op) => {
      const r = operandRegister(op);
      return r !== null && live.has(r);
    });
    if (fromLive) live.add(dst);
    else live.delete(dst);
  }
  return false;
}

/**
 * Pure: is this relocation actually a CALL SITE, or only the place the sink's address was materialised?
 *
 * A relocation names where the linker patches an address in. On MIPS the usual idiom is `lui`/`addiu` into a
 * scratch register followed immediately by `jalr` — there the relocation and the call are the same place, and the
 * instructions above it really are the argument setup.
 *
 * **But the compiler is free to hoist.** In the real `run_init_sbus`, `memcpy`'s address is loaded at the second
 * instruction of the function into `s0`, a callee-saved register, and called from several places much later:
 *
 *     0x0800cfc0  lui   v0, 0        ; RELOC memcpy
 *     0x0800cfc4  sw    s0, 0x318(sp)
 *     0x0800cfc8  addiu s0, v0, 0    ; RELOC memcpy      <- parked in s0, called later via `jalr s0`
 *
 * The twenty instructions before that are the function prologue and the tail of whatever preceded it. Chasing an
 * argument register through them answers a question about code that has nothing to do with this sink, and the
 * answer would be reported with the same confidence as a real one — including, in the worst direction, a
 * "bounded before use" row asserting a check that was never on any path.
 *
 * So a site qualifies only when a call using the materialised register appears within a few instructions, or when
 * the call is direct. Everything else is reported as an unattributed site, which is a gap, not a clean result.
 */
export function findAdjacentCall(after: readonly DisasmLine[], lookahead = 5): boolean {
  const materialised = new Set<string>();
  for (let i = 0; i < Math.min(lookahead, after.length); i++) {
    const ins = after[i];
    if (!ins) continue;
    if (CALL_MNEMONICS.has(ins.mnemonic)) {
      const target = operandRegister(ins.operands[0]);
      // A direct call (`jal <symbol>` / `bl <symbol>`) names no register and is unambiguously this sink's call.
      if (target === null) return true;
      if (materialised.has(target)) return true;
      continue;
    }
    if (!definesFirstOperand(ins.mnemonic)) continue;
    const dst = operandRegister(ins.operands[0]);
    if (dst) materialised.add(dst);
  }
  return false;
}

/** A bare register name, or null when the operand is an immediate, a memory reference or a label. */
function operandRegister(op: string | undefined): string | null {
  if (!op) return null;
  const bare = op.replace(/^\$/, '').trim();
  return /^[a-z][a-z0-9]{0,3}$/i.test(bare) ? bare : null;
}

/** A sink reference located in a module, with the evidence read from the instructions before it. */
export interface SinkCallSite {
  sink: string;
  /** Virtual address of the reference. */
  addr: number;
  /** The function the address falls inside, from the symbol table. Null when no symbol covers it. */
  fn: string | null;
  evidence: CallSiteEvidence | null;
  /** Why there is no evidence, when there is none. */
  evidenceGap?: string;
}

/** A function symbol, for mapping an address to the code it belongs to. */
export interface FnSymbol {
  name: string;
  vaddr: number;
  size: number;
}

/** Pure: which function contains an address. */
export function containingFunction(fns: readonly FnSymbol[], addr: number): string | null {
  for (const f of fns) {
    if (f.size > 0 && addr >= f.vaddr && addr < f.vaddr + f.size) return f.name;
  }
  return null;
}

/**
 * Pure: collapse a relocation list into one entry per logical reference.
 *
 * MIPS materialises a 32-bit address as a `lui`/`addiu` pair, so a single call to `__kmalloc` emits TWO
 * relocations (`R_MIPS_HI16` then `R_MIPS_LO16`) at consecutive instructions. Counting them raw doubles every
 * sink and would report a module as touching an allocator twice as often as it does. Entries for the same symbol
 * within `windowBytes` collapse to the first, which is the `lui` — and the earlier of the pair is also the right
 * place to open a disassembly window from.
 */
export function dedupeRelocations(
  relocs: ReadonlyArray<{ name: string; vaddr: number }>,
  windowBytes = 16,
): Array<{ name: string; vaddr: number }> {
  const sorted = [...relocs].sort((a, b) => a.name.localeCompare(b.name) || a.vaddr - b.vaddr);
  const out: Array<{ name: string; vaddr: number }> = [];
  for (const r of sorted) {
    const prev = out[out.length - 1];
    if (prev && prev.name === r.name && r.vaddr - prev.vaddr <= windowBytes) continue;
    out.push(r);
  }
  return out.sort((a, b) => a.vaddr - b.vaddr);
}

// === Reading the object ===

const SHT_SYMTAB = 2;
const SHN_UNDEF = 0;

/** Little/big-endian scalar reads over the raw object. */
function elfReader(buf: Uint8Array, little: boolean) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    u16: (o: number) => dv.getUint16(o, little),
    u32: (o: number) => dv.getUint32(o, little),
    u64: (o: number) => Number(dv.getBigUint64(o, little)),
  };
}

/**
 * Pure: read the UNDEFINED symbols out of an `ET_REL` object's `.symtab`.
 *
 * This is the kernel API the module loader will bind, and it is a materially stronger signal than the userland
 * sweep's equivalent: there is no dynamic loader in a kernel module, no PLT, no `@GLIBC_2.14` suffix, and no
 * string-superset fallback — a name here is a name the kernel must export or the module will not load. So a
 * module that lists `sock_create` genuinely opens a socket, in a way "the string `system` appears in the file"
 * never established for a userland binary.
 *
 * `.symtab` rather than `.dynsym` is the whole difference from `binvuln.parseDynamicSymbols`, and it is why that
 * function could not be reused: a relocatable object has no dynamic segment at all.
 *
 * Returns `null` when the object carries no readable symbol table — reported as a gap, never as "no imports".
 */
export function parseUndefinedSymbols(buf: Uint8Array): Set<string> | null {
  if (buf.length < 64) return null;
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) return null;
  const is64 = buf[4] === 2;
  const little = buf[5] === 1;
  if (buf[4] !== 1 && buf[4] !== 2) return null;
  if (buf[5] !== 1 && buf[5] !== 2) return null;
  try {
    const r = elfReader(buf, little);
    const shoff = is64 ? r.u64(0x28) : r.u32(0x20);
    const shentsize = r.u16(is64 ? 0x3a : 0x2e);
    const shnum = r.u16(is64 ? 0x3c : 0x30);
    if (!shoff || !shentsize || !shnum) return null;
    if (shoff + shnum * shentsize > buf.length) return null;

    let symOff = 0;
    let symSize = 0;
    let symEnt = 0;
    let strIdx = -1;
    for (let i = 0; i < shnum; i++) {
      const sh = shoff + i * shentsize;
      if (r.u32(sh + 4) !== SHT_SYMTAB) continue;
      symOff = is64 ? r.u64(sh + 0x18) : r.u32(sh + 0x10);
      symSize = is64 ? r.u64(sh + 0x20) : r.u32(sh + 0x14);
      symEnt = is64 ? r.u64(sh + 0x38) : r.u32(sh + 0x24);
      // sh_link sits at 0x28 in ELF64 and 0x18 in ELF32 — the same pair of offsets binvuln's reader documents,
      // and the same reason for care: firmware is overwhelmingly ELF32, so an ELF64-only mistake hides.
      strIdx = r.u32(sh + (is64 ? 0x28 : 0x18));
      break;
    }
    if (!symOff || !symSize || !symEnt || strIdx < 0 || strIdx >= shnum) return null;

    const strSh = shoff + strIdx * shentsize;
    const strOff = is64 ? r.u64(strSh + 0x18) : r.u32(strSh + 0x10);
    const strSize = is64 ? r.u64(strSh + 0x20) : r.u32(strSh + 0x14);
    if (!strOff || strOff + strSize > buf.length) return null;
    if (symOff + symSize > buf.length) return null;

    const out = new Set<string>();
    const count = Math.floor(symSize / symEnt);
    for (let i = 0; i < count; i++) {
      const sym = symOff + i * symEnt;
      // st_shndx is at 0x0e in ELF32 and 0x06 in ELF64 — the two layouts order the fields differently, they are
      // not the same struct at two widths.
      const shndx = r.u16(sym + (is64 ? 0x06 : 0x0e));
      if (shndx !== SHN_UNDEF) continue;
      const nameOff = r.u32(sym);
      if (nameOff === 0 || nameOff >= strSize) continue;
      let end = strOff + nameOff;
      while (end < strOff + strSize && buf[end] !== 0) end++;
      const name = Buffer.from(buf.subarray(strOff + nameOff, end)).toString('latin1');
      if (name) out.add(name);
    }
    return out;
  } catch {
    return null;
  }
}

/** Printable text of a bounded prefix, for the `.modinfo` scan. */
function printableText(buf: Uint8Array): string {
  return Buffer.from(buf).toString('latin1');
}

// === The result ===

/** How the call-site pass fared, so an empty `sites` list can never read as "nothing to find". */
export interface CallSitePassStatus {
  available: boolean;
  /** Why not, when not. */
  reason?: string;
  /** Modules the budget actually disassembled. */
  modulesExamined: number;
  /** Modules that ranked in but did not fit the budget, NAMED rather than counted. */
  modulesDropped: string[];
  /** Sink references dropped by the per-module safety bound. Zero on every corpus image; reported so it cannot hide. */
  sitesDropped: number;
  /**
   * References where the sink's address is materialised but called elsewhere. NOT examined, and counted rather
   * than silently treated as clean — see `findAdjacentCall`.
   */
  sitesHoisted: number;
  /** The rule the budget applied, stated so a bound is never read as an answer. */
  rule: string;
}

export interface KmodModuleResult extends RankedKmod {
  /** Null when the symbol table could not be read — distinct from an empty API surface. */
  symbolsRead: boolean;
  sites: SinkCallSite[];
}

export interface KmodResult {
  available: boolean;
  reason: string;
  /** Every `.ko` found, whether or not it ranked into the disassembly budget. */
  modules: KmodModuleResult[];
  modulesFound: number;
  /** Objects that looked like modules and were not `ET_REL` — counted so the exclusion is a stated rule. */
  notRelocatable: number;
  /** Modules whose symbol table could not be read. Never folded into "imports nothing". */
  symbolTableUnreadable: number;
  provenance: ProvenanceUsability;
  callSitePass: CallSitePassStatus;
  findings: FindingDraft[];
}

export interface KmodAdvisoryCandidate {
  cveId: string;
  advisoryUrl: string;
  matchBasis: {
    module: string;
    author: string;
    productMarker: string;
    function: string;
    version: string | null;
    versionFrom: 'version-field' | 'description-record' | null;
  };
}

/**
 * Correlate only module advisories whose identity can be tied to bytes we actually read.
 *
 * NVD currently gives CVE-2015-3036 no affected CPE or version range, so `1.02.66` MUST NOT be compared to a
 * fabricated bound. The real WDR3600 module does, however, carry all four independent identity anchors named by
 * the advisory: NetUSB.ko, author KCodes, a NetUSB description, and the exact `run_init_sbus` function. That earns
 * an identity-level candidate and nothing stronger. A same-named file without those anchors earns no row.
 */
export function kmodAdvisoryCandidates(module: KmodModuleResult): KmodAdvisoryCandidate[] {
  const moduleName = path.basename(module.file);
  const isNetUsb = moduleName.toLowerCase() === 'netusb.ko';
  const isKCodes = module.identity.author?.trim().toLowerCase() === 'kcodes';
  const product = module.identity.descriptions.find((d) => /\bnetusb\b/i.test(d));
  const functionSeen = module.sites.some((s) => s.fn === 'run_init_sbus');
  if (!isNetUsb || !isKCodes || !product || !functionSeen) return [];
  const version = module.identity.version ?? module.identity.versionCandidate?.value ?? null;
  return [
    {
      cveId: 'CVE-2015-3036',
      advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2015-3036',
      matchBasis: {
        module: moduleName,
        author: module.identity.author as string,
        productMarker: product,
        function: 'run_init_sbus',
        version,
        versionFrom: module.identity.version
          ? 'version-field'
          : module.identity.versionCandidate
            ? 'description-record'
            : null,
      },
    },
  ];
}

// === Findings ===

/**
 * Pure: compose the ledger rows.
 *
 * Two kinds, and the split is the proof-state discipline made concrete:
 *
 * - **The API surface** is `static_confirmed`. The undefined symbols are in the object's symbol table; that a
 *   module opens a kernel socket and allocates from the kernel heap is a fact about the bytes, and it is stated
 *   as exactly that — never as "is remotely exploitable".
 * - **A call site** is `needs_runtime_reproduction`. The window shows what the instructions do; whether a bound
 *   exists elsewhere in the program is a question the window cannot answer, so the row says what was seen, names
 *   the window it was seen in, and stops.
 *
 * Severity and proof state are the two axes this ledger keeps separate: a wire-length reaching an allocator with
 * no visible check is `high` because of what it would mean, and `needs_runtime_reproduction` because nothing has
 * been proven. A site whose chain IS compared in view is dropped to `info` and says why — that is the direction
 * that let a reviewer decline a plausible CVE on this very module.
 */
export function buildKmodFindings(mods: readonly KmodModuleResult[]): FindingDraft[] {
  const out: FindingDraft[] = [];
  for (const m of mods) {
    const api = m.api;
    const who = [m.identity.license, m.identity.author].filter(Boolean).join(', ');
    const version = m.identity.version ?? m.identity.versionCandidate?.value;
    const label = version ? `${path.basename(m.file)} ${version}` : path.basename(m.file);

    if (api.socket && api.alloc) {
      const sev: FindingSeverity = m.keys.nonGpl ? 'high' : 'medium';
      const versionNote = m.identity.versionCandidate
        ? ` The version is read from a description record — ${m.identity.versionCandidate.from} — rather than a version= field, so treat it as the vendor's own stamp and not a parsed field.`
        : '';
      out.push({
        kind: 'kernel-module-network-surface',
        severity: sev,
        proofState: 'static_confirmed',
        title: `Kernel module answers the network: ${label}`,
        evidenceChannel: 'static_bytes',
        evidence: {
          path: m.file,
          size: m.size,
          license: m.identity.license ?? null,
          author: m.identity.author ?? null,
          version: version ?? null,
          versionFrom: m.identity.versionCandidate ? 'description-record' : m.identity.version ? 'version-field' : null,
          vermagic: m.identity.vermagic ?? null,
          socketApi: api.socket ?? [],
          allocApi: api.alloc ?? [],
          copyApi: [...(api['length-copy'] ?? []), ...(api['unbounded-copy'] ?? [])],
          importCount: m.importCount,
          rankKeys: m.keys,
        },
        rationale: `${m.file}${who ? ` (${who})` : ''} imports ${fmtList(api.socket)} and allocates with ${fmtList(api.alloc)}. Those are undefined symbols in the object's own .symtab, so the module loader must bind them for it to load at all — this is a fact about the bytes, not an inference. A kernel socket answers before any userland daemon does, which is why the service map cannot see it: there is no init script or inetd entry to enumerate. It does NOT follow that the module is remotely exploitable; what follows is that its parser runs in kernel context on input from off-box.${versionNote}`,
      });
    }

    for (const candidate of kmodAdvisoryCandidates(m)) {
      out.push({
        kind: 'kernel-module-cve-candidate',
        severity: 'high',
        proofState: 'needs_runtime_reproduction',
        title: `${candidate.cveId} identity match: ${label}`,
        evidenceChannel: 'external_advisory',
        evidence: {
          path: m.file,
          ...candidate.matchBasis,
          cveId: candidate.cveId,
          advisoryUrl: candidate.advisoryUrl,
          affectedVersionRange: null,
        },
        rationale: `NVD describes ${candidate.cveId} in the KCodes NetUSB kernel module and names run_init_sbus. This object independently identifies itself as KCodes NetUSB and contains that exact function, so it is a strong published-advisory candidate. It is NOT a version verdict: NVD currently supplies no affected CPE/version range for this CVE, the module's ${candidate.matchBasis.version ?? 'unknown'} stamp cannot be compared to a bound that does not exist, and the vulnerable stack-copy path has not been reproduced. Confirm by patch diff or a controlled runtime test before asserting vulnerability.`,
      });
    }

    for (const s of m.sites) {
      const e = s.evidence;
      if (!e) continue;
      const where = s.fn ? s.fn : `offset 0x${s.addr.toString(16)}`;
      const shortNote = e.truncated ? ', and this chase ran out of window still following a live register' : '';
      const callNote = e.crossedCall
        ? ', and it crossed a call, so the value may be a return rather than anything local'
        : '';
      const windowNote = `This is a statement about the instructions in view. A bound enforced in the caller, or further back than the window reaches, is invisible here${shortNote}${callNote}.`;
      // Only a WIRE-ORDER length that is bounded earns a row. Measured over the corpus: 265 sites are compared
      // without ever being byte-swapped — a locally-computed size that the code happens to test — and a row for
      // each would have put 265 `info` entries in the ledger saying nothing had gone wrong. The one site that is
      // both is the finding worth having, because it is the shape a reviewer used to DECLINE a CVE on this
      // module: the vendor does bound this one. The other 265 stay in the provider's result, where the whole
      // site table is readable, rather than in a ledger meant for findings.
      if (e.compared) {
        if (!e.byteSwapped) continue;
        out.push({
          kind: 'kernel-module-checked-alloc',
          severity: 'info',
          proofState: 'static_confirmed',
          title: `Wire-order length bounded before use: ${s.sink} in ${path.basename(m.file)}`,
          evidenceChannel: 'static_bytes',
          evidence: {
            path: m.file,
            sink: s.sink,
            addr: `0x${s.addr.toString(16)}`,
            fn: s.fn,
            chain: e.chain,
            compared: true,
            byteSwapped: e.byteSwapped,
            rotated: e.rotated,
            addend: e.addend,
            crossedCall: e.crossedCall,
            windowTruncated: e.truncated,
            windowInstructions: WINDOW_INSTRUCTIONS,
          },
          rationale: `In ${where}, a value passes through a byte-order reversal — so it arrived from outside — and is COMPARED before it reaches ${s.sink}'s size argument at 0x${s.addr.toString(16)} (chain ${e.chain.join(' ← ')}). Recorded because it is the same measurement as the lead beside it with the opposite outcome, and a reader needs to see that this pass distinguishes them rather than flagging every allocation. Whether the comparison is a SUFFICIENT bound is NOT decided here — that reading is the operator's, and it is the reading that lets a plausible CVE be declined on evidence. ${windowNote}`,
        });
        continue;
      }
      if (!e.byteSwapped) continue;
      const addendNote = e.addend !== null ? `, with 0x${e.addend.toString(16)} added along the way` : '';
      out.push({
        kind: 'kernel-module-wire-length-alloc',
        severity: 'high',
        proofState: 'needs_runtime_reproduction',
        title: `Byte-swapped length reaches ${s.sink} unchecked in view: ${path.basename(m.file)}`,
        evidenceChannel: 'static_bytes',
        evidence: {
          path: m.file,
          sink: s.sink,
          addr: `0x${s.addr.toString(16)}`,
          fn: s.fn,
          chain: e.chain,
          compared: false,
          byteSwapped: true,
          rotated: e.rotated,
          addend: e.addend,
          crossedCall: e.crossedCall,
          windowTruncated: e.truncated,
          windowInstructions: WINDOW_INSTRUCTIONS,
          license: m.identity.license ?? null,
        },
        rationale: `In ${where}, a value passes through a byte-order reversal and reaches ${s.sink}'s size argument at 0x${s.addr.toString(16)}${addendNote} (chain ${e.chain.join(' ← ')}). A byte swap on the path to an allocation size means the value arrived in network byte order — from outside the machine. No comparison against that value appears in the instructions before the call. ${windowNote} This is a LEAD: it names a call site worth reading, and proves nothing about reachability or exploitability.`,
      });
    }
  }
  return out;
}

/**
 * Symbol names for a rationale sentence, plain.
 *
 * No backticks: this text is stored evidence, and it is rendered by the findings ledger, the exported HTML
 * report, the disclosure draft and MCP — none of which interpret markdown, so the quotes reach a reader as
 * literal characters. A kernel symbol is unambiguous without them.
 */
function fmtList(names: readonly string[] | undefined, max = 4): string {
  if (!names || names.length === 0) return 'nothing';
  const head = names.slice(0, max);
  return names.length > max ? `${head.join(', ')} (+${names.length - max} more)` : head.join(', ');
}

// === The runner ===

/** How many filesystem entries the walk visits before it stops. Mirrors the sweep bounds elsewhere. */
const WALK_CAP = 40000;

/**
 * How many ranked modules get the disassembly pass.
 *
 * The two cheap layers run over EVERYTHING — 628 `.ko` across the corpus read in about five seconds — so this
 * bounds only the third. Raised from 8 once the per-module disassembly was batched into one radare2 invocation:
 * at 8 the GL.iNet dropped 52 eligible modules, and a list of 52 names is a bound the reader cannot act on. At 64
 * that image still dropped exactly one (`xt_FULLCONENAT.ko`), so this seats every eligible module on all five
 * rootfs images — the GL.iNet, with 375 modules and 65 eligible, is the corpus's worst case at ~5 s.
 */
const DISASM_MODULE_CAP = 128;

/**
 * A safety bound on sink references per module, not a selection rule.
 *
 * The busiest module in the corpus (`NetUSB.ko`) carries 148, so this never bites on real input; it exists only
 * so a pathological object cannot build an unbounded command line. When it DOES bite it is counted and reported,
 * because a truncated set that reads as complete is the failure this provider already had once — at a cap of 24
 * it silently dropped the allocation site the whole pass exists to find.
 */
const SITES_PER_MODULE_CAP = 2000;

/** Instructions of context read before each sink reference — the argument setup. */
const WINDOW_INSTRUCTIONS = 20;

/**
 * Instructions read AFTER the reference, to establish that a call actually happens there.
 *
 * Small on purpose: the `lui`/`addiu`/`jalr` idiom puts the call two instructions past the relocation, and
 * widening this would start accepting an unrelated later call as evidence that this relocation is a call site.
 */
const AFTER_INSTRUCTIONS = 6;

/** Modules whose score is zero carry no signal at all; disassembling them would spend the budget on noise. */
const MIN_SCORE_FOR_DISASM = 4;

/** Probe radare2 the way `compmap` does: a present binary proves availability, only ENOENT is absent. */
async function radare2Available(): Promise<{ ok: boolean; reason?: string }> {
  try {
    await execFileAsync('rabin2', ['-v'], { timeout: 8000 });
    return { ok: true };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { ok: false, reason: 'radare2 (rabin2) is not installed in this deployment.' };
    return { ok: true };
  }
}

/** Walk a rootfs for `.ko` files, bounded. */
function findModules(root: string): string[] {
  const out: string[] = [];
  const stack: string[] = [root];
  let visited = 0;
  while (stack.length > 0 && visited < WALK_CAP) {
    const dir = stack.pop();
    if (dir === undefined) break;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      visited++;
      if (visited >= WALK_CAP) break;
      const abs = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) stack.push(abs);
      else if (e.isFile() && e.name.endsWith('.ko')) out.push(abs);
    }
  }
  return out.sort();
}

/** Read one module's identity and kernel API from its bytes alone. */
export function readModule(abs: string, rel: string): { rec: KmodRecord; relocatable: boolean; symbolsRead: boolean } {
  let bytes: Uint8Array;
  let size = 0;
  try {
    const st = fs.statSync(abs);
    size = st.size;
    bytes = fs.readFileSync(abs);
  } catch {
    return {
      rec: { file: rel, size: 0, identity: { descriptions: [], depends: [] }, api: {}, importCount: 0 },
      relocatable: false,
      symbolsRead: false,
    };
  }
  const relocatable = isRelocatableObject(bytes);
  const identity = readIdentity(printableText(bytes));
  const undef = parseUndefinedSymbols(bytes);
  const api = undef ? classifyKernelApi([...undef]) : {};
  return {
    rec: { file: rel, size, identity, api, importCount: undef ? undef.size : 0 },
    relocatable,
    symbolsRead: undef !== null,
  };
}

/** Pure: order a module's sink references so the per-module cap keeps the ones worth reading. */
export function rankSites(
  relocs: ReadonlyArray<{ name: string; vaddr: number }>,
): Array<{ name: string; vaddr: number }> {
  const priority = (n: string): number => {
    if (KERNEL_API.alloc.includes(n)) return 0;
    if (KERNEL_API['user-boundary'].includes(n)) return 1;
    if (KERNEL_API['length-copy'].includes(n)) return 2;
    return 3;
  };
  return [...relocs].sort((a, b) => priority(a.name) - priority(b.name) || a.vaddr - b.vaddr);
}

/** Read the function symbols radare2 reports, so a call site can be attributed to the code it sits in. */
async function readFunctionSymbols(abs: string): Promise<FnSymbol[]> {
  try {
    const { stdout } = await execFileAsync('rabin2', ['-sj', abs], { timeout: 30000, maxBuffer: 32 * 1024 * 1024 });
    const parsed = JSON.parse(stdout) as {
      symbols?: Array<{ name?: string; vaddr?: number; size?: number; type?: string }>;
    };
    return (parsed.symbols ?? [])
      .filter((s) => s.type === 'FUNC' && typeof s.vaddr === 'number' && typeof s.size === 'number' && s.name)
      .map((s) => ({ name: s.name as string, vaddr: s.vaddr as number, size: s.size as number }));
  } catch {
    return [];
  }
}

/** Read the relocations naming a sink. In an ET_REL object these ARE the call sites, with no analysis in between. */
async function readSinkRelocations(
  abs: string,
  sinks: ReadonlySet<string>,
): Promise<Array<{ name: string; vaddr: number }>> {
  try {
    const { stdout } = await execFileAsync('rabin2', ['-Rj', abs], { timeout: 30000, maxBuffer: 64 * 1024 * 1024 });
    const parsed = JSON.parse(stdout) as { relocs?: Array<{ name?: string; vaddr?: number }> };
    const hits = (parsed.relocs ?? [])
      .filter((r) => typeof r.vaddr === 'number' && r.name && sinks.has(r.name))
      .map((r) => ({ name: r.name as string, vaddr: r.vaddr as number }));
    return dedupeRelocations(hits);
  } catch {
    return [];
  }
}

/** Sites disassembled per r2 invocation. Bounds the command line, nothing else — see `readWindows`. */
const SITES_PER_BATCH = 400;

/**
 * Disassemble the window before EVERY sink reference in a module, in one radare2 invocation.
 *
 * **This is not an optimisation, it is what makes the pass correct.** One spawn per site costs ~47 ms, so a
 * module with 148 sinks needs seven seconds and a per-module cap to stay affordable — and any cap here truncates
 * by ADDRESS, which is code layout, which is arrival order wearing a different hat. That is precisely what rule 4
 * forbids, and it was not hypothetical: with a cap of 24 the sweep examined the first 24 allocation sites of
 * `NetUSB.ko` by address and stopped, while the site the whole provider exists to find sits at **position 135**.
 * The headline result was missing from the first real run, and the cap was the entire reason.
 *
 * Batched, the same 148 windows take **56 ms** in a single process, so the cap can be removed rather than made
 * cleverer. `?e` writes a marker line between windows; the parse splits on it and never has to infer boundaries
 * from the disassembly itself.
 */
async function readWindows(abs: string, addrs: readonly number[]): Promise<Map<number, DisasmLine[]>> {
  const out = new Map<number, DisasmLine[]>();
  for (let i = 0; i < addrs.length; i += SITES_PER_BATCH) {
    const chunk = addrs.slice(i, i + SITES_PER_BATCH);
    // Both sides of the relocation in one contiguous listing: `pd -N` gives the argument setup, `pd M` gives
    // enough to tell a call site from an address the compiler parked in a saved register.
    const cmd = chunk
      .map(
        (a) =>
          `?e ${SITE_MARKER}0x${a.toString(16)}${SITE_MARKER}; pd -${WINDOW_INSTRUCTIONS} @ 0x${a.toString(16)}; ` +
          `pd ${AFTER_INSTRUCTIONS} @ 0x${a.toString(16)}`,
      )
      .join('; ');
    try {
      const { stdout } = await execFileAsync('r2', ['-2', '-N', '-q', '-e', 'scr.color=0', '-c', cmd, abs], {
        timeout: 120000,
        maxBuffer: 128 * 1024 * 1024,
      });
      for (const [addr, text] of splitMarkedWindows(stdout)) out.set(addr, parseDisasm(text));
    } catch {
      // A failed batch leaves its addresses absent from the map, and the caller reports them as unexamined
      // rather than as examined-and-clean.
    }
  }
  return out;
}

const SITE_MARKER = '==FIRMLAB-SITE==';

/** Pure: split a batched listing on its markers, back into one window per address. */
export function splitMarkedWindows(stdout: string): Array<[number, string]> {
  const out: Array<[number, string]> = [];
  const parts = stdout.split(SITE_MARKER);
  // parts = [preamble, "0xADDR", window, "0xADDR", window, ...]
  for (let i = 1; i + 1 < parts.length; i += 2) {
    const addr = Number.parseInt((parts[i] ?? '').trim(), 16);
    if (Number.isFinite(addr)) out.push([addr, parts[i + 1] ?? '']);
  }
  return out;
}

/** Which architecture family radare2 reports, for the argument-register map. */
async function readArch(abs: string): Promise<{ family: string; bits: number }> {
  try {
    const { stdout } = await execFileAsync('rabin2', ['-Ij', abs], { timeout: 20000, maxBuffer: 4 * 1024 * 1024 });
    const parsed = JSON.parse(stdout) as { info?: { arch?: string; bits?: number } };
    return { family: parsed.info?.arch ?? '', bits: parsed.info?.bits ?? 32 };
  } catch {
    return { family: '', bits: 32 };
  }
}

/** Pure: the register carrying argument `n` on this architecture, or null when the family is unknown. */
export function argRegister(archFamily: string, bits: number, n: number): string | null {
  const key = archFamily === 'arm' && bits === 64 ? 'arm64' : archFamily;
  const regs = ARG_REGS[key];
  return regs?.[n] ?? null;
}

/**
 * Run the kernel-module sweep over an extracted rootfs.
 *
 * Layers 1 and 2 need no external tool and run over every module. Layer 3 needs radare2 and runs over the ranked
 * head of the list; with radare2 absent the pass reports `available: false` with the reason and the first two
 * layers still produce their rows — a missing disassembler costs the call sites, not the inventory.
 */
export async function runKmod(rootfsPath: string | null): Promise<KmodResult> {
  const empty: Omit<KmodResult, 'available' | 'reason'> = {
    modules: [],
    modulesFound: 0,
    notRelocatable: 0,
    symbolTableUnreadable: 0,
    provenance: { intreeTagInUse: false, licenceDeclared: false, note: 'No module was read.' },
    callSitePass: {
      available: false,
      modulesExamined: 0,
      modulesDropped: [],
      sitesDropped: 0,
      sitesHoisted: 0,
      rule: 'Not reached.',
    },
    findings: [],
  };
  if (!rootfsPath) {
    return {
      ...empty,
      available: false,
      reason:
        'No rootfs has been extracted, so there are no kernel modules to read. That is not a statement about the firmware.',
    };
  }

  const files = findModules(rootfsPath);
  if (files.length === 0) {
    return {
      ...empty,
      available: true,
      reason:
        'The rootfs carries no .ko files. A monolithic kernel with everything compiled in produces exactly ' +
        'this result, and so does a carve that missed lib/modules — the two are not distinguished here.',
    };
  }

  const recs: KmodRecord[] = [];
  let notRelocatable = 0;
  let symbolTableUnreadable = 0;
  const symbolsReadBy = new Map<string, boolean>();
  for (const abs of files) {
    const rel = path.relative(rootfsPath, abs);
    const { rec, relocatable, symbolsRead } = readModule(abs, rel);
    if (!relocatable) {
      notRelocatable++;
      continue;
    }
    if (!symbolsRead) symbolTableUnreadable++;
    symbolsReadBy.set(rel, symbolsRead);
    recs.push(rec);
  }

  const provenance = assessProvenanceUsability(recs.map((r) => r.identity));
  const ranked = rankModules(recs, provenance);

  const r2 = await radare2Available();
  const eligible = ranked.filter((m) => m.keys.score >= MIN_SCORE_FOR_DISASM);
  const chosen = r2.ok ? eligible.slice(0, DISASM_MODULE_CAP) : [];
  const dropped = eligible.slice(chosen.length).map((m) => m.file);

  const sinkNames = new Set<string>(Object.keys(SINK_SIZE_ARG));
  let sitesDropped = 0;
  let hoistedSites = 0;
  const results: KmodModuleResult[] = ranked.map((m) => ({
    ...m,
    symbolsRead: symbolsReadBy.get(m.file) ?? false,
    sites: [],
  }));
  const byFile = new Map(results.map((r) => [r.file, r]));

  for (const m of chosen) {
    const abs = path.join(rootfsPath, m.file);
    const target = byFile.get(m.file);
    if (!target) continue;
    const [arch, fns, relocs] = await Promise.all([
      readArch(abs),
      readFunctionSymbols(abs),
      readSinkRelocations(abs, sinkNames),
    ]);
    const ranked = rankSites(relocs);
    const sites = ranked.slice(0, SITES_PER_MODULE_CAP);
    if (ranked.length > sites.length) sitesDropped += ranked.length - sites.length;
    const windows = await readWindows(
      abs,
      sites.map((s) => s.vaddr),
    );
    for (const site of sites) {
      const argIndex = SINK_SIZE_ARG[site.name];
      const fn = containingFunction(fns, site.vaddr);
      if (argIndex === undefined) continue;
      const reg = argRegister(arch.family, arch.bits, argIndex);
      if (!reg) {
        target.sites.push({
          sink: site.name,
          addr: site.vaddr,
          fn,
          evidence: null,
          evidenceGap: `No argument-register map for architecture "${arch.family}/${arch.bits}", so the size argument could not be chased.`,
        });
        continue;
      }
      const listing = windows.get(site.vaddr);
      if (!listing || listing.length === 0) {
        target.sites.push({
          sink: site.name,
          addr: site.vaddr,
          fn,
          evidence: null,
          evidenceGap: 'radare2 returned no disassembly for this address.',
        });
        continue;
      }
      const before = listing.filter((l) => l.addr < site.vaddr);
      const after = listing.filter((l) => l.addr >= site.vaddr);
      if (!findAdjacentCall(after)) {
        hoistedSites++;
        target.sites.push({
          sink: site.name,
          addr: site.vaddr,
          fn,
          evidence: null,
          evidenceGap: `The sink's address is materialised here but no call follows within ${AFTER_INSTRUCTIONS} instructions — the compiler parked it in a register and calls it elsewhere, so the instructions before this point are not its argument setup and were not read as such.`,
        });
        continue;
      }
      target.sites.push({ sink: site.name, addr: site.vaddr, fn, evidence: chaseSizeArgument(before, reg) });
    }
  }

  const findings = buildKmodFindings(results);
  const callSitePass: CallSitePassStatus = {
    available: r2.ok,
    modulesExamined: chosen.length,
    modulesDropped: dropped,
    sitesDropped,
    sitesHoisted: hoistedSites,
    rule: `Modules scoring at least ${MIN_SCORE_FOR_DISASM} are eligible (a non-GPL licence weighs 8, a kernel socket 4, out-of-tree 2, allocator-plus-copy 2, the syscall edge 1); the top ${DISASM_MODULE_CAP} by score then path are disassembled, EVERY sink reference in each (bounded only by a ${SITES_PER_MODULE_CAP} safety limit no corpus module approaches), allocators first. The order is by SCORE and then PATH, never by walk order, so the selected set is not an artifact of how the vendor laid out lib/modules.`,
  };
  if (!r2.ok && r2.reason) callSitePass.reason = r2.reason;

  const skipNote = notRelocatable > 0 ? `, ${notRelocatable} skipped as not relocatable objects` : '';
  const symNote = symbolTableUnreadable > 0 ? `, ${symbolTableUnreadable} with an unreadable symbol table` : '';
  const passNote = r2.ok
    ? ` ${chosen.length} of ${eligible.length} eligible module(s) disassembled.`
    : ` The call-site pass did not run: ${r2.reason ?? 'radare2 unavailable'}`;

  return {
    available: true,
    reason: `${recs.length} kernel module(s) read${skipNote}${symNote}.${passNote} An empty list of call sites means the ranked modules showed none in view — not that this rootfs has none.`,
    modules: results,
    modulesFound: files.length,
    notRelocatable,
    symbolTableUnreadable,
    provenance,
    callSitePass,
    findings,
  };
}
