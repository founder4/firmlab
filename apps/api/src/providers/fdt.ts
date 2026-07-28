/**
 * FDT (Flattened Device Tree) — the ONE binary reader for the format in this repo.
 *
 * The walk already existed, buried inside `carve.ts`'s `parseFitImages`, where it served a single purpose: find the
 * absolute byte range of a FIT sub-image's inlined `data` so the carve chain could slice it out. A FIT *is* an FDT,
 * so that code was a device-tree parser that threw the device tree away. Rather than grow a second, subtly different
 * one next to it, the walk lives here and both callers share it — `carve.ts` for sub-image ranges, `devicetree.ts`
 * for the tree itself. A format with a NUL-terminated string table, 4-byte token alignment and three sub-blocks has
 * too many off-by-one opportunities to implement twice.
 *
 * What this module refuses to do:
 *
 *  - **It will not report a tree it could not finish reading.** `walkFdt` returns `complete:false` plus the reason
 *    when the token stream ends anywhere other than `FDT_END`, and counts properties whose name did not resolve to a
 *    printable token inside the strings block. Both matter, and not hypothetically: on the GL.iNet BE3600 the raw
 *    image contains the FDT magic at file offset 10186216 with a header that validates perfectly (totalsize 60082,
 *    version 17, every offset in range) — but the blob is a device tree stored inside a UBI volume, so the raw file
 *    splices the next eraseblock's `UBI#` EC/VID headers into the middle of it. It diverges from the true blob at
 *    byte 37821: the strings block is clobbered, so every property NAME decodes wrong while the values still look
 *    right, and the walk hits an invalid token at 37824 after emitting about 60% of the nodes. A header check does
 *    not catch that. Finishing the walk does.
 *  - **It will not guess a property's type beyond what dtc guesses.** FDT stores no type information; `dtc -O dts`
 *    infers one, and this module implements its exact `util_is_printable_string` rule (must end in NUL, every
 *    NUL-separated segment non-empty and printable). The naive version — "ends in NUL and the rest is printable" —
 *    reads `clock-frequency = <0x7d00>` as a string list, because the cell's high bytes are zero. That was the first
 *    bug found against real bytes here.
 *  - **It will not accept a magic match as a device tree.** `scanFdtCandidates` validates the whole header
 *    (version range, block alignment, every offset and size inside `totalsize` and inside the buffer). The
 *    IMOU-Ranger-2C image contains three `d00dfeed` byte sequences in compressed data, all three with garbage
 *    headers (version 4294442687, and so on). Magic alone is four bytes of coincidence.
 */

/** `0xd00dfeed` — the FDT header magic, big-endian at the start of every flattened device tree. */
export const FDT_MAGIC = 0xd00dfeed;

const FDT_BEGIN_NODE = 0x1;
const FDT_END_NODE = 0x2;
const FDT_PROP = 0x3;
const FDT_NOP = 0x4;
const FDT_END = 0x9;

/** The FDT header is 40 bytes through `size_dt_struct` (v17); the memory-reserve block follows it. */
const HEADER_BYTES = 40;

/** Read a big-endian u32; bounds-guarded, never throws (0 out of range, which every caller treats as invalid). */
export function be32(b: Uint8Array, o: number): number {
  if (o < 0 || o + 3 >= b.length) return 0;
  return (((b[o] ?? 0) << 24) | ((b[o + 1] ?? 0) << 16) | ((b[o + 2] ?? 0) << 8) | (b[o + 3] ?? 0)) >>> 0;
}

function alignUp(n: number, a: number): number {
  return Math.ceil(n / a) * a;
}

/**
 * The decoded FDT header. `base` is the absolute offset of the header within the buffer it was read from, so every
 * `off*` field is relative to `base` and every offset this module hands back is absolute — a blob embedded at a
 * non-zero offset (a FIT sub-image, a raw-image hit) needs no separate slice.
 */
export interface FdtHeader {
  base: number;
  totalSize: number;
  offStruct: number;
  offStrings: number;
  offMemReserve: number;
  version: number;
  lastCompVersion: number;
  bootCpuidPhys: number;
  sizeStrings: number;
  sizeStruct: number;
}

/**
 * Pure: read and VALIDATE an FDT header at `base`. Returns null unless the magic matches and the header is
 * internally consistent — version in the range any real dtc has emitted, both block offsets correctly aligned
 * (struct on 4, memory-reserve on 8, as the spec requires), and every block fully inside both `totalSize` and the
 * buffer. These checks are what separate a device tree from four coincidental bytes in a compressed payload.
 */
export function readFdtHeader(buf: Uint8Array, base = 0): FdtHeader | null {
  if (base < 0 || base + HEADER_BYTES > buf.length) return null;
  if (be32(buf, base) !== FDT_MAGIC) return null;

  const totalSize = be32(buf, base + 4);
  const offStruct = be32(buf, base + 8);
  const offStrings = be32(buf, base + 12);
  const offMemReserve = be32(buf, base + 16);
  const version = be32(buf, base + 20);
  const lastCompVersion = be32(buf, base + 24);
  const bootCpuidPhys = version >= 2 ? be32(buf, base + 28) : 0;

  // dtc has emitted 16 or 17 for two decades; 2 is the oldest version that carries a boot_cpuid field at all.
  if (version < 2 || version > 17) return null;
  if (lastCompVersion < 2 || lastCompVersion > version) return null;
  if (totalSize < HEADER_BYTES || base + totalSize > buf.length) return null;
  if (offStruct % 4 !== 0 || offMemReserve % 8 !== 0) return null;
  if (offStruct < HEADER_BYTES || offStrings < HEADER_BYTES || offMemReserve < HEADER_BYTES) return null;
  if (offStruct >= totalSize || offStrings >= totalSize || offMemReserve >= totalSize) return null;

  // size_dt_strings arrived in v3 and size_dt_struct in v17; before that the block runs to the next one. The old
  // `offStruct + sizeStruct || buf.length` idiom silently walked zero tokens on a v16 blob, because `offStruct + 0`
  // is truthy — deriving the size instead is the honest reading of a header that simply does not carry it.
  const sizeStrings = version >= 3 ? be32(buf, base + 32) : totalSize - offStrings;
  const sizeStruct = version >= 17 ? be32(buf, base + 36) : Math.max(0, offStrings - offStruct);
  if (sizeStruct < 4 || offStruct + sizeStruct > totalSize) return null;
  if (sizeStrings < 0 || offStrings + sizeStrings > totalSize) return null;

  return {
    base,
    totalSize,
    offStruct,
    offStrings,
    offMemReserve,
    version,
    lastCompVersion,
    bootCpuidPhys,
    sizeStrings,
    sizeStruct,
  };
}

/**
 * Pure: every offset in `buf` carrying a header that `readFdtHeader` accepts. Overlapping hits are possible and
 * kept — a FIT is itself an FDT and legitimately contains more of them — so the caller decides what each one is.
 */
export function scanFdtCandidates(buf: Uint8Array, limit = 64): FdtHeader[] {
  const out: FdtHeader[] = [];
  for (let i = 0; i + HEADER_BYTES <= buf.length && out.length < limit; i++) {
    if (buf[i] !== 0xd0 || buf[i + 1] !== 0x0d || buf[i + 2] !== 0xfe || buf[i + 3] !== 0xed) continue;
    const header = readFdtHeader(buf, i);
    if (header) out.push(header);
  }
  return out;
}

/** Read a NUL-terminated byte string as ASCII, stopping at `end`. Returns null if it is not terminated in range. */
function readCString(buf: Uint8Array, start: number, end: number): string | null {
  if (start < 0 || start >= end || start >= buf.length) return null;
  const stop = Math.min(end, buf.length);
  let e = start;
  while (e < stop && (buf[e] ?? 0) !== 0) e++;
  if (e >= stop) return null; // ran off the end without a terminator
  let s = '';
  for (let i = start; i < e; i++) s += String.fromCharCode(buf[i] ?? 0);
  return s;
}

/** A property name is usable only if it terminated inside the strings block and is non-empty printable ASCII. */
function isUsableName(name: string | null): name is string {
  if (name === null || name.length === 0 || name.length > 255) return false;
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

/** Callbacks for a streaming walk. `path` is the live node stack, root first (the root node's name is empty). */
export interface FdtWalkVisitor {
  beginNode?(name: string, path: readonly string[]): void;
  /** `valueOffset` is ABSOLUTE in the buffer walked — that is what makes a FIT sub-image carve-able in place. */
  prop?(name: string, value: Uint8Array, valueOffset: number, path: readonly string[]): void;
  endNode?(name: string, path: readonly string[]): void;
}

/** What the walk actually managed to read — the integrity report, never just "here is a tree". */
export interface FdtWalkOutcome {
  /** True only when the token stream terminated on `FDT_END` with a balanced node stack. */
  complete: boolean;
  nodeCount: number;
  propCount: number;
  /** Properties whose name did not resolve to a printable token in the strings block (a clobbered strings block). */
  unnamedProps: number;
  maxDepth: number;
  /** Present when `complete` is false: what stopped the walk and where. */
  stopReason?: string;
}

const MAX_TOKENS = 500_000;
const MAX_DEPTH = 64;

/**
 * Pure: stream the struct block, emitting node/property events. Never throws and never loops — bounded by a token
 * budget and a depth cap, both of which are reported as an incomplete walk rather than silently truncating a tree.
 *
 * A property whose name cannot be resolved is still emitted (with an empty name) and counted in `unnamedProps`, so
 * a caller can tell "this tree has a property I could not name" from "this tree has no such property". Dropping it
 * would turn a corrupt blob into a plausible-looking one.
 */
export function walkFdt(buf: Uint8Array, header: FdtHeader, visitor: FdtWalkVisitor): FdtWalkOutcome {
  const structStart = header.base + header.offStruct;
  const structEnd = Math.min(structStart + header.sizeStruct, buf.length);
  const stringsStart = header.base + header.offStrings;
  const stringsEnd = Math.min(stringsStart + header.sizeStrings, buf.length);

  // Every FDT alignment is relative to the START OF THE BLOB, not to the buffer holding it. Aligning absolute
  // positions works only while the blob sits at a multiple of 4 — which real dtbs usually do, so the mistake
  // survives a corpus and dies on the first tree embedded at an odd offset.
  const align = (p: number): number => header.base + alignUp(p - header.base, 4);

  const path: string[] = [];
  let nodeCount = 0;
  let propCount = 0;
  let unnamedProps = 0;
  let maxDepth = 0;
  let pos = structStart;
  let tokens = 0;

  const stop = (reason: string): FdtWalkOutcome => ({
    complete: false,
    nodeCount,
    propCount,
    unnamedProps,
    maxDepth,
    stopReason: reason,
  });

  while (pos + 4 <= structEnd) {
    if (++tokens > MAX_TOKENS) return stop(`token budget of ${MAX_TOKENS} exhausted at offset ${pos}`);
    const token = be32(buf, pos);
    pos += 4;

    if (token === FDT_BEGIN_NODE) {
      const name = readCString(buf, pos, structEnd);
      if (name === null) return stop(`unterminated node name at offset ${pos}`);
      pos = align(pos + name.length + 1);
      if (path.length >= MAX_DEPTH) return stop(`node nesting exceeded ${MAX_DEPTH} levels at offset ${pos}`);
      path.push(name);
      nodeCount++;
      maxDepth = Math.max(maxDepth, path.length);
      visitor.beginNode?.(name, path);
    } else if (token === FDT_END_NODE) {
      if (path.length === 0) return stop(`FDT_END_NODE with no open node at offset ${pos - 4}`);
      const name = path[path.length - 1] as string;
      visitor.endNode?.(name, path);
      path.pop();
    } else if (token === FDT_PROP) {
      const len = be32(buf, pos);
      const nameOff = be32(buf, pos + 4);
      pos += 8;
      const valuePos = pos;
      if (valuePos + len > structEnd) return stop(`property value at offset ${valuePos} runs past the struct block`);
      pos = align(pos + len);
      const raw = readCString(buf, stringsStart + nameOff, stringsEnd);
      const named = isUsableName(raw);
      if (!named) unnamedProps++;
      propCount++;
      visitor.prop?.(named ? raw : '', buf.subarray(valuePos, valuePos + len), valuePos, path);
    } else if (token === FDT_NOP) {
      // padding — nothing to do
    } else if (token === FDT_END) {
      if (path.length !== 0) return stop(`FDT_END with ${path.length} node(s) still open`);
      return { complete: true, nodeCount, propCount, unnamedProps, maxDepth };
    } else {
      return stop(`invalid token 0x${token.toString(16)} at offset ${pos - 4}`);
    }
  }
  return stop(`struct block ended at offset ${structEnd} without an FDT_END token`);
}

// === The tree ============================================================================================

/** One property: its name, its raw bytes (a view, not a copy) and where those bytes live in the buffer. */
export interface FdtProperty {
  name: string;
  value: Uint8Array;
  offset: number;
}

/** One node. `path` is the canonical absolute path (`/` for the root, `/soc/serial@78af000` for a child). */
export interface FdtNode {
  name: string;
  path: string;
  props: FdtProperty[];
  children: FdtNode[];
}

/** A `/memreserve/` entry — a physical range the kernel must not use. Rarely populated; reported when it is. */
export interface FdtReservation {
  address: number;
  size: number;
}

/** A parsed device tree plus the honest account of how much of it could be read. */
export interface ParsedFdt {
  header: FdtHeader;
  root: FdtNode;
  reservations: FdtReservation[];
  outcome: FdtWalkOutcome;
}

/** Read a big-endian u64 as a JS number (flash offsets and RAM bases stay well inside 2^53). */
function be64(b: Uint8Array, o: number): number {
  return be32(b, o) * 0x1_0000_0000 + be32(b, o + 4);
}

/** Pure: the memory-reserve block, read until the terminating all-zero entry or the start of the struct block. */
export function readMemReservations(buf: Uint8Array, header: FdtHeader, limit = 64): FdtReservation[] {
  const out: FdtReservation[] = [];
  const start = header.base + header.offMemReserve;
  const end = Math.min(header.base + header.offStruct, buf.length);
  for (let o = start; o + 16 <= end && out.length < limit; o += 16) {
    const address = be64(buf, o);
    const size = be64(buf, o + 8);
    if (address === 0 && size === 0) break;
    out.push({ address, size });
  }
  return out;
}

/**
 * Pure: build the whole tree. Returns null only when the header itself is unreadable; a tree the walk could not
 * finish is still returned, with `outcome.complete === false` — the caller decides whether a partial tree is worth
 * anything, and in this codebase it is worth reporting as a rejection, not as a result.
 */
export function parseFdt(buf: Uint8Array, base = 0): ParsedFdt | null {
  const header = readFdtHeader(buf, base);
  if (!header) return null;

  const root: FdtNode = { name: '', path: '/', props: [], children: [] };
  const stack: FdtNode[] = [];
  let current: FdtNode | null = null;

  const outcome = walkFdt(buf, header, {
    beginNode(name) {
      if (stack.length === 0) {
        current = root;
        stack.push(root);
        return;
      }
      const parent = stack[stack.length - 1] as FdtNode;
      const node: FdtNode = {
        name,
        path: parent.path === '/' ? `/${name}` : `${parent.path}/${name}`,
        props: [],
        children: [],
      };
      parent.children.push(node);
      stack.push(node);
      current = node;
    },
    prop(name, value, offset) {
      if (current) current.props.push({ name, value, offset });
    },
    endNode() {
      stack.pop();
      current = stack.length > 0 ? (stack[stack.length - 1] as FdtNode) : null;
    },
  });

  return { header, root, reservations: readMemReservations(buf, header), outcome };
}

// === Property value typing ===============================================================================

/** A property value, typed the only way FDT allows: by inspecting the bytes, exactly as dtc does. */
export type FdtValue =
  | { type: 'empty' }
  | { type: 'stringlist'; strings: string[] }
  | { type: 'cells'; cells: number[] }
  | { type: 'bytes'; length: number };

/**
 * dtc's `util_is_printable_string`: the value must end in NUL, and every NUL-separated segment must be non-empty
 * and printable. The "non-empty" clause is the load-bearing one — without it a `<0x0>` cell (four NUL bytes) reads
 * as a list of empty strings, and `<0x7d00>` reads as a string because its two high bytes are zero.
 */
export function isPrintableStringList(v: Uint8Array): boolean {
  if (v.length === 0) return false;
  if ((v[v.length - 1] ?? 1) !== 0) return false;
  let i = 0;
  while (i < v.length) {
    const start = i;
    while (i < v.length) {
      const c = v[i] ?? 0;
      if (c === 0 || c < 0x20 || c > 0x7e) break;
      i++;
    }
    if ((v[i] ?? 1) !== 0 || i === start) return false;
    i++;
  }
  return true;
}

/** Split a NUL-separated string list into its segments (byte-wise, so no NUL literal is needed anywhere). */
function splitStrings(v: Uint8Array): string[] {
  const out: string[] = [];
  let s = '';
  for (let i = 0; i < v.length; i++) {
    const c = v[i] ?? 0;
    if (c === 0) {
      out.push(s);
      s = '';
    } else {
      s += String.fromCharCode(c);
    }
  }
  if (s.length > 0) out.push(s);
  return out;
}

/** Pure: type a property value. Zero length means the property is a boolean whose presence is the `true`. */
export function decodeFdtValue(v: Uint8Array, maxCells = 64): FdtValue {
  if (v.length === 0) return { type: 'empty' };
  if (isPrintableStringList(v)) return { type: 'stringlist', strings: splitStrings(v) };
  if (v.length % 4 === 0 && v.length / 4 <= maxCells) {
    const cells: number[] = [];
    for (let i = 0; i < v.length; i += 4) cells.push(be32(v, i));
    return { type: 'cells', cells };
  }
  return { type: 'bytes', length: v.length };
}

// === Node accessors ======================================================================================

/** The raw property, or undefined. */
export function prop(node: FdtNode, name: string): FdtProperty | undefined {
  return node.props.find((p) => p.name === name);
}

/** True when the property exists at all — which for a zero-length property is the whole meaning (`read-only`). */
export function hasProp(node: FdtNode, name: string): boolean {
  return node.props.some((p) => p.name === name);
}

/** Every string in a string-list property (`compatible` is the canonical multi-entry one), or []. */
export function propStrings(node: FdtNode, name: string): string[] {
  const p = prop(node, name);
  if (!p) return [];
  const v = decodeFdtValue(p.value);
  return v.type === 'stringlist' ? v.strings : [];
}

/** The first string of a string property, or undefined when absent or not a string. */
export function propString(node: FdtNode, name: string): string | undefined {
  return propStrings(node, name)[0];
}

/** Every u32 cell of a cell property, or []. A long `reg` exceeds the default cell cap, so it is raised here. */
export function propCells(node: FdtNode, name: string, maxCells = 256): number[] {
  const p = prop(node, name);
  if (!p) return [];
  if (p.value.length === 0 || p.value.length % 4 !== 0) return [];
  const cells: number[] = [];
  for (let i = 0; i < p.value.length && cells.length < maxCells; i += 4) cells.push(be32(p.value, i));
  return cells;
}

/** The single u32 of a one-cell property (`#address-cells`, `index`), or undefined. */
export function propU32(node: FdtNode, name: string): number | undefined {
  const p = prop(node, name);
  if (!p || p.value.length !== 4) return undefined;
  return be32(p.value, 0);
}

/** Depth-first walk over the tree, root included. */
export function eachNode(root: FdtNode, fn: (node: FdtNode, depth: number) => void, depth = 0): void {
  fn(root, depth);
  for (const child of root.children) eachNode(child, fn, depth + 1);
}

/** Resolve an absolute node path (`/soc/serial@78af000`) to its node, or undefined. */
export function nodeAt(root: FdtNode, path: string): FdtNode | undefined {
  if (path === '/' || path === '') return root;
  let node = root;
  for (const part of path.split('/')) {
    if (part === '') continue;
    const next = node.children.find((c) => c.name === part);
    if (!next) return undefined;
    node = next;
  }
  return node;
}
