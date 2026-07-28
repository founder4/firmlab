/**
 * Open the bytes extraction actually wrote to disk — the surface that lets an operator CHECK the evidence a
 * finding cites instead of trusting the finding.
 *
 * docs/BACKLOG.md carries an entry that was withdrawn because it had been written from a filename without opening
 * the file: "BeanView's `private_key.pem` is extracted and unanalysed". The file begins `-----BEGIN PUBLIC KEY-----`.
 * That is the precise failure this workbench exists to prevent, and it happened for a structural reason — there was
 * no way to open the file. The GL.iNet carve produces 6497 files and no route served a single one of them, so every
 * finding in the ledger cited evidence the operator could not check, and the ledger asked to be trusted at exactly
 * the point this project says nothing should be. The design follows from that:
 *
 *  • The root is the EXTRACTION DIRECTORY, not the rootfs. A browser rooted at `rootfsPath` shows BeanView-Camera
 *    (54 carved volumes, no rootfs) and Asus-Router (a truncated SquashFS) an empty tree — the exact conflation of
 *    "nothing came out" with "no rootfs was recognised" that extract-diagnose.ts exists to break.
 *  • The guard is layered and every layer NAMES ITSELF. A refusal that says "denied" teaches nothing; a refusal
 *    that says which rule refused is itself a fact. `etc/passwd -> /dev/null` in DVRF is not an attack on the
 *    browser, it is how that image ships, so the listing REPORTS the escape rather than hiding the entry, and only
 *    a read through it is refused. The lexical containment test is the one `resolveInsideRootfs` (decompile.ts)
 *    already applies across the providers; what is added here is the symlink leg, which a browser needs and a
 *    "resolve one named binary" call never did.
 *  • Text-vs-binary is decided from the BYTES. extract-recover.ts dispatches on magic rather than extension because
 *    binwalk names a raw LZMA stream `.7z`; in firmware an extension is a hint, and `private_key.pem` holding a
 *    public key is the same mistake one layer up.
 *  • Every read states its bound. A truncated read is not the file: the result says at which byte it stopped and
 *    how many bytes are really there (CLAUDE.md rule 4). A listing's cap sorts before it truncates, so the set that
 *    survives is a property of the directory rather than of readdir order.
 *
 * What it refuses to claim: reading a file proves those bytes are on disk in THIS extraction, and nothing else. It
 * is not evidence about the running device — an extraction is a carve of an image, and several corpus images carve
 * partially or not at all. It is not a claim that the extraction is complete either, which is why a listing is
 * never served without the extraction verdict beside it (`describeExtraction`).
 *
 * Everything here reads the filesystem and returns a verdict, the way extract-diagnose.ts does, and imports no
 * store — so the tests exercise the real rules against real trees, real symlinks included, rather than a model of
 * them.
 */
import fs from 'node:fs';
import path from 'node:path';

/** What a read of these bytes does and does not establish. Rendered wherever a file's contents are shown. */
export const EVIDENCE_CLAIM =
  'These bytes are what the extractor wrote to disk for this image. Reading them establishes that the content is ' +
  'present in THIS extraction — it is not evidence about the running device, and it is not a claim that the ' +
  'extraction recovered everything the image contains.';

/** Entries returned for one directory before the cap applies. */
export const MAX_ENTRIES = 2000;
/** Default slice served by a read when the caller names no limit. */
export const DEFAULT_READ_BYTES = 64 * 1024;
/** Hard ceiling on a single read, whatever the caller asks for. */
export const MAX_READ_BYTES = 1024 * 1024;
/** Bytes sampled when deciding text-vs-binary. Enough to catch a NUL in any real header. */
export const CLASSIFY_SAMPLE_BYTES = 8192;

/**
 * Why a path was refused. Each value is a distinct rule, because "denied" is not an answer: an operator who asked
 * for `../../etc/shadow` and an operator who asked for a symlink the firmware itself points at `/dev/null` need
 * different sentences back.
 */
export type PathRule =
  | 'absolute-path'
  | 'nul-in-path'
  | 'escapes-root'
  | 'symlink-escapes-root'
  | 'not-found'
  | 'not-a-file'
  | 'not-a-directory'
  | 'unreadable';

export interface PathRefused {
  ok: false;
  rule: PathRule;
  /** The sentence naming which rule refused, and why that rule exists. */
  reason: string;
  /** Where the symlink pointed, when a symlink is what refused it — that is information about the firmware. */
  symlinkTarget?: string;
}

export interface PathResolved {
  ok: true;
  /** Absolute path on disk, lexically normalised and proven to be inside the root. */
  abs: string;
  /** Root-relative path with forward slashes; '' is the root itself. */
  rel: string;
  /** True when the last component is a symlink that stays inside the root (following it is allowed). */
  viaSymlink: boolean;
}

export type PathResolution = PathResolved | PathRefused;

/** Normalise a root-relative request to forward slashes; '' for the root. */
function toRel(root: string, abs: string): string {
  const rel = path.relative(root, abs);
  return rel === '' ? '' : rel.split(path.sep).join('/');
}

/**
 * The containment predicate every provider here already uses (`resolveInsideRootfs`, `runFsAudit`, `runGhidra`):
 * a path is inside the root when it IS the root or begins with the root plus a separator. Comparing prefixes
 * without the separator would accept `/data/extract/abc-evil` as inside `/data/extract/abc`.
 */
function contains(root: string, abs: string): boolean {
  return abs === root || abs.startsWith(root + path.sep);
}

/** realpath, or null when the path does not resolve (a dangling symlink, or a component we may not traverse). */
function realpathOrNull(p: string): string | null {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

/**
 * Resolve a caller-supplied relative path against the extraction root, refusing anything that leaves it.
 *
 * Three separate escapes are possible and they are checked in order, each with its own rule, because they mean
 * different things: an absolute path is a caller mistake, `..` traversal is a caller attack, and a symlink pointing
 * out of the tree is usually the FIRMWARE — DVRF ships `etc/passwd -> /dev/null` and a browser that silently
 * returned `/dev/null`'s contents would be reporting the host's bytes as the device's.
 *
 * The symlink leg is checked with realpath, so a symlinked ANCESTOR is caught too: `resolveInsideRootfs`'s lexical
 * test alone passes `some-link/etc/passwd` when `some-link` points outside, and a browser walks ancestors where a
 * "resolve one named binary" call never did. A dangling symlink cannot be realpath'd at all, so its target is
 * resolved lexically instead and judged by the same containment rule — a link to a path that does not exist yet
 * still tells us where it points.
 */
export function resolvePath(root: string, requested: string): PathResolution {
  const raw = requested ?? '';
  if (raw.includes('\u0000')) {
    return {
      ok: false,
      rule: 'nul-in-path',
      reason:
        'The requested path contains a NUL byte, which no filesystem path can hold. Refused before touching the filesystem, because the underlying syscall would truncate at the NUL and open a different path than the one that was asked for.',
    };
  }
  if (path.isAbsolute(raw)) {
    return {
      ok: false,
      rule: 'absolute-path',
      reason: `Refused by the absolute-path rule: '${raw}' is an absolute path, and every path here is relative to the extraction root. An absolute path would address the machine running FirmLab rather than the firmware.`,
    };
  }

  const rootAbs = path.resolve(root);
  const abs = path.resolve(rootAbs, raw);
  if (!contains(rootAbs, abs)) {
    return {
      ok: false,
      rule: 'escapes-root',
      reason: `Refused by the containment rule: '${raw}' normalises to a path outside the extraction root. Only bytes this extraction produced are browsable here.`,
    };
  }

  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(abs);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      return {
        ok: false,
        rule: 'not-found',
        reason: `No such entry in this extraction: '${raw || '.'}'. It was never carved, or it was named wrongly.`,
      };
    }
    return {
      ok: false,
      rule: 'unreadable',
      reason: `'${raw || '.'}' exists in this extraction but could not be read (${code ?? 'unknown error'}).`,
    };
  }

  const isLink = stat.isSymbolicLink();
  const realRoot = realpathOrNull(rootAbs) ?? rootAbs;
  const real = realpathOrNull(abs);
  if (real !== null) {
    if (!contains(realRoot, real)) {
      const target = isLink ? safeReadlink(abs) : null;
      return {
        ok: false,
        rule: 'symlink-escapes-root',
        reason: `Refused by the symlink rule: '${raw}' resolves through a symlink to '${real}', which is outside the extraction root. That is a fact about the firmware, not a fault — the link is reported in the listing and left unfollowed, because the bytes on the other side belong to the machine running FirmLab, not to the device.`,
        ...(target ? { symlinkTarget: target } : {}),
      };
    }
    return { ok: true, abs, rel: toRel(rootAbs, abs), viaSymlink: isLink };
  }

  // realpath failed. For a symlink that means the target does not exist (dangling) — still judge where it points.
  if (isLink) {
    const target = safeReadlink(abs);
    const lexical = path.isAbsolute(target) ? path.resolve(target) : path.resolve(path.dirname(abs), target);
    if (!contains(rootAbs, lexical)) {
      return {
        ok: false,
        rule: 'symlink-escapes-root',
        reason: `Refused by the symlink rule: '${raw}' is a symlink to '${target}', which lies outside the extraction root. The target does not exist here either, so following it would have produced a host path or an error — never the device's bytes.`,
        symlinkTarget: target,
      };
    }
    return { ok: true, abs, rel: toRel(rootAbs, abs), viaSymlink: true };
  }

  return {
    ok: false,
    rule: 'unreadable',
    reason: `'${raw || '.'}' exists in this extraction but its real path could not be resolved.`,
  };
}

function safeReadlink(abs: string): string {
  try {
    return fs.readlinkSync(abs);
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Directory listing
// ---------------------------------------------------------------------------------------------------------------

export type EntryType = 'file' | 'dir' | 'symlink' | 'other';

export interface DirEntryView {
  name: string;
  /** Root-relative path, forward slashes. */
  path: string;
  type: EntryType;
  /** Bytes for a regular file; 0 for directories and symlinks, matching the FsEntry convention in extract.ts. */
  size: number;
  mode: number;
  /** `drwxr-xr-x` — the permission bits an operator reads for setuid/world-writable at a glance. */
  modeString: string;
  /** True for a file whose setuid bit is set; the fact fsaudit hunts, visible while browsing. */
  setuid?: boolean;
  symlinkTarget?: string;
  /** A symlink whose target resolves outside the extraction root. Reported, never followed. */
  symlinkEscapes?: boolean;
  /** Where a contained symlink lands, root-relative — so the operator can jump to it. */
  symlinkResolved?: string;
}

export interface DirListing {
  /** Root-relative path of the directory listed; '' is the extraction root. */
  path: string;
  entries: DirEntryView[];
  /** Entries the directory holds, before the cap. */
  totalEntries: number;
  fileCount: number;
  dirCount: number;
  symlinkCount: number;
  truncated: boolean;
  /** Present when truncated: what was dropped and by what rule. Never silent. */
  truncationRule?: string;
  /** An empty directory is a result, and it says so rather than rendering as nothing. */
  note?: string;
}

/** Render the low 12 mode bits the way `ls -l` does, so setuid/sticky are visible without decoding octal. */
export function modeString(mode: number, type: EntryType): string {
  const head = type === 'dir' ? 'd' : type === 'symlink' ? 'l' : type === 'other' ? '?' : '-';
  const bits = ['r', 'w', 'x'];
  let out = head;
  for (let group = 0; group < 3; group++) {
    for (let bit = 0; bit < 3; bit++) {
      const mask = 1 << (8 - (group * 3 + bit));
      out += (mode & mask) === 0 ? '-' : (bits[bit] as string);
    }
  }
  const chars = out.split('');
  if ((mode & 0o4000) !== 0) chars[3] = (mode & 0o100) !== 0 ? 's' : 'S';
  if ((mode & 0o2000) !== 0) chars[6] = (mode & 0o010) !== 0 ? 's' : 'S';
  if ((mode & 0o1000) !== 0) chars[9] = (mode & 0o001) !== 0 ? 't' : 'T';
  return chars.join('');
}

function entryType(stat: fs.Stats): EntryType {
  if (stat.isSymbolicLink()) return 'symlink';
  if (stat.isDirectory()) return 'dir';
  if (stat.isFile()) return 'file';
  return 'other';
}

/**
 * List one directory inside the extraction root.
 *
 * Sorting happens BEFORE the cap: directories first, then by name. That matters more than it looks — capping the
 * raw readdir order makes the surviving set an artifact of how the extractor happened to write the tree, which is
 * exactly the truncation CLAUDE.md rule 4 forbids. A capped listing says how many entries the directory really
 * holds and by what rule the rest were dropped, so the count is never mistaken for the contents.
 *
 * Symlinks are listed, never followed. Whether the target escapes the root is part of the entry, because on real
 * firmware that is a finding in itself: DVRF's `etc/passwd -> /dev/null` is how the image ships its account
 * database, and a browser that hid the entry would hide that.
 */
export function listDirectory(root: string, requested: string, limit = MAX_ENTRIES): DirListing | PathRefused {
  const resolved = resolvePath(root, requested);
  if (!resolved.ok) return resolved;

  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved.abs);
  } catch {
    return {
      ok: false,
      rule: 'unreadable',
      reason: `'${resolved.rel || '.'}' could not be stat'd, so its type is unknown and it cannot be listed.`,
    };
  }
  if (!stat.isDirectory()) {
    return {
      ok: false,
      rule: 'not-a-directory',
      reason: `'${resolved.rel}' is not a directory, so there is nothing to list. Read it instead.`,
    };
  }

  let names: string[];
  try {
    names = fs.readdirSync(resolved.abs);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return {
      ok: false,
      rule: 'unreadable',
      reason: `'${resolved.rel || '.'}' is a directory this deployment cannot read (${code ?? 'unknown error'}).`,
    };
  }

  const rootAbs = path.resolve(root);
  const all: DirEntryView[] = [];
  for (const name of names) {
    const abs = path.join(resolved.abs, name);
    const rel = toRel(rootAbs, abs);
    let entryStat: fs.Stats;
    try {
      entryStat = fs.lstatSync(abs);
    } catch {
      // A node that vanished or cannot be lstat'd is still a node the directory holds; say so rather than drop it.
      all.push({ name, path: rel, type: 'other', size: 0, mode: 0, modeString: '?---------' });
      continue;
    }
    const type = entryType(entryStat);
    const view: DirEntryView = {
      name,
      path: rel,
      type,
      size: type === 'file' ? entryStat.size : 0,
      mode: entryStat.mode,
      modeString: modeString(entryStat.mode, type),
      ...(type === 'file' && (entryStat.mode & 0o4000) !== 0 ? { setuid: true } : {}),
    };
    if (type === 'symlink') {
      const target = safeReadlink(abs);
      view.symlinkTarget = target;
      const lexical = path.isAbsolute(target) ? path.resolve(target) : path.resolve(path.dirname(abs), target);
      const real = realpathOrNull(abs) ?? lexical;
      const realRoot = realpathOrNull(rootAbs) ?? rootAbs;
      if (contains(realRoot, real) && contains(rootAbs, lexical)) view.symlinkResolved = toRel(realRoot, real);
      else view.symlinkEscapes = true;
    }
    all.push(view);
  }

  const rank = (e: DirEntryView): number => (e.type === 'dir' ? 0 : 1);
  all.sort((a, b) => rank(a) - rank(b) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const cap = Math.max(1, Math.min(limit, MAX_ENTRIES));
  const shown = all.slice(0, cap);
  const truncated = all.length > shown.length;

  const listing: DirListing = {
    path: resolved.rel,
    entries: shown,
    totalEntries: all.length,
    fileCount: all.filter((e) => e.type === 'file').length,
    dirCount: all.filter((e) => e.type === 'dir').length,
    symlinkCount: all.filter((e) => e.type === 'symlink').length,
    truncated,
  };
  if (truncated) {
    listing.truncationRule = `${all.length} entries are present and ${shown.length} are shown. The cap is ${cap}; entries are sorted directories-first then by name BEFORE it applies, so the omitted set is decided by that order and not by the order the extractor happened to write the directory. Narrow the path to see the rest.`;
  }
  if (all.length === 0) {
    listing.note = `'${resolved.rel || '.'}' exists in the extraction and holds no entries. An empty directory is what the extractor produced here — it is not evidence that the firmware has nothing at this path.`;
  }
  return listing;
}

// ---------------------------------------------------------------------------------------------------------------
// Text-vs-binary, from the bytes
// ---------------------------------------------------------------------------------------------------------------

export interface ByteClassification {
  kind: 'text' | 'binary' | 'empty';
  /** Which rule decided it, in words — the classification is never a bare label. */
  reason: string;
  sampled: number;
  nulBytes: number;
  nonPrintable: number;
  /** The sample decodes as UTF-8 without replacement. False on a truncated multi-byte sequence too. */
  utf8: boolean;
}

/** Above this share of non-printable bytes, a NUL-free file is still not something to render as text. */
export const NON_PRINTABLE_LIMIT = 0.1;

/**
 * Pure: decide text-vs-binary from the BYTES, never from the name.
 *
 * The extension is the thing this codebase has already been burned by (extract-recover.ts dispatches on magic
 * because binwalk calls a raw LZMA stream `.7z`), and one layer up it is how a `private_key.pem` holding a public
 * key survived unopened. So: a single NUL settles it — no text encoding in a firmware tree emits one — and
 * otherwise the share of non-printable bytes decides, with the UTF-8 check keeping a UTF-8 config file from being
 * called binary for its accented characters.
 *
 * The sample is a prefix, so the answer is about the prefix. A file whose first 8 KB are ASCII and whose tail is a
 * compressed blob classifies as text, and the read that carries this classification also carries its own bound —
 * which is the honest pairing, rather than a whole-file scan nobody budgeted for.
 */
export function classifyBytes(sample: Uint8Array): ByteClassification {
  if (sample.length === 0) {
    return {
      kind: 'empty',
      reason: 'The file holds 0 bytes. There is nothing to classify — an empty file is a result, not text.',
      sampled: 0,
      nulBytes: 0,
      nonPrintable: 0,
      utf8: true,
    };
  }

  let nulBytes = 0;
  let control = 0;
  let high = 0;
  for (const b of sample) {
    if (b === 0) nulBytes++;
    else if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d && b !== 0x0c) control++;
    else if (b === 0x7f) control++;
    else if (b >= 0x80) high++;
  }

  let utf8 = true;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(sample);
  } catch {
    utf8 = false;
  }

  if (nulBytes > 0) {
    return {
      kind: 'binary',
      reason: `Binary: ${nulBytes} NUL byte(s) in the first ${sample.length} bytes. A NUL settles it on its own — no text encoding a firmware tree carries emits one, which is why the decision needs no extension.`,
      sampled: sample.length,
      nulBytes,
      nonPrintable: control + (utf8 ? 0 : high),
      utf8,
    };
  }

  const nonPrintable = control + (utf8 ? 0 : high);
  const ratio = nonPrintable / sample.length;
  if (ratio > NON_PRINTABLE_LIMIT) {
    return {
      kind: 'binary',
      reason: `Binary: ${nonPrintable} of ${sample.length} sampled bytes are non-printable (${(ratio * 100).toFixed(1)}%, over the ${(NON_PRINTABLE_LIMIT * 100).toFixed(0)}% limit)${utf8 ? '' : ' and the sample is not valid UTF-8'}.`,
      sampled: sample.length,
      nulBytes,
      nonPrintable,
      utf8,
    };
  }

  return {
    kind: 'text',
    reason: `Text: no NUL bytes and ${nonPrintable} of ${sample.length} sampled bytes non-printable (${(ratio * 100).toFixed(1)}%)${utf8 ? ', valid UTF-8' : ''}. Decided from the bytes; the file's name played no part. This describes the sampled prefix, not necessarily the whole file.`,
    sampled: sample.length,
    nulBytes,
    nonPrintable,
    utf8,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Hexdump
// ---------------------------------------------------------------------------------------------------------------

/**
 * Pure: render bytes as `hexdump -C` does — absolute offset, hex columns split into two groups, ASCII gutter.
 *
 * The offset column is ABSOLUTE, seeded from `baseOffset`, because a bounded read of a large file is a window into
 * it and a window whose offsets restart at zero silently claims to be the start of the file. Short final lines keep
 * their column alignment so the gutter stays readable.
 */
export function hexdump(bytes: Uint8Array, baseOffset = 0, bytesPerLine = 16): string {
  const perLine = Math.max(1, bytesPerLine);
  const half = Math.floor(perLine / 2);
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += perLine) {
    const chunk = bytes.subarray(i, i + perLine);
    const offset = (baseOffset + i).toString(16).padStart(8, '0');
    const cells: string[] = [];
    for (let j = 0; j < perLine; j++) {
      const b = chunk[j];
      cells.push(b === undefined ? '  ' : b.toString(16).padStart(2, '0'));
      if (half > 0 && j === half - 1) cells.push('');
    }
    let ascii = '';
    for (const b of chunk) ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
    lines.push(`${offset}  ${cells.join(' ')}  |${ascii}|`);
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------------------------------------------
// Bounded reads
// ---------------------------------------------------------------------------------------------------------------

export interface ReadRange {
  offset: number;
  limit: number;
  /** Every adjustment the request received, stated. A silently clamped request is a request answered wrongly. */
  adjustments: string[];
}

/**
 * Pure: turn caller-supplied offset/limit into a range this deployment will actually serve, saying what it changed.
 *
 * A clamp applied silently is the same defect class as a truncation applied silently: the caller asked for one
 * thing, got another, and has no way to tell. So every adjustment is a sentence the result carries.
 */
export function parseReadRange(offsetRaw: unknown, limitRaw: unknown, size: number): ReadRange {
  const adjustments: string[] = [];

  let offset = Number(offsetRaw ?? 0);
  if (!Number.isFinite(offset) || offsetRaw === '' || offsetRaw === null || offsetRaw === undefined) {
    if (offsetRaw !== undefined && offsetRaw !== null && offsetRaw !== '') {
      adjustments.push(`offset '${String(offsetRaw)}' is not a number; read from byte 0 instead.`);
    }
    offset = 0;
  }
  offset = Math.floor(offset);
  if (offset < 0) {
    adjustments.push(`offset ${offset} is negative; read from byte 0 instead.`);
    offset = 0;
  }
  if (offset > size) {
    adjustments.push(`offset ${offset} is past the end of the file (${size} bytes); nothing was read.`);
    offset = size;
  }

  let limit = Number(limitRaw ?? DEFAULT_READ_BYTES);
  if (!Number.isFinite(limit) || limitRaw === '' || limitRaw === null || limitRaw === undefined) {
    if (limitRaw !== undefined && limitRaw !== null && limitRaw !== '') {
      adjustments.push(`limit '${String(limitRaw)}' is not a number; served the default ${DEFAULT_READ_BYTES}.`);
    }
    limit = DEFAULT_READ_BYTES;
  }
  limit = Math.floor(limit);
  if (limit <= 0) {
    adjustments.push(`limit ${limit} is not a positive byte count; served the default ${DEFAULT_READ_BYTES}.`);
    limit = DEFAULT_READ_BYTES;
  }
  if (limit > MAX_READ_BYTES) {
    adjustments.push(
      `limit ${limit} exceeds this deployment's ${MAX_READ_BYTES}-byte ceiling; served ${MAX_READ_BYTES}.`,
    );
    limit = MAX_READ_BYTES;
  }

  return { offset, limit, adjustments };
}

export type ReadView = 'text' | 'hex';

export interface FileRead {
  path: string;
  /** Full size on disk, always — the number a truncated read must be compared against. */
  size: number;
  offset: number;
  bytesRead: number;
  /**
   * True when the window is not the whole file — in EITHER direction. A read at offset 4000 that runs to EOF is
   * still not the file, and calling it complete because nothing remains after it would hide the 4000 bytes that
   * were skipped. `unreadBefore`/`unreadAfter` say which side.
   */
  truncated: boolean;
  unreadBefore: number;
  unreadAfter: number;
  /** Present when truncated: which bytes were not read, on which side, and the rule that bounded the window. */
  truncationRule?: string;
  classification: ByteClassification;
  /** Which rendering was served, and why — a binary file is not shown as text even if asked for. */
  view: ReadView;
  viewReason: string;
  text?: string;
  hexdump?: string;
  adjustments: string[];
  claim: string;
}

/**
 * Read a bounded slice of one file inside the extraction root and say exactly what the slice is.
 *
 * The bound is the point. A read that returns 64 KB of a 7 MB binary and does not say so hands the caller a
 * truncated file that looks like a whole one — and "a bound is not an answer" is the rule this workbench already
 * enforces on findings, ELF sweeps and probe budgets. So the result always carries the full size, the offset it
 * started at, the byte it stopped at, and what remains.
 *
 * `view` is a preference, not an instruction: a file the bytes say is binary is rendered as a hexdump whatever was
 * asked for, and the result says which rule chose. Rendering a binary as text would show the operator a mangled
 * string and invite exactly the kind of conclusion-from-appearance this module exists to replace.
 */
export function readFileSlice(
  root: string,
  requested: string,
  offsetRaw: unknown,
  limitRaw: unknown,
  preferred?: ReadView,
): FileRead | PathRefused {
  const resolved = resolvePath(root, requested);
  if (!resolved.ok) return resolved;

  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved.abs);
  } catch {
    return {
      ok: false,
      rule: 'unreadable',
      reason: `'${resolved.rel}' could not be stat'd, so its size is unknown and it cannot be read.`,
    };
  }
  if (stat.isDirectory()) {
    return {
      ok: false,
      rule: 'not-a-file',
      reason: `'${resolved.rel}' is a directory. List it instead of reading it.`,
    };
  }
  if (!stat.isFile()) {
    return {
      ok: false,
      rule: 'not-a-file',
      reason: `'${resolved.rel}' is not a regular file (it is a device node, socket or fifo the extractor recreated). Its contents are a property of this machine, not of the firmware, so they are not served.`,
    };
  }

  const size = stat.size;
  const range = parseReadRange(offsetRaw, limitRaw, size);
  const want = Math.min(range.limit, Math.max(0, size - range.offset));
  const buffer = Buffer.alloc(want);
  let bytesRead = 0;
  if (want > 0) {
    let fd: number | null = null;
    try {
      fd = fs.openSync(resolved.abs, 'r');
      bytesRead = fs.readSync(fd, buffer, 0, want, range.offset);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      return {
        ok: false,
        rule: 'unreadable',
        reason: `'${resolved.rel}' exists but could not be opened for reading (${code ?? 'unknown error'}).`,
      };
    } finally {
      if (fd !== null) fs.closeSync(fd);
    }
  }

  const bytes = buffer.subarray(0, bytesRead);
  const classification = classifyBytes(bytes.subarray(0, CLASSIFY_SAMPLE_BYTES));
  const end = range.offset + bytesRead;
  const unreadBefore = range.offset;
  const unreadAfter = size - end;
  const truncated = unreadBefore > 0 || unreadAfter > 0;

  let view: ReadView;
  let viewReason: string;
  if (classification.kind === 'binary') {
    view = 'hex';
    viewReason =
      preferred === 'text'
        ? `Rendered as a hexdump despite the request for text: ${classification.reason}`
        : classification.reason;
  } else if (preferred === 'hex') {
    view = 'hex';
    viewReason = `Rendered as a hexdump because it was asked for. ${classification.reason}`;
  } else {
    view = 'text';
    viewReason = classification.reason;
  }

  const result: FileRead = {
    path: resolved.rel,
    size,
    offset: range.offset,
    bytesRead,
    truncated,
    unreadBefore,
    unreadAfter,
    classification,
    view,
    viewReason,
    adjustments: range.adjustments,
    claim: EVIDENCE_CLAIM,
  };
  if (truncated) {
    const sides = [
      unreadBefore > 0 ? `${unreadBefore} byte(s) BEFORE it were skipped by the offset` : '',
      unreadAfter > 0 ? `${unreadAfter} byte(s) AFTER it were not read (the per-read limit is ${range.limit})` : '',
    ].filter(Boolean);
    result.truncationRule = `This is a ${bytesRead}-byte window of a ${size}-byte file, bytes ${range.offset}–${end}: ${sides.join(', and ')}. What is shown is a slice, not the file — nothing here licenses a claim about the bytes outside the window.`;
  }
  if (view === 'text') result.text = new TextDecoder('utf-8').decode(bytes);
  else result.hexdump = hexdump(bytes, range.offset);
  return result;
}

// ---------------------------------------------------------------------------------------------------------------
// What is browsable at all, and why
// ---------------------------------------------------------------------------------------------------------------

/** The facts about an image's extraction the caller reads off the extract job (no store import here). */
export interface ExtractionFacts {
  /** The extract job's status, or null when no extract job exists for this image. */
  jobStatus: 'queued' | 'running' | 'done' | 'error' | null;
  jobError?: string | null;
  outputDir?: string | null;
  rootfsPath?: string | null;
  extractor?: string | undefined;
  /** `noRootfsDiagnosis.verdict` from the extract result, when extraction produced no rootfs. */
  noRootfsVerdict?: string | undefined;
}

export type ExtractionBrowseState = 'never-run' | 'in-progress' | 'failed' | 'no-output' | 'volumes-only' | 'rootfs';

export interface ExtractionBrowseView {
  state: ExtractionBrowseState;
  /** Is there anything on disk to browse at all? */
  browsable: boolean;
  /** The sentence an empty tree must be read next to. Never omitted. */
  verdict: string;
  /** Root-relative path of the recognised rootfs inside the extraction root, when there is one. */
  rootfsRel?: string;
  extractor?: string;
}

/**
 * Decide what an operator opening the browser is actually looking at, and say it.
 *
 * An empty tree has at least five causes and they call for opposite next moves: nothing was ever extracted, the
 * extraction is still running, it failed, it produced nothing, or it produced carved volumes but no rootfs. A
 * browser that renders all five as an empty list is the "empty result means clean" failure wearing a different
 * hat — so the verdict is computed here and served WITH every listing, not behind a second call the caller may
 * never make. Where extraction already diagnosed itself (extract-diagnose.ts), that verdict is quoted rather than
 * paraphrased: it is the one that was written from the bytes.
 */
export function describeExtraction(facts: ExtractionFacts): ExtractionBrowseView {
  const { jobStatus, outputDir, rootfsPath } = facts;

  if (jobStatus === null) {
    return {
      state: 'never-run',
      browsable: false,
      verdict:
        'No extraction has run for this image, so there is nothing on disk to browse. This is an unasked question, not an empty filesystem: run extraction first, and read its verdict before concluding anything about what the image contains.',
    };
  }
  if (jobStatus === 'queued' || jobStatus === 'running') {
    return {
      state: 'in-progress',
      browsable: false,
      verdict:
        'Extraction is still running. Whatever is on disk right now is a partial carve mid-write, so nothing here is a complete answer yet.',
    };
  }
  if (jobStatus === 'error') {
    return {
      state: 'failed',
      browsable: Boolean(outputDir && dirHasEntries(outputDir)),
      verdict: `Extraction failed${facts.jobError ? `: ${facts.jobError}` : '.'} Anything visible below is whatever the failed run had already written — a partial carve, not the image's filesystem.`,
    };
  }

  const hasOutput = Boolean(outputDir && dirHasEntries(outputDir));
  if (!hasOutput) {
    return {
      state: 'no-output',
      browsable: false,
      verdict:
        facts.noRootfsVerdict ??
        'Extraction ran and produced nothing on disk. The image may be encrypted, may use a container no extractor here understands, or may hold no filesystem at all — this is an unanswered question, not a clean result.',
      ...(facts.extractor ? { extractor: facts.extractor } : {}),
    };
  }

  if (!rootfsPath) {
    return {
      state: 'volumes-only',
      browsable: true,
      // The fallback is not a formality. Asus-Router's stored extract result predates extract-diagnose.ts and
      // carries no verdict at all, so the sentence has to say that the diagnosis is MISSING rather than imply the
      // extractor had nothing to report — an absent field and an empty finding are the same conflation one layer up.
      verdict: `Extraction produced content but no recognised Linux rootfs, so what you are browsing is the raw carve: volumes, partitions and blobs as the extractor wrote them. ${facts.noRootfsVerdict ?? 'No diagnosis of the missing rootfs was recorded — this extraction predates the diagnosis, so WHY there is no rootfs is unknown rather than answered. Re-run extraction to find out.'}`,
      ...(facts.extractor ? { extractor: facts.extractor } : {}),
    };
  }

  const rootfsRel =
    outputDir && rootfsPath
      ? path.relative(path.resolve(outputDir), path.resolve(rootfsPath)).split(path.sep).join('/')
      : '';
  return {
    state: 'rootfs',
    browsable: true,
    verdict: `Extraction recovered a rootfs at '${rootfsRel || '.'}'. You are browsing the WHOLE carve, not just the rootfs, because the carve also holds the volumes and blobs that never became one. A carve is what the extractor recovered from this image — it is not a guarantee that the image held nothing more.`,
    ...(rootfsRel ? { rootfsRel } : {}),
    ...(facts.extractor ? { extractor: facts.extractor } : {}),
  };
}

/** Does this directory exist and hold at least one entry? Cheap — one readdir, no walk. */
function dirHasEntries(dir: string): boolean {
  try {
    return fs.readdirSync(dir).length > 0;
  } catch {
    return false;
  }
}
