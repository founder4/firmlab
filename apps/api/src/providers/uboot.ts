/**
 * U-Boot provider — the bootloader-analysis track. A `bootloader` image (a raw flash dump, a `u-boot.bin`, or a
 * whole firmware image that carries the U-Boot environment partition) has no rootfs to run and no MCU to emulate,
 * so its analysis is offline structural parsing: locate the U-Boot environment block in the REAL bytes, decode the
 * `key=value` variables, and reason about the boot posture (root-shell boot args, an interruptible autoboot, a
 * network boot path, an exposed serial console) strictly from what the variables actually contain.
 *
 * Everything here is PURE + unit-tested (the env decoder, the block locator, the audit) except the thin runner,
 * which only reads a bounded prefix of the image and composes the pure parts. It is HONEST: no env block found
 * degrades to found:false with an explicit reason; it never fabricates a boot configuration, and every finding
 * quotes the offending variable. Proof states top out at `static_confirmed` (a fact about the stored env bytes,
 * never a device claim) — a boot-args root shell or a netboot path is `needs_runtime_reproduction` because it is a
 * lead that only a real boot confirms.
 */
import fs from 'node:fs';
import type { FindingDraft } from '../findings-normalize.js';

/** The decoded U-Boot environment: the stored CRC, the `key=value` variables, and how many were parsed. */
export interface ParsedEnv {
  crc: number;
  vars: Record<string, string>;
  entryCount: number;
}

/** Outcome of a U-Boot analysis run over one image. Honest: `found:false` when no env block is present. */
export interface UbootResult {
  available: boolean;
  found: boolean;
  varCount: number;
  vars: Record<string, string>;
  findings: FindingDraft[];
  reason: string;
}

// A key is a C-identifier-ish token; a value is any run of printable ASCII (spaces and '=' allowed). A chunk that
// carries a CRC/flags header byte or firmware padding fails these, which is exactly how a wrong start offset loses.
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_.\-]*$/;
const PRINTABLE_RE = /^[\x20-\x7e]*$/;

/** Read `[start,end)` of a byte buffer as an ASCII string (one char per byte; non-ASCII bytes survive for the RE). */
function sliceAscii(buf: Uint8Array, start: number, end: number): string {
  let s = '';
  for (let i = start; i < end; i++) s += String.fromCharCode(buf[i] as number);
  return s;
}

/**
 * Parse NUL-separated `key=value` entries starting at `start`, until a double-NUL (empty entry) or the buffer end.
 * Only well-formed entries (identifier key + printable value) are kept; the first occurrence of a key wins.
 */
function parseEntries(buf: Uint8Array, start: number): Record<string, string> {
  const vars: Record<string, string> = {};
  const n = buf.length;
  let i = start;
  while (i < n) {
    let j = i;
    while (j < n && (buf[j] as number) !== 0) j++;
    if (j === i) break; // empty entry → the terminating double-NUL (or a leading NUL)
    const entry = sliceAscii(buf, i, j);
    const eq = entry.indexOf('=');
    if (eq > 0) {
      const key = entry.slice(0, eq);
      const value = entry.slice(eq + 1);
      if (KEY_RE.test(key) && PRINTABLE_RE.test(value) && !(key in vars)) vars[key] = value;
    }
    i = j + 1;
  }
  return vars;
}

/**
 * Pure: decode a U-Boot environment blob. Layout is `<4-byte little-endian CRC32><entries>`, where `<entries>` is
 * NUL-separated `key=value` up to a double-NUL. Redundant-env stores insert ONE flags byte after the CRC, so the
 * entry data begins at offset 4 (plain) or 5 (redundant); a header-less ASCII block begins at offset 0. We try all
 * three and keep whichever yields the most valid entries. Offset 0 is tried first so a clean header-less parse wins
 * ties over a coincidental mid-key offset, while a real binary CRC/flags header makes the earlier offsets lose.
 */
export function parseUbootEnv(buf: Uint8Array): ParsedEnv {
  const crc =
    buf.length >= 4
      ? ((buf[0] as number) | ((buf[1] as number) << 8) | ((buf[2] as number) << 16) | ((buf[3] as number) << 24)) >>> 0
      : 0;
  let best: Record<string, string> = {};
  for (const start of [0, 4, 5]) {
    if (start > buf.length) continue;
    const vars = parseEntries(buf, start);
    if (Object.keys(vars).length > Object.keys(best).length) best = vars;
  }
  return { crc, vars: best, entryCount: Object.keys(best).length };
}

/** Case-sensitive byte search for an ASCII needle. */
function indexOfAscii(buf: Uint8Array, needle: string, from = 0): number {
  const n = needle.length;
  outer: for (let i = from; i + n <= buf.length; i++) {
    for (let k = 0; k < n; k++) {
      if ((buf[i + k] as number) !== needle.charCodeAt(k)) continue outer;
    }
    return i;
  }
  return -1;
}

/** The earliest offset of a distinctive U-Boot env marker (`bootcmd=` / `bootargs=`), or -1. */
function findMarker(buf: Uint8Array): number {
  const a = indexOfAscii(buf, 'bootcmd=');
  const b = indexOfAscii(buf, 'bootargs=');
  if (a < 0) return b;
  if (b < 0) return a;
  return Math.min(a, b);
}

const SCAN_WINDOW = 64 * 1024;

/**
 * Pure: locate a plausible U-Boot environment inside a raw firmware image. Anchors on a `bootcmd=`/`bootargs=`
 * marker, then walks backward to the block start (a preceding double-NUL, a binary byte such as the CRC header, or
 * a bounded window edge) and forward to the terminating double-NUL. When the block is abutted by a binary header
 * (the backward scan stopped on a non-printable byte) the returned slice includes 4 header bytes so parseUbootEnv's
 * offset-4 path lands on the entries; otherwise the header-less ASCII region is returned (offset-0 path). Returns
 * null when no marker is present. parseUbootEnv works on either shape.
 */
export function findEnvBlock(image: Uint8Array): Uint8Array | null {
  const marker = findMarker(image);
  if (marker < 0) return null;
  const lo = Math.max(0, marker - SCAN_WINDOW);
  const hi = Math.min(image.length, marker + SCAN_WINDOW);

  // Backward: extend to the first printable byte of the contiguous ASCII env region.
  let asciiStart = marker;
  let stoppedOnBinary = false;
  let zeroRun = 0;
  for (let p = marker - 1; p >= lo; p--) {
    const b = image[p] as number;
    if (b >= 0x20 && b <= 0x7e) {
      asciiStart = p;
      zeroRun = 0;
    } else if (b === 0) {
      zeroRun++;
      if (zeroRun >= 2) break; // a previous block's terminating double-NUL — the boundary
    } else {
      stoppedOnBinary = true; // a CRC/flags header byte or firmware padding
      break;
    }
  }

  // Forward: extend to (and include) the terminating double-NUL.
  let end = hi;
  zeroRun = 0;
  for (let p = marker; p < hi; p++) {
    const b = image[p] as number;
    if (b === 0) {
      zeroRun++;
      if (zeroRun >= 2) {
        end = p + 1;
        break;
      }
    } else {
      zeroRun = 0;
    }
  }

  if (stoppedOnBinary && asciiStart - 4 >= 0) return image.slice(asciiStart - 4, end);
  return image.slice(asciiStart, end);
}

/** Truncate a variable value for evidence so a huge bootargs can't bloat the finding. */
function truncate(s: string, n = 200): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

const NETBOOT_RE = /\b(tftp|dhcp|nfs|bootp)/i;

/**
 * Pure: turn a decoded env into honest boot-posture findings. Every finding quotes the offending variable and only
 * asserts what the variables actually show:
 *   - boot args drop to a root shell (`init=/bin/sh`, `rdinit=`, ` single`) → high / needs_runtime_reproduction.
 *   - an interruptible autoboot (`bootdelay` present, not 0/-1)             → medium / static_confirmed.
 *   - a network boot path in `bootcmd`/`preboot` (tftp/dhcp/nfs/bootp)      → medium / needs_runtime_reproduction.
 *   - an exposed serial console on the kernel command line (`console=`)     → info / static_confirmed.
 */
export function auditBootEnv(vars: Record<string, string>): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const bootargs = vars.bootargs;
  const bootdelay = vars.bootdelay;

  if (bootargs) {
    const markers: string[] = [];
    if (/\binit=\/bin\/sh\b/.test(bootargs)) markers.push('init=/bin/sh');
    if (/\brdinit=/.test(bootargs)) markers.push('rdinit=');
    if (/(?:^|\s)single(?:\s|$)/.test(bootargs)) markers.push('single');
    if (markers.length > 0) {
      drafts.push({
        kind: 'uboot-root-shell',
        title: 'U-Boot boot args drop to an unauthenticated root shell',
        severity: 'high',
        proofState: 'needs_runtime_reproduction',
        evidence: { var: 'bootargs', value: truncate(bootargs), markers },
        rationale:
          'The stored kernel command line hands PID 1 / an interactive shell to whoever powers the device on ' +
          '(no authentication). Confirmed by a real boot — hence needs_runtime_reproduction, not asserted device compromise.',
      });
    }
  }

  if (bootdelay !== undefined && bootdelay.trim() !== '' && bootdelay.trim() !== '0' && bootdelay.trim() !== '-1') {
    drafts.push({
      kind: 'uboot-autoboot-interruptible',
      title: `Autoboot is interruptible to a U-Boot console (bootdelay=${truncate(bootdelay.trim(), 16)})`,
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { var: 'bootdelay', value: truncate(bootdelay) },
      rationale:
        'A positive bootdelay lets anyone with serial access press a key during the countdown to drop to the ' +
        'U-Boot prompt and rewrite the boot flow. The value is literally present in the env bytes.',
    });
  }

  for (const name of ['bootcmd', 'preboot'] as const) {
    const val = vars[name];
    if (!val) continue;
    const m = NETBOOT_RE.exec(val);
    if (!m) continue;
    drafts.push({
      kind: 'uboot-netboot',
      title: `U-Boot ${name} uses a network boot path (${m[1]})`,
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
      evidence: { var: name, value: truncate(val), scheme: m[1] },
      rationale:
        'The device fetches boot code over the network at power-on; an attacker on the LAN can answer with a ' +
        'rogue DHCP/TFTP/NFS server and supply their own image. A LAN-position lead — needs_runtime_reproduction.',
    });
  }

  if (bootargs) {
    const cm = /\bconsole=(\S+)/.exec(bootargs);
    if (cm) {
      drafts.push({
        kind: 'uboot-serial-console',
        title: `Kernel serial console exposed (console=${truncate(cm[1] ?? '', 32)})`,
        severity: 'info',
        proofState: 'static_confirmed',
        evidence: { var: 'bootargs', value: truncate(bootargs), console: cm[1] },
        rationale:
          'A serial console on the kernel command line means physical UART access yields boot logs and, combined ' +
          'with a boot-args shell, an interactive session. The console= directive is present in the env bytes.',
      });
    }
  }

  return drafts;
}

const READ_CAP = 32 * 1024 * 1024;
const VAR_CAP = 60;

/** Read at most `cap` bytes from the head of a file. */
function readBounded(p: string, cap: number): Uint8Array {
  const fd = fs.openSync(p, 'r');
  try {
    const len = Math.min(fs.fstatSync(fd).size, cap);
    const buf = Buffer.allocUnsafe(len);
    fs.readSync(fd, buf, 0, len, 0);
    return buf;
  } finally {
    fs.closeSync(fd);
  }
}

/** Cap the surfaced variable map, keeping the boot-relevant keys first so the audit inputs are never dropped. */
function capVars(vars: Record<string, string>, cap: number): Record<string, string> {
  const keys = Object.keys(vars);
  if (keys.length <= cap) return vars;
  const chosen = new Set<string>();
  for (const k of ['bootargs', 'bootcmd', 'preboot', 'bootdelay', 'baudrate', 'ipaddr', 'serverip']) {
    if (k in vars) chosen.add(k);
  }
  for (const k of keys) {
    if (chosen.size >= cap) break;
    chosen.add(k);
  }
  const out: Record<string, string> = {};
  for (const k of chosen) out[k] = vars[k] as string;
  return out;
}

function notFound(reason: string): UbootResult {
  return { available: true, found: false, varCount: 0, vars: {}, findings: [], reason };
}

/**
 * Analyze the U-Boot environment stored in a firmware image — offline and honest. Reads a bounded prefix, locates
 * the env block, decodes it, and audits the boot posture. No env block or no parseable variables → found:false with
 * an explicit reason; a successful decode is `static_confirmed` (a fact about the stored env, not device behavior).
 */
export function runUbootAnalysis(imagePath: string): UbootResult {
  let buf: Uint8Array;
  try {
    buf = readBounded(imagePath, READ_CAP);
  } catch {
    return notFound('The image could not be read.');
  }
  const block = findEnvBlock(buf);
  if (!block) return notFound('No U-Boot environment found in the image.');
  const { vars, entryCount } = parseUbootEnv(block);
  if (entryCount === 0) return notFound('No U-Boot environment found in the image.');
  const varCount = Object.keys(vars).length;
  return {
    available: true,
    found: true,
    varCount,
    vars: capVars(vars, VAR_CAP),
    findings: auditBootEnv(vars),
    reason: `Parsed ${varCount} U-Boot environment variable${varCount === 1 ? '' : 's'} from the image. Static analysis of the stored env bytes — proves the boot configuration, not device behavior.`,
  };
}
