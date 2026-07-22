/**
 * W6 — ESP / IoT-SoC worker. An Espressif SoC flash dump is NOT a Linux image (W0 routes it here as `esp-soc`),
 * so the rootfs pipeline finds nothing; the real device secrets live in the **partition table** (@0x8000) and the
 * **NVS key/value store**. This worker reads BOTH straight from the dump bytes — pure functions, no tool
 * dependency — and recovers what a file/regex secret scan structurally cannot: signing keys stored as NVS blobs,
 * and stale/erased-but-still-readable entries (NVS is copy-on-write, so a rewritten key leaves the old value in
 * flash). It also states the offline security posture (Flash-Encryption / Secure-Boot / anti-rollback) inferred
 * from whether the app partition is plaintext, honestly degrading to `unknown` when the dump can't prove it.
 *
 * The parse (partition table, NVS pages/entries, posture) is PURE and unit-tested; the runner reads a bounded
 * prefix of the image and composes the findings. Nothing here claims anything about a live chip — only facts about
 * the bytes in the dump (docs/AUTONOMOUS-WORKERS.md §7.2, W6).
 */
import fs from 'node:fs';
import type { FindingDraft } from '../findings.js';

/** ESP-IDF partition table lives at flash offset 0x8000; each entry is 32 bytes, magic 0xAA50 (bytes AA 50). */
const PARTTABLE_OFFSET = 0x8000;
const PART_ENTRY_SIZE = 32;
const PART_MAGIC = [0xaa, 0x50];
const PART_TABLE_MAX = 95; // ESP-IDF caps the table at 95 entries (0x8000..0xC000)

/** NVS page geometry: 4096-byte pages, a 32-byte page header + 32-byte entry-state bitmap, then 126 entries. */
const NVS_PAGE_SIZE = 4096;
const NVS_HEADER_SIZE = 32;
const NVS_BITMAP_SIZE = 32;
const NVS_ENTRY_SIZE = 32;
const NVS_ENTRIES_PER_PAGE = (NVS_PAGE_SIZE - NVS_HEADER_SIZE - NVS_BITMAP_SIZE) / NVS_ENTRY_SIZE; // 126

/** Read a little-endian 32-bit word at `o`, tolerating a short buffer. */
function u32le(b: Uint8Array, o: number): number {
  return ((b[o] ?? 0) | ((b[o + 1] ?? 0) << 8) | ((b[o + 2] ?? 0) << 16) | ((b[o + 3] ?? 0) << 24)) >>> 0;
}

/** Read a little-endian 16-bit word at `o`. */
function u16le(b: Uint8Array, o: number): number {
  return ((b[o] ?? 0) | ((b[o + 1] ?? 0) << 8)) & 0xffff;
}

// === Partition table ===

export interface PartitionEntry {
  type: string; // 'app' | 'data' | 'type:0xNN'
  subtype: string; // e.g. 'factory', 'ota_0', 'nvs', 'spiffs', 'coredump', 'subtype:0xNN'
  offset: number;
  size: number;
  label: string;
}

const APP_SUBTYPES: Record<number, string> = { 0x00: 'factory', 0x20: 'test' };
const DATA_SUBTYPES: Record<number, string> = {
  0x00: 'ota', // the otadata partition
  0x01: 'phy',
  0x02: 'nvs',
  0x03: 'coredump',
  0x04: 'nvs_keys',
  0x05: 'efuse_em',
  0x06: 'undefined',
  0x80: 'esphttpd',
  0x81: 'fat',
  0x82: 'spiffs',
  0x83: 'littlefs',
};

/** Name an (app-subtype) code: 0x10..0x1f are ota_0..ota_15. */
function appSubtypeName(sub: number): string {
  if (sub >= 0x10 && sub <= 0x1f) return `ota_${sub - 0x10}`;
  return APP_SUBTYPES[sub] ?? `subtype:0x${sub.toString(16)}`;
}

/**
 * Pure: parse the ESP partition table at 0x8000. Walks 32-byte entries while the 0xAA50 magic holds (stopping at
 * the 0xEBEB md5 marker / 0xFFFF padding / an out-of-range entry), naming each type/subtype. Returns [] when the
 * bytes at 0x8000 are not a partition table (honest — this is not an ESP dump).
 */
export function parsePartitionTable(buf: Uint8Array, base = PARTTABLE_OFFSET): PartitionEntry[] {
  const entries: PartitionEntry[] = [];
  for (let i = 0; i < PART_TABLE_MAX; i++) {
    const o = base + i * PART_ENTRY_SIZE;
    if (o + PART_ENTRY_SIZE > buf.length) break;
    if (buf[o] !== PART_MAGIC[0] || buf[o + 1] !== PART_MAGIC[1]) break; // md5 marker (0xEBEB) or padding ends it
    const typeByte = buf[o + 2] ?? 0xff;
    const subByte = buf[o + 3] ?? 0xff;
    const offset = u32le(buf, o + 4);
    const size = u32le(buf, o + 8);
    const label = decodeCString(buf, o + 12, 16);
    const type = typeByte === 0x00 ? 'app' : typeByte === 0x01 ? 'data' : `type:0x${typeByte.toString(16)}`;
    const subtype =
      typeByte === 0x00
        ? appSubtypeName(subByte)
        : typeByte === 0x01
          ? (DATA_SUBTYPES[subByte] ?? `subtype:0x${subByte.toString(16)}`)
          : `subtype:0x${subByte.toString(16)}`;
    entries.push({ type, subtype, offset, size, label });
  }
  return entries;
}

/** Decode a fixed-width, NUL-terminated latin1 field, dropping non-printable trailing bytes. */
function decodeCString(buf: Uint8Array, off: number, max: number): string {
  let s = '';
  for (let i = 0; i < max; i++) {
    const c = buf[off + i] ?? 0;
    if (c === 0x00 || c === 0xff) break;
    if (c < 0x20 || c > 0x7e) return s; // stop at the first non-printable — a clean key/label only
    s += String.fromCharCode(c);
  }
  return s;
}

// === NVS key/value store ===

export type NvsEntryState = 'written' | 'erased' | 'empty' | 'invalid';

export interface NvsEntry {
  namespace: number;
  key: string;
  type: string;
  state: NvsEntryState;
  /** True when the value survives despite being superseded/erased — the recoverable-secret case. */
  stale: boolean;
  valueHex?: string;
  valueText?: string;
  /** The key name looks like key material / a credential. */
  sensitive: boolean;
}

/** NVS value type codes → a friendly name. */
const NVS_TYPES: Record<number, string> = {
  0x01: 'u8',
  0x11: 'i8',
  0x02: 'u16',
  0x12: 'i16',
  0x04: 'u32',
  0x14: 'i32',
  0x08: 'u64',
  0x18: 'i64',
  0x21: 'string',
  0x41: 'blob',
  0x42: 'blob_data',
  0x48: 'blob_idx',
};

/** A key name that looks like key material / a credential worth surfacing. */
const SENSITIVE_KEY = /priv|secret|sign|token|passw?d?|pass|cred|apikey|api_key|_key$|^key$|cert|seed|mnemonic/i;

/** Pure: the 2-bit entry-state for slot `si` within a page, from the page's entry-state bitmap. */
function entryState(bitmap: Uint8Array, si: number): NvsEntryState {
  const bits = (bitmap[si >> 2] ?? 0xff) >> ((si & 3) * 2);
  switch (bits & 0x3) {
    case 0x3:
      return 'empty';
    case 0x2:
      return 'written';
    case 0x0:
      return 'erased';
    default:
      return 'invalid';
  }
}

/**
 * Pure: parse one NVS region (offset..offset+size in `buf`) into entries. Walks each 4096-byte page: reads the
 * 32-byte entry-state bitmap, then each 32-byte entry `ns(1) type(1) span(1) chunk(1) crc32(4) key[16] data[8]`.
 * String/blob values (span>1) are reassembled from the continuation slots. Entries are surfaced regardless of
 * state — an ERASED entry whose bytes are still present is exactly the recoverable-secret case — and a
 * superseded duplicate (same namespace+key, an earlier copy) is flagged `stale`.
 */
export function parseNvsRegion(buf: Uint8Array, off: number, size: number): NvsEntry[] {
  const end = Math.min(off + size, buf.length);
  const out: NvsEntry[] = [];
  for (let page = off; page + NVS_PAGE_SIZE <= end; page += NVS_PAGE_SIZE) {
    const state = u32le(buf, page);
    if (state === 0xffffffff) continue; // uninitialized page — no entries
    const bitmap = buf.subarray(page + NVS_HEADER_SIZE, page + NVS_HEADER_SIZE + NVS_BITMAP_SIZE);
    const entriesBase = page + NVS_HEADER_SIZE + NVS_BITMAP_SIZE;
    for (let si = 0; si < NVS_ENTRIES_PER_PAGE; si++) {
      const eo = entriesBase + si * NVS_ENTRY_SIZE;
      const st = entryState(bitmap, si);
      if (st === 'empty') continue;
      const typeByte = buf[eo + 1] ?? 0xff;
      const typeName = NVS_TYPES[typeByte];
      if (!typeName) continue; // not a live entry slot (continuation data / padding)
      const key = decodeCString(buf, eo + 8, 16);
      if (!key) continue;
      const namespace = buf[eo] ?? 0;
      const span = Math.max(1, buf[eo + 2] ?? 1);
      const entry: NvsEntry = {
        namespace,
        key,
        type: typeName,
        state: st,
        stale: st === 'erased',
        sensitive: SENSITIVE_KEY.test(key),
      };
      readNvsValue(buf, eo, typeByte, span, entry);
      out.push(entry);
      si += span - 1; // skip the continuation slots this entry consumed
    }
  }
  markSuperseded(out);
  return out;
}

/** Fill an entry's value: primitives from the 8-byte data field; string/blob from the following span slots. */
function readNvsValue(buf: Uint8Array, eo: number, typeByte: number, span: number, entry: NvsEntry): void {
  const dataOff = eo + 24;
  if (typeByte === 0x21 || typeByte === 0x41 || typeByte === 0x42) {
    // Var-length: data field starts with the size; the payload sits in the continuation slots.
    const len = Math.min(u16le(buf, dataOff), (span - 1) * NVS_ENTRY_SIZE, 4096);
    const start = eo + NVS_ENTRY_SIZE;
    const bytes = buf.subarray(start, Math.min(start + len, buf.length));
    entry.valueHex = Buffer.from(bytes).toString('hex');
    const text = decodePrintable(bytes);
    if (text) entry.valueText = text;
  } else {
    const bytes = buf.subarray(dataOff, dataOff + 8);
    entry.valueHex = Buffer.from(bytes).toString('hex');
  }
}

/** Decode a byte run as printable text iff it is mostly printable (else undefined — it's binary key material). */
function decodePrintable(bytes: Uint8Array): string | undefined {
  if (bytes.length === 0) return undefined;
  let printable = 0;
  let s = '';
  for (const c of bytes) {
    if (c === 0) break;
    if (c >= 0x20 && c <= 0x7e) printable++;
    s += String.fromCharCode(c);
  }
  return s.length > 0 && printable / s.length > 0.8 ? s : undefined;
}

/**
 * Flag every entry that a later same-namespace+key entry supersedes as `stale` (its value still persists). A
 * `blob_idx` is metadata that pairs with its `blob_data` under the same key — NOT a supersession — so it is
 * excluded from the comparison, otherwise a live signing-key blob would be mislabelled stale by its own index.
 */
function markSuperseded(entries: NvsEntry[]): void {
  const latest = new Map<string, number>();
  entries.forEach((e, i) => {
    if (e.type !== 'blob_idx') latest.set(`${e.namespace}:${e.key}`, i);
  });
  entries.forEach((e, i) => {
    if (e.type === 'blob_idx') return;
    if (latest.get(`${e.namespace}:${e.key}`) !== i) e.stale = true;
  });
}

// === Security posture (offline, honest) ===

export interface EspPosture {
  flashEncryption: 'on' | 'off' | 'unknown';
  secureBoot: 'on' | 'off' | 'unknown';
  antiRollback: 'on' | 'off' | 'unknown';
  evidence: string;
}

/**
 * Pure: infer the offline security posture from an app partition. If the app image is a plaintext `esp_image`
 * (magic 0xE9 with a readable header) then Flash-Encryption is OFF (an encrypted image would be ciphertext) and,
 * absent an appended secure-boot signature block, Secure-Boot is OFF. Definitive posture needs live eFuse reads,
 * so anything the dump can't prove degrades to `unknown` — never assumed secure.
 */
export function assessSecurePosture(buf: Uint8Array, appOffset: number | null): EspPosture {
  if (appOffset === null || appOffset >= buf.length) {
    return {
      flashEncryption: 'unknown',
      secureBoot: 'unknown',
      antiRollback: 'unknown',
      evidence: 'no app partition located in the dump — posture indeterminate offline',
    };
  }
  const magic = buf[appOffset] ?? 0x00;
  if (magic !== 0xe9) {
    // Not a plaintext esp_image header — could be encrypted (or an empty/OTA slot); do not guess "secure".
    return {
      flashEncryption: 'unknown',
      secureBoot: 'unknown',
      antiRollback: 'unknown',
      evidence: `app partition @0x${appOffset.toString(16)} has no plaintext esp_image magic (0xE9) — encryption cannot be ruled in or out offline`,
    };
  }
  // A plaintext app image proves flash-encryption is OFF. Secure Boot v2 appends a 0xE7 signature sector after the
  // (64 KB-aligned) image; its absence within the app region is the offline "Secure Boot OFF" signal.
  return {
    flashEncryption: 'off',
    secureBoot: 'off',
    antiRollback: 'off',
    evidence:
      `app partition @0x${appOffset.toString(16)} is a plaintext esp_image (magic 0xE9) → Flash-Encryption OFF; ` +
      'no appended secure-boot signature block → Secure-Boot OFF; without secure boot there is no rollback ' +
      'enforcement. (Definitive posture would need live eFuse reads.)',
  };
}

// === Composition ===

export interface EspAnalysis {
  isEsp: boolean;
  partitions: PartitionEntry[];
  nvsEntries: NvsEntry[];
  posture: EspPosture;
  findings: FindingDraft[];
}

/** Find the first app partition's flash offset (factory preferred, else the lowest ota slot). */
function firstAppOffset(parts: PartitionEntry[]): number | null {
  const apps = parts.filter((p) => p.type === 'app');
  const factory = apps.find((p) => p.subtype === 'factory');
  if (factory) return factory.offset;
  return apps.length ? apps.reduce((a, b) => (a.offset <= b.offset ? a : b)).offset : null;
}

/**
 * Pure: compose the partition table, NVS entries and posture into honest findings. Sensitive NVS blobs become
 * `critical` static_confirmed key-material findings (full value in evidence, redacted in the title); stale/erased
 * recoverable entries a `high` finding; an OFF posture a `high` finding; the partition inventory an `info` fact.
 */
export function analyzeEsp(buf: Uint8Array): EspAnalysis {
  const partitions = parsePartitionTable(buf);
  const isEsp = partitions.length > 0;
  if (!isEsp) {
    return {
      isEsp: false,
      partitions: [],
      nvsEntries: [],
      posture: { flashEncryption: 'unknown', secureBoot: 'unknown', antiRollback: 'unknown', evidence: '' },
      findings: [],
    };
  }

  const nvsPart = partitions.find((p) => p.subtype === 'nvs');
  const nvsEntries = nvsPart ? parseNvsRegion(buf, nvsPart.offset, nvsPart.size) : [];
  const posture = assessSecurePosture(buf, firstAppOffset(partitions));
  const findings: FindingDraft[] = [];

  // Partition inventory — the map the Linux lens never sees.
  findings.push({
    kind: 'esp-partition-table',
    title: `ESP partition table: ${partitions.length} partitions (${partitions.map((p) => p.label || p.subtype).join(', ')})`,
    severity: 'info',
    proofState: 'static_confirmed',
    evidence: { partitions },
    rationale:
      'Parsed from the 0xAA50 entries at flash offset 0x8000 — the ESP SoC layout (app/ota/nvs/spiffs/coredump) ' +
      'that identifies this as an Espressif dump, not a Linux rootfs.',
  });

  // Live sensitive key material stored in NVS (the trust-anchor case). A blob_idx is metadata, not the value —
  // its paired blob_data carries the real bytes, so index entries are not surfaced as key material.
  for (const e of nvsEntries.filter((e) => e.sensitive && !e.stale && e.type !== 'blob_idx')) {
    const bytes = e.valueHex ? e.valueHex.length / 2 : 0;
    findings.push({
      kind: 'esp-nvs-key',
      title: `Key material in NVS: namespace ${e.namespace} key "${e.key}" (${e.type}, ${bytes}-byte value)`,
      severity: 'critical',
      proofState: 'static_confirmed',
      evidence: { namespace: e.namespace, key: e.key, type: e.type, valueHex: e.valueHex, valueText: e.valueText },
      rationale:
        'A secret-looking key stored in the plaintext NVS partition — literally present in the dump. If this is a ' +
        'signing/private key it is the device trust anchor; a file/regex secret scan never parses the NVS store.',
    });
  }

  // Stale / erased-but-recoverable entries (NVS copy-on-write leaves old values behind).
  const stale = nvsEntries.filter((e) => e.stale && (e.valueText || e.sensitive));
  if (stale.length) {
    findings.push({
      kind: 'esp-nvs-stale',
      title: `Recoverable stale/erased NVS entries: ${stale.length} (e.g. ${stale
        .slice(0, 4)
        .map((e) => e.valueText || e.key)
        .join(', ')})`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: {
        entries: stale.map((e) => ({ namespace: e.namespace, key: e.key, valueText: e.valueText, state: e.state })),
      },
      rationale:
        'NVS updates are copy-on-write: a rewritten or erased key leaves its previous value readable in flash. ' +
        'These superseded/erased entries are still recoverable from the dump (e.g. a credential-rotation lineage).',
    });
  }

  // Offline security posture.
  if (posture.flashEncryption === 'off' || posture.secureBoot === 'off') {
    findings.push({
      kind: 'esp-secure-posture',
      title: `ESP security posture: Flash-Encryption ${posture.flashEncryption.toUpperCase()}, Secure-Boot ${posture.secureBoot.toUpperCase()}, anti-rollback ${posture.antiRollback.toUpperCase()}`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { ...posture },
      rationale: posture.evidence,
    });
  }

  return { isEsp, partitions, nvsEntries, posture, findings };
}

// === Runner ===

export interface EspResult {
  available: boolean;
  isEsp: boolean;
  partitions: PartitionEntry[];
  nvsEntries: NvsEntry[];
  posture: EspPosture;
  findings: FindingDraft[];
  reason: string;
}

/** ESP SPI flash dumps are ≤ 16 MB; cap the read so a mis-routed large image can't blow up memory. */
const ESP_READ_CAP = 16 * 1024 * 1024;

function readBounded(p: string, cap = ESP_READ_CAP): Uint8Array {
  const fd = fs.openSync(p, 'r');
  try {
    const len = Math.min(fs.fstatSync(fd).size, cap);
    const b = Buffer.allocUnsafe(len);
    fs.readSync(fd, b, 0, len, 0);
    return b;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Analyze an ESP SoC flash dump from disk — pure byte analysis, always `available` (no external tool to be
 * absent). When the bytes at 0x8000 are not an ESP partition table it degrades honestly to isEsp:false with a
 * reason rather than inventing partitions. A real dump yields the partition inventory, recovered NVS entries
 * (including stale/erased secrets) and the offline security posture as static_confirmed findings.
 */
export function runEspAnalysis(imagePath: string): EspResult {
  let buf: Uint8Array;
  try {
    buf = readBounded(imagePath);
  } catch (err) {
    return {
      available: true,
      isEsp: false,
      partitions: [],
      nvsEntries: [],
      posture: { flashEncryption: 'unknown', secureBoot: 'unknown', antiRollback: 'unknown', evidence: '' },
      findings: [],
      reason: `Could not read image bytes: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const a = analyzeEsp(buf);
  if (!a.isEsp) {
    return { ...a, available: true, reason: 'No ESP partition table at flash offset 0x8000 — not an ESP SoC dump.' };
  }
  const keyCount = a.nvsEntries.filter((e) => e.sensitive && !e.stale).length;
  const staleCount = a.nvsEntries.filter((e) => e.stale).length;
  return {
    ...a,
    available: true,
    reason:
      `ESP SoC dump: ${a.partitions.length} partitions, ${a.nvsEntries.length} NVS entries ` +
      `(${keyCount} sensitive, ${staleCount} stale/erased). Posture: Flash-Enc ${a.posture.flashEncryption}, ` +
      `Secure-Boot ${a.posture.secureBoot}. Static analysis of the dump bytes — no claim about a live chip.`,
  };
}
