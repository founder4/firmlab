/**
 * W3 — Linux/router **nvram key-value store** parser. `esp.ts` (W6) reads the device NVS of an Espressif dump;
 * this is the other half of docs/AUTONOMOUS-WORKERS.md §3.2(5): the app's secret scan is file/regex based and
 * "never parses these key-value stores", so a credential that lives in a *flash partition* rather than in a file
 * is structurally invisible to fsaudit/gitleaks/auxsecrets — none of which ever open the raw image.
 *
 * The format was read off the corpus, not assumed. Nine stores exist in the deployed `/data`, and every one is
 * the same shape — an optional 4-byte little-endian CRC32 header, then NUL-terminated `name=value` records, then
 * an **empty record** that ends the list, then padding (0x00, 0xFF, or stale bytes from a longer previous env):
 *
 *   AliExpress-Repeater.bin @0x32000  271 recs, CRC 0x6a3f2c00 over [4:0x4000)  → `Login`, `Password`, `wanPppoe*`
 *   AliExpress-Repeater.bin @0x36000  305 recs, CRC 0x2bd85424 over [4:0x2000)  → RT2860 wifi: `WPAPSK*`, `Key1Str`
 *   Tenda-Camera.bin        @0x40000   56 recs, CRC 0xfca7c6f4 over [4:0x1000)
 *   IMOU-Ranger-2C.bin      @0x30000   38 recs, CRC 0x94bfcaf8 over [4:0x10000)
 *   BeanView-Camera.bin     @0x60000   22 recs, CRC 0x65b8694c over [4:0x10000)
 *   Xiaomi-Repeater 2018/23 @0x30000   19/18 recs, CRC ok            → `miio_token_seed`
 *   plus headerless copies compiled into bootloaders (`fw_printenv` @0x614c, WR940N `4254` @0x1ad50).
 *
 * Three facts from those bytes shape the code. (1) The **CRC is computed over the whole partition including its
 * padding**, so verifying it means recovering the partition size by trying the standard flash sizes — and a match
 * is decisive, which is why `confidence` distinguishes `crc-verified` from `structural`. (2) A store is **not**
 * simply "a run of key=value strings": 93 files under `/data/extract` contain a run of 8+ such records and almost
 * none is a store — they are kernel `.modinfo` sections and `.rodata` pools of `"opt="` format strings in
 * sudo/ppecfg/tor/libsqlite3/minidlnad. What separates them is that a real store *terminates with an empty
 * record*, has mostly-unique keys, and is not an all-empty-value template table; those three rules plus the CRC
 * take 10,712 scanned files down to the real stores with no false positive. (3) Real stores contain garbage — the Xiaomi 2018 env has a
 * corrupt `bootcmd\xc2\xc2=` record wedged between good ones — so a malformed record is counted and skipped, never
 * treated as end-of-store.
 *
 * Everything except `runNvramScan` is pure and unit-tested. Proof states follow the house rule: a credential
 * literally present in the bytes is `static_confirmed`; a flag whose *effect* depends on the running device (a
 * telnet/ssh enable, an interruptible boot delay) is `needs_runtime_reproduction` — a lead, never a verdict.
 * **Values are never emitted.** Like `fsaudit`'s shadow-hash redaction, evidence carries the key, the value's
 * length and a class (`well-known-default` / `opaque`), never the secret itself.
 *
 * Known limitation, stated rather than hidden: a store is only entered where the preceding byte is 0x00/0xFF (or at
 * offset 0), which is true of every store that lives in flash but not of a copy compiled into an ELF behind
 * non-zero alignment padding. Tenda-Camera's bootloader default env (@0x21940, padded with 0x02) is therefore
 * entered two records late — 54 of its 56 records, all real. Relaxing the rule readmits the mid-record starts that
 * an aligned grid scan produces, so the trade is deliberate and the shortfall is visible in `recordCount`.
 *
 * What this deliberately does NOT do: the DVRF `nvram admin/admin` cited in §3.2(5) is *not* an nvram store. It is
 * the Broadcom `router_defaults[]` string pool inside `usr/lib/libshared.so` (`http_passwd\0admin\0` at 0xa7dcc) —
 * a pointer array whose name/value pairing lives in relocations, not in the string bytes, so it cannot be recovered
 * by adjacency and is not guessed at here. The grounded `admin/admin` case is AliExpress-Repeater's store.
 */
import fs from 'node:fs';
import type { FindingSeverity, ProofState } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';
import { scanContentSecrets } from './fsaudit.js';

// === Bounds ===
// Every cap below states what it dropped through `NvramStore.capped` — a bound is not an answer.

/** Longest single record accepted. The corpus maximum is a 232-byte `mtdparts=`; 4 KiB is generous. */
const MAX_RECORD_BYTES = 4096;
/** Most records parsed from one store. The corpus maximum is 305 (AliExpress wifi config). */
const MAX_RECORDS = 4096;
/** Most body bytes walked for one store. The largest observed partition is 0x10000. */
const MAX_BODY_BYTES = 512 * 1024;
/** Most stores returned from one blob. The corpus maximum is 2 per image. */
const MAX_STORES = 16;
/** Bytes of an image read by the runner — an SPI flash dump; larger inputs are truncated and say so. */
const SCAN_READ_CAP = 64 * 1024 * 1024;

// === Acceptance thresholds (each derived from the corpus separation measured in the header) ===

/** Records a headerless (CRC-unverifiable) store must have. The smallest real one is 11 (WR940N U-Boot defaults). */
const MIN_RECORDS = 8;
/** Valid/total record ratio. Real stores: 0.95–1.00. A `.rodata` coincidence run: 0.29 (ipq_cnss2.ko). */
const MIN_VALID_RATIO = 0.8;
/** Unique-key ratio. Real stores: 0.95–1.00. `.modinfo` alias tables: 0.11–0.15; usb_modeswitch `.rodata`: 0.55. */
const MIN_UNIQUE_RATIO = 0.75;
/** Empty-value ratio above which the run is a `"opt="` format-string table. Real stores peak at 0.45; sudo/ppecfg: 1.00. */
const MAX_EMPTY_RATIO = 0.9;

/**
 * Flash partition sizes tried when recovering the CRC region. 0x1000 / 0x2000 / 0x4000 / 0x10000 are the four
 * observed in the corpus; the rest are the neighbouring standard erase-block sizes. Each extra candidate can only
 * *add* verification power (a spurious match is 2^-32 and must still pass the structural checks).
 */
const CRC_REGION_SIZES = [0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000];

/**
 * Kernel-module `.modinfo` keys. A `.ko` section is genuinely a run of NUL-terminated `key=value` records — it is
 * the single most common false positive in the corpus (40 records in ipq_cnss2.ko) — and none of these names is
 * ever an nvram key, so their presence in an unverified run rejects it outright.
 */
const MODINFO_KEYS = new Set([
  'vermagic',
  'srcversion',
  'parmtype',
  'parm',
  'import_ns',
  'retpoline',
  'intree',
  'depends',
]);

// === CRC32 ===

let crcTable: Int32Array | null = null;

/** Build the standard reflected CRC-32 (IEEE 802.3, poly 0xEDB88320) table once. */
function crc32Table(): Int32Array {
  if (crcTable) return crcTable;
  const t = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c;
  }
  crcTable = t;
  return t;
}

/**
 * Pure: CRC-32 (zlib/U-Boot flavour) over `buf[from, to)`. Implemented here rather than taken from `node:zlib` so
 * the parser stays a pure function a unit test can drive with a plain array.
 */
export function crc32(buf: Uint8Array, from = 0, to = buf.length): number {
  const t = crc32Table();
  const end = Math.min(to, buf.length);
  let c = -1;
  for (let i = Math.max(0, from); i < end; i++) c = (t[(c ^ (buf[i] ?? 0)) & 0xff] ?? 0) ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

// === Record parsing ===

export interface NvramRecord {
  key: string;
  value: string;
  /** Absolute offset of the record's first byte in the buffer it was parsed from. */
  offset: number;
}

/** A key byte. Leading digits are allowed because they are real: AliExpress ships `3g_pppPass`, `3g_wanAPN`. */
function isKeyStartByte(c: number): boolean {
  return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x5f;
}

/** A subsequent key byte: alphanumeric plus `_ . : -`. Anything else (a 0xC2 as in the Xiaomi env) is garbage. */
function isKeyByte(c: number): boolean {
  return isKeyStartByte(c) || c === 0x2e || c === 0x3a || c === 0x2d;
}

/** Decode `buf[from, to)` as latin1 — values carry raw 8-bit bytes and must not be mangled by UTF-8 decoding. */
function latin1(buf: Uint8Array, from: number, to: number): string {
  let s = '';
  for (let i = from; i < to; i++) s += String.fromCharCode(buf[i] ?? 0);
  return s;
}

interface RunParse {
  records: NvramRecord[];
  malformed: number;
  /** The run's very first record did not parse — the candidate offset is mis-aligned, not a store start. */
  firstRecordMalformed: boolean;
  /** An empty record was reached: the store declared its own end. */
  terminated: boolean;
  /** Offset just past the run (past the terminator when there is one). */
  end: number;
  capped: string | null;
}

/**
 * Pure: walk NUL-terminated records from `body` until the **empty record** that ends the list, a bound, or the end
 * of the buffer. A record that is not `name=value` with a plausible key is counted as malformed and skipped — it
 * does not end the run, because real stores contain them (the Xiaomi 2018 env carries a corrupt `bootcmd\xc2\xc2=`
 * between two good records, and stopping there would have lost the four records after it, the terminator with them).
 * Bails early once the valid/total ratio is hopeless so a `.rodata` candidate costs ~16 records, not 512 KiB.
 */
export function parseNvramRecords(buf: Uint8Array, body: number): RunParse {
  const records: NvramRecord[] = [];
  let malformed = 0;
  let firstRecordMalformed = false;
  let terminated = false;
  let capped: string | null = null;
  const limit = Math.min(buf.length, body + MAX_BODY_BYTES);
  let pos = body;

  while (pos < limit) {
    const total = records.length + malformed;
    if (total >= MAX_RECORDS) {
      capped = `record cap reached (${MAX_RECORDS}); the store continues past this point`;
      break;
    }
    if (total >= 16 && total % 16 === 0 && records.length / total < MIN_VALID_RATIO) break; // not a record store

    // Find this record's terminating NUL, bounded so one runaway string can't scan the whole buffer.
    const scanEnd = Math.min(pos + MAX_RECORD_BYTES + 1, limit);
    let nul = -1;
    for (let i = pos; i < scanEnd; i++) {
      if (buf[i] === 0) {
        nul = i;
        break;
      }
    }
    if (nul < 0) {
      capped =
        pos + MAX_RECORD_BYTES + 1 <= limit
          ? `record at 0x${pos.toString(16)} exceeds ${MAX_RECORD_BYTES} bytes`
          : null;
      break; // no terminator: truncated blob, or an over-long record
    }
    if (nul === pos) {
      terminated = true;
      pos = nul + 1;
      break;
    }

    // Split on the first '=' and validate the key's byte shape.
    let eq = -1;
    for (let i = pos; i < nul; i++) {
      if (buf[i] === 0x3d) {
        eq = i;
        break;
      }
    }
    let ok = eq > pos && isKeyStartByte(buf[pos] ?? 0);
    if (ok) {
      for (let i = pos + 1; i < eq; i++) {
        if (!isKeyByte(buf[i] ?? 0)) {
          ok = false;
          break;
        }
      }
    }
    if (!ok) {
      if (records.length === 0 && malformed === 0) firstRecordMalformed = true;
      malformed++;
    } else {
      records.push({ key: latin1(buf, pos, eq), value: latin1(buf, eq + 1, nul), offset: pos });
    }
    pos = nul + 1;
  }

  if (!capped && pos >= limit && limit < buf.length) capped = `body scan capped at ${MAX_BODY_BYTES} bytes`;
  return { records, malformed, firstRecordMalformed, terminated, end: pos, capped };
}

// === Store detection ===

export interface NvramCrc {
  /** The little-endian word stored in the 4-byte header. */
  stored: number;
  /** Size of the partition region the CRC covers, header excluded — recovered by trying the standard sizes. */
  regionSize: number;
}

export type NvramConfidence = 'crc-verified' | 'structural';

export interface NvramStore {
  /** Offset of the CRC header, or of the first record when the store is headerless. */
  offset: number;
  headerBytes: 0 | 4;
  bodyOffset: number;
  recordCount: number;
  malformedCount: number;
  /** The store ended with its own empty record (rather than running into the end of the blob). */
  terminated: boolean;
  crc: NvramCrc | null;
  confidence: NvramConfidence;
  records: NvramRecord[];
  /** Keys appearing more than once — a field-modified env keeps the superseded copies (Xiaomi 2018 has 3 `bootcmd`). */
  duplicateKeys: string[];
  /** Non-null when a bound truncated the parse, stating what was dropped. */
  capped: string | null;
}

/**
 * Pure: if `buf[offset]` starts a 4-byte CRC header, recover the partition size the CRC covers. Returns null when
 * no standard size matches — in which case the four bytes are simply not a header and must not be reported as one.
 * Computes the CRC once over the largest candidate, reading off each shorter candidate's value as it goes.
 */
export function verifyNvramCrc(buf: Uint8Array, offset: number): NvramCrc | null {
  if (offset + 4 > buf.length) return null;
  const stored =
    ((buf[offset] ?? 0) |
      ((buf[offset + 1] ?? 0) << 8) |
      ((buf[offset + 2] ?? 0) << 16) |
      ((buf[offset + 3] ?? 0) << 24)) >>>
    0;
  const t = crc32Table();
  let c = -1;
  let i = offset + 4;
  for (const size of CRC_REGION_SIZES) {
    const end = offset + size;
    if (end > buf.length) break;
    for (; i < end; i++) c = (t[(c ^ (buf[i] ?? 0)) & 0xff] ?? 0) ^ (c >>> 8);
    if ((c ^ -1) >>> 0 === stored) return { stored, regionSize: size };
  }
  return null;
}

/** Keys seen more than once, in first-appearance order. */
function findDuplicateKeys(records: NvramRecord[]): string[] {
  const seen = new Set<string>();
  const dup = new Set<string>();
  for (const r of records) {
    if (seen.has(r.key)) dup.add(r.key);
    else seen.add(r.key);
  }
  return [...dup];
}

/**
 * Pure: read `buf` starting at `offset` as an nvram store, or return null when it is not one.
 *
 * Tries headerless first and only claims a 4-byte header when its CRC actually verifies — an unverifiable header
 * is not a header, and reporting one would be an invention. A CRC-verified store is accepted on the CRC alone
 * (plus a well-formed first record); an unverified one must additionally clear every structural rule the corpus
 * separation established, because without the CRC those rules are the only thing standing between a store and a
 * `.rodata` string pool.
 */
export function parseNvramStore(buf: Uint8Array, offset = 0): NvramStore | null {
  for (const headerBytes of [0, 4] as const) {
    const body = offset + headerBytes;
    if (body >= buf.length || !isKeyStartByte(buf[body] ?? 0)) continue;

    const run = parseNvramRecords(buf, body);
    const n = run.records.length;
    const total = n + run.malformed;
    if (total === 0 || run.firstRecordMalformed || n < 2 || n / total < MIN_VALID_RATIO) continue;

    const crc = headerBytes === 4 ? verifyNvramCrc(buf, offset) : null;
    if (headerBytes === 4 && !crc) continue; // never claim a header we cannot verify

    if (!crc) {
      if (n < MIN_RECORDS || !run.terminated) continue;
      const keys = run.records.map((r) => r.key);
      if (new Set(keys).size / n < MIN_UNIQUE_RATIO) continue; // duplicate-dominated: a .modinfo alias table
      if (run.records.filter((r) => r.value === '').length / n >= MAX_EMPTY_RATIO) continue; // an `opt=` template table
      if (keys.some((k) => MODINFO_KEYS.has(k))) continue; // a kernel module's .modinfo section
    }

    return {
      offset,
      headerBytes,
      bodyOffset: body,
      recordCount: n,
      malformedCount: run.malformed,
      terminated: run.terminated,
      crc,
      confidence: crc ? 'crc-verified' : 'structural',
      records: run.records,
      duplicateKeys: findDuplicateKeys(run.records),
      capped: run.capped,
    };
  }
  return null;
}

export interface NvramDetection {
  isStore: boolean;
  store: NvramStore | null;
  /** Why the answer is what it is — an empty result states its reason rather than reading as a clean one. */
  reason: string;
}

/** Pure: does this blob begin with an nvram store? Says no with a reason rather than returning noise. */
export function detectNvramStore(buf: Uint8Array): NvramDetection {
  const store = parseNvramStore(buf, 0);
  if (!store) {
    return {
      isStore: false,
      store: null,
      reason:
        'Not an nvram store: the bytes do not open with NUL-terminated name=value records that terminate with an ' +
        'empty record, and no 4-byte CRC32 header verifies over a standard flash partition size.',
    };
  }
  const how = store.crc
    ? `CRC32 0x${store.crc.stored.toString(16).padStart(8, '0')} verifies over the ${store.crc.regionSize}-byte partition`
    : 'no CRC header; accepted on record structure alone (terminator + unique keys + non-empty values)';
  return { isStore: true, store, reason: `nvram store: ${store.recordCount} record(s), ${how}.` };
}

/**
 * Pure: locate every nvram store inside a larger blob (a whole flash image, a carved partition, a bootloader with
 * its compiled-in default environment). Alignment-free: a store may begin only at offset 0 or immediately after a
 * 0x00 or 0xFF byte, which is exactly true of every store in the corpus (records are NUL-terminated and partitions
 * sit in erased flash) and cheaply rejects the mid-record starts that an aligned grid scan produces.
 */
export function findNvramStores(buf: Uint8Array, maxStores = MAX_STORES): NvramStore[] {
  const out: NvramStore[] = [];
  let coveredTo = 0;
  for (let o = 0; o < buf.length && out.length < maxStores; o++) {
    if (o < coveredTo) continue;
    if (o > 0) {
      const prev = buf[o - 1] ?? 0;
      if (prev !== 0x00 && prev !== 0xff) continue;
    }
    if (!isKeyStartByte(buf[o] ?? 0) && !isKeyStartByte(buf[o + 4] ?? 0)) continue;
    const store = parseNvramStore(buf, o);
    if (!store) continue;
    out.push(store);
    const last = store.records[store.records.length - 1];
    coveredTo = last ? last.offset + last.key.length + last.value.length + 2 : store.bodyOffset + 1;
  }
  return out;
}

// === Security-relevant keys ===

/**
 * Credential keys. `Login`/`Password`/`wanPppoe*`/`sta_pass`/`3g_pppPass` are literally the AliExpress-Repeater
 * store's key names; `http_passwd`/`http_username`/`ppp_passwd` are the Broadcom names in DVRF's `libshared.so`
 * defaults pool. The rest is the same keyword shape `esp.ts` uses for NVS. Absence of a match is not a clean
 * result — it means no key in this store *named* itself a credential.
 */
const CREDENTIAL_KEY = /passw|pass$|^pass_|login|username|^user$|_user$|admin|credential|secret|token|seed/i;

/** Wireless / RADIUS key material. Every one of these names is present in the AliExpress RT2860 config store. */
const WIFI_KEY = /psk|wpa_?key|wep_?key|key[0-9]*str|radius_.*key|wds[0-9]*key|pincode|wscnewkey/i;

/**
 * Remote-service enablement flags. `remote_management`/`remote_upgrade`/`remote_ftp`/`remote_samba`/`http_enable`
 * are the Broadcom names present in DVRF's `libshared.so`; `telnet`/`ssh`/`dropbear` are the well-known vendor
 * spellings and are matched here **although no store in this corpus contains one** — a store that does not match
 * has not been shown to disable anything, it has only been shown not to name it.
 */
const SERVICE_KEY =
  /^(?:.*_)?(?:telnet|telnetd|ssh|sshd|dropbear)(?:_.*)?$|remote_management|remote_upgrade|remote_ftp|remote_samba|remote_mgt/i;

/** Values that mean "on". Grounded on the corpus's `1`/`0` flags; the word forms are the usual vendor spellings. */
const TRUTHY = new Set(['1', 'on', 'yes', 'true', 'enable', 'enabled']);

/**
 * Credentials shipped as a factory default. Both entries are literally in the corpus — AliExpress-Repeater's
 * `Login` and `Password` are `admin`, and its `WPAPSK1`/`Key1Str` are `12345678` — and the rest are the standard
 * list. Matching only ever *classifies* the value; the value itself never leaves this module.
 */
const WELL_KNOWN_DEFAULTS = new Set([
  'admin',
  'password',
  'root',
  'guest',
  'user',
  'pass',
  'default',
  'support',
  'service',
  '1234',
  '12345',
  '123456',
  '1234567',
  '12345678',
  '123456789',
  '0000',
  '000000',
  '888888',
  'admin123',
  'administrator',
]);

export type NvramValueClass = 'well-known-default' | 'opaque';

/** Classify a value for evidence WITHOUT disclosing it — the only thing that ever leaves this module. */
function classifyValue(value: string): NvramValueClass {
  return WELL_KNOWN_DEFAULTS.has(value.toLowerCase()) ? 'well-known-default' : 'opaque';
}

/**
 * A one- or two-digit integer is a mode/index/flag selector, never key material. Running this over the real corpus
 * is what surfaced the rule: without it AliExpress-Repeater reported `LoginFlag=0`, `sta_wep_key_index=0` and
 * `sta_wep_key_fmt=1` as credentials, purely because their *names* contain `login` and `key`. The real secrets in
 * the same store (`admin`, `12345678`, a 5-char WEP key, a 24-char token) are all longer than two characters.
 */
function isSelectorValue(value: string): boolean {
  return /^\d{1,2}$/.test(value);
}

/** A short, stable label for a store, used as the evidence `path` and in titles. */
function storeLabel(store: NvramStore): string {
  return `nvram store @0x${store.offset.toString(16)}`;
}

// === Findings ===

/**
 * Pure: compose findings from parsed stores.
 *
 *   - the store inventory                        → `info`   / static_confirmed (the parse is a fact about the bytes)
 *   - a credential key with a non-empty value    → `critical` when the value is a well-known default, else `high`
 *                                                  / static_confirmed (the credential is literally in the flash)
 *   - a wifi/RADIUS key with a non-empty value   → `high`   / static_confirmed, `critical` for a default PSK
 *   - a telnet/ssh/remote-management flag set    → `medium` / needs_runtime_reproduction (whether the service is
 *                                                  actually reachable depends on the device booting and its firewall)
 *   - an interruptible boot delay                → `low`    / needs_runtime_reproduction (needs physical serial)
 *   - a PEM private key inside a value           → delegated to fsaudit's already-tested `scanContentSecrets`
 *
 * Values are never included. Evidence carries the key, the value's byte length and its class.
 */
export function nvramFindings(stores: NvramStore[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  if (stores.length === 0) return drafts;

  drafts.push({
    kind: 'nvram-store',
    title: `nvram key-value store${stores.length > 1 ? 's' : ''} in flash: ${stores.length} (${stores
      .map((s) => `0x${s.offset.toString(16)}: ${s.recordCount} records, ${s.confidence}`)
      .join('; ')})`,
    severity: 'info',
    proofState: 'static_confirmed',
    evidence: {
      stores: stores.map((s) => ({
        offset: s.offset,
        headerBytes: s.headerBytes,
        recordCount: s.recordCount,
        malformedCount: s.malformedCount,
        terminated: s.terminated,
        confidence: s.confidence,
        crcRegionSize: s.crc?.regionSize ?? null,
        duplicateKeys: s.duplicateKeys,
        capped: s.capped,
      })),
    },
    rationale:
      'A router nvram/U-Boot-environment partition parsed straight out of the flash image. The rootfs secret scan ' +
      'never sees this — it lives in a partition, not a file — so its contents are reported here as facts about the ' +
      'bytes. Record values are redacted throughout.',
  });

  for (const store of stores) {
    const label = storeLabel(store);
    for (const rec of store.records) {
      if (rec.value === '') continue; // an empty slot is a template, not a configured secret

      const isCredential = CREDENTIAL_KEY.test(rec.key);
      const isWifiKey = WIFI_KEY.test(rec.key);
      if ((isCredential || isWifiKey) && !isSelectorValue(rec.value)) {
        const cls = classifyValue(rec.value);
        const severity: FindingSeverity = cls === 'well-known-default' ? 'critical' : 'high';
        drafts.push({
          kind: isWifiKey && !isCredential ? 'nvram-wifi-key' : 'nvram-credential',
          title: `${isWifiKey && !isCredential ? 'Wireless key' : 'Credential'} in nvram: ${rec.key} (${
            cls === 'well-known-default' ? 'a well-known default' : `${rec.value.length}-byte value`
          }) @0x${store.offset.toString(16)}`,
          severity,
          proofState: 'static_confirmed',
          evidence: {
            path: label,
            key: rec.key,
            offset: rec.offset,
            valueLength: rec.value.length,
            valueClass: cls,
            value: '<redacted>',
            storeConfidence: store.confidence,
          },
          rationale:
            cls === 'well-known-default'
              ? 'This key holds a well-known default credential, literally present in the shipped flash image — the ' +
                'same value on every unit until an owner changes it. The value is redacted; its presence is a static fact.'
              : 'A configured credential/key value is present in the nvram partition of the shipped image. The value ' +
                'is redacted in evidence; that it is there, non-empty, and readable without booting the device is a static fact.',
        });
        continue;
      }

      if (SERVICE_KEY.test(rec.key) && TRUTHY.has(rec.value.trim().toLowerCase())) {
        drafts.push({
          kind: 'nvram-service-enabled',
          title: `Remote service enabled in nvram: ${rec.key} @0x${store.offset.toString(16)}`,
          severity: 'medium',
          proofState: 'needs_runtime_reproduction',
          evidence: { path: label, key: rec.key, offset: rec.offset, enabled: true, storeConfidence: store.confidence },
          rationale:
            'The stored default turns on a remote-access service (telnet/ssh/remote management). Whether it is ' +
            'actually reachable depends on the device booting, the interface coming up and the firewall — so this is ' +
            'a lead needing runtime reproduction, not a verdict about a live device.',
        });
      }
    }

    drafts.push(...bootConsoleFindings(store, label));
  }

  // An nvram value can carry a whole PEM block; reuse the tested detector rather than writing a second one.
  drafts.push(
    ...scanContentSecrets(
      stores.map((s) => ({ path: storeLabel(s), content: s.records.map((r) => `${r.key}=${r.value}`).join('\n') })),
    ),
  );

  return drafts;
}

/**
 * Pure: the boot-time debug surface a U-Boot environment exposes — a non-zero `bootdelay` (the autoboot countdown
 * can be interrupted over serial into a bootloader shell) and an unmuted serial console. Both are `low` and
 * `needs_runtime_reproduction`: they describe a surface that requires physical access to the board to use, and the
 * environment being flashed does not prove the running device honours it.
 */
function bootConsoleFindings(store: NvramStore, label: string): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const proofState: ProofState = 'needs_runtime_reproduction';
  // The LAST record wins: a store may carry superseded duplicates (Xiaomi 2018 has three `bootcmd`).
  const value = (key: string): string | null => {
    let v: string | null = null;
    for (const r of store.records) if (r.key === key) v = r.value;
    return v;
  };

  const bootdelay = value('bootdelay');
  const delay = bootdelay === null ? Number.NaN : Number.parseInt(bootdelay, 10);
  if (Number.isFinite(delay) && delay > 0) {
    drafts.push({
      kind: 'nvram-boot-interruptible',
      title: `Bootloader autoboot is interruptible: bootdelay=${delay}s @0x${store.offset.toString(16)}`,
      severity: 'low',
      proofState,
      evidence: { path: label, key: 'bootdelay', bootdelaySeconds: delay, storeConfidence: store.confidence },
      rationale:
        'A non-zero bootdelay leaves an autoboot countdown an attacker with serial access can interrupt to reach the ' +
        'bootloader shell — from there the kernel command line and the flash are writable. Requires physical access, ' +
        'so it is a lead needing runtime reproduction.',
    });
  }

  const muted = value('console_mute');
  if (muted !== null && !TRUTHY.has(muted.trim().toLowerCase())) {
    drafts.push({
      kind: 'nvram-console-unmuted',
      title: `Serial console left unmuted: console_mute=${muted} @0x${store.offset.toString(16)}`,
      severity: 'low',
      proofState,
      evidence: { path: label, key: 'console_mute', value: muted, storeConfidence: store.confidence },
      rationale:
        'The stored environment does not mute the serial console, so boot output (and often a shell) is exposed on ' +
        'the UART header. Reaching it needs physical access, so this is a lead needing runtime reproduction.',
    });
  }
  return drafts;
}

// === Runner ===

export interface NvramResult {
  available: boolean;
  stores: NvramStore[];
  findings: FindingDraft[];
  bytesScanned: number;
  reason: string;
}

/** Read at most `cap` bytes of a file (a mis-sized image cannot exhaust memory). */
function readBounded(p: string, cap: number): { bytes: Uint8Array; size: number } {
  const fd = fs.openSync(p, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const len = Math.min(size, cap);
    const b = Buffer.allocUnsafe(len);
    fs.readSync(fd, b, 0, len, 0);
    return { bytes: b, size };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Scan a firmware image (or any carved blob) on disk for nvram stores. Always `available` — this is pure byte
 * analysis with no external tool to be absent — and degrades honestly: an unreadable file, or a file with no store,
 * says so rather than reading as a clean result. Findings are returned, never synced; the caller owns the source.
 */
export function runNvramScan(imagePath: string): NvramResult {
  let read: { bytes: Uint8Array; size: number };
  try {
    read = readBounded(imagePath, SCAN_READ_CAP);
  } catch (err) {
    return {
      available: true,
      stores: [],
      findings: [],
      bytesScanned: 0,
      reason: `Could not read image bytes: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const stores = findNvramStores(read.bytes);
  const findings = nvramFindings(stores);
  const truncated = read.size > read.bytes.length ? ` (first ${read.bytes.length} of ${read.size} bytes only)` : '';

  if (stores.length === 0) {
    // An absence must say what it does and does not cover: no store found is not "this device has no nvram".
    const why =
      'This means no run of NUL-terminated name=value records ended with an empty record or carried a verifying ' +
      'CRC32 header — not that the device has no nvram: a vendor store behind an unknown header, or one held in a ' +
      'file rather than a partition, would read the same way.';
    return {
      available: true,
      stores,
      findings,
      bytesScanned: read.bytes.length,
      reason: `No nvram key-value store found in ${read.bytes.length} byte(s)${truncated}. ${why}`,
    };
  }

  const capped = stores.filter((s) => s.capped);
  const inventory = stores
    .map((s) => {
      const how = s.crc ? `CRC32 verified over ${s.crc.regionSize} bytes` : 'headerless (structural match)';
      return `0x${s.offset.toString(16)} — ${s.recordCount} record(s), ${how}`;
    })
    .join('; ');
  const bounds = capped.length
    ? ` ${capped.length} store(s) hit a parse bound: ${capped.map((s) => s.capped).join('; ')}.`
    : '';
  return {
    available: true,
    stores,
    findings,
    bytesScanned: read.bytes.length,
    reason: `${stores.length} nvram store(s)${truncated}: ${inventory}. ${findings.length} finding(s); all values redacted.${bounds}`,
  };
}
