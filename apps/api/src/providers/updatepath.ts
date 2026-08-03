/**
 * Update-mechanism integrity (OWASP ISTG-FW, FSTM stage 7) — the question docs/METHODOLOGY-GAPS.md §4 ranks #4 of
 * seven and nobody had asked: does this firmware's update path authenticate what it flashes, and can it be rolled
 * back? All three sub-questions are answerable from bytes alone, which is why this provider is pure static analysis
 * with no new tool dependency.
 *
 * It is composed out of what already exists rather than beside it: `parseDynamicSymbols` (binvuln) reads what an
 * updater ELF really imports, `extractPems` (certs) recognises PEM material, `parseOtaHeader` (encrypted) reads a
 * framed vendor OTA header, and the anti-rollback vocabulary is `esp.ts`'s `'on' | 'off' | 'unknown'` so two
 * providers do not name the same property differently.
 *
 * ## What this provider refuses to claim
 *
 * This is the detector on that list most likely to MANUFACTURE A FALSE NEGATIVE, and a wrong "unsigned firmware"
 * line discredits the whole ledger, so the refusals are the design:
 *
 *  - **"No verification symbols found" is never "the firmware is unsigned."** Verification routinely lives in the
 *    bootloader (not in this image), in SoC mask ROM, in a statically-linked blob with no symbol table, behind a
 *    vendor-named wrapper, or in a server-side check the device never performs locally. The honest finding is
 *    scoped to what was read — *"the updaters we found import/invoke no signature-verification routine"* — it is
 *    `needs_runtime_reproduction` at most, and it names every place that was not looked at (`unexamined`).
 *  - **"We could not find an updater" is `blocked_by_platform`,** not a clean result, and it states the exact
 *    patterns that were searched. Corpus images with a partial or absent rootfs make this branch real, not theory.
 *  - **A signature block present proves the bytes are there, not that anything checks them.** `static_confirmed`
 *    covers "this image carries a PKCS#7 block"; "this device verifies its updates" is a rung above this provider.
 *  - **The strongest positive available is the conjunction** — a signature/verifiable-integrity structure in the
 *    image AND a verify routine in the update path AND key material on the device — and it is stated as a
 *    conjunction with each part attributed to the bytes it came from (`update-verify-chain`).
 *  - **A `source` edge is not a call.** A script is credited with what the files it sources verify, because the
 *    OpenWrt entry point `sbin/sysupgrade` verifies nothing itself and reaches `ucert -V` through
 *    `lib/upgrade/fwtool.sh` — read one file at a time, the false negative comes from the unit of analysis rather
 *    than from the bytes. But the credit is STATIC and stays static: it never raises a proof state, and every
 *    credited item is stored with the file its line physically lives in, so no reader is ever told `sysupgrade`
 *    contains a line it does not contain. See the section header above `parseSourceDirectives`.
 *
 * Everything that decides is pure and unit-tested; the runner only walks the rootfs, reads bounded prefixes and
 * composes. Absence of an extractor or of a rootfs degrades honestly and says which question went unanswered.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';
import { type SymbolSource, extractSymbols, parseDynamicSymbols } from './binvuln.js';
import { parseOtaHeader } from './encrypted.js';
import { extractPems } from './pem-scan.js';

// ===========================================================================================================
// Part 1 — what integrity metadata does the IMAGE itself carry?
// ===========================================================================================================

/** One integrity structure read out of the image bytes, with where it was found and what it can be trusted for. */
export interface IntegrityItem {
  /** `signature` authenticates an origin; `checksum` only detects accidental corruption. The distinction is the point. */
  strength: 'signature' | 'checksum';
  kind: string;
  detail: string;
  /** Byte offset in the image, when the structure has one. */
  offset?: number;
}

export interface ImageIntegrity {
  /** The outer container recognised, or `unknown` when the image opens with a vendor header we do not decode. */
  container: 'fit' | 'uimage' | 'tplink' | 'ota-framed' | 'unknown';
  containerNote: string;
  items: IntegrityItem[];
  /** Sibling files beside the uploaded image that look like detached signatures/digests. */
  siblings: string[];
}

// --- Flattened device tree / FIT ---------------------------------------------------------------------------

export interface FdtHeader {
  totalSize: number;
  offDtStruct: number;
  offDtStrings: number;
  sizeDtStrings: number;
  version: number;
}

/** Read a big-endian u32, tolerating a short buffer. */
function u32be(b: Uint8Array, o: number): number {
  return (((b[o] ?? 0) << 24) | ((b[o + 1] ?? 0) << 16) | ((b[o + 2] ?? 0) << 8) | (b[o + 3] ?? 0)) >>> 0;
}

const FDT_MAGIC = 0xd00dfeed;

/**
 * Pure: parse a flattened-device-tree header (a U-Boot FIT image is an FDT). Returns null when the magic is absent
 * or the declared offsets do not fit inside the declared total size — a coincidental magic must not be read as a
 * container.
 */
export function parseFdtHeader(buf: Uint8Array): FdtHeader | null {
  if (buf.length < 40) return null;
  if (u32be(buf, 0) !== FDT_MAGIC) return null;
  const totalSize = u32be(buf, 4);
  const offDtStruct = u32be(buf, 8);
  const offDtStrings = u32be(buf, 12);
  const version = u32be(buf, 20);
  const sizeDtStrings = u32be(buf, 32);
  if (!totalSize || offDtStrings === 0 || offDtStrings + sizeDtStrings > totalSize) return null;
  if (offDtStruct === 0 || offDtStruct >= totalSize) return null;
  return { totalSize, offDtStruct, offDtStrings, sizeDtStrings, version };
}

/**
 * Pure: read a FIT's integrity posture out of its property-NAME string block.
 *
 * Every property name used anywhere in an FDT appears exactly once in `dt_strings`, so the presence or absence of
 * `signature`, `key-name-hint` and `hashed-nodes` there settles whether the container declares signed
 * configurations — without walking the multi-megabyte structure block. `algo` + `value` with no `signature` is the
 * hash-only shape.
 */
export function classifyFitStrings(strings: string): { signed: boolean; hashed: boolean; props: string[] } {
  // The block is NUL-separated. The separator is written as an escape and never as the byte: a literal NUL in a
  // source file passes tsc, biome and vitest, and makes grep skip the whole file without saying so.
  const props = strings.split('\u0000').filter((s) => s.length > 0);
  const has = (p: string): boolean => props.includes(p);
  return {
    signed: has('signature') || has('key-name-hint') || has('hashed-nodes') || has('sign-images'),
    hashed: has('algo') && has('value'),
    props,
  };
}

// --- Legacy uImage -----------------------------------------------------------------------------------------

export interface UImageHeader {
  headerCrc: number;
  dataCrc: number;
  dataSize: number;
  name: string;
}

const UIMAGE_MAGIC = 0x27051956;

/** Pure: parse a legacy U-Boot uImage header (64 bytes, big-endian). Null when the magic is absent. */
export function parseUImageHeader(buf: Uint8Array): UImageHeader | null {
  if (buf.length < 64) return null;
  if (u32be(buf, 0) !== UIMAGE_MAGIC) return null;
  let name = '';
  for (let i = 32; i < 64; i++) {
    const c = buf[i] ?? 0;
    if (c === 0) break;
    if (c < 0x20 || c > 0x7e) break;
    name += String.fromCharCode(c);
  }
  return { headerCrc: u32be(buf, 4), dataCrc: u32be(buf, 24), dataSize: u32be(buf, 12), name };
}

// --- TP-Link vendor header ---------------------------------------------------------------------------------

export interface TpLinkHeader {
  vendor: string;
  hardwareId: number;
  /** Total firmware length the header declares — validated against the file size before the header is believed. */
  firmwareLength: number;
  /** The stored 16-byte integrity field at 0x4c, hex. */
  checksumHex: string;
}

const TPLINK_HEADER_SIZE = 0x200;
const TPLINK_MD5_OFFSET = 0x4c;

/**
 * The two 16-byte constants OpenWrt's `mktplinkfw` substitutes into the checksum field before hashing. They are
 * published in the tool's source, which is exactly what makes the resulting field a checksum rather than a MAC:
 * the "key" is public, so anyone can recompute it for a modified image.
 *
 * These are here to be VERIFIED against the bytes in hand, never asserted from recall — `verifyTpLinkChecksum`
 * recomputes and only a byte-for-byte match is ever reported (the same discipline `component-cve.ts` applies to a
 * CVE range).
 */
export const TPLINK_MD5_SALTS: ReadonlyArray<{ name: string; bytes: Uint8Array }> = [
  {
    name: 'mktplinkfw md5salt_normal',
    bytes: Uint8Array.from([
      0xdc, 0xd7, 0x3a, 0xa5, 0xc3, 0x95, 0x98, 0xfb, 0xdd, 0xf9, 0xe7, 0xf9, 0x1f, 0xd9, 0x35, 0xa4,
    ]),
  },
  {
    name: 'mktplinkfw md5salt_boot',
    bytes: Uint8Array.from([
      0x8c, 0xef, 0x33, 0x5b, 0xd5, 0xc5, 0xce, 0xfa, 0xa7, 0x9c, 0x28, 0xda, 0xb2, 0xe9, 0x0f, 0x42,
    ]),
  },
];

/**
 * Pure: recognise a TP-Link vendor firmware header, STRUCTURALLY rather than by the vendor string alone. The
 * declared `fw_length` must equal the file size and the kernel data must start immediately after the 0x200-byte
 * header; a stray "TP-LINK" string somewhere in a blob satisfies neither, so it is not mistaken for a container.
 */
export function parseTpLinkHeader(buf: Uint8Array, fileSize: number): TpLinkHeader | null {
  if (buf.length < TPLINK_HEADER_SIZE) return null;
  let vendor = '';
  for (let i = 4; i < 28; i++) {
    const c = buf[i] ?? 0;
    if (c === 0) break;
    if (c < 0x20 || c > 0x7e) return null;
    vendor += String.fromCharCode(c);
  }
  if (!/^TP-LINK/i.test(vendor)) return null;
  const firmwareLength = u32be(buf, 0x7c);
  const kernelOffset = u32be(buf, 0x80);
  if (firmwareLength !== fileSize) return null;
  if (kernelOffset !== TPLINK_HEADER_SIZE) return null;
  return {
    vendor,
    hardwareId: u32be(buf, 0x40),
    firmwareLength,
    checksumHex: Buffer.from(buf.subarray(TPLINK_MD5_OFFSET, TPLINK_MD5_OFFSET + 16)).toString('hex'),
  };
}

/**
 * Recompute the TP-Link header checksum with each published salt and report which one (if any) reproduces the
 * stored bytes. A match is the whole claim: the image's integrity field is an MD5 whose key is public, so it
 * detects corruption and authenticates nothing. No match ⇒ null, and the field is reported as an undecoded
 * 16-byte value rather than as a forgeable checksum we could not actually forge.
 */
export function verifyTpLinkChecksum(image: Uint8Array, header: TpLinkHeader): string | null {
  if (image.length < header.firmwareLength) return null;
  const stored = Buffer.from(header.checksumHex, 'hex');
  for (const salt of TPLINK_MD5_SALTS) {
    const probe = Buffer.from(image.subarray(0, header.firmwareLength));
    probe.set(salt.bytes, TPLINK_MD5_OFFSET);
    if (crypto.createHash('md5').update(probe).digest().equals(stored)) return salt.name;
  }
  return null;
}

// --- Generic signature structures --------------------------------------------------------------------------

/** DER for `OBJECT IDENTIFIER 1.2.840.113549.1.7.2` (PKCS#7 / CMS signedData) — the tag, the length, the OID. */
const PKCS7_SIGNED_DATA_OID = Uint8Array.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);

/** Pure: every offset in `buf` at which a PKCS#7/CMS signedData OID appears, biased by `base`. */
export function findPkcs7SignedData(buf: Uint8Array, base = 0): number[] {
  const out: number[] = [];
  const n = PKCS7_SIGNED_DATA_OID.length;
  outer: for (let i = 0; i + n <= buf.length; i++) {
    for (let k = 0; k < n; k++) {
      if (buf[i + k] !== PKCS7_SIGNED_DATA_OID[k]) continue outer;
    }
    out.push(base + i);
    i += n - 1;
  }
  return out;
}

/** Armored signature envelopes that carry their own labels, so a text scan settles them without heuristics. */
const ARMORED_SIGNATURES: ReadonlyArray<{ marker: string; kind: string }> = [
  { marker: '-----BEGIN PGP SIGNATURE-----', kind: 'OpenPGP detached signature' },
  { marker: '-----BEGIN SIGNATURE-----', kind: 'PEM-armored signature block' },
  { marker: '-----BEGIN PKCS7-----', kind: 'PEM-armored PKCS#7 block' },
];

/**
 * A usign/signify block. Both a PUBLIC KEY and a SIGNATURE open with `untrusted comment:`, and the comment line is
 * what tells them apart — `signed by key <id>` versus `public key <id>`. Conflating them is not academic: the
 * GL.iNet BE3600 image carries BOTH, an appended signature 167 bytes from the end of the file and a shipped public
 * key inside the squashfs, and reading the embedded key as a signature over the image would have manufactured the
 * central claim of this provider out of a file that happens to be in the payload.
 */
const USIGN_MARKER = 'untrusted comment:';
const USIGN_SIGNED_BY = /untrusted comment:\s*signed by key\s+(\S+)/;

/** Pure: armored signature envelopes present in a text view of the bytes, with the offset of each first match. */
export function findArmoredSignatures(text: string, base = 0): IntegrityItem[] {
  const out: IntegrityItem[] = [];
  for (const { marker, kind } of ARMORED_SIGNATURES) {
    const at = text.indexOf(marker);
    if (at < 0) continue;
    out.push({ strength: 'signature', kind, detail: `armored block beginning "${marker}"`, offset: base + at });
  }
  // Scan every usign block, not just the first: an image can carry a shipped public key and an appended signature.
  for (let at = text.indexOf(USIGN_MARKER); at >= 0; at = text.indexOf(USIGN_MARKER, at + 1)) {
    // ONLY this block's comment line. A fixed-width window bled past a `public key` block into a later
    // `signed by key` one and reported the key as a signature — the exact conflation this branch exists to stop.
    const lineEnd = text.indexOf('\n', at);
    const line = text.slice(at, lineEnd < 0 ? Math.min(text.length, at + 200) : lineEnd);
    const m = USIGN_SIGNED_BY.exec(line);
    if (!m) continue; // a `public key` block is trust material, not a signature over these bytes
    out.push({
      strength: 'signature',
      kind: 'usign/signify Ed25519 signature (OpenWrt)',
      detail: `armored block labelled "signed by key ${m[1]}"`,
      offset: base + at,
    });
  }
  return out;
}

/** A sibling file beside the uploaded image that carries a detached signature or digest for it. */
const SIBLING_RE = /\.(sig|sign|asc|gpg|pem|cer|crt|p7s|ucert|sha1|sha256|sha512|md5|hash|cms)$/i;

/** Pure: which of `names` look like detached integrity material for `imageName`. */
export function classifySiblings(imageName: string, names: string[]): string[] {
  const stem = imageName.replace(/\.[^.]*$/, '');
  return names
    .filter((n) => n !== imageName)
    .filter((n) => SIBLING_RE.test(n) && (n.startsWith(imageName) || n.startsWith(stem)))
    .sort();
}

// ===========================================================================================================
// Part 2 — does the UPDATER verify anything?
// ===========================================================================================================

/**
 * Symbols whose presence in a binary's import list means an ASYMMETRIC SIGNATURE CHECK is linked in. Matched as
 * EXACT names, never as substrings: TP-Link's httpd imports `RSA_modpow`, `RSA_bignum_from_bytes` and
 * `wc_FreeRsaKey` for its SSH/TLS stacks, and a prefix match on `RSA_` would have reported that binary as
 * verifying update signatures. It does not — it has no verify entry point at all.
 */
export const SIGNATURE_VERIFY_SYMBOLS: ReadonlyArray<string> = [
  // OpenSSL / LibreSSL
  'EVP_DigestVerify',
  'EVP_DigestVerifyInit',
  'EVP_DigestVerifyUpdate',
  'EVP_DigestVerifyFinal',
  'EVP_VerifyFinal',
  'EVP_PKEY_verify',
  'EVP_PKEY_verify_init',
  'RSA_verify',
  'RSA_verify_PKCS1_PSS',
  'RSA_verify_PKCS1_PSS_mgf1',
  'DSA_verify',
  'ECDSA_verify',
  'ECDSA_do_verify',
  'X509_verify',
  'PKCS7_verify',
  'CMS_verify',
  // mbedTLS
  'mbedtls_pk_verify',
  'mbedtls_pk_verify_ext',
  'mbedtls_rsa_pkcs1_verify',
  'mbedtls_rsa_rsassa_pss_verify',
  'mbedtls_ecdsa_verify',
  'mbedtls_ecdsa_read_signature',
  // wolfSSL
  'wc_SignatureVerify',
  'wc_RsaSSL_Verify',
  'wc_RsaPSS_Verify',
  'wc_ecc_verify_hash',
  'wc_ed25519_verify_msg',
  // libsodium / NaCl
  'crypto_sign_open',
  'crypto_sign_verify_detached',
  // libubox (OpenWrt usign/ucert) and TweetNaCl-style Ed25519
  'edsign_verify',
  'edsign_verify_init',
  'ed25519_verify',
  // libgcrypt / nettle / BearSSL
  'gcry_pk_verify',
  'nettle_rsa_pkcs1_verify',
  'nettle_ecdsa_verify',
  'br_rsa_pkcs1_vrfy',
  'br_ecdsa_vrfy_asn1',
];

/**
 * Digest routines. Their presence proves an INTEGRITY check at most — a checksum detects a corrupted download and
 * stops nobody who can recompute it. Kept separate from the list above so a finding can never say "verifies"
 * about a binary that only hashes.
 */
export const DIGEST_SYMBOLS: ReadonlyArray<string> = [
  'MD5_Init',
  'MD5_Update',
  'MD5_Final',
  'md5_verify_digest',
  'SHA1_Init',
  'SHA1_Update',
  'SHA256_Init',
  'SHA256_Update',
  'SHA512_Init',
  'sha512_init',
  'sha512_final',
  'EVP_DigestInit',
  'EVP_DigestInit_ex',
  'EVP_DigestUpdate',
  'EVP_DigestFinal_ex',
  'mbedtls_md5',
  'mbedtls_sha1',
  'mbedtls_sha256',
  'mbedtls_sha512',
  'wc_Md5Update',
  'wc_ShaUpdate',
  'wc_Sha256Update',
  'crc32',
  'crc32_le',
];

/**
 * Commands a SHELL updater invokes to verify something. Firmware updaters are as often `/bin/sh` as ELF — the
 * whole OpenWrt sysupgrade path is shell — so a symbol-only detector would report the most modern image in the
 * corpus as importing no verification at all. Each entry carries the executable it needs, so the runner can check
 * whether that executable is actually IN the rootfs.
 */
export const VERIFY_COMMANDS: ReadonlyArray<{
  re: RegExp;
  strength: 'signature' | 'checksum';
  binary: string;
  label: string;
}> = [
  { re: /\bucert\s+-[A-Za-z]*V/, strength: 'signature', binary: 'ucert', label: 'ucert -V (OpenWrt Ed25519 cert)' },
  { re: /\busign\s+-[A-Za-z]*V/, strength: 'signature', binary: 'usign', label: 'usign -V (OpenWrt Ed25519)' },
  { re: /\bsignify\s+-[A-Za-z]*V/, strength: 'signature', binary: 'signify', label: 'signify -V' },
  { re: /\bgpgv\b/, strength: 'signature', binary: 'gpgv', label: 'gpgv' },
  { re: /\bgpg\s+[^\n|;&]*--verify/, strength: 'signature', binary: 'gpg', label: 'gpg --verify' },
  {
    re: /\bopenssl\s+(?:dgst|rsautl|pkeyutl|smime|cms|ts)\b[^\n|;&]*-verify/,
    strength: 'signature',
    binary: 'openssl',
    label: 'openssl … -verify',
  },
  { re: /\bsha256sum\s+-[A-Za-z]*c/, strength: 'checksum', binary: 'sha256sum', label: 'sha256sum -c' },
  { re: /\bsha1sum\s+-[A-Za-z]*c/, strength: 'checksum', binary: 'sha1sum', label: 'sha1sum -c' },
  { re: /\bmd5sum\s+-[A-Za-z]*c/, strength: 'checksum', binary: 'md5sum', label: 'md5sum -c' },
  { re: /\bcksum\b/, strength: 'checksum', binary: 'cksum', label: 'cksum' },
];

/**
 * Writes that actually commit an image to flash — what makes a file the update path rather than a mention of it.
 *
 * Only WRITE PRIMITIVES belong here. `sysupgrade` and `fw_setenv` were in this list and had to come out: the word
 * `sysupgrade` appears in comments, variable names and log lines throughout an OpenWrt rootfs, so it labelled
 * `lib/upgrade/common.sh` — which flashes nothing — as committing an image to flash, and `fw_setenv` writes the
 * boot environment, not firmware. The `of=` target is deliberately loose about what follows `/dev/`, because the
 * Tenda camera's real script writes to `of=/dev/$upgradeblock` and a device-name whitelist missed it entirely.
 */
export const FLASH_WRITE_PATTERNS: ReadonlyArray<{ re: RegExp; label: string }> = [
  { re: /\bdd\s+[^\n]*\bof=(?:"|')?\/dev\/\S+/, label: 'dd of=/dev/…' },
  { re: /\bmtd\s+(?:-[A-Za-z]+\s+)*write\b/, label: 'mtd write' },
  { re: /\bflashcp\b/, label: 'flashcp' },
  { re: /\bflash_erase(?:all)?\b/, label: 'flash_erase' },
  { re: /\bnandwrite\b/, label: 'nandwrite' },
  { re: /\bubiupdatevol\b/, label: 'ubiupdatevol' },
  { re: /\bubiformat\b/, label: 'ubiformat' },
];

/** Version/rollback vocabulary, kept deliberately narrow so a changelog string cannot pass for a version check. */
export const ROLLBACK_PATTERNS: ReadonlyArray<{ re: RegExp; label: string }> = [
  { re: /\banti[_-]?rollback\b/i, label: 'anti-rollback' },
  { re: /\brollback[_-]?(?:protect|counter|index|version)\b/i, label: 'rollback counter' },
  { re: /\bsecure[_-]?version\b/i, label: 'secure_version' },
  { re: /\bmin(?:imum)?[_-]?(?:fw[_-]?)?version\b/i, label: 'minimum version floor' },
  { re: /\bcompat[_-]?version\b/i, label: 'compat_version' },
  { re: /\bdowngrade\b/i, label: 'downgrade' },
  { re: /\bversion[_-]?(?:cmp|compare|check)\b/i, label: 'version comparison' },
];

/** How a candidate came to our attention — it decides how much the finding is entitled to imply. */
export type Discovery = 'path' | 'symbol';

export interface UpdaterCandidate {
  path: string;
  kind: 'elf' | 'script';
  discoveredBy: Discovery;
  /** Why this file is believed to be part of the update path — quoted in the finding, never left implicit. */
  why: string;
  /** For an ELF: whether the names came from the real dynamic symbol table or from the weaker string superset. */
  symbolSource?: SymbolSource;
  signatureFns: string[];
  digestFns: string[];
  /** For a script: verification commands it invokes. Its OWN lines only — sourced ones live in `sourced`. */
  verifyCommands: string[];
  /** Verification executables the script invokes that are NOT present in the rootfs. */
  missingVerifiers: string[];
  flashWrites: string[];
  rollbackMarkers: string[];
  /**
   * Evidence credited to this candidate from files it `source`s, each labelled with the file the line physically
   * lives in. Deliberately NOT merged into the fields above: `sbin/sysupgrade` invokes no verifier, it reaches
   * one, and a reader must be able to tell those apart. Optional forever — a result stored before this pass
   * existed has no such field, and `[]` there would claim a search that never ran.
   */
  sourced?: SourcedEvidence[];
  /** `source` directives that could not be resolved statically, with why. An honest unknown, not a silent drop. */
  unresolvedSources?: UnresolvedSource[];
  /** Where following `source` edges stopped short — depth, cycle or file bound. A bound is not an answer. */
  sourceBounds?: string[];
  /**
   * True when this pass followed `source` edges for this candidate, whatever it found. It exists so that an empty
   * `sourced` is readable: WITHOUT it, a candidate that sources nothing and a result written before the pass
   * existed are the same absence, and a reader is left unable to tell "there is no chain" from "nobody looked" —
   * which is the distinction this whole provider is built around. Optional forever: absent means an older build.
   */
  sourcesFollowed?: boolean;
}

/** Paths whose `update`/`upgrade` is about something other than firmware — the glob's own false positives. */
const NOT_FIRMWARE_UPDATE =
  /(?:ddns|ip[_-]?update|ipupdate|updated?[_-]?dns|dyn(?:amic)?[_-]?dns|tzoupdate|ez-ipupdate|apn[_-]?db|dpi|clients|plugins|vpn[_-]?domain|qdiscs|modem|affinity|smp|cable[_-]?mac|odhcpd|wgserver|wps|dpp|hostapd|supplicant|route)/i;

/** Files that are documentation, translations or package bookkeeping, never code that runs during an update. */
const NON_EXECUTABLE_SUFFIX = /\.(?:json|html?|htm|css|js|gz|png|svg|md|txt|po|mo|control|list|prerm|postinst|conf)$/i;

/** UCI config lives in `etc/config/` and is data with no extension — `etc/config/upgrade` is settings, not code. */
const CONFIG_DIR = /(?:^|\/)etc\/config\//;

/** Names that are the update path itself wherever they appear. */
const STRONG_NAME =
  /^(?:sysupgrade|upgraded?|fwupdate|fw_update|firmware_?upgrade|firmware_?update|otad?|ota_?upgrade|ota_?update|force_upgrade|update_?firmware|upgrade_?firmware|doupgrade|do_upgrade)$/i;

/** Directories whose contents are, by construction, the update helper library. */
const STRONG_DIR = /(?:^|\/)(?:lib\/upgrade|etc\/upgrade|usr\/lib\/upgrade|sd_otaupgrade|ota)\//i;

/**
 * A generic `*update*` / `*upgrade*` mention — a candidate, but a weak one, and labelled as such.
 *
 * `ota` needs its word boundaries. Without them the pattern matched `quota`, and the sweep opened
 * `lib/modules/5.4.213/nft_quota.ko`, `xt_quota.ko` and DVRF's `usr/lib/iptables/libxt_quota.so` as firmware
 * updaters — on DVRF the iptables plugin became "the 1 updater located", which would have printed a
 * no-verification finding about a netfilter match extension.
 */
const WEAK_NAME = /(?:update|upgrade|\bota\b)/i;

export interface PathClassification {
  tier: 'strong' | 'weak' | 'excluded';
  /**
   * What the tier rests on. A `name` match identifies the file itself as an update entry point; a `directory`
   * match only says it sits in the update helper tree, which on the GL.iNet is 30 one-line `lib/upgrade/keep.d/*`
   * package manifests that are data, not code. Directory-basis candidates therefore have to show verification or
   * flash evidence in their content before they count.
   */
  basis: 'name' | 'directory' | 'none';
  why: string;
}

/**
 * Pure: is this rootfs-relative path plausibly part of the update path, and on what evidence?
 *
 * Name matching alone is both over- and under-inclusive, so the answer is TIERED and the reason travels with it.
 * The exclusions are not cosmetic: a bare `*update*` glob over the DVRF rootfs returns `ez-ipupdate`, `ipupdated`
 * and `tzoupdate-1.11` — three dynamic-DNS clients — and reporting "the updater imports no verify routine" about a
 * DDNS client would be a fabricated finding about a program that has nothing to do with firmware.
 */
export function classifyUpdaterPath(rel: string): PathClassification {
  const base = rel.split('/').pop() ?? rel;
  const stem = base.replace(/\.(?:sh|lua|py|pl)$/i, '');
  if (NON_EXECUTABLE_SUFFIX.test(base)) {
    return {
      tier: 'excluded',
      basis: 'none',
      why: 'documentation / translation / package bookkeeping, not code run during an update',
    };
  }
  if (CONFIG_DIR.test(`/${rel}`)) {
    return { tier: 'excluded', basis: 'none', why: 'UCI configuration data, not code run during an update' };
  }
  if (STRONG_NAME.test(stem)) {
    return { tier: 'strong', basis: 'name', why: `file name "${base}" is a firmware-update entry point` };
  }
  if (STRONG_DIR.test(`/${rel}`)) {
    return { tier: 'strong', basis: 'directory', why: `lives in the update helper directory of "${rel}"` };
  }
  if (NOT_FIRMWARE_UPDATE.test(rel)) {
    return {
      tier: 'excluded',
      basis: 'none',
      why: `"${base}" updates something other than firmware (DNS/config/database/radio)`,
    };
  }
  if (WEAK_NAME.test(base)) return { tier: 'weak', basis: 'name', why: `file name "${base}" mentions update/upgrade` };
  return { tier: 'excluded', basis: 'none', why: 'no update-path evidence in the name' };
}

/**
 * Pure: a symbol name that means this binary handles firmware updates even though nothing in its PATH said so.
 * TP-Link's update logic lives inside `usr/bin/httpd`, which no name-based hunt reaches; it exports
 * `upgradeFirmware`, `checkAndUpgradeFirmware` and `isSysUpgradeNeedChecksum`. Requiring BOTH an update verb and a
 * firmware/image noun in the same identifier keeps `update_dns_list` and `apn_db_update` out.
 */
export function isUpdaterSymbol(name: string): boolean {
  if (/sysupgrade/i.test(name)) return true;
  const verb = /(?:upgrade|update|flash|burn|write)/i.test(name);
  const noun = /(?:firmware|fwimage|fw_image|rootfs|kernel|image|bootloader)/i.test(name);
  return verb && noun;
}

/** Pure: split a symbol set into the signature-verify and digest names it actually contains (exact matches only). */
export function assessSymbols(symbols: ReadonlySet<string>): { signatureFns: string[]; digestFns: string[] } {
  return {
    signatureFns: SIGNATURE_VERIFY_SYMBOLS.filter((s) => symbols.has(s)),
    digestFns: DIGEST_SYMBOLS.filter((s) => symbols.has(s)),
  };
}

export interface ScriptAssessment {
  verifyCommands: string[];
  /** Executables the verification commands need — the runner checks each against the rootfs. */
  verifierBinaries: string[];
  signatureCommands: string[];
  flashWrites: string[];
  rollbackMarkers: string[];
}

/**
 * Pure: read a shell/lua updater as text. Comment lines are stripped first — the Tenda camera's `force_upgrade`
 * has its entire MD5 check inside a `: <<'COMMENT'` heredoc, and counting a disabled check as a check is precisely
 * the false reassurance this provider exists to avoid.
 */
export function assessScript(text: string): ScriptAssessment {
  const live = stripInertText(text);
  const verifyCommands: string[] = [];
  const verifierBinaries: string[] = [];
  const signatureCommands: string[] = [];
  for (const c of VERIFY_COMMANDS) {
    if (!c.re.test(live)) continue;
    verifyCommands.push(c.label);
    verifierBinaries.push(c.binary);
    if (c.strength === 'signature') signatureCommands.push(c.label);
  }
  const flashWrites = FLASH_WRITE_PATTERNS.filter((p) => p.re.test(live)).map((p) => p.label);
  const rollbackMarkers = ROLLBACK_PATTERNS.filter((p) => p.re.test(live)).map((p) => p.label);
  return { verifyCommands, verifierBinaries, signatureCommands, flashWrites, rollbackMarkers };
}

// === Reaching past the file that was read: shell `source` / `.` / `include` resolution ======================

/**
 * Why this exists. `sbin/sysupgrade` is the OpenWrt update entry point and it verifies nothing in its own text:
 * it opens with `. /lib/functions.sh` and `include /lib/upgrade`, and the `ucert -V` that authenticates the image
 * lives in `lib/upgrade/fwtool.sh`. Analysed a file at a time, the two surface as unrelated candidates and the
 * entry point is reported as invoking no verification at all — a false negative manufactured by the unit of
 * analysis, which is exactly the class of mistake this provider exists to refuse.
 *
 * ## What a resolved source edge proves, and what it does not
 *
 * It proves ONE static fact: this file names that file at a command position where a POSIX shell would read it.
 * It does NOT prove the sourced verification is reached at runtime. Sourcing a file defines its functions; it does
 * not call them. The call may sit behind a branch, behind a flag nobody sets (see `findEnforcementFlags`, whose
 * worked example is this very `fwtool.sh`), or — the GL.iNet case — inside a function that returns 0 without
 * verifying anything. So crediting NEVER raises a proof state and never converts an absence into a positive. All
 * it does is stop the provider from reporting "nothing here verifies" about a file whose whole job is to delegate.
 *
 * Two consequences run through the types below. Credited evidence is kept in its own `sourced` field with the
 * file and the chain that reached it attached, never merged into the candidate's own `verifyCommands`. And a
 * directive that cannot be followed — an interpolated path, a path leaving the rootfs, a depth or cycle bound —
 * is recorded with its reason and travels into the negative findings, because an absence measured across a
 * partially-followed graph is weaker than one measured across a fully-followed one and the reader cannot tell
 * which without being told.
 *
 * ## What it refuses to resolve
 *
 * A path built out of a variable (`. "$LIB_DIR/foo.sh"`) is not knowable from the bytes; guessing one would be
 * the fabrication this file is otherwise careful about, and dropping it silently would hide that the graph is
 * incomplete, so it becomes an `unresolvedSources` entry naming the spec and the reason. A path that leaves the
 * extracted rootfs is refused the same way — `resolveInsideRootfs` in decompile.ts is the containment pattern,
 * and here it is done on the STRING so the answer is pure and the test can reach it.
 */

/** The three ways the corpus's shell updaters pull in another file. */
export type SourceDirective = '.' | 'source' | 'include';

/** One `source`/`.`/`include` word as it was written, before anything tries to turn it into a path. */
export interface SourceMention {
  directive: SourceDirective;
  /** The operand, surrounding quotes stripped. Kept verbatim otherwise, so a reason can quote it back. */
  spec: string;
}

/**
 * A directive only counts at COMMAND POSITION — line start, or after `;`, `&`, `|`, `(`, or one of the shell
 * keywords that open a command list. Without that anchor, `source` matched inside `datasource=` and a bare `.`
 * matched inside ordinary prose, and the resolver then spent its budget on paths that were never directives.
 */
const SOURCE_DIRECTIVE_RE =
  /(?:^|[;&|(]|\b(?:then|else|elif|do)[ \t])[ \t]*(\.|source|include)[ \t]+("[^"\n]*"|'[^'\n]*'|[^\s;&|()<>]+)/gm;

/** Bound on how many directives one file contributes, so a pathological script cannot swell the edge list. */
export const SOURCE_MENTION_CAP = 64;

/**
 * Pure: the `source`/`.`/`include` directives a script contains. Inert text is stripped first for the same reason
 * `assessScript` strips it — a directive inside a `#` comment or a commented-out heredoc does not execute, and
 * crediting a script with a file it only mentions in a comment is the mirror image of the bug this pass fixes.
 */
export function parseSourceDirectives(text: string): SourceMention[] {
  const live = stripInertText(text);
  const out: SourceMention[] = [];
  SOURCE_DIRECTIVE_RE.lastIndex = 0;
  for (let m = SOURCE_DIRECTIVE_RE.exec(live); m !== null; m = SOURCE_DIRECTIVE_RE.exec(live)) {
    const directive = m[1] as SourceDirective;
    const raw = m[2] ?? '';
    const quoted = (raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"));
    out.push({ directive, spec: quoted ? raw.slice(1, -1) : raw });
  }
  return out;
}

/**
 * Read-only view of the extracted rootfs, by ROOTFS-RELATIVE path. An interface rather than direct `fs` calls so
 * every decision below stays pure and unit-testable — the runner passes a walk-backed implementation, a test
 * passes a map. `read` returns null for anything that is not a readable regular file inside the rootfs, which is
 * the same answer a symlink pointing outside gets: the walk never records one, so it is simply not there.
 */
export interface ShellFileReader {
  read(rel: string): string | null;
  /** Regular-file names directly inside a rootfs-relative directory (`''` is the root), or null if there is none. */
  list(dir: string): string[] | null;
}

/** How a spec was turned into a path — recorded so a reader can check the assumption instead of trusting it. */
export type SourceBasis = 'absolute' | 'relative-to-script-directory' | 'directory-expansion' | 'none';

export interface ResolvedSpec {
  /** Rootfs-relative targets. Empty means unresolved, and then `reason` says why. */
  targets: string[];
  reason: string | null;
  basis: SourceBasis;
}

/** A `$`, `${`, backtick or `$(` anywhere in the operand: the path is composed at runtime and cannot be read here. */
const INTERPOLATION_RE = /[$`]/;

/**
 * Normalise `spec` to a rootfs-relative path, or null when it would leave the rootfs.
 *
 * A leading `/` is rootfs-absolute, because that is what it means to a process running on the device: `/etc/passwd`
 * is the image's own file, not the analysis host's. `..` that pops above the root is the escape this refuses —
 * the same containment `resolveInsideRootfs` performs with `path.resolve`, done on the string so it stays pure.
 */
export function normalizeInsideRootfs(baseDir: string, spec: string): string | null {
  const joined = spec.startsWith('/') ? spec.slice(1) : baseDir ? `${baseDir}/${spec}` : spec;
  const out: string[] = [];
  for (const part of joined.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (out.length === 0) return null;
      out.pop();
      continue;
    }
    out.push(part);
  }
  return out.length > 0 ? out.join('/') : null;
}

/** Translate a shell glob (only `*` and `?`, which is all a source line realistically carries) into a matcher. */
function globToRegExp(pattern: string): RegExp {
  let body = '';
  for (const ch of pattern) {
    if (ch === '*') body += '[^/]*';
    else if (ch === '?') body += '[^/]';
    else body += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${body}$`);
}

function dirnameOf(rel: string): string {
  const cut = rel.lastIndexOf('/');
  return cut < 0 ? '' : rel.slice(0, cut);
}

function expandGlob(parent: string, pattern: string, spec: string, reader: ShellFileReader): ResolvedSpec {
  const listed = reader.list(parent);
  if (!listed) {
    return {
      targets: [],
      reason: `no directory "${parent || '/'}" in the walked rootfs to expand "${spec}" against`,
      basis: 'none',
    };
  }
  const re = globToRegExp(pattern);
  const targets = listed
    .filter((n) => re.test(n))
    .sort()
    .map((n) => (parent ? `${parent}/${n}` : n));
  if (targets.length === 0) {
    return { targets: [], reason: `nothing in "${parent || '/'}" matches "${pattern}"`, basis: 'none' };
  }
  return { targets, reason: null, basis: 'directory-expansion' };
}

/**
 * Pure: turn one directive into the rootfs-relative file(s) it would read, or into a stated reason it could not
 * be followed. Every branch that returns no target returns a REASON with it; nothing is dropped silently.
 *
 * Three interpretations are assumptions rather than facts, and each is labelled in `basis` so the finding can
 * carry the assumption instead of hiding it: a relative spec is resolved against the referencing script's own
 * directory (a shell resolves it against the runtime CWD, which no static pass knows); a slash-less operand is
 * refused outright, because POSIX `.` looks such a name up on `$PATH`; and `include DIR` is read as OpenWrt's
 * `include()` helper, which sources every `*.sh` in the directory — that is precisely the edge by which
 * `sbin/sysupgrade` reaches `lib/upgrade/fwtool.sh`.
 */
export function resolveSourceSpec(fromRel: string, mention: SourceMention, reader: ShellFileReader): ResolvedSpec {
  const { spec, directive } = mention;
  if (spec.length === 0) return { targets: [], reason: 'the directive names no operand', basis: 'none' };
  if (INTERPOLATION_RE.test(spec)) {
    return {
      targets: [],
      reason: `"${spec}" is built from a variable or a command substitution, so the path exists only at runtime — recorded as unresolved rather than guessed`,
      basis: 'none',
    };
  }
  const absolute = spec.startsWith('/');
  if (!absolute && !spec.includes('/')) {
    return {
      targets: [],
      reason: `"${spec}" contains no slash, so a POSIX shell resolves it through $PATH — which is not knowable from these bytes`,
      basis: 'none',
    };
  }
  const rel = normalizeInsideRootfs(absolute ? '' : dirnameOf(fromRel), spec);
  if (rel === null) {
    return {
      targets: [],
      reason: `"${spec}" resolves outside the extracted rootfs, so it was refused rather than followed`,
      basis: 'none',
    };
  }
  const base = rel.slice(rel.lastIndexOf('/') + 1);
  const parent = dirnameOf(rel);
  if (/[*?]/.test(parent)) {
    return {
      targets: [],
      reason: `"${spec}" globs a directory component, which this pass does not expand`,
      basis: 'none',
    };
  }
  if (/[*?]/.test(base)) return expandGlob(parent, base, spec, reader);

  const basis: SourceBasis = absolute ? 'absolute' : 'relative-to-script-directory';
  if (directive === 'include') {
    const listed = reader.list(rel);
    if (listed) {
      const targets = listed
        .filter((n) => n.endsWith('.sh'))
        .sort()
        .map((n) => `${rel}/${n}`);
      if (targets.length === 0) {
        return {
          targets: [],
          reason: `include "${spec}" names a directory holding no *.sh file`,
          basis: 'directory-expansion',
        };
      }
      return { targets, reason: null, basis: 'directory-expansion' };
    }
  }
  if (reader.read(rel) === null) {
    return {
      targets: [],
      reason: `no readable regular file at "${rel}" in the walked rootfs (symlinks are not followed), so the directive names something this image does not ship where it says`,
      basis,
    };
  }
  return { targets: [rel], reason: null, basis };
}

/** One directive and what became of it, kept whether it resolved or not. */
export interface SourceEdge {
  /** The file the directive is written in — NOT necessarily the candidate the closure started from. */
  from: string;
  directive: SourceDirective;
  spec: string;
  targets: string[];
  reason: string | null;
  basis: SourceBasis;
}

/** A file reached through source edges, with the chain that reached it so the credit stays traceable. */
export interface ReachedScript {
  path: string;
  /** From the starting script to this file inclusive — what a finding prints so the reader can retrace it. */
  via: string[];
  depth: number;
}

export interface SourceClosure {
  root: string;
  reached: ReachedScript[];
  edges: SourceEdge[];
  /** The subset of `edges` that resolved to nothing — each carries its own reason. */
  unresolved: SourceEdge[];
  /** Every place the walk stopped short, in prose. Empty means the graph below `root` was followed whole. */
  bounds: string[];
  depthLimit: number;
}

/**
 * How many hops to follow. Two, not one: OpenWrt's entry point reaches `fwtool.sh` through `include /lib/upgrade`
 * at hop one, and the helper it lands on may pull in one more before the verification appears. Deeper than that
 * and a rootfs's shell library graph is being walked rather than its update path, which is a different question.
 */
export const SOURCE_DEPTH_LIMIT = 2;

/** How many distinct files one closure may read, whatever the depth allows. */
export const SOURCE_FILE_CAP = 32;

/**
 * Pure: follow `source` edges out of one script, bounded and cycle-safe.
 *
 * Shell libraries source each other in cycles as a matter of course (`functions.sh` pulls in a helper that pulls
 * `functions.sh` back), so an unbounded walk does not merely go slow — it does not terminate. Three bounds hold
 * it: a target already on the CURRENT chain is a cycle and is reported by name; a target already read on another
 * branch is a diamond, read once and not re-read; and depth and file caps stop the rest. Every one of the three
 * states what it did not follow in `bounds`, which the findings then carry, because a graph followed part-way is
 * a weaker basis for "nothing here verifies" than one followed whole.
 */
export function resolveSourceClosure(
  root: string,
  text: string,
  reader: ShellFileReader,
  opts: { depthLimit?: number; fileCap?: number } = {},
): SourceClosure {
  const depthLimit = opts.depthLimit ?? SOURCE_DEPTH_LIMIT;
  const fileCap = opts.fileCap ?? SOURCE_FILE_CAP;
  const edges: SourceEdge[] = [];
  const reached: ReachedScript[] = [];
  const bounds: string[] = [];
  const seen = new Set<string>([root]);

  const visit = (from: string, fromText: string, depth: number, chain: string[]): void => {
    const mentions = parseSourceDirectives(fromText);
    const followed = mentions.slice(0, SOURCE_MENTION_CAP);
    if (mentions.length > followed.length) {
      bounds.push(
        `${from} contains ${mentions.length} source directives; only the first ${SOURCE_MENTION_CAP} were followed`,
      );
    }
    for (const mention of followed) {
      const r = resolveSourceSpec(from, mention, reader);
      edges.push({ from, directive: mention.directive, spec: mention.spec, ...r });
      for (const target of r.targets) {
        if (chain.includes(target)) {
          bounds.push(`a source cycle was not followed: ${[...chain, target].join(' → ')}`);
          continue;
        }
        if (seen.has(target)) continue;
        if (reached.length >= fileCap) {
          bounds.push(
            `the ${fileCap}-file source-closure bound was reached, so ${target} (sourced by ${from}) was not read`,
          );
          continue;
        }
        const targetText = reader.read(target);
        if (targetText === null) continue;
        seen.add(target);
        reached.push({ path: target, via: [...chain, target], depth: depth + 1 });
        if (depth + 1 >= depthLimit) {
          // Only a bound that actually DROPPED something is worth stating. A leaf reached at the depth limit has
          // nothing below it, and announcing a truncation there would weaken every negative finding it touches
          // for no reason — the "guard reports on the branch where it found nothing wrong" failure, again.
          const further = parseSourceDirectives(targetText).length;
          if (further > 0) {
            bounds.push(
              `the ${depthLimit}-hop source-depth bound was reached, so the ${further} further source directive(s) in ${target} were not followed`,
            );
          }
          continue;
        }
        visit(target, targetText, depth + 1, [...chain, target]);
      }
    }
  };
  visit(root, text, 0, [root]);

  return { root, reached, edges, unresolved: edges.filter((e) => e.targets.length === 0), bounds, depthLimit };
}

/** Verification/flash evidence found in a file another script sources, with where it physically lives. */
export interface SourcedEvidence {
  /** The file the lines are IN. Every title and rationale that quotes them names this, never the candidate. */
  file: string;
  via: string[];
  verifyCommands: string[];
  signatureCommands: string[];
  missingVerifiers: string[];
  flashWrites: string[];
  rollbackMarkers: string[];
}

/** A directive that named something this pass could not turn into a file, and the reason it could not. */
export interface UnresolvedSource {
  from: string;
  directive: SourceDirective;
  spec: string;
  reason: string;
}

/**
 * Pure: credit a candidate with what the files it sources do.
 *
 * Returns the SAME object when there is nothing to add, so a script that sources nothing behaves exactly as it
 * did before this pass existed — including the identity of the value, which is the cheapest possible proof that
 * the old path is untouched.
 *
 * `verifierMissing` is injected rather than read from the filesystem here for the usual reason in this codebase:
 * the decision has to be reachable from a unit test, and anything that touches the rootfs is the runner's job.
 */
export function creditSourcedEvidence(
  candidate: UpdaterCandidate,
  closure: SourceClosure,
  readScript: (rel: string) => string | null,
  verifierMissing: (binary: string) => boolean,
): UpdaterCandidate {
  const sourced: SourcedEvidence[] = [];
  for (const r of closure.reached) {
    const text = readScript(r.path);
    if (text === null) continue;
    const a = assessScript(text);
    if (a.verifyCommands.length === 0 && a.flashWrites.length === 0 && a.rollbackMarkers.length === 0) continue;
    sourced.push({
      file: r.path,
      via: r.via,
      verifyCommands: a.verifyCommands,
      signatureCommands: a.signatureCommands,
      missingVerifiers: a.verifierBinaries.filter(verifierMissing),
      flashWrites: a.flashWrites,
      rollbackMarkers: a.rollbackMarkers,
    });
  }
  const unresolvedSources: UnresolvedSource[] = closure.unresolved.map((e) => ({
    from: e.from,
    directive: e.directive,
    spec: e.spec,
    reason: e.reason ?? 'unresolved',
  }));
  // `sourcesFollowed` is set on EVERY candidate this pass considered, including the ones that source nothing, and
  // that is the whole point of it. Omitting the fields when they are empty made "this build followed the edges and
  // there were none" indistinguishable from "an older build never followed edges at all" — the reader gets an
  // absence and cannot tell which, which is the conflation this provider exists to refuse. Measured on the real
  // Tenda camera: `usr/bin/force_upgrade` genuinely sources nothing, and the panel could only say it did not know.
  // The arrays stay omitted when empty (nothing is gained by shipping `[]`); the flag carries the fact.
  if (sourced.length === 0 && unresolvedSources.length === 0 && closure.bounds.length === 0) {
    return { ...candidate, sourcesFollowed: true };
  }
  return {
    ...candidate,
    sourcesFollowed: true,
    ...(sourced.length > 0 ? { sourced } : {}),
    ...(unresolvedSources.length > 0 ? { unresolvedSources } : {}),
    ...(closure.bounds.length > 0 ? { sourceBounds: [...closure.bounds] } : {}),
  };
}

/** One credited item and the file it came from. `own` distinguishes "this file does it" from "it reaches it". */
export interface CreditedItem {
  item: string;
  file: string;
  via: string[];
  own: boolean;
}

/** Which verification commands count as authenticating an ORIGIN rather than detecting corruption. */
const SIGNATURE_COMMAND_RE = /ucert|usign|signify|gpg|openssl/;

/** Pure: verification commands credited to this candidate, each labelled with the file the line lives in. */
export function creditedVerifyCommands(c: UpdaterCandidate): CreditedItem[] {
  const out: CreditedItem[] = c.verifyCommands.map((item) => ({ item, file: c.path, via: [c.path], own: true }));
  for (const s of c.sourced ?? []) {
    for (const item of s.verifyCommands) out.push({ item, file: s.file, via: s.via, own: false });
  }
  return out;
}

/** Pure: the credited commands that authenticate an origin, own and sourced, each attributed. */
export function creditedSignatureCommands(c: UpdaterCandidate): CreditedItem[] {
  const out: CreditedItem[] = c.verifyCommands
    .filter((v) => SIGNATURE_COMMAND_RE.test(v))
    .map((item) => ({ item, file: c.path, via: [c.path], own: true }));
  for (const s of c.sourced ?? []) {
    for (const item of s.signatureCommands) out.push({ item, file: s.file, via: s.via, own: false });
  }
  return out;
}

/** Pure: flash writes credited to this candidate, each attributed to the file that commits the image. */
export function creditedFlashWrites(c: UpdaterCandidate): CreditedItem[] {
  const out: CreditedItem[] = c.flashWrites.map((item) => ({ item, file: c.path, via: [c.path], own: true }));
  for (const s of c.sourced ?? []) {
    for (const item of s.flashWrites) out.push({ item, file: s.file, via: s.via, own: false });
  }
  return out;
}

/**
 * Pure: rollback markers credited to this candidate. Names only, because the rollback finding is scoped to "the
 * update path" as a whole rather than to any one file, so there is nothing here to misattribute.
 */
export function creditedRollbackMarkers(c: UpdaterCandidate): string[] {
  return [...c.rollbackMarkers, ...(c.sourced ?? []).flatMap((s) => s.rollbackMarkers)];
}

/** A verification command whose executable is not in the rootfs, keyed by the file that actually invokes it. */
export interface VerifierAbsence {
  /** The file containing the invocation. The finding's title names THIS, whatever candidate reached it. */
  file: string;
  missing: string[];
  commands: string[];
  /** Update-path candidates that reach `file` through a source edge, with the chain. */
  reachedFrom: { candidate: string; via: string[] }[];
}

/**
 * Pure: gather invoked-but-absent verifiers, keyed by the file the invocation is IN.
 *
 * Keying by that file rather than by the candidate is what keeps the credit honest in both directions: the same
 * `fwtool.sh` fact reached from `sbin/sysupgrade` and found again when `fwtool.sh` is itself a candidate produces
 * one finding, not two, and its title names `fwtool.sh` — the file that contains the line — in both cases.
 */
export function collectVerifierAbsences(updaters: ReadonlyArray<UpdaterCandidate>): VerifierAbsence[] {
  const byFile = new Map<string, VerifierAbsence>();
  const at = (file: string): VerifierAbsence => {
    const prev = byFile.get(file);
    if (prev) return prev;
    const next: VerifierAbsence = { file, missing: [], commands: [], reachedFrom: [] };
    byFile.set(file, next);
    return next;
  };
  const union = (into: string[], from: ReadonlyArray<string>): void => {
    for (const v of from) if (!into.includes(v)) into.push(v);
  };
  for (const u of updaters) {
    if (u.missingVerifiers.length > 0) {
      const e = at(u.path);
      union(e.missing, u.missingVerifiers);
      union(e.commands, u.verifyCommands);
    }
    for (const s of u.sourced ?? []) {
      if (s.missingVerifiers.length === 0) continue;
      const e = at(s.file);
      union(e.missing, s.missingVerifiers);
      union(e.commands, s.verifyCommands);
      if (!e.reachedFrom.some((r) => r.candidate === u.path)) e.reachedFrom.push({ candidate: u.path, via: s.via });
    }
  }
  return [...byFile.values()];
}

/**
 * Pure: everything the source-following pass could NOT follow, as prose for a negative finding's bounds list.
 *
 * A negative ("the updaters located invoke no signature verification") measured over a partially-followed source
 * graph is weaker than one measured over a fully-followed one, and only saying so lets a reader tell them apart.
 */
export function sourceFollowingNotes(updaters: ReadonlyArray<UpdaterCandidate>): string[] {
  const notes: string[] = [];
  for (const u of updaters) {
    for (const b of u.sourceBounds ?? []) if (!notes.includes(b)) notes.push(b);
    for (const s of u.unresolvedSources ?? []) {
      const note = `${s.from} runs \`${s.directive} ${s.spec}\` and it was not followed: ${s.reason}`;
      if (!notes.includes(note)) notes.push(note);
    }
  }
  return notes;
}

// === Enforcement flags: a guard that fails open unless a variable nobody sets is set ========================

/** A shell variable that decides whether a verification failure is fatal, and whether anything ever sets it. */
export interface EnforcementFlag {
  name: string;
  /** The script the guard was read in, rootfs-relative. */
  guardPath: string;
  /** The test expression it appears in, quoted so a reader can check the parse rather than trust it. */
  evidence: string;
  /** Every script that ASSIGNS it, rootfs-relative. Empty is the finding. */
  assignedIn: string[];
}

/**
 * Names worth asking about. Deliberately a curated list rather than "every variable in a conditional": the
 * generic form drowns in `$FORCE`, `$DEBUG`, `$1` and every ordinary option flag, and a detector whose output
 * needs hand-filtering is one nobody reads. These are the variables that decide whether a FAILED verification
 * aborts, across the update frameworks the corpus actually ships.
 */
const ENFORCEMENT_FLAG_RE =
  /\b(REQUIRE_[A-Z0-9_]*(?:SIGNATURE|METADATA|VERIFY|CERT)|[A-Z0-9_]*(?:SIGNATURE|SECUREBOOT|SECURE_BOOT|VERIFY)_(?:REQUIRED|ENFORCE[D]?|MANDATORY)|ENFORCE_[A-Z0-9_]+)\b/g;

/** An assignment of NAME anywhere a shell could make one: `NAME=`, `export NAME=`, `read NAME`, `local NAME=`. */
function assignsVariable(text: string, name: string): boolean {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `(?:^|[;&|(]|\\b(?:export|local|readonly|declare|set)\\s+)\\s*${n}\\s*=|\\bread\\s+[^\\n]*\\b${n}\\b`,
    'm',
  ).test(text);
}

/**
 * Pure: find enforcement flags that gate a verification and that NOTHING in the filesystem assigns.
 *
 * The GL.iNet BE3600 is the worked example and the reason this exists. `lib/upgrade/fwtool.sh` opens
 * `fwtool_check_signature` with `[ ! -x /usr/bin/ucert ] && { if [ "$REQUIRE_IMAGE_SIGNATURE" = 1 ]; then return 1;
 * else return 0; fi; }` — so a missing verifier makes the signature check *pass*, and the only thing that would
 * make it fail closed is a variable that appears nowhere in that rootfs except in the three lines reading it.
 * `ucert` is not packaged either, so the check returns 0 unconditionally on a shipped device: a guard that fails
 * open because a dependency was dropped and the fail-closed switch was never thrown.
 *
 * **The generalisation is the point.** "A security check whose enforcement is opt-in, and the opt-in never
 * happens" is a shape, not an OpenWrt quirk, and it is the difference between a check that was SKIPPED and one
 * that was DISABLED — which no amount of counting verify-symbols can tell apart.
 *
 * `allScripts` must be every script read, not just the updaters: a flag legitimately set by an unrelated init
 * script or a build-time config fragment is not this defect, and looking only at the guard's own file would
 * report one whenever the assignment lives elsewhere.
 */
export function findEnforcementFlags(
  guards: ReadonlyArray<{ path: string; text: string }>,
  allScripts: ReadonlyArray<{ path: string; text: string }>,
): EnforcementFlag[] {
  const out = new Map<string, EnforcementFlag>();
  for (const g of guards) {
    const live = stripInertText(g.text);
    for (const m of live.matchAll(ENFORCEMENT_FLAG_RE)) {
      const name = m[0];
      // Only count it as a GUARD when it is read in a test, not merely mentioned. `$` before the name, inside a
      // `[ … ]`/`[[ … ]]`/`test` expression on the same line.
      const line = live.slice(live.lastIndexOf('\n', m.index) + 1, live.indexOf('\n', m.index) + 1 || undefined);
      if (!new RegExp(`\\$\\{?${name}\\b`).test(line)) continue;
      if (!/\[\[?[^\]]*\]|(?:^|\s)test\s/.test(line)) continue;
      const prev = out.get(name);
      if (prev) continue;
      out.set(name, { name, guardPath: g.path, evidence: line.trim().slice(0, 200), assignedIn: [] });
    }
  }
  for (const flag of out.values()) {
    flag.assignedIn = allScripts.filter((s) => assignsVariable(stripInertText(s.text), flag.name)).map((s) => s.path);
  }
  return [...out.values()];
}

/**
 * Pure: turn an unassigned enforcement flag into a finding.
 *
 * The FACT is `static_confirmed` and is stated as the fact: the variable gates a check in this script, and nothing
 * in this filesystem assigns it. The CONSEQUENCE — that the check is therefore disabled on a shipped device — is
 * one step weaker and is written as such: the value could arrive from the environment of whatever invokes the
 * script, from a bootloader variable, or from a binary's `setenv`, none of which this pass reads. Overstating that
 * step would make this the same kind of confident-but-unearned claim the provider's negative findings avoid.
 */
export function buildEnforcementFindings(flags: ReadonlyArray<EnforcementFlag>): FindingDraft[] {
  return flags
    .filter((f) => f.assignedIn.length === 0)
    .map((f) => ({
      kind: 'update-enforcement-flag-never-set',
      title: `\`$${f.name}\` decides whether a failed check aborts in ${f.guardPath}, and nothing in this filesystem sets it`,
      severity: 'high' as const,
      proofState: 'static_confirmed' as const,
      evidence: { flag: f.name, guard: f.guardPath, expression: f.evidence, assignedIn: f.assignedIn },
      rationale: `The guard reads \`${f.evidence}\`, so the failure path is fatal only when \`${f.name}\` is set — and no script in this rootfs assigns it. That the variable is read and never assigned here is a fact about the bytes; that the check is consequently inert on a shipped device is a strong inference and not a certainty, because the value could still arrive from the environment of whatever invokes this script, a bootloader variable, or a binary calling setenv. This is the difference between a check that was SKIPPED and one that was DISABLED, which counting verification symbols cannot tell apart.`,
    }));
}

/**
 * Pure: drop `#` comments and `<<'HEREDOC'` blocks used to comment code out, so a disabled check is not counted.
 * Deliberately simple and conservative — it only removes text that cannot execute in a POSIX shell.
 */
export function stripInertText(text: string): string {
  const out: string[] = [];
  let heredoc: string | null = null;
  for (const raw of text.split('\n')) {
    if (heredoc !== null) {
      if (raw.trim() === heredoc) heredoc = null;
      continue;
    }
    const open = /<<-?\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]/.exec(raw);
    if (open?.[1]) {
      heredoc = open[1];
      continue;
    }
    const line = raw.replace(/(^|\s)#.*$/, '$1');
    if (line.trim()) out.push(line);
  }
  return out.join('\n');
}

// ===========================================================================================================
// Part 3 — key material and rollback posture
// ===========================================================================================================

export interface KeyMaterial {
  path: string;
  kind: string;
}

/** The system TLS trust store — a public-key pile that has nothing to do with authenticating an update. */
const CA_BUNDLE_PATH = /(?:^|\/)(?:etc\/ssl\/certs|usr\/share\/ca-certificates|etc\/ca-certificates|usr\/lib\/ssl)\//;

/** A path token that ties key material to the UPDATE path specifically, rather than to TLS or to logging. */
const UPDATE_ANCHOR_PATH =
  /(?:secboot|secure_?boot|bootloader|sign|verify|update|upgrade|\bota\b|firmware|(?:^|\/)fw(?:\/|_))/i;

/**
 * Pure: is this file an update-verification trust anchor kept on the device?
 *
 * The first version answered "is there a public key here", and on the GL.iNet that returned the entire Mozilla CA
 * bundle — 40 root certificates that authenticate TLS servers and could not verify a firmware image if they tried.
 * Worse, they then fed the three-part conjunction, so the strongest positive this provider can state would have
 * been attributed to `AC_RAIZ_FNMT-RCM.crt`. So an anchor now needs an update-shaped reason to be here: an OpenWrt
 * usign/opkg key, or public key material sitting on a path that names signing, secure boot, firmware or updates.
 *
 * A file containing PRIVATE key material is never returned. That is the secret-scanning providers' finding, and
 * filing a private key as a "trust anchor" would be both a wrong label and a quiet way to leak one into a title.
 */
export function classifyKeyMaterial(rel: string, head: string): KeyMaterial | null {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(head)) return null;
  if (CA_BUNDLE_PATH.test(`/${rel}`)) return null;

  const isOpkgKey = /(?:^|\/)etc\/opkg\/keys\//.test(rel) || /key-build\.pub$/.test(rel);
  if (isOpkgKey && head.includes(USIGN_MARKER)) {
    return { path: rel, kind: 'usign Ed25519 public key (OpenWrt package/image signing)' };
  }
  if (/\.pub$/i.test(rel) && head.includes(USIGN_MARKER)) {
    return { path: rel, kind: 'usign/signify Ed25519 public key' };
  }
  if (!UPDATE_ANCHOR_PATH.test(`/${rel}`)) return null;
  if (head.includes('-----BEGIN PUBLIC KEY-----') || head.includes('-----BEGIN RSA PUBLIC KEY-----')) {
    return { path: rel, kind: 'PEM public key on an update/secure-boot path' };
  }
  // A certificate is a public key with an identity attached; certs.ts details them, this only records the anchor.
  if (extractPems(head).length > 0) {
    return { path: rel, kind: 'PEM certificate on an update path (see the certs provider)' };
  }
  return null;
}

/** The anti-rollback vocabulary is `esp.ts`'s, so the two providers describe the same property with one word. */
export type RollbackState = 'on' | 'off' | 'unknown';

export interface RollbackPosture {
  state: RollbackState;
  evidence: string;
  markers: string[];
}

/**
 * Pure: the rollback posture of the update path.
 *
 * `on` needs a marker that actually bounds the acceptable version downward (an anti-rollback counter, a secure
 * version, a minimum-version floor). A `compat_version` or a bare `downgrade` mention is a COMPATIBILITY check,
 * not rollback protection — OpenWrt's `compat_version` gates whether config survives, and `sysupgrade -F` walks
 * straight past it — so those degrade to `unknown` with the marker quoted rather than being scored as protection.
 * No updater examined at all is `unknown` too: nothing was measured, so nothing is claimed.
 */
export function assessRollback(candidates: UpdaterCandidate[]): RollbackPosture {
  const markers = [...new Set(candidates.flatMap(creditedRollbackMarkers))].sort();
  if (candidates.length === 0) {
    return {
      state: 'unknown',
      evidence: 'no updater was examined, so rollback protection was never measured',
      markers,
    };
  }
  const enforcing = markers.filter((m) => m !== 'compat_version' && m !== 'downgrade');
  if (enforcing.length > 0) {
    return {
      state: 'on',
      evidence: `the update path references ${enforcing.join(', ')} — a version floor the updater can enforce`,
      markers,
    };
  }
  if (markers.length > 0) {
    return {
      state: 'unknown',
      evidence: `the update path references ${markers.join(', ')}, which gate compatibility rather than bound the version downward — rollback protection is neither shown nor ruled out`,
      markers,
    };
  }
  return {
    state: 'off',
    evidence: `none of the ${candidates.length} updater(s) read reference a version floor, an anti-rollback counter or a downgrade check`,
    markers,
  };
}

// ===========================================================================================================
// Composition — the honest verdict
// ===========================================================================================================

/** The patterns the rootfs hunt looks for, stated verbatim whenever it comes back empty. */
export const SEARCHED_FOR: ReadonlyArray<string> = [
  'sysupgrade / upgraded',
  'fwupdate / fw_update / firmware_update',
  'ota / otad / ota_upgrade / force_upgrade',
  'files under lib/upgrade, etc/upgrade, sd_otaUpgrade',
  'any file whose name mentions update/upgrade/ota',
  'any ELF exporting an update symbol (upgradeFirmware, sysupgrade, …)',
];

/**
 * The places this provider structurally cannot look. Attached to every negative finding, because a negative that
 * does not say where it did not look is the thing that reads as "clean".
 */
export const UNEXAMINED_PLACES: ReadonlyArray<string> = [
  'the bootloader — usually a separate flash region that is not part of this image, and the most common place a real signature check lives',
  'SoC mask ROM / secure-boot eFuses, which no image dump can show',
  'statically-linked verification with no symbol table — the routine is in the code, the name is not',
  'a vendor-named wrapper around a verify routine, which matches no known symbol',
  'a server-side check performed by the update service and never by the device',
  'kernel modules and non-ELF blobs, which this sweep does not walk',
];

export interface UpdatePathResult {
  available: boolean;
  imageIntegrity: ImageIntegrity;
  updaters: UpdaterCandidate[];
  /** Candidates the per-image cap left out, chosen by merit — stated so the list never reads as exhaustive. */
  droppedUpdaters: number;
  keyMaterial: KeyMaterial[];
  rollback: RollbackPosture;
  /** How many rootfs entries were walked and how many ELFs were opened — a bound, stated, never implied. */
  filesWalked: number;
  elfsExamined: number;
  /** The ELF examination budget ran out, so binaries beyond it were never opened — stated, never left implicit. */
  elfBudgetExhausted: boolean;
  truncated: boolean;
  /**
   * Enforcement flags that gate a verification and that nothing in the filesystem assigns. Optional forever:
   * absent on every result stored before this pass existed, and `[]` would claim a search that never ran.
   */
  enforcementFlags?: EnforcementFlag[];
  findings: FindingDraft[];
  reason: string;
}

/** Cap what a title quotes so one enormous path or symbol list cannot swallow the ledger. */
function short(list: string[], n = 4): string {
  return list.length <= n ? list.join(', ') : `${list.slice(0, n).join(', ')} +${list.length - n} more`;
}

/**
 * Pure: choose which updater candidates survive the per-image cap.
 *
 * The cap has to exist, and WHICH candidates it keeps must not be an accident of directory order — the same rule
 * `selectFindings` in binvuln.ts exists to enforce, and the same way of learning it. On the real GL.iNet the walk
 * reached `lib/upgrade/keep.d/` first, its 30 package-manifest files filled the cap, and `sbin/sysupgrade` — the
 * update entry point, the single most important file for this question — never got opened. The list read as "40
 * updaters" and was in fact the prefix of a directory traversal.
 *
 * So the order is merit: a file whose NAME is an update entry point first, then one that actually invokes a
 * verification, then one that writes to flash, then the rest. Ties break on path so the same rootfs yields the
 * same list on any filesystem.
 */
export function selectUpdaters(
  candidates: UpdaterCandidate[],
  cap: number,
): { kept: UpdaterCandidate[]; dropped: number } {
  if (cap <= 0) return { kept: [], dropped: candidates.length };
  const score = (c: UpdaterCandidate): number => {
    let s = 0;
    if (c.why.startsWith('entry point')) s += 8;
    if (c.signatureFns.length > 0 || creditedVerifyCommands(c).length > 0) s += 4;
    if (creditedFlashWrites(c).length > 0) s += 2;
    if (c.discoveredBy === 'symbol') s += 1;
    return s;
  };
  const ordered = [...candidates].sort((a, b) => score(b) - score(a) || a.path.localeCompare(b.path));
  return { kept: ordered.slice(0, cap), dropped: Math.max(0, ordered.length - cap) };
}

/**
 * Pure: compose everything measured into findings.
 *
 * The severities encode the refusals. Presence facts about the image bytes are `static_confirmed`; anything whose
 * point is an ABSENCE — no verify routine found, no rollback floor found — is `needs_runtime_reproduction` and
 * carries `unexamined`, because an absence measured through one lens is a lead, not a verdict. Finding no updater
 * at all is `blocked_by_platform` with the search terms listed, never an empty pass.
 */
export function buildUpdatePathFindings(
  integrity: ImageIntegrity,
  updaters: UpdaterCandidate[],
  keyMaterial: KeyMaterial[],
  rollback: RollbackPosture,
  hasRootfs: boolean,
  bounds: { elfBudgetExhausted: boolean; walkTruncated: boolean } = { elfBudgetExhausted: false, walkTruncated: false },
): FindingDraft[] {
  // A bound that truncated the search belongs in every negative finding: an absence measured over part of the
  // rootfs is weaker than one measured over all of it, and the reader cannot tell which without being told.
  const boundNotes = [
    bounds.elfBudgetExhausted
      ? `the ${ELF_SCAN_CAP}-binary examination budget was exhausted, so some ELFs were never opened`
      : '',
    bounds.walkTruncated ? `the ${WALK_CAP}-entry walk bound was reached, so part of the rootfs was never visited` : '',
    // A source edge that could not be followed bounds the search exactly the way a cap does: part of the update
    // path was never read, so an absence measured here does not cover it.
    ...sourceFollowingNotes(updaters),
  ].filter(Boolean);
  const drafts: FindingDraft[] = [];
  const signatureItems = integrity.items.filter((i) => i.strength === 'signature');
  const checksumItems = integrity.items.filter((i) => i.strength === 'checksum');

  // --- The image side -------------------------------------------------------------------------------------
  for (const item of signatureItems) {
    drafts.push({
      kind: 'update-image-signature-block',
      title: `Update image carries a ${item.kind}${item.offset === undefined ? '' : ` at 0x${item.offset.toString(16)}`}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { kind: item.kind, detail: item.detail, offset: item.offset ?? null, container: integrity.container },
      rationale:
        'The signature structure is literally present in the image bytes. That is all this proves: it does NOT ' +
        'show that the device checks it, that the key is trusted, or that the signature is even valid — those are ' +
        'rungs above static structure recognition.',
    });
  }

  for (const item of checksumItems) {
    drafts.push({
      kind: 'update-image-unauthenticated-integrity',
      title: `Update image integrity is a ${item.kind}, which detects corruption and authenticates nothing`,
      severity: item.detail.includes('verified by recomputation') ? 'high' : 'medium',
      proofState: 'static_confirmed',
      evidence: { kind: item.kind, detail: item.detail, offset: item.offset ?? null, container: integrity.container },
      rationale: [
        item.detail,
        'A checksum stops a corrupted download; it stops nobody who can recompute it, which is anyone who can',
        'modify the image. Whether a signature is enforced elsewhere (bootloader, SoC ROM, update server) is a',
        'separate question this does not answer.',
      ].join(' '),
    });
  }

  if (integrity.container !== 'unknown' && signatureItems.length === 0 && checksumItems.length === 0) {
    drafts.push({
      kind: 'update-image-no-integrity-metadata',
      title: `The ${integrity.container} container declares neither a signature nor a checksum over the payload`,
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { container: integrity.container, note: integrity.containerNote },
      rationale: [
        integrity.containerNote,
        "The absence is a fact about this container's own metadata, read from its declared structure. It does not",
        'prove the device accepts an arbitrary image — an outer transport or the bootloader may still authenticate it.',
      ].join(' '),
    });
  }

  // --- The updater side -----------------------------------------------------------------------------------
  if (updaters.length === 0) {
    drafts.push({
      kind: 'update-path-not-located',
      title: hasRootfs
        ? 'No updater could be located in the extracted rootfs — the update-integrity question is unanswered'
        : 'No rootfs was extracted, so the updater could not be looked for at all',
      severity: 'info',
      proofState: 'blocked_by_platform',
      evidence: {
        searchedFor: [...SEARCHED_FOR],
        hasRootfs,
        unexamined: [...UNEXAMINED_PLACES],
        ...(boundNotes.length > 0 ? { boundsThatTruncatedTheSearch: boundNotes } : {}),
      },
      rationale: [
        'The question was asked and could not be answered. This is NOT a finding that the firmware has no updater —',
        `it is a record that the search (${SEARCHED_FOR.join('; ')}) came back empty here, so nothing about`,
        'signature verification or downgrade protection has been established either way.',
      ].join(' '),
    });
  }

  // "Verifies" now means "verifies, or reaches a file that does" — the OpenWrt entry point verifies nothing in
  // its own text. Every credited item keeps the file it came from, so nothing below can attribute it wrongly.
  const verifying = updaters.filter((u) => u.signatureFns.length > 0 || creditedVerifyCommands(u).length > 0);
  const signatureCapable = updaters.filter(
    (u) =>
      u.signatureFns.length > 0 ||
      u.missingVerifiers.length > 0 ||
      creditedSignatureCommands(u).length > 0 ||
      (u.sourced ?? []).some((s) => s.missingVerifiers.length > 0),
  );

  const candidatePaths = new Set(updaters.map((u) => u.path));
  for (const a of collectVerifierAbsences(updaters)) {
    // The title names the file that CONTAINS the invocation. When that file is only reached through a source
    // edge, the chain is appended — a reader must never be told `sbin/sysupgrade` runs a line it does not run.
    const reach = candidatePaths.has(a.file) ? null : a.reachedFrom[0];
    const reachNote = reach ? ` (reached from ${reach.candidate} via ${reach.via.join(' → ')})` : '';
    drafts.push({
      kind: 'update-verifier-binary-absent',
      title: `${a.file} invokes ${short(a.missing)} to verify an update, and that executable is not in this rootfs${reachNote}`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: {
        path: a.file,
        missing: a.missing,
        commands: a.commands,
        ...(a.reachedFrom.length > 0 ? { reachedFrom: a.reachedFrom } : {}),
      },
      rationale: [
        'The verification command and the absence of the program it runs are both facts about these bytes: the',
        'check as written cannot execute from this filesystem. Shell updaters commonly treat a missing verifier',
        'as a pass rather than a failure, so read this as a disabled check unless the caller is shown to fail closed.',
        reach
          ? `The invocation is in ${a.file}, not in ${reach.candidate}; the link between them is a static source edge, which shows the file would be READ, not that the check is reached at runtime.`
          : '',
      ]
        .filter(Boolean)
        .join(' '),
    });
  }

  if (updaters.length > 0 && signatureCapable.length === 0) {
    const withDigest = updaters.filter((u) => u.digestFns.length > 0 || u.verifyCommands.length > 0);
    drafts.push({
      kind: 'update-no-signature-verification-found',
      title: `The ${updaters.length} updater(s) located import and invoke no signature-verification routine`,
      severity: withDigest.length > 0 ? 'medium' : 'high',
      proofState: 'needs_runtime_reproduction',
      evidence: {
        updaters: updaters.map((u) => ({
          path: u.path,
          kind: u.kind,
          why: u.why,
          symbolSource: u.symbolSource ?? null,
          digestFns: u.digestFns,
          verifyCommands: u.verifyCommands,
          ...((u.sourced ?? []).length > 0
            ? {
                sourced: (u.sourced ?? []).map((s) => ({ file: s.file, via: s.via, verifyCommands: s.verifyCommands })),
              }
            : {}),
        })),
        unexamined: [...UNEXAMINED_PLACES],
        ...(boundNotes.length > 0 ? { boundsThatTruncatedTheSearch: boundNotes } : {}),
      },
      rationale: [
        `What was measured: ${updaters.map((u) => u.path).join(', ')}.`,
        boundNotes.length > 0 ? `The search was itself bounded — ${boundNotes.join('; ')}.` : '',
        `None of them names a signature-verify entry point${
          withDigest.length > 0
            ? `, though ${short(withDigest.map((u) => u.path))} do compute a digest — integrity, not authentication`
            : ''
        }.`,
        `This is explicitly NOT "the firmware is unsigned": verification may live in ${UNEXAMINED_PLACES.slice(0, 3).join('; ')}.`,
        'Settling it needs the bootloader or a live update attempt, which is why this stays a lead.',
      ]
        .filter(Boolean)
        .join(' '),
    });
  }

  // Only when NOTHING in the update path verifies. An OpenWrt rootfs splits one update path across five files, so
  // per-file reporting would have printed four HIGH "flashes without checking" findings for `nand.sh`,
  // `platform.sh`, `stage2` and `common.sh` while `fwtool.sh` — the sibling they are invoked alongside — was
  // calling `ucert -V`. The unverified-write claim is about the path as a whole or it is misleading. Following
  // source edges makes that whole larger in BOTH directions, which is why `verifying` is credited above.
  const flashers = updaters.filter((c) => creditedFlashWrites(c).length > 0);
  if (flashers.length > 0 && verifying.length === 0) {
    drafts.push({
      kind: 'update-flash-write-without-check',
      title: `${short(
        flashers.map((f) => f.path),
        3,
      )} ${flashers.length === 1 ? 'commits' : 'commit'} an image to flash and nothing in the located update path verifies it first`,
      severity: 'high',
      proofState: 'needs_runtime_reproduction',
      evidence: {
        flashers: flashers.map((f) => ({ path: f.path, flashWrites: f.flashWrites, why: f.why })),
        verifiersFound: 0,
        unexamined: [...UNEXAMINED_PLACES],
      },
      rationale: [
        'The flash writes and the absence of any verification call are both facts about these files. The caveat is',
        'the scope: a caller, a bootloader or an update server may verify before any of this runs, and this provider',
        'cannot see that, so the claim stays a lead about the files that were read rather than a verdict about the',
        'device.',
      ].join(' '),
    });
  }

  // --- Key material and rollback --------------------------------------------------------------------------
  if (keyMaterial.length > 0) {
    drafts.push({
      kind: 'update-trust-anchor-present',
      title: `Update trust anchor on the device: ${short(keyMaterial.map((k) => k.path))}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { keys: keyMaterial },
      rationale:
        'Public key material for verifying updates is present in the filesystem — the third element a real ' +
        'verification chain needs. Its presence proves the key is shipped, not that any code consults it.',
    });
  }

  if (rollback.state === 'off') {
    drafts.push({
      kind: 'update-rollback-unprotected',
      title: 'No downgrade/rollback protection found anywhere in the update path that was read',
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
      evidence: { state: rollback.state, evidence: rollback.evidence, unexamined: [...UNEXAMINED_PLACES] },
      rationale: [
        `${rollback.evidence}.`,
        'An attacker who can present an older, vulnerable image therefore has nothing in this layer stopping them.',
        'Not proven: the version floor may be enforced in the bootloader or server-side, so this is a lead to settle',
        'against a real downgrade attempt.',
      ].join(' '),
    });
  } else if (rollback.state === 'on') {
    drafts.push({
      kind: 'update-rollback-check-present',
      title: `The update path references a version floor (${short(rollback.markers)})`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { state: rollback.state, markers: rollback.markers, evidence: rollback.evidence },
      rationale: `${rollback.evidence}. The marker is in the bytes; whether the comparison is enforced (and cannot be overridden with a force flag) is a runtime question.`,
    });
  }

  // --- The conjunction ------------------------------------------------------------------------------------
  if (signatureItems.length > 0 && verifying.length > 0 && keyMaterial.length > 0) {
    const verifier = verifying[0] as UpdaterCandidate;
    const credited = creditedVerifyCommands(verifier);
    const ownCommands = credited.filter((v) => v.own);
    const sourcedCommands = credited.filter((v) => !v.own);
    const reached = sourcedCommands[0];
    // Part (2) has to name the file the call is written in. Where that file is not the candidate itself, the
    // wording says "reaches … in <file>" and prints the chain, because "sysupgrade invokes ucert -V" is false.
    const part2 =
      verifier.signatureFns.length > 0
        ? `${verifier.path} imports ${short(verifier.signatureFns)}`
        : ownCommands.length > 0
          ? `${verifier.path} invokes ${short(ownCommands.map((v) => v.item))}`
          : `${verifier.path} reaches ${short(sourcedCommands.map((v) => v.item))} in ${reached?.file ?? '(unknown)'} through ${reached?.via.join(' → ') ?? '(unknown)'}`;
    drafts.push({
      kind: 'update-verify-chain',
      title: 'All three elements of an authenticated update are present in this image',
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: {
        signatureInImage: signatureItems.map((i) => i.kind),
        verifierInUpdater: {
          path: verifier.path,
          symbols: verifier.signatureFns,
          commands: verifier.verifyCommands,
          symbolSource: verifier.symbolSource ?? null,
          ...(sourcedCommands.length > 0
            ? { creditedFrom: sourcedCommands.map((v) => ({ command: v.item, file: v.file, via: v.via })) }
            : {}),
        },
        keyOnDevice: keyMaterial.map((k) => k.path),
      },
      rationale: [
        `Stated as the conjunction it is, with each part attributed: (1) the image carries ${short(signatureItems.map((i) => i.kind))};`,
        `(2) ${part2};`,
        `(3) ${short(keyMaterial.map((k) => k.path))} is on the device.`,
        'Each is a fact about the bytes. Together they show the mechanism is BUILT — they do not show it is reached',
        'on the real update path, that the key is the one used, or that a failure is fatal rather than logged.',
        reached
          ? `Part (2) rests on a static source edge: ${verifier.path} would READ ${reached.file}, which is not the same as calling what it defines.`
          : '',
      ]
        .filter(Boolean)
        .join(' '),
    });
  }

  return drafts;
}

// ===========================================================================================================
// Runner
// ===========================================================================================================

const IMAGE_HEAD_CAP = 2 * 1024 * 1024;
const IMAGE_TAIL_CAP = 1 * 1024 * 1024;
const TPLINK_VERIFY_CAP = 64 * 1024 * 1024; // recomputing MD5 over a larger image is not worth the wall-clock
const FDT_STRINGS_CAP = 256 * 1024;
const WALK_CAP = 20000;
const ELF_SCAN_CAP = 500;
const SCRIPT_READ_CAP = 512 * 1024;
const BIN_READ_CAP = 4 * 1024 * 1024;
const KEY_HEAD_CAP = 8 * 1024;
const CANDIDATE_CAP = 40;

/** Read `[offset, offset+len)` of a file; a short/failed read yields what it got. */
function readAt(p: string, offset: number, len: number): Uint8Array {
  if (len <= 0) return new Uint8Array(0);
  try {
    const fd = fs.openSync(p, 'r');
    try {
      const buf = Buffer.allocUnsafe(len);
      const read = fs.readSync(fd, buf, 0, len, offset);
      return buf.subarray(0, read);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return new Uint8Array(0);
  }
}

function fileSizeOf(p: string): number {
  try {
    return fs.statSync(p).size;
  } catch {
    return 0;
  }
}

/**
 * Read the image's integrity posture. Bounded: a head and a tail prefix plus, for a FIT, a targeted read of the
 * property-name block (which sits at the very end of a 100 MB container and is a few dozen bytes long).
 */
export function scanImageIntegrity(imagePath: string): ImageIntegrity {
  const size = fileSizeOf(imagePath);
  const head = readAt(imagePath, 0, Math.min(size, IMAGE_HEAD_CAP));
  const tailLen = Math.min(Math.max(size - head.length, 0), IMAGE_TAIL_CAP);
  const tailStart = size - tailLen;
  const tail = tailLen > 0 ? readAt(imagePath, tailStart, tailLen) : new Uint8Array(0);

  const items: IntegrityItem[] = [];
  let container: ImageIntegrity['container'] = 'unknown';
  let containerNote =
    'The image opens with no container header this analysis decodes, so any integrity structure it defines was not read.';

  const fdt = parseFdtHeader(head);
  const uimage = parseUImageHeader(head);
  const tplink = parseTpLinkHeader(head, size);

  if (fdt) {
    container = 'fit';
    const strings = Buffer.from(
      readAt(imagePath, fdt.offDtStrings, Math.min(fdt.sizeDtStrings, FDT_STRINGS_CAP)),
    ).toString('latin1');
    const fit = classifyFitStrings(strings);
    containerNote = `FIT/FDT v${fdt.version} container; its property-name block declares: ${fit.props.join(', ') || '(none read)'}.`;
    if (fit.signed) {
      items.push({
        strength: 'signature',
        kind: 'FIT signature node',
        detail: 'the FIT declares signature properties over its configurations',
      });
    }
    if (fit.hashed && !fit.signed) {
      items.push({
        strength: 'checksum',
        kind: 'FIT hash node',
        detail:
          'the FIT declares hash properties (algo/value) and no signature/key-name-hint property, so the container authenticates nothing.',
      });
    }
  } else if (uimage) {
    container = 'uimage';
    containerNote = `Legacy U-Boot uImage "${uimage.name}", ${uimage.dataSize} payload bytes.`;
    items.push({
      strength: 'checksum',
      kind: 'uImage CRC32 header/data checksum',
      detail: `the uImage header carries CRC32 fields (header 0x${uimage.headerCrc.toString(16)}, data 0x${uimage.dataCrc.toString(16)}) and no signature field.`,
    });
  } else if (tplink) {
    container = 'tplink';
    containerNote = `TP-Link vendor header ("${tplink.vendor}", hardware id 0x${tplink.hardwareId.toString(16)}), ${tplink.firmwareLength} bytes declared and present.`;
    const wholeImage = size <= TPLINK_VERIFY_CAP ? readAt(imagePath, 0, tplink.firmwareLength) : new Uint8Array(0);
    const salt = wholeImage.length >= tplink.firmwareLength ? verifyTpLinkChecksum(wholeImage, tplink) : null;
    items.push({
      strength: 'checksum',
      kind: salt ? 'TP-Link keyed-MD5 header checksum' : 'TP-Link 16-byte header integrity field',
      offset: TPLINK_MD5_OFFSET,
      detail: salt
        ? `verified by recomputation: hashing the image with the published "${salt}" constant substituted at 0x4c reproduces the stored value ${tplink.checksumHex} byte-for-byte, so the key is public.`
        : `the stored value is ${tplink.checksumHex}; no published constant reproduced it here, so what it covers was not established.`,
    });
  } else {
    const ota = parseOtaHeader(head, size);
    if (ota.ivBlock || ota.lengthField !== null) {
      container = 'ota-framed';
      containerNote = `Framed vendor OTA header (read with the encrypted provider's parser): ${ota.lengthField !== null ? `length field ${ota.lengthField}` : 'no length field'}${ota.ivBlock ? `, framed 16-byte block at 0x${ota.ivBlock.offset.toString(16)}` : ''}.`;
    }
  }

  // Generic structures, wherever the container came out.
  for (const off of findPkcs7SignedData(head, 0)) {
    items.push({
      strength: 'signature',
      kind: 'PKCS#7/CMS signedData structure',
      detail: 'DER OID 1.2.840.113549.1.7.2 present in the image bytes',
      offset: off,
    });
  }
  for (const off of findPkcs7SignedData(tail, tailStart)) {
    items.push({
      strength: 'signature',
      kind: 'PKCS#7/CMS signedData structure (appended)',
      detail: 'DER OID 1.2.840.113549.1.7.2 present near the end of the image',
      offset: off,
    });
  }
  items.push(...findArmoredSignatures(Buffer.from(head).toString('latin1'), 0));
  if (tail.length > 0) items.push(...findArmoredSignatures(Buffer.from(tail).toString('latin1'), tailStart));

  let siblings: string[] = [];
  try {
    siblings = classifySiblings(path.basename(imagePath), fs.readdirSync(path.dirname(imagePath)));
  } catch {
    siblings = [];
  }
  for (const s of siblings) {
    items.push({
      strength: 'signature',
      kind: `detached integrity file "${s}"`,
      detail: 'a sibling file beside the uploaded image',
    });
  }

  // Dedupe by (kind, offset): the same appended block can be seen from both the head and the tail window.
  const seen = new Set<string>();
  const deduped = items.filter((i) => {
    const key = `${i.kind}@${i.offset ?? -1}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { container, containerNote, items: deduped, siblings };
}

/** Is this file an ELF? Reads only the first four bytes. */
function isElf(abs: string): boolean {
  const b = readAt(abs, 0, 4);
  return b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;
}

/** Extract printable ASCII runs (>= 3 chars) so the string fallback has something to tokenize. */
function binaryStrings(buf: Uint8Array): string {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] as number;
    if (b >= 0x20 && b <= 0x7e) cur += String.fromCharCode(b);
    else {
      if (cur.length >= 3) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= 3) out.push(cur);
  return out.join('\n');
}

/** Where a verification executable would live if the rootfs shipped it. */
const BIN_DIRS = ['usr/bin', 'bin', 'usr/sbin', 'sbin', 'usr/local/bin', 'usr/libexec'];

function verifierPresent(root: string, name: string): boolean {
  for (const d of BIN_DIRS) {
    try {
      if (fs.existsSync(path.join(root, d, name))) return true;
    } catch {
      // an unreadable directory is not evidence of absence, but it is also not presence — keep looking
    }
  }
  return false;
}

interface WalkHit {
  rel: string;
  abs: string;
}

/**
 * A `ShellFileReader` over the walked rootfs, by rootfs-relative path.
 *
 * Containment holds three times over, which is deliberate: the walk only ever produces paths under `root` and
 * skips symlinks outright (so one pointing at `/etc/passwd` on the analysis host is simply not in the map),
 * `normalizeInsideRootfs` refuses a spec that climbs above the root, and the prefix check below refuses anything
 * that somehow got past both. A containment rule that rests on a caller's invariant is the kind that stops
 * holding the day the caller changes.
 */
function rootfsShellReader(root: string, files: ReadonlyArray<WalkHit>): ShellFileReader {
  const byPath = new Map<string, string>();
  const dirs = new Map<string, string[]>();
  for (const f of files) {
    byPath.set(f.rel, f.abs);
    const cut = f.rel.lastIndexOf('/');
    const dir = cut < 0 ? '' : f.rel.slice(0, cut);
    const name = f.rel.slice(cut + 1);
    const list = dirs.get(dir);
    if (list) list.push(name);
    else dirs.set(dir, [name]);
  }
  const cache = new Map<string, string | null>();
  return {
    read(rel: string): string | null {
      const hit = cache.get(rel);
      if (hit !== undefined) return hit;
      let text: string | null = null;
      const abs = byPath.get(rel);
      if (abs && (abs === root || abs.startsWith(root + path.sep))) {
        const size = fileSizeOf(abs);
        if (size > 0 && size <= SCRIPT_READ_CAP) text = Buffer.from(readAt(abs, 0, size)).toString('latin1');
      }
      cache.set(rel, text);
      return text;
    },
    list(dir: string): string[] | null {
      return dirs.get(dir) ?? null;
    },
  };
}

/** Bounded, order-stable walk of the rootfs. Sorted so the same rootfs yields the same candidate set anywhere. */
function walkRootfs(root: string): { files: WalkHit[]; walked: number; truncated: boolean } {
  const files: WalkHit[] = [];
  let walked = 0;
  let truncated = false;
  const stack: string[] = [root];
  while (stack.length > 0) {
    if (walked >= WALK_CAP) {
      truncated = true;
      break;
    }
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    const subdirs: string[] = [];
    for (const e of entries) {
      if (walked >= WALK_CAP) {
        truncated = true;
        break;
      }
      walked++;
      if (e.isSymbolicLink()) continue;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        subdirs.push(abs);
        continue;
      }
      if (!e.isFile()) continue;
      files.push({ rel: path.relative(root, abs).split(path.sep).join('/'), abs });
    }
    for (let i = subdirs.length - 1; i >= 0; i--) stack.push(subdirs[i] as string);
  }
  return { files, walked, truncated };
}

/** Read one ELF updater candidate's symbol facts, preferring the real dynamic symbol table over the string superset. */
function assessElf(rel: string, abs: string, discoveredBy: Discovery, why: string): UpdaterCandidate {
  const bytes = readAt(abs, 0, Math.min(fileSizeOf(abs), BIN_READ_CAP));
  const dyn = parseDynamicSymbols(bytes);
  const symbols = dyn ?? extractSymbols(binaryStrings(bytes));
  const { signatureFns, digestFns } = assessSymbols(symbols);
  const rollbackMarkers = ROLLBACK_PATTERNS.filter((p) => [...symbols].some((s) => p.re.test(s))).map((p) => p.label);
  return {
    path: rel,
    kind: 'elf',
    discoveredBy,
    why,
    symbolSource: dyn ? 'dynsym' : 'strings',
    signatureFns,
    digestFns,
    verifyCommands: [],
    missingVerifiers: [],
    flashWrites: [],
    rollbackMarkers,
  };
}

/**
 * Locate the update path in an extracted rootfs and read what it verifies.
 *
 * Two discovery routes, because either alone manufactures a false negative: by PATH (which finds OpenWrt's
 * `sbin/sysupgrade` and `lib/upgrade/fwtool.sh`) and by SYMBOL (which finds TP-Link's update logic living inside
 * `usr/bin/httpd`, a file no name-based hunt would ever open). Every candidate records which route found it.
 */
export function findUpdaters(rootfsPath: string): {
  updaters: UpdaterCandidate[];
  droppedUpdaters: number;
  keyMaterial: KeyMaterial[];
  filesWalked: number;
  elfsExamined: number;
  elfBudgetExhausted: boolean;
  truncated: boolean;
  enforcementFlags: EnforcementFlag[];
} {
  const root = path.resolve(rootfsPath);
  const { files, walked, truncated } = walkRootfs(root);
  // Collected in full and capped only at the END, so the cap chooses on merit instead of on traversal order.
  const found: UpdaterCandidate[] = [];
  const keyMaterial: KeyMaterial[] = [];
  const claimed = new Set<string>();
  let elfsExamined = 0;
  // Every script text the walk reads, kept so the enforcement-flag pass can ask "does ANYTHING assign this",
  // not merely "does the guard's own file assign it" — a flag set by an unrelated init script is not the defect.
  const scriptTexts: { path: string; text: string }[] = [];

  // Route 1: the path says so.
  for (const f of files) {
    const cls = classifyUpdaterPath(f.rel);
    if (cls.tier === 'excluded') continue;
    const entryPoint = cls.tier === 'strong' && cls.basis === 'name';
    const why = `${entryPoint ? 'entry point' : 'path match'} — ${cls.why}`;
    if (isElf(f.abs)) {
      if (elfsExamined >= ELF_SCAN_CAP) continue;
      elfsExamined++;
      found.push(assessElf(f.rel, f.abs, 'path', why));
      claimed.add(f.rel);
      continue;
    }
    const size = fileSizeOf(f.abs);
    if (size === 0 || size > SCRIPT_READ_CAP) continue;
    const text = Buffer.from(readAt(f.abs, 0, size)).toString('latin1');
    if (!/^(?:#!|--|\s*local\s|\s*function\s)/.test(text) && !/\n/.test(text.slice(0, 4096))) continue;
    const a = assessScript(text);
    scriptTexts.push({ path: f.rel, text });
    // Only a file whose own NAME is an update entry point gets in on the name alone. Anything reached through the
    // helper directory or a generic mention has to show verification or a flash write in its content: on the real
    // GL.iNet, `lib/upgrade/keep.d/` holds 30 one-line package manifests that are data, and counting them as
    // updaters both flooded the list and (before the cap became merit-ordered) evicted `sbin/sysupgrade` from it.
    if (!entryPoint && a.verifyCommands.length === 0 && a.flashWrites.length === 0) continue;
    found.push({
      path: f.rel,
      kind: 'script',
      discoveredBy: 'path',
      why,
      signatureFns: [],
      digestFns: [],
      verifyCommands: a.verifyCommands,
      missingVerifiers: a.verifierBinaries.filter((b) => !verifierPresent(root, b)),
      flashWrites: a.flashWrites,
      rollbackMarkers: a.rollbackMarkers,
    });
    claimed.add(f.rel);
  }

  // Route 2: the symbols say so, whatever the file is called.
  for (const f of files) {
    if (elfsExamined >= ELF_SCAN_CAP) break;
    if (claimed.has(f.rel)) continue;
    if (NON_EXECUTABLE_SUFFIX.test(f.rel)) continue;
    if (!isElf(f.abs)) continue;
    elfsExamined++;
    const bytes = readAt(f.abs, 0, Math.min(fileSizeOf(f.abs), BIN_READ_CAP));
    const dyn = parseDynamicSymbols(bytes);
    if (!dyn) continue; // route 2 requires a REAL symbol table — a string mention is far too weak to open on
    const hits = [...dyn].filter(isUpdaterSymbol).sort();
    if (hits.length === 0) continue;
    const { signatureFns, digestFns } = assessSymbols(dyn);
    found.push({
      path: f.rel,
      kind: 'elf',
      discoveredBy: 'symbol',
      why: `dynamic symbol table names firmware-update routines (${short(hits)})`,
      symbolSource: 'dynsym',
      signatureFns,
      digestFns,
      verifyCommands: [],
      missingVerifiers: [],
      flashWrites: [],
      rollbackMarkers: ROLLBACK_PATTERNS.filter((p) => hits.some((h) => p.re.test(h))).map((p) => p.label),
    });
  }

  // Trust anchors kept on the device.
  for (const f of files) {
    if (keyMaterial.length >= CANDIDATE_CAP) break;
    const size = fileSizeOf(f.abs);
    if (size === 0 || size > KEY_HEAD_CAP * 8) continue;
    if (!/(?:\.pub|\.pem|\.crt|\.cer|\.key)$/i.test(f.rel) && !/(?:^|\/)etc\/opkg\/keys\//.test(f.rel)) continue;
    const head = Buffer.from(readAt(f.abs, 0, Math.min(size, KEY_HEAD_CAP))).toString('latin1');
    const k = classifyKeyMaterial(f.rel, head);
    if (k) keyMaterial.push(k);
  }

  const { kept, dropped } = selectUpdaters(found, CANDIDATE_CAP);

  // Credit each surviving script with what the files it sources do. Done AFTER the cap so the work is bounded by
  // the cap rather than by however many candidates the walk turned up; the entry point that most needs crediting
  // scores 8 for being an entry point and is never the one the cap drops.
  const reader = rootfsShellReader(root, files);
  const credited = kept.map((u) => {
    if (u.kind !== 'script') return u; // an ELF sources nothing
    const text = reader.read(u.path);
    if (text === null) return u;
    const closure = resolveSourceClosure(u.path, text, reader);
    return creditSourcedEvidence(
      u,
      closure,
      (rel) => reader.read(rel),
      (b) => !verifierPresent(root, b),
    );
  });

  // A file the update path sources IS part of the update path, so it may hold an enforcement guard too — and its
  // text is a place an assignment could legitimately live. Both sides of `findEnforcementFlags` grow by it.
  for (const u of credited) {
    for (const s of u.sourced ?? []) {
      if (scriptTexts.some((t) => t.path === s.file)) continue;
      const text = reader.read(s.file);
      if (text !== null) scriptTexts.push({ path: s.file, text });
    }
  }

  // Guards are looked for only in the scripts that ARE part of the update path; assignments are looked for in
  // every script read, which is the asymmetry that keeps the answer honest.
  const updatePathFiles = new Set(credited.flatMap((u) => [u.path, ...(u.sourced ?? []).map((s) => s.file)]));
  const guardTexts = scriptTexts.filter((t) => updatePathFiles.has(t.path));
  return {
    updaters: credited,
    droppedUpdaters: dropped,
    keyMaterial,
    filesWalked: walked,
    elfsExamined,
    elfBudgetExhausted: elfsExamined >= ELF_SCAN_CAP,
    truncated,
    enforcementFlags: findEnforcementFlags(guardTexts, scriptTexts),
  };
}

/**
 * Assess the update mechanism of one image: what the image itself carries, what the updater in its rootfs
 * verifies, and whether anything bounds the version downward. Always `available` (no external tool), and a missing
 * rootfs degrades to the image half plus an explicit `blocked_by_platform` record of the half that went unasked.
 */
export function runUpdatePath(imagePath: string, rootfsPath: string | null): UpdatePathResult {
  const imageIntegrity = scanImageIntegrity(imagePath);

  let updaters: UpdaterCandidate[] = [];
  let droppedUpdaters = 0;
  let keyMaterial: KeyMaterial[] = [];
  let filesWalked = 0;
  let elfsExamined = 0;
  let elfBudgetExhausted = false;
  let truncated = false;
  let enforcementFlags: EnforcementFlag[] = [];
  let rootfsUsable = false;
  if (rootfsPath) {
    try {
      rootfsUsable = fs.statSync(rootfsPath).isDirectory();
    } catch {
      rootfsUsable = false;
    }
  }
  if (rootfsUsable && rootfsPath) {
    const found = findUpdaters(rootfsPath);
    updaters = found.updaters;
    droppedUpdaters = found.droppedUpdaters;
    keyMaterial = found.keyMaterial;
    filesWalked = found.filesWalked;
    elfsExamined = found.elfsExamined;
    elfBudgetExhausted = found.elfBudgetExhausted;
    truncated = found.truncated;
    enforcementFlags = found.enforcementFlags;
  }

  const rollback = assessRollback(updaters);
  const findings = [
    ...buildUpdatePathFindings(imageIntegrity, updaters, keyMaterial, rollback, rootfsUsable, {
      elfBudgetExhausted,
      walkTruncated: truncated,
    }),
    ...buildEnforcementFindings(enforcementFlags),
  ];

  const sigCount = imageIntegrity.items.filter((i) => i.strength === 'signature').length;
  const sumCount = imageIntegrity.items.filter((i) => i.strength === 'checksum').length;
  const capNote =
    droppedUpdaters > 0
      ? ` The ${CANDIDATE_CAP}-candidate cap kept the ${updaters.length} strongest and dropped ${droppedUpdaters} further candidate(s) — ordered by entry-point/verification/flash evidence, not by directory order.`
      : '';
  const walkNote = truncated
    ? ` The ${WALK_CAP}-entry walk bound was reached, so part of the rootfs was never visited and is absent from these counts, not cleared by them.`
    : '';
  const elfNote = elfBudgetExhausted
    ? ` The ${ELF_SCAN_CAP}-binary examination budget was exhausted, so ELFs beyond it were never opened for update symbols and are absent from these counts, not cleared by them.`
    : '';
  const creditedFiles = [...new Set(updaters.flatMap((u) => (u.sourced ?? []).map((s) => s.file)))];
  const followNotes = sourceFollowingNotes(updaters);
  const sourceNote =
    creditedFiles.length > 0
      ? ` ${creditedFiles.length} sourced file(s) (${short(creditedFiles)}) were credited to the script that sources them — a static edge showing the file would be READ, not that its check runs.`
      : '';
  const unfollowedNote =
    followNotes.length > 0 ? ` Source edges not followed: ${followNotes.length} — ${short(followNotes, 2)}` : '';

  return {
    available: true,
    imageIntegrity,
    updaters,
    droppedUpdaters,
    keyMaterial,
    rollback,
    filesWalked,
    elfsExamined,
    elfBudgetExhausted,
    truncated,
    ...(rootfsUsable ? { enforcementFlags } : {}),
    findings,
    reason:
      `Update-path integrity: container ${imageIntegrity.container} (${sigCount} signature structure(s), ${sumCount} checksum structure(s)); ` +
      `${updaters.length} updater(s) located across ${filesWalked} rootfs entries; ${keyMaterial.length} trust anchor(s); ` +
      `rollback ${rollback.state}.${capNote}${walkNote}${elfNote}${sourceNote}${unfollowedNote} A missing verify routine is a lead about what was read, never a verdict that the firmware is unsigned.`,
  };
}
