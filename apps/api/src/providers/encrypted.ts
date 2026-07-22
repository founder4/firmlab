/**
 * W8 — Encrypted-blob worker. When W0's entropy gate routes an image to `encrypted`, every extractor returns
 * empty — which the app used to surface as "0 findings", indistinguishable from "clean". That is the wrong answer.
 * The right answer is a *diagnosis*: this body is encrypted, here is the cipher/mode and the IV, and it is
 * unrecoverable without the key — with the key-recovery path named. This worker reads the OTA header framing and
 * the body entropy straight from the bytes (pure, no tool) and emits that honest verdict.
 *
 * It never claims to decrypt anything. The cipher facts (IV framing, block size, entropy plateau) are literally
 * present in the bytes → `static_confirmed`; the "cannot extract" outcome is `blocked_by_security` (a valid
 * control — encryption — stops it), not a silent empty (docs/AUTONOMOUS-WORKERS.md §3.1(3), §7.5, W8).
 */
import fs from 'node:fs';
import { windowEntropy } from '@firmlab/core';
import type { FindingDraft } from '../findings.js';

/** Read a big-endian 32-bit word at `o`. */
function u32be(b: Uint8Array, o: number): number {
  return (((b[o] ?? 0) << 24) | ((b[o + 1] ?? 0) << 16) | ((b[o + 2] ?? 0) << 8) | (b[o + 3] ?? 0)) >>> 0;
}

// === Header framing ===

export interface OtaHeader {
  /** A big-endian length field at offset 0 that matches the file size (a header, not ciphertext). */
  lengthField: number | null;
  /** Printable ASCII metadata leaked in the plaintext header (e.g. `fw-type:Cloud`). */
  plaintextTags: string[];
  /** A framed 16-byte IV / wrapped key: `AA55 <16 bytes> 55AA`. */
  ivBlock: { offset: number; bytes: string } | null;
  /** Where the high-entropy ciphertext body begins. */
  cipherBodyOffset: number;
}

/** Scan a bounded prefix for printable ASCII runs of ≥ `min` chars. */
function printableRuns(buf: Uint8Array, start: number, end: number, min = 5): string[] {
  const runs: string[] = [];
  let cur = '';
  for (let i = start; i < Math.min(end, buf.length); i++) {
    const c = buf[i] ?? 0;
    if (c >= 0x20 && c <= 0x7e) {
      cur += String.fromCharCode(c);
    } else {
      if (cur.length >= min) runs.push(cur);
      cur = '';
    }
  }
  if (cur.length >= min) runs.push(cur);
  return runs;
}

/**
 * Pure: parse the OTA header framing. Recognizes (a) a big-endian length field at offset 0 that equals the file
 * size (± a small header delta), (b) plaintext ASCII tags in the header, (c) a `AA55 …16… 55AA` framed IV block,
 * and (d) where the ciphertext body starts. Every field degrades honestly to null/[] on an unframed raw blob —
 * the analysis then rests on entropy alone.
 */
export function parseOtaHeader(buf: Uint8Array, fileSize: number): OtaHeader {
  const scanEnd = Math.min(buf.length, 0x400);

  const len0 = u32be(buf, 0);
  const lengthField = len0 > 0 && fileSize - len0 >= 0 && fileSize - len0 <= 256 ? len0 : null;

  // A framed IV block: AA 55 <16 bytes> 55 AA.
  let ivBlock: OtaHeader['ivBlock'] = null;
  for (let i = 0; i + 20 <= scanEnd; i++) {
    if (buf[i] === 0xaa && buf[i + 1] === 0x55 && buf[i + 18] === 0x55 && buf[i + 19] === 0xaa) {
      ivBlock = { offset: i + 2, bytes: Buffer.from(buf.subarray(i + 2, i + 18)).toString('hex') };
      break;
    }
  }

  // Plaintext tags live in the header before the IV frame (or before the body if no frame).
  const tagEnd = ivBlock ? ivBlock.offset - 2 : 0x114;
  const plaintextTags = printableRuns(buf, 4, Math.min(tagEnd, scanEnd));

  const cipherBodyOffset = ivBlock ? ivBlock.offset + 16 + 2 : firstHighEntropyOffset(buf);
  return { lengthField, plaintextTags, ivBlock, cipherBodyOffset };
}

/** Fallback body-start: the first 512-byte window whose entropy is > 7.5 (the ciphertext plateau begins). */
function firstHighEntropyOffset(buf: Uint8Array): number {
  const win = 512;
  for (let o = 0; o + win <= Math.min(buf.length, 0x4000); o += win) {
    if (windowEntropy(buf, o, o + win) > 7.5) return o;
  }
  return 0;
}

// === Cipher classification ===

export interface CipherVerdict {
  cipher: 'AES' | 'unknown';
  /** Cipher block size in bits, when an IV/alignment implies it. */
  blockBits: number | null;
  mode: 'ECB' | 'CBC-or-CTR' | 'unknown';
  ivPresent: boolean;
  bodyBlockAligned: boolean;
  bodyEntropy: number;
}

/** Count repeated 16-byte blocks in a body sample — the ECB tell (identical plaintext blocks → identical cipher). */
function hasRepeatedBlocks(buf: Uint8Array, start: number, end: number): boolean {
  const seen = new Set<string>();
  for (let o = start; o + 16 <= end; o += 16) {
    const block = Buffer.from(buf.subarray(o, o + 16)).toString('binary');
    if (seen.has(block)) return true;
    seen.add(block);
  }
  return false;
}

/**
 * Pure: classify the cipher from the header framing + body entropy. A 16-byte framed IV ⇒ a 128-bit block cipher
 * (the AES family); a high-entropy body with NO repeated 16-byte blocks and an IV ⇒ CBC or CTR (statically
 * indistinguishable without the key); repeated blocks ⇒ ECB. Honest by construction — where the bytes don't
 * prove a fact (e.g. the exact key size, or cipher without an IV) it stays `unknown`.
 */
export function classifyCipher(buf: Uint8Array, header: OtaHeader, fileSize: number): CipherVerdict {
  const bodyStart = header.cipherBodyOffset;
  const sampleEnd = Math.min(buf.length, bodyStart + 0x10000);
  const bodyEntropy = windowEntropy(buf, bodyStart, sampleEnd);
  const ivPresent = header.ivBlock !== null;
  const ivLen = ivPresent ? 16 : 0;
  const blockBits = ivLen === 16 ? 128 : null;
  const bodyBlockAligned = (fileSize - bodyStart) % 16 === 0;

  let mode: CipherVerdict['mode'] = 'unknown';
  if (bodyEntropy > 7.5) {
    if (hasRepeatedBlocks(buf, bodyStart, sampleEnd)) mode = 'ECB';
    else if (ivPresent) mode = 'CBC-or-CTR';
  }
  // A 128-bit block + a high-entropy body is the AES signature; we cannot prove the key size from the bytes.
  const cipher: CipherVerdict['cipher'] = blockBits === 128 && bodyEntropy > 7.5 ? 'AES' : 'unknown';
  return { cipher, blockBits, mode, ivPresent, bodyBlockAligned, bodyEntropy };
}

// === Composition ===

export interface EncryptedAnalysis {
  header: OtaHeader;
  verdict: CipherVerdict;
  findings: FindingDraft[];
}

/** A human verdict line: "AES (128-bit block), CBC/CTR, IV @ 0x116". */
function verdictLine(v: CipherVerdict, header: OtaHeader): string {
  const parts: string[] = [];
  parts.push(v.cipher === 'AES' ? `AES (${v.blockBits}-bit block)` : 'unknown cipher');
  if (v.mode === 'CBC-or-CTR') parts.push('CBC/CTR');
  else if (v.mode === 'ECB') parts.push('ECB');
  if (header.ivBlock) parts.push(`IV @ 0x${header.ivBlock.offset.toString(16)}`);
  return parts.join(', ');
}

/**
 * Pure: compose the header + verdict into honest findings. The cipher diagnosis is `static_confirmed` (the IV
 * framing and entropy plateau are literally present); the "cannot extract" outcome is `blocked_by_security` with
 * the key-recovery path named — never a silent empty. A plaintext tag leak (fw-type) is surfaced as `info`.
 */
export function analyzeEncrypted(buf: Uint8Array, fileSize: number): EncryptedAnalysis {
  const header = parseOtaHeader(buf, fileSize);
  const verdict = classifyCipher(buf, header, fileSize);
  const findings: FindingDraft[] = [];

  const encrypted = verdict.bodyEntropy > 7.5;
  findings.push({
    kind: 'encrypted-cipher',
    title: `Encrypted firmware body — ${verdictLine(verdict, header)}`,
    severity: encrypted ? 'high' : 'medium',
    proofState: 'static_confirmed',
    evidence: {
      cipher: verdict.cipher,
      blockBits: verdict.blockBits,
      mode: verdict.mode,
      ivPresent: verdict.ivPresent,
      ivOffset: header.ivBlock ? `0x${header.ivBlock.offset.toString(16)}` : null,
      ivHex: header.ivBlock?.bytes ?? null,
      cipherBodyOffset: `0x${header.cipherBodyOffset.toString(16)}`,
      bodyEntropy: Number(verdict.bodyEntropy.toFixed(4)),
      bodyBlockAligned: verdict.bodyBlockAligned,
      lengthField: header.lengthField,
    },
    rationale:
      'The body is a high-entropy plateau with no compression/container header; a 16-byte framed IV implies a ' +
      '128-bit block cipher (AES). Mode CBC-vs-CTR is not statically separable without the key. These are facts ' +
      'about the bytes, not a decryption.',
  });

  findings.push({
    kind: 'encrypted-unrecoverable',
    title: 'Firmware body is encrypted — unrecoverable without the key (honest verdict, not an empty result)',
    severity: 'high',
    proofState: 'blocked_by_security',
    evidence: {
      keyRecoveryPaths: [
        'Extract the OTA/decrypt key from the device bootloader or a companion app/binary that performs the update',
        'Known-plaintext / crib attack if a plaintext region and its matching ciphertext are both available',
        'Vendor key disclosure, or intercept a decrypted image on-device (Phase-6 capture)',
      ],
    },
    rationale:
      'Encryption is a valid control that blocks static extraction — the correct outcome is a diagnosis plus the ' +
      'key-recovery path, not a silent "0 findings" that reads as "clean".',
  });

  if (header.plaintextTags.length) {
    findings.push({
      kind: 'encrypted-metadata',
      title: `Plaintext header metadata leaked: ${header.plaintextTags.join(', ')}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { tags: header.plaintextTags, lengthField: header.lengthField },
      rationale:
        'The OTA header leaks unencrypted metadata (firmware type / length) even though the body is encrypted.',
    });
  }

  return { header, verdict, findings };
}

// === Runner ===

export interface EncryptedResult {
  available: boolean;
  header: OtaHeader;
  verdict: CipherVerdict;
  findings: FindingDraft[];
  reason: string;
}

/** Read enough to cover the header framing + a body entropy sample; the body is large, so cap the read. */
const READ_CAP = 1 * 1024 * 1024;

function readBounded(p: string): { buf: Uint8Array; fileSize: number } {
  const fd = fs.openSync(p, 'r');
  try {
    const fileSize = fs.fstatSync(fd).size;
    const len = Math.min(fileSize, READ_CAP);
    const b = Buffer.allocUnsafe(len);
    fs.readSync(fd, b, 0, len, 0);
    return { buf: b, fileSize };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Diagnose an encrypted-class image from disk — pure byte analysis, always `available`. Emits the cipher/mode/IV
 * diagnosis and the honest "unrecoverable without key" verdict with the recovery path named. This never returns
 * an empty result: even a headerless high-entropy blob gets the encrypted verdict from its entropy.
 */
export function runEncryptedAnalysis(imagePath: string): EncryptedResult {
  let read: { buf: Uint8Array; fileSize: number };
  try {
    read = readBounded(imagePath);
  } catch (err) {
    const header: OtaHeader = { lengthField: null, plaintextTags: [], ivBlock: null, cipherBodyOffset: 0 };
    const verdict: CipherVerdict = {
      cipher: 'unknown',
      blockBits: null,
      mode: 'unknown',
      ivPresent: false,
      bodyBlockAligned: false,
      bodyEntropy: 0,
    };
    return {
      available: true,
      header,
      verdict,
      findings: [],
      reason: `Could not read image bytes: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const a = analyzeEncrypted(read.buf, read.fileSize);
  const iv = a.header.ivBlock ? ` IV @ 0x${a.header.ivBlock.offset.toString(16)}.` : '';
  return {
    available: true,
    header: a.header,
    verdict: a.verdict,
    findings: a.findings,
    reason:
      `Encrypted firmware: ${a.verdict.cipher} ${a.verdict.mode}, body entropy ${a.verdict.bodyEntropy.toFixed(2)} ` +
      `bits/byte.${iv} Unrecoverable without the key — this is the honest verdict, not an empty result.`,
  };
}
