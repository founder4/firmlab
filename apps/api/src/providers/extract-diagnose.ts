/**
 * Why extraction found no rootfs — the verdict that has to exist so an empty result is not silence.
 *
 * `rootfsPath: null` is the single least informative thing this workbench can say, and it was saying it for three
 * different situations that call for three different next moves. docs/AUTONOMOUS-WORKERS.md §3.1(3) names this as
 * one of the app's structural failures — GL.iNet and the encrypted GE800 "returned empty rather than 'encrypted,
 * here's the cipher' / 'container needs FIT→UBI split'" — and the fix there was to diagnose, not to try harder.
 * Same fix here, for the cases binwalk leaves behind:
 *
 *  • Volumes came out, none of them a rootfs. BeanView-Camera yields 27 JFFS2 volumes and 772 files that are the
 *    camera's DATA partitions (`devinfo`, `home`, `voice`, `.aac` clips — and a `private_key.pem`). Reporting
 *    "no rootfs" throws all of it away, including the key.
 *  • A filesystem was carved and could not be unpacked. Asus-Router carves a structurally coherent SquashFS 4.0
 *    whose last 512 bytes are zero, with an id table that points into that zero region: the IMAGE is truncated.
 *    unsquashfs and sasquatch both say "File system corruption detected", which reads like a tool problem and is
 *    not one — no extractor recovers bytes that are not there.
 *  • A compressed blob decompresses partway and stops. AliExpress-Repeater's kernel LZMA yields 384 KB of a
 *    declared 7.6 MB. Again the input, not the tool.
 *
 * The distinction matters because it decides what the operator does next: hunt for a better extractor, re-download
 * the image, or go analyse the data partitions that DID come out. Everything here is pure — it reads bytes and
 * directory listings and returns a verdict — so the wording is unit-tested rather than confirmed by eye.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { BlobAttempt } from './extract-recover.js';

/** SquashFS compression ids, as stored in the superblock. */
const SQUASHFS_COMPRESSION: Record<number, string> = {
  1: 'gzip',
  2: 'lzma',
  3: 'lzo',
  4: 'xz',
  5: 'lz4',
  6: 'zstd',
};

export interface SquashfsSuperblock {
  inodes: number;
  /** Numeric compression id and its name (`unknown(N)` when it is not one of the six standard ids). */
  compressionId: number;
  compression: string;
  /** Size the filesystem declares for itself — compare against the carved blob to detect a short read. */
  bytesUsed: number;
  idTableStart: number;
}

/**
 * Pure: parse a SquashFS 4.0 superblock (little-endian), or null when the bytes are not one.
 *
 * Only the fields that answer "why did unsquashfs refuse" are read: the compression the volume needs, the size it
 * believes it has, and where its id table lives — the structure whose absence produces the misleading
 * "File system corruption detected".
 */
export function parseSquashfsSuperblock(buf: Uint8Array): SquashfsSuperblock | null {
  if (buf.length < 0x60) return null;
  // 'hsqs' — SquashFS 4.0 little-endian.
  if (!(buf[0] === 0x68 && buf[1] === 0x73 && buf[2] === 0x71 && buf[3] === 0x73)) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const compressionId = dv.getUint16(0x14, true);
  return {
    inodes: dv.getUint32(0x04, true),
    compressionId,
    compression: SQUASHFS_COMPRESSION[compressionId] ?? `unknown(${compressionId})`,
    bytesUsed: Number(dv.getBigUint64(0x28, true)),
    idTableStart: Number(dv.getBigUint64(0x30, true)),
  };
}

export interface SquashfsDiagnosis {
  superblock: SquashfsSuperblock;
  /** Bytes actually present in the carved blob. */
  blobSize: number;
  /** The volume declares more bytes than the blob holds — the carve or the image stops short. */
  short: boolean;
  /** The id table the superblock points at lies inside a run of trailing zero bytes. */
  idTableInZeroFill: boolean;
  verdict: string;
}

/** How much trailing zero padding is enough to call a tail "zero-filled" rather than coincidence. */
const ZERO_TAIL_PROBE = 512;

/**
 * Pure: decide what a carved-but-unopenable SquashFS blob actually suffers from.
 *
 * A truncated image and a missing extractor produce the SAME message from unsquashfs, and they need opposite
 * responses, so this separates them from the bytes: if the id table the superblock points at sits in trailing zero
 * padding, no extractor will ever read it, and saying "install a better tool" would send the operator hunting for
 * something that cannot help.
 */
export function diagnoseSquashfs(blob: Uint8Array): SquashfsDiagnosis | null {
  const superblock = parseSquashfsSuperblock(blob);
  if (!superblock) return null;
  const blobSize = blob.length;
  const short = superblock.bytesUsed > blobSize;
  const tail = blob.subarray(Math.max(0, blobSize - ZERO_TAIL_PROBE));
  const tailAllZero = tail.length > 0 && tail.every((b) => b === 0);
  const idTableInZeroFill =
    tailAllZero && superblock.idTableStart >= Math.max(0, blobSize - ZERO_TAIL_PROBE) && superblock.idTableStart > 0;

  let verdict: string;
  if (short) {
    verdict = `The SquashFS declares ${superblock.bytesUsed} bytes and only ${blobSize} were carved, so the volume is cut short. This is missing data, not a missing extractor.`;
  } else if (idTableInZeroFill) {
    verdict = `The SquashFS is structurally coherent (${superblock.inodes} inodes, ${superblock.compression}-compressed, ${superblock.bytesUsed} bytes) but its id table at offset ${superblock.idTableStart} falls inside ${ZERO_TAIL_PROBE} bytes of trailing zero padding — the image is truncated and zero-filled where the filesystem's tail should be. unsquashfs reports this as "File system corruption detected", which reads like a tool problem and is not one: no extractor recovers bytes that are absent. Re-acquire the image.`;
  } else if (superblock.compressionId === 2) {
    verdict = `The SquashFS uses LZMA (compression id 2), which mainline unsquashfs dropped; sasquatch is the extractor that reads it. ${superblock.inodes} inodes, ${superblock.bytesUsed} bytes.`;
  } else {
    verdict = `The SquashFS parses (${superblock.inodes} inodes, ${superblock.compression}-compressed, ${superblock.bytesUsed} bytes) but the extractor could not unpack it. The blob is complete, so this is an extractor or format-variant gap rather than missing data.`;
  }
  return { superblock, blobSize, short, idTableInZeroFill, verdict };
}

/**
 * Pure: read a raw ("alone" format) LZMA header — the shape binwalk carves out of a uImage and names `.7z`.
 *
 * The header is 13 bytes: a properties byte, a 4-byte dictionary size, and an 8-byte uncompressed size. That last
 * field is the useful one: it says how much payload is supposed to be in there, which turns "a blob we did not
 * open" into "3.8 MB of compressed data that claims to hold 7.6 MB, unexamined". Returns null when the bytes are
 * not a plausible LZMA-alone stream — the properties byte encodes lc/lp/pb and cannot exceed 224.
 */
export function parseLzmaHeader(buf: Uint8Array): { dictSize: number; uncompressedSize: number } | null {
  if (buf.length < 13) return null;
  const props = buf[0] as number;
  if (props > 224) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const dictSize = dv.getUint32(1, true);
  // Power-of-two-ish dictionaries only; a random blob rarely lands on one.
  if (dictSize === 0 || (dictSize & (dictSize - 1)) !== 0) return null;
  const uncompressedSize = Number(dv.getBigUint64(5, true));
  // 0xFFFFFFFFFFFFFFFF means "unknown", which is legal but tells us nothing; anything absurd is not a real stream.
  if (uncompressedSize === 0 || uncompressedSize > 0x1_0000_0000) return null;
  return { dictSize, uncompressedSize };
}

export interface ExtractedVolume {
  dir: string;
  files: number;
  /** Top-level entry names, capped — what the operator would see if they opened it. */
  topLevel: string[];
}

export interface NoRootfsDiagnosis {
  verdict: string;
  /** Directories that hold extracted content but are not a Linux rootfs. */
  volumes: ExtractedVolume[];
  totalFiles: number;
  /** Per carved filesystem blob that produced nothing, why it produced nothing. */
  blobs: { path: string; diagnosis: string }[];
}

/** Directory names binwalk gives an extracted volume; the ones worth reporting when none is a rootfs. */
const VOLUME_DIR_RE = /^(squashfs-root|jffs2-root|cramfs-root|ubifs-root|cpio-root|rootfs)(-\d+)?$/;

/** Names that make a directory a Linux rootfs — the same markers `findRootfs` looks for. */
const ROOTFS_MARKERS = new Set(['bin', 'etc', 'sbin', 'lib']);

function countFiles(dir: string, cap = 5000): number {
  let n = 0;
  const stack = [dir];
  while (stack.length > 0 && n < cap) {
    const cur = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.isDirectory()) stack.push(path.join(cur, e.name));
      else if (e.isFile()) n++;
      if (n >= cap) break;
    }
  }
  return n;
}

/** Collect the extracted volume directories under `root`, bounded. */
function collectVolumes(root: string, maxDepth = 4): ExtractedVolume[] {
  const out: ExtractedVolume[] = [];
  const stack: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  while (stack.length > 0 && out.length < 64) {
    const { dir, depth } = stack.pop() as { dir: string; depth: number };
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const abs = path.join(dir, e.name);
      if (VOLUME_DIR_RE.test(e.name)) {
        let topLevel: string[] = [];
        try {
          topLevel = fs.readdirSync(abs).slice(0, 12);
        } catch {}
        out.push({ dir: abs, files: countFiles(abs), topLevel });
      } else if (depth < maxDepth) {
        stack.push({ dir: abs, depth: depth + 1 });
      }
    }
  }
  return out.sort((a, b) => b.files - a.files);
}

/** Find carved filesystem blobs (files, not directories) that a volume directory did not come from. */
function collectBlobs(root: string, maxDepth = 4): string[] {
  const out: string[] = [];
  const stack: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  while (stack.length > 0 && out.length < 32) {
    const { dir, depth } = stack.pop() as { dir: string; depth: number };
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth) stack.push({ dir: abs, depth: depth + 1 });
      } else if (e.isFile() && /\.(squashfs|sqfs|7z|lzma|xz|lzo|gz|jffs2|cramfs|ubifs)$/i.test(e.name)) {
        out.push(abs);
      }
    }
  }
  return out;
}

/** Read a carved blob whole (they are bounded by BLOB_DIAGNOSE_CAP) so both its header and tail are readable. */
function readBlob(abs: string): Uint8Array | null {
  try {
    const size = fs.statSync(abs).size;
    if (size <= 0) return null;
    const fd = fs.openSync(abs, 'r');
    try {
      const buf = Buffer.alloc(size);
      fs.readSync(fd, buf, 0, size, 0);
      return buf;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

/** Files larger than this are not slurped whole for diagnosis; the superblock check needs head and tail only. */
const BLOB_DIAGNOSE_CAP = 64 * 1024 * 1024;

/**
 * Explain an extraction that produced no rootfs, from whatever it left on disk.
 *
 * The three outcomes are deliberately different sentences, because they call for different next moves: content
 * came out but none of it is a rootfs (go look at the content — it may hold keys); a filesystem was carved and
 * could not be opened (why, from its own superblock); or nothing came out at all.
 */
export function diagnoseNoRootfs(outputDir: string, recoveryAttempts: readonly BlobAttempt[] = []): NoRootfsDiagnosis {
  const volumes = collectVolumes(outputDir).filter((v) => v.files > 0);
  const totalFiles = volumes.reduce((n, v) => n + v.files, 0);

  // Which blobs are worth reporting, and this is where the first version got it backwards. A carved `.jffs2` whose
  // volume DID come out is not an unopened payload — BeanView's 666 files came from exactly those blobs, and
  // listing all 29 of them as "no extractor opened it" was both false and a wall of text that buried the one line
  // that mattered. Filesystem blobs are only news when nothing was extracted at all; a COMPRESSED payload is news
  // either way, because binwalk never turns one into a volume directory.
  const anyVolume = volumes.length > 0;
  const blobs: NoRootfsDiagnosis['blobs'] = [];
  const seenBlob = new Set<string>();
  for (const blobPath of collectBlobs(outputDir)) {
    const isCompressed = /\.(7z|lzma|xz|lzo|gz)$/i.test(blobPath);
    if (anyVolume && !isCompressed) continue;
    let size = 0;
    try {
      size = fs.statSync(blobPath).size;
    } catch {
      continue;
    }
    if (size === 0 || size > BLOB_DIAGNOSE_CAP) continue;
    // binwalk re-run leaves `_img.extracted` AND `_img-0.extracted` holding the same carve, so the same blob is
    // found twice. Key on name+size: the second copy is the same fact, not a second finding.
    const key = `${path.basename(blobPath)}@${size}`;
    if (seenBlob.has(key)) continue;
    seenBlob.add(key);
    const bytes = readBlob(blobPath);
    if (!bytes) continue;
    const recovery = recoveryAttempts.find((attempt) => path.resolve(attempt.blob) === path.resolve(blobPath));
    const recoveredDiagnosis = recovery
      ? recovery.outcome === 'decompressed'
        ? `${recovery.format} payload opened to ${recovery.bytes ?? 0} bytes and was rescanned; no Linux rootfs was found in the decompressed bytes.`
        : recovery.outcome === 'partial'
          ? `${recovery.format} decompression recovered ${recovery.bytes ?? 0} bytes before the stream failed; the recovered bytes were rescanned and no Linux rootfs was found. ${recovery.note}`
          : recovery.note
      : null;
    if (recoveredDiagnosis) {
      blobs.push({ path: blobPath, diagnosis: recoveredDiagnosis });
      continue;
    }
    const squash = diagnoseSquashfs(bytes);
    if (squash) {
      blobs.push({ path: blobPath, diagnosis: squash.verdict });
      continue;
    }
    const lzma = parseLzmaHeader(bytes);
    if (lzma) {
      blobs.push({
        path: blobPath,
        diagnosis: `A raw LZMA stream of ${size} bytes, declaring ${lzma.uncompressedSize} bytes uncompressed, was carved and never unpacked — binwalk names these \`.7z\` and does not always recurse into them. The payload is UNEXAMINED, which is not the same as absent.`,
      });
      continue;
    }
    blobs.push({
      path: blobPath,
      diagnosis: `A ${size}-byte blob was carved and no extractor here opened it. Unexamined, not clean.`,
    });
  }

  const parts: string[] = [];
  if (volumes.length > 0) {
    const names = [...new Set(volumes.flatMap((v) => v.topLevel))].slice(0, 10);
    parts.push(
      `${volumes.length} volume(s) were extracted holding ${totalFiles} file(s), and none is a Linux rootfs — no bin/etc/lib among them. They look like data partitions${names.length ? ` (${names.join(', ')})` : ''}. The contents are on disk and worth reading even though no rootfs exists.`,
    );
  }
  const SHOWN = 4;
  for (const b of blobs.slice(0, SHOWN)) parts.push(`${path.basename(b.path)}: ${b.diagnosis}`);
  if (blobs.length > SHOWN) {
    parts.push(`${blobs.length - SHOWN} further carved blob(s) are unexamined for the same reason.`);
  }
  if (parts.length === 0) {
    parts.push(
      'Nothing was extracted: no filesystem volume and no carvable container. The image may be encrypted, may use a container no extractor here understands, or may not contain a filesystem at all — this is an unanswered question, not a clean result.',
    );
  }
  return { verdict: parts.join(' '), volumes, totalFiles, blobs };
}
