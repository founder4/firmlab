/**
 * Byte-only extraction diagnosis shared by every runtime that consumes `@firmlab/core`.
 *
 * A truncated image and a missing extractor can produce the same external-tool error, so these parsers decide
 * from the bytes which condition is actually supported. Filesystem traversal and recovery-attempt binding stay
 * in the API adapter; this module accepts only bytes and has no platform or tool dependency.
 */

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

export interface LzmaHeader {
  dictSize: number;
  uncompressedSize: number;
}

/**
 * Pure: read a raw ("alone" format) LZMA header — the shape binwalk carves out of a uImage and names `.7z`.
 *
 * The header is 13 bytes: a properties byte, a 4-byte dictionary size, and an 8-byte uncompressed size. That last
 * field is the useful one: it says how much payload is supposed to be in there, which turns "a blob we did not
 * open" into "3.8 MB of compressed data that claims to hold 7.6 MB, unexamined". Returns null when the bytes are
 * not a plausible LZMA-alone stream — the properties byte encodes lc/lp/pb and cannot exceed 224.
 */
export function parseLzmaHeader(buf: Uint8Array): LzmaHeader | null {
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
