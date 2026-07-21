/**
 * Built-in magic-byte signature scanner.
 *
 * This is FirmLab's tool-independent answer to `binwalk -B`: a single linear pass over the image that finds
 * the structural landmarks that matter in firmware — filesystems, compression streams, kernels/bootloaders,
 * executables, device trees, certificates. It exists so the workbench produces a real structure map for ANY
 * uploaded blob without requiring the heavy Docker toolchain; when binwalk IS available the API merges its
 * richer output on top (see `mergeSignatureSources`).
 *
 * The scanner is deliberately conservative: each rule carries a confidence, and rules that would fire on
 * common byte coincidences are marked `low` so the UI can de-emphasize them.
 */
import type { SignatureCategory, SignatureConfidence, SignatureHit } from './types.js';

interface SignatureRule {
  id: string;
  description: string;
  category: SignatureCategory;
  confidence: SignatureConfidence;
  /** Magic bytes to match. */
  magic: number[];
  /** If set, the rule only fires when the magic sits at exactly this absolute offset. */
  atOffset?: number;
  /** Optional decoder returning header-derived metadata (size, version…). */
  decode?: (buf: Uint8Array, offset: number) => Record<string, string | number> | undefined;
}

function u32le(buf: Uint8Array, off: number): number {
  return (
    ((buf[off] ?? 0) | ((buf[off + 1] ?? 0) << 8) | ((buf[off + 2] ?? 0) << 16) | ((buf[off + 3] ?? 0) << 24)) >>> 0
  );
}
function u32be(buf: Uint8Array, off: number): number {
  return (
    (((buf[off] ?? 0) << 24) | ((buf[off + 1] ?? 0) << 16) | ((buf[off + 2] ?? 0) << 8) | (buf[off + 3] ?? 0)) >>> 0
  );
}
function ascii(bytes: string): number[] {
  return [...bytes].map((c) => c.charCodeAt(0));
}

/** The signature registry. Ordering does not matter; overlaps are resolved by the caller. */
export const SIGNATURE_RULES: readonly SignatureRule[] = [
  // === Filesystems ===
  {
    id: 'squashfs-le',
    description: 'SquashFS filesystem (little-endian)',
    category: 'filesystem',
    confidence: 'high',
    magic: ascii('hsqs'),
    decode: (buf, off) => ({ major: buf[off + 28] ?? 0, minor: buf[off + 30] ?? 0, size: u32le(buf, off + 40) }),
  },
  {
    id: 'squashfs-be',
    description: 'SquashFS filesystem (big-endian)',
    category: 'filesystem',
    confidence: 'high',
    magic: ascii('sqsh'),
  },
  {
    id: 'jffs2-le',
    description: 'JFFS2 filesystem node (little-endian)',
    category: 'filesystem',
    confidence: 'medium',
    magic: [0x85, 0x19],
  },
  {
    id: 'jffs2-be',
    description: 'JFFS2 filesystem node (big-endian)',
    category: 'filesystem',
    confidence: 'medium',
    magic: [0x19, 0x85],
  },
  {
    id: 'cramfs',
    description: 'CramFS filesystem',
    category: 'filesystem',
    confidence: 'high',
    magic: [0x45, 0x3d, 0xcd, 0x28],
  },
  {
    id: 'ubi',
    description: 'UBI erase-count / volume header',
    category: 'filesystem',
    confidence: 'high',
    magic: ascii('UBI#'),
  },
  {
    id: 'ubifs',
    description: 'UBIFS filesystem node',
    category: 'filesystem',
    confidence: 'high',
    magic: [0x31, 0x18, 0x10, 0x06],
  },
  {
    id: 'yaffs2',
    description: 'YAFFS2 object header (heuristic)',
    category: 'filesystem',
    confidence: 'low',
    magic: [0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff],
  },
  {
    id: 'romfs',
    description: 'romfs filesystem',
    category: 'filesystem',
    confidence: 'high',
    magic: ascii('-rom1fs-'),
  },

  // === Compression ===
  {
    id: 'gzip',
    description: 'gzip compressed stream',
    category: 'compression',
    confidence: 'medium',
    magic: [0x1f, 0x8b, 0x08],
  },
  {
    id: 'xz',
    description: 'XZ compressed stream',
    category: 'compression',
    confidence: 'high',
    magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
  },
  {
    id: 'bzip2',
    description: 'bzip2 compressed stream',
    category: 'compression',
    confidence: 'medium',
    magic: ascii('BZh'),
  },
  {
    id: 'lzma',
    description: 'LZMA compressed stream (heuristic)',
    category: 'compression',
    confidence: 'low',
    magic: [0x5d, 0x00, 0x00],
  },
  {
    id: 'lz4',
    description: 'LZ4 frame',
    category: 'compression',
    confidence: 'medium',
    magic: [0x04, 0x22, 0x4d, 0x18],
  },
  {
    id: 'zstd',
    description: 'Zstandard compressed stream',
    category: 'compression',
    confidence: 'high',
    magic: [0x28, 0xb5, 0x2f, 0xfd],
  },

  // === Bootloaders / kernels / images ===
  {
    id: 'uimage',
    description: 'U-Boot uImage header',
    category: 'bootloader',
    confidence: 'high',
    magic: [0x27, 0x05, 0x19, 0x56],
    // U-Boot legacy header: ih_size@12, ih_load@16, ih_os@28, ih_arch@29 (see U-Boot image.h).
    decode: (buf, off) => ({
      dataSize: u32be(buf, off + 12),
      loadAddr: u32be(buf, off + 16).toString(16),
      osCode: buf[off + 28] ?? 0,
      archCode: buf[off + 29] ?? 0,
    }),
  },
  {
    id: 'trx',
    description: 'TRX firmware container (Broadcom)',
    category: 'container',
    confidence: 'high',
    magic: ascii('HDR0'),
    decode: (buf, off) => ({ totalSize: u32le(buf, off + 4) }),
  },
  {
    id: 'dtb',
    description: 'Flattened Device Tree (DTB)',
    category: 'kernel',
    confidence: 'high',
    magic: [0xd0, 0x0d, 0xfe, 0xed],
    decode: (buf, off) => ({ totalSize: u32be(buf, off + 4) }),
  },
  {
    id: 'android-boot',
    description: 'Android boot image',
    category: 'container',
    confidence: 'high',
    magic: ascii('ANDROID!'),
  },
  {
    id: 'arm-zimage',
    description: 'Linux ARM zImage magic',
    category: 'kernel',
    confidence: 'medium',
    magic: [0x18, 0x28, 0x6f, 0x01],
  },

  // === Executables ===
  {
    id: 'elf',
    description: 'ELF executable / shared object',
    category: 'executable',
    confidence: 'high',
    magic: [0x7f, 0x45, 0x4c, 0x46],
    decode: (buf, off) => {
      const bits = buf[off + 4] === 2 ? 64 : 32;
      const endian = buf[off + 5] === 2 ? 'big' : 'little';
      const machine = endian === 'little' ? (buf[off + 18] ?? 0) : (buf[off + 19] ?? 0);
      return { bits, endian, machine };
    },
  },
  {
    id: 'pe-mz',
    description: 'DOS/PE executable (MZ)',
    category: 'executable',
    confidence: 'low',
    magic: ascii('MZ'),
  },

  // === Platform firmware ===
  {
    id: 'uefi-fv',
    description: 'UEFI firmware volume (_FVH)',
    category: 'bootloader',
    confidence: 'medium',
    magic: ascii('_FVH'),
  },

  // === SoC / bare-metal boot images ===
  {
    // ESP-IDF partition table lives at the default flash offset 0x8000; each 32-byte entry starts with the
    // magic 0x50AA (little-endian → bytes AA 50). Anchoring at 0x8000 keeps this specific — it is the reliable
    // "this is an ESP SoC flash dump" landmark that a Linux/JFFS2 signature lens completely misses.
    id: 'esp-parttable',
    description: 'ESP-IDF partition table (entry magic @ 0x8000)',
    category: 'container',
    confidence: 'high',
    magic: [0xaa, 0x50],
    atOffset: 0x8000,
  },
  {
    // RP2350 (Raspberry Pi Pico 2) firmware carries a PICOBIN boot block whose start marker is the u32
    // 0xFFFFDED3 (little-endian → D3 DE FF FF). Its IMAGE_TYPE item then declares the CPU (Arm Cortex-M33 vs
    // RISC-V Hazard3) — decode that separately (parsePicobin) so we never disassemble RISC-V as Arm garbage.
    id: 'picobin',
    description: 'RP2350 PICOBIN boot block (start marker)',
    category: 'bootloader',
    confidence: 'high',
    magic: [0xd3, 0xde, 0xff, 0xff],
  },

  // === Containers / archives ===
  {
    id: 'cpio-newc',
    description: 'CPIO archive (newc)',
    category: 'container',
    confidence: 'medium',
    magic: ascii('070701'),
  },
  {
    id: 'tar',
    description: 'POSIX tar archive',
    category: 'container',
    confidence: 'low',
    magic: ascii('ustar'),
  },
  {
    id: 'zip',
    description: 'ZIP / JAR / APK archive',
    category: 'container',
    confidence: 'medium',
    magic: [0x50, 0x4b, 0x03, 0x04],
  },
  {
    id: 'iso9660',
    description: 'ISO 9660 CD/DVD image',
    category: 'container',
    confidence: 'low',
    magic: ascii('CD001'),
  },

  // === Crypto / certificates ===
  {
    id: 'pem-cert',
    description: 'PEM certificate / key block',
    category: 'certificate',
    confidence: 'high',
    magic: ascii('-----BEGIN '),
  },
  {
    id: 'openssh-key',
    description: 'OpenSSH private key',
    category: 'crypto',
    confidence: 'high',
    magic: ascii('openssh-key-v1'),
  },

  // === Images (asset detection, low priority) ===
  {
    id: 'png',
    description: 'PNG image',
    category: 'image',
    confidence: 'medium',
    magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  },
  {
    id: 'jpeg',
    description: 'JPEG image',
    category: 'image',
    confidence: 'low',
    magic: [0xff, 0xd8, 0xff],
  },

  // === Extended pack: offset-anchored filesystems ===
  {
    id: 'ext',
    description: 'ext2/3/4 filesystem superblock',
    category: 'filesystem',
    confidence: 'high',
    // s_magic 0xEF53 lives at byte 0x38 of the superblock, which starts at 0x400 → absolute 0x438.
    magic: [0x53, 0xef],
    atOffset: 0x438,
  },
  {
    id: 'f2fs',
    description: 'F2FS filesystem superblock',
    category: 'filesystem',
    confidence: 'high',
    magic: [0x10, 0x20, 0xf5, 0xf2],
    atOffset: 0x400,
  },
  {
    id: 'erofs',
    description: 'EROFS filesystem superblock',
    category: 'filesystem',
    confidence: 'high',
    magic: [0xe2, 0xe1, 0xf5, 0xe0],
    atOffset: 0x400,
  },
  {
    id: 'cramfs-be',
    description: 'CramFS filesystem (big-endian)',
    category: 'filesystem',
    confidence: 'high',
    magic: [0x28, 0xcd, 0x3d, 0x45],
  },

  // === Extended pack: kernels ===
  {
    id: 'linux-ikcfg',
    description: 'Embedded Linux kernel config (IKCFG)',
    category: 'kernel',
    confidence: 'high',
    magic: ascii('IKCFG_ST'),
  },
  {
    id: 'bzimage',
    description: 'Linux x86 kernel bzImage',
    category: 'kernel',
    confidence: 'high',
    // Setup-header 'HdrS' magic sits at a fixed offset in the boot sector.
    magic: ascii('HdrS'),
    atOffset: 0x202,
  },
  {
    id: 'arm64-linux',
    description: 'Linux ARM64 kernel Image',
    category: 'kernel',
    confidence: 'high',
    // "ARM\x64" magic at offset 56 of the arm64 Image header.
    magic: ascii('ARMd'),
    atOffset: 0x38,
  },

  // === Extended pack: compression / archives ===
  {
    id: 'lzop',
    description: 'lzop compressed stream',
    category: 'compression',
    confidence: 'high',
    magic: [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a],
  },
  {
    id: '7zip',
    description: '7-Zip archive',
    category: 'container',
    confidence: 'high',
    magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c],
  },
  {
    id: 'rar',
    description: 'RAR archive',
    category: 'container',
    confidence: 'high',
    magic: [...ascii('Rar!'), 0x1a, 0x07],
  },
  {
    id: 'android-sparse',
    description: 'Android sparse image',
    category: 'container',
    confidence: 'high',
    magic: [0x3a, 0xff, 0x26, 0xed],
  },
  {
    id: 'cpio-odc',
    description: 'CPIO archive (odc / portable ASCII)',
    category: 'container',
    confidence: 'medium',
    magic: ascii('070707'),
  },
];

/** True when `magic` matches `buf` starting at `off`. */
function matchesAt(buf: Uint8Array, off: number, magic: number[]): boolean {
  if (off + magic.length > buf.length) return false;
  for (let i = 0; i < magic.length; i++) {
    if (buf[off + i] !== magic[i]) return false;
  }
  return true;
}

export interface ScanOptions {
  /** Cap on hits returned so a pathological input can't blow up memory. Default 5000. */
  maxHits?: number;
  /** Skip `low`-confidence rules entirely. Default false. */
  highConfidenceOnly?: boolean;
}

/**
 * Single linear scan of the buffer against all rules. Rules are indexed by their first magic byte so the hot
 * loop only evaluates candidate rules per position, keeping this near-linear for large images.
 */
export function scanSignatures(buf: Uint8Array, options: ScanOptions = {}): SignatureHit[] {
  const maxHits = options.maxHits ?? 5000;
  const rulesByFirstByte = new Map<number, SignatureRule[]>();
  for (const rule of SIGNATURE_RULES) {
    if (options.highConfidenceOnly && rule.confidence === 'low') continue;
    const first = rule.magic[0];
    if (first === undefined) continue;
    const list = rulesByFirstByte.get(first) ?? [];
    list.push(rule);
    rulesByFirstByte.set(first, list);
  }

  const hits: SignatureHit[] = [];
  for (let off = 0; off < buf.length; off++) {
    const candidates = rulesByFirstByte.get(buf[off] ?? -1);
    if (!candidates) continue;
    for (const rule of candidates) {
      if (rule.atOffset !== undefined && rule.atOffset !== off) continue;
      if (!matchesAt(buf, off, rule.magic)) continue;
      const meta = rule.decode?.(buf, off);
      hits.push({
        offset: off,
        id: rule.id,
        description: rule.description,
        category: rule.category,
        confidence: rule.confidence,
        ...(meta ? { meta } : {}),
      });
      if (hits.length >= maxHits) return hits;
    }
  }
  return hits;
}
