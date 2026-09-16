/**
 * Built-in magic-byte signature scanner.
 *
 * This is FirmLab's tool-independent answer to `binwalk -B`: a single linear pass over the image that finds
 * the structural landmarks that matter in firmware — filesystems, compression streams, kernels/bootloaders,
 * executables, device trees, certificates. It exists so the workbench produces a real structure map for ANY
 * uploaded blob without requiring the heavy Docker toolchain; when binwalk IS available the API merges its
 * richer output on top (see `mergeSignatureSources`).
 *
 * The scanner is deliberately conservative on two independent axes, and the whole design turns on keeping them
 * apart:
 *
 *   - `confidence` is the RULE's prior — how often this magic is a real boundary, declared once by whoever wrote
 *     the rule. `low` rules are the ones the UI de-emphasizes and `highConfidenceOnly` drops.
 *   - `tier` is what the bytes AT ONE OFFSET sustained — the four-level rubric in `SignatureTier`
 *     (magic 25 / structural 60 / consistent 85 / verified 99), plus the outcome that is not a tier at all: a
 *     structural check that FAILS rejects the match, and no hit is emitted.
 *
 * That rejection path is the whole point. A scanner that is "magic + decode with no rejection" reports every
 * three-byte coincidence as a find — on the corpus, hundreds of hits per image where a rejecting scanner returns
 * a handful, and the operator has no way to tell which is which because both arrive as a row in the same table.
 * So `verify` is where a rule earns anything above the prior, and the scan counts what it threw away
 * (`rejected`, `rejectedByRule`) rather than silently shortening its own list: a count whose denominator is
 * invisible is not a measurement.
 *
 * What the rubric deliberately does NOT do is rewrite `confidence`. A rule whose prior is `low` can still reach
 * `consistent` at one offset (the evidence there was good) without becoming a rule you should trust everywhere,
 * and a `high` rule that fails its check is rejected at that offset without being demoted globally.
 */
import type { SignatureCategory, SignatureConfidence, SignatureHit, SignatureTier } from './types.js';

/** Score for each rubric tier. Exported so a caller can rank hits without re-deriving the ladder. */
export const TIER_SCORE: Readonly<Record<SignatureTier, number>> = {
  magic: 25,
  structural: 60,
  consistent: 85,
  verified: 99,
};

/**
 * The outcome of a rule's structural check at one offset. `rejected` is a first-class verdict, not an error:
 * it means the question was asked and the bytes answered no — which is exactly the information a scanner
 * without a rejection path throws away.
 */
export interface SignatureVerdict {
  tier: SignatureTier | 'rejected';
  /** What was read and what it implied. Becomes the hit's `rationale`, or the reason it was dropped. */
  why: string;
}

/** Accept at `tier`, recording what was read. */
function at(tier: SignatureTier, why: string): SignatureVerdict {
  return { tier, why };
}
/** Reject: the magic matched but the structure behind it did not hold. */
function no(why: string): SignatureVerdict {
  return { tier: 'rejected', why };
}

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
  /**
   * Structural check run at the match offset. Returns the tier the bytes there sustain, or rejects the match.
   * A rule without one never rises above its derived base tier — it has not looked at anything but the magic.
   */
  verify?: (buf: Uint8Array, offset: number) => SignatureVerdict;
}

/**
 * Base tier for a rule that ran no structural check, derived from what the rule already declares — no extra
 * field to keep in sync with the prior.
 *
 * A `high` prior means the author judged the magic specific enough to stand alone, which is exactly the
 * `structural` claim. `atOffset` adds one rung because a fixed absolute offset is itself a structural
 * constraint a coincidence cannot satisfy: the ESP partition-table magic is two bytes, and would be pure noise
 * anywhere other than 0x8000.
 */
function baseTier(rule: SignatureRule): SignatureTier {
  const floor: SignatureTier = rule.confidence === 'high' ? 'structural' : 'magic';
  if (rule.atOffset === undefined) return floor;
  return floor === 'structural' ? 'consistent' : 'structural';
}

/** True when every byte in [from, to) is printable ASCII (used by the vendor-string checks below). */
function printableAscii(buf: Uint8Array, from: number, to: number): boolean {
  if (to > buf.length) return false;
  for (let i = from; i < to; i++) {
    const b = buf[i] ?? 0;
    if (b < 0x20 || b > 0x7e) return false;
  }
  return to > from;
}

/** Length of the printable-ASCII run at `off`, stopping at `max` bytes. */
function asciiRun(buf: Uint8Array, off: number, max: number): number {
  let n = 0;
  while (n < max) {
    const b = buf[off + n];
    if (b === undefined || b < 0x20 || b > 0x7e) break;
    n++;
  }
  return n;
}

/** True when `needle` occurs in buf[from, to). Bounded cross-reference for the container formats below. */
function containsAt(buf: Uint8Array, needle: number[], from: number, to: number): boolean {
  const end = Math.min(to, buf.length) - needle.length;
  for (let i = Math.max(0, from); i <= end; i++) {
    let hit = true;
    for (let j = 0; j < needle.length; j++) {
      if (buf[i + j] !== needle[j]) {
        hit = false;
        break;
      }
    }
    if (hit) return true;
  }
  return false;
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

/**
 * TRX container check, shared by HDR0 (v1) and HDR1 (v2) — the same 28-byte header with a different magic.
 * `len` is the total length including the header, and the first partition offset must sit inside it. Both are
 * declared by the format, which is what makes this `consistent` rather than a guess.
 */
function trxVerify(buf: Uint8Array, off: number): SignatureVerdict {
  const len = u32le(buf, off + 4);
  if (len < 28) return no(`declared length ${len} is smaller than the 28-byte TRX header`);
  if (len > 256 * 1024 * 1024) return no(`declared length ${len} exceeds any plausible firmware image`);
  const firstPart = u32le(buf, off + 16);
  if (firstPart !== 0 && (firstPart < 28 || firstPart >= len)) {
    return no(`first partition offset ${firstPart} falls outside the declared image`);
  }
  if (off + len <= buf.length) return at('consistent', `declared length ${len} fits the buffer from this offset`);
  return at('structural', `declared length ${len} is plausible, but runs past the end of this buffer`);
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
    // RFC 1952 makes exactly one field absolute: FLG bits 5-7 are reserved and MUST be zero. XFL and OS are
    // deliberately NOT checked — real firmware carries gzip members produced by every packer under the sun and
    // rejecting on a surprising OS byte would drop true positives to win a cosmetic reduction in noise.
    verify: (buf, off) => {
      const flg = buf[off + 3];
      if (flg === undefined) return no('truncated: no FLG byte after the gzip magic');
      if ((flg & 0xe0) !== 0) return no(`FLG 0x${flg.toString(16)} sets a reserved bit (RFC 1952 §2.3.1)`);
      return at('consistent', `FLG 0x${flg.toString(16)} has its reserved bits clear`);
    },
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
    // `5d 00 00` is three bytes and the most prolific false positive in the whole registry. The alone-format
    // header carries two fields a coincidence rarely satisfies: the dictionary size is a u32 LE that encoders
    // emit as a power of two, and the uncompressed size is a u64 LE that is either the unknown marker
    // (all-ones) or a plausible length. Checking both is what turns this rule from noise into a lead.
    verify: (buf, off) => {
      const dict = u32le(buf, off + 1);
      if (dict < 0x1000 || dict > 0x40000000) return no(`dictionary size 0x${dict.toString(16)} out of range`);
      if ((dict & (dict - 1)) !== 0) return no(`dictionary size 0x${dict.toString(16)} is not a power of two`);
      const lo = u32le(buf, off + 5);
      const hi = u32le(buf, off + 9);
      const unknown = lo === 0xffffffff && hi === 0xffffffff;
      // Above 2^40 the declared size is larger than any firmware payload we will ever see — treat as garbage.
      if (!unknown && (hi > 0xff || (hi === 0 && lo === 0))) {
        return no(`declared uncompressed size ${hi}:${lo} is neither the unknown marker nor a plausible length`);
      }
      return at(
        'consistent',
        `dictionary size 0x${dict.toString(16)} is a power of two and the declared size is ${unknown ? 'the unknown marker' : 'plausible'}`,
      );
    },
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
    verify: trxVerify,
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
    // The four magic bytes are only the first four of `e_ident`. The next three are enumerations with exactly
    // two, two and one legal values, and a coincidental `\x7fELF` in compressed data almost never gets all
    // three right. Without this the rule fires inside every squashfs blob that happens to contain the string.
    verify: (buf, off) => {
      const cls = buf[off + 4];
      const data = buf[off + 5];
      const ver = buf[off + 6];
      if (cls !== 1 && cls !== 2) return no(`EI_CLASS ${cls} is neither ELFCLASS32 nor ELFCLASS64`);
      if (data !== 1 && data !== 2) return no(`EI_DATA ${data} is neither ELFDATA2LSB nor ELFDATA2MSB`);
      if (ver !== 1) return no(`EI_VERSION ${ver} is not EV_CURRENT`);
      return at(
        'consistent',
        `e_ident declares ${cls === 2 ? 64 : 32}-bit ${data === 2 ? 'big' : 'little'}-endian, EV_CURRENT`,
      );
    },
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
    // `_FVH` is four printable ASCII bytes, and `inferIdentity` routes a whole image to `uefi-bios` on it — the
    // single highest-leverage magic in the registry, and until now the least checked.
    magic: ascii('_FVH'),
    // EFI_FIRMWARE_VOLUME_HEADER puts the signature at byte 40, so the header STARTS 40 bytes before the match:
    // ZeroVector[16] @-40 (all zero by definition), FvLength u64 @-8, HeaderLength u16 @+8. Checking the zero
    // vector and a sane header length is a two-sided constraint a stray ASCII run cannot satisfy.
    verify: (buf, off) => {
      const base = off - 40;
      if (base < 0) return no('no room for the 40-byte EFI_FIRMWARE_VOLUME_HEADER prefix before the signature');
      for (let i = base; i < base + 16; i++) {
        if (buf[i] !== 0) return no(`ZeroVector byte at +${i - base} is not zero`);
      }
      const headerLength = (buf[off + 8] ?? 0) | ((buf[off + 9] ?? 0) << 8);
      if (headerLength < 0x48 || headerLength > 0x400) {
        return no(`HeaderLength ${headerLength} outside the 0x48..0x400 a firmware volume header can occupy`);
      }
      const fvLength = u32le(buf, off - 8) + u32le(buf, off - 4) * 2 ** 32;
      if (fvLength < headerLength) return no(`FvLength ${fvLength} is smaller than its own header`);
      return at('consistent', `zero vector clean, HeaderLength ${headerLength}, FvLength ${fvLength}`);
    },
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
    // RFC 7468 labels are uppercase words separated by single spaces, closed by `-----`. Requiring the closing
    // dashes is what separates a real PEM header from prose that happens to start with the dash run — and it is
    // cheap, because the label is bounded at 64 characters.
    verify: (buf, off) => {
      const start = off + 11;
      for (let i = start; i < Math.min(start + 64, buf.length - 4); i++) {
        const b = buf[i] ?? 0;
        if ((b >= 0x41 && b <= 0x5a) || b === 0x20) continue;
        if (b === 0x2d && matchesAt(buf, i, ascii('-----'))) {
          const label = String.fromCharCode(...buf.subarray(start, i));
          return at('consistent', `RFC 7468 label "${label.trim()}" closed by its dash run`);
        }
        return no('the label after -----BEGIN is not an uppercase RFC 7468 label closed by -----');
      }
      return no('no closing ----- within 64 bytes of -----BEGIN');
    },
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

  // === Vendor / platform firmware containers ===
  //
  // Clean-room rules: each magic is paired with a check of fields the format itself declares, and every one of
  // them can REJECT. That constraint is why this pack is ~20 rules and not the ~130 the backlog sketches — a
  // magic we cannot check structurally is a rule that fires on coincidences we would then have to explain away,
  // and several vendors' headers (Realtek, Sercomm, MediaTek) are not reconstructible with confidence from
  // first principles here, so they are left out rather than guessed at. See docs/BACKLOG.md.
  //
  // The descriptions also refuse to over-claim attribution. A magic identifies a CONTAINER FORMAT, not a brand:
  // SEAMA ships on several vendors' devices and HDR1 is a Broadcom TRX variant that Xiaomi among others reuses,
  // so both are named by format with the vendor as a "commonly" aside. Only where the magic is genuinely
  // vendor-private (fwup-ptn, the Netgear CHK magic) does the description name one.
  {
    id: 'seama',
    description: 'SEAMA firmware container (commonly D-Link)',
    category: 'container',
    confidence: 'high',
    magic: [0x5e, 0xa3, 0xa4, 0x17],
    decode: (buf, off) => ({ metaSize: (buf[off + 6] ?? 0) * 256 + (buf[off + 7] ?? 0), size: u32be(buf, off + 8) }),
    // magic u32BE @0, reserved u16BE @4, metasize u16BE @6, size u32BE @8, md5[16] @12, metadata follows.
    // `size` is legitimately 0 in the outer "seal" header, so it is NOT a rejection criterion; the metadata
    // block, however, is a short key=value string and a huge one means this is not a SEAMA header.
    verify: (buf, off) => {
      const metaSize = (buf[off + 6] ?? 0) * 256 + (buf[off + 7] ?? 0);
      if (metaSize > 0x1000) return no(`metadata size ${metaSize} is far larger than a SEAMA metadata block`);
      const size = u32be(buf, off + 8);
      if (size > 256 * 1024 * 1024) return no(`declared payload size ${size} exceeds any plausible image`);
      return at('consistent', `metadata ${metaSize} B, payload ${size} B, both within the format's range`);
    },
  },
  {
    id: 'wrgg',
    description: 'WRGG firmware header (commonly D-Link)',
    category: 'container',
    confidence: 'high',
    magic: ascii('wrgg0'),
    // The header opens with a NUL-terminated ASCII signature in a 32-byte field, e.g. `wrgg03_dlob.hans_...`.
    // Requiring it to be printable AND terminated inside the field is what a stray `wrgg0` in text cannot do.
    verify: (buf, off) => {
      const run = asciiRun(buf, off, 32);
      if (run === 32) return no('the 32-byte signature field is not NUL-terminated');
      if (run < 6) return no(`signature field holds only ${run} printable bytes`);
      if (buf[off + run] !== 0) return no('the signature field ends on a non-printable byte that is not NUL');
      return at('consistent', `NUL-terminated signature "${String.fromCharCode(...buf.subarray(off, off + run))}"`);
    },
  },
  {
    id: 'netgear-chk',
    description: 'Netgear CHK firmware header',
    category: 'container',
    confidence: 'high',
    magic: [0x2a, 0x23, 0x24, 0x5e],
    decode: (buf, off) => ({ kernelLen: u32be(buf, off + 0x18), rootfsLen: u32be(buf, off + 0x1c) }),
    // magic @0, header_len u32BE @4, reserved[8], kernel/rootfs checksums, kernel_len @0x18, rootfs_len @0x1c,
    // image+header checksums, then a NUL-terminated ASCII board_id filling the header out to header_len.
    verify: (buf, off) => {
      const headerLen = u32be(buf, off + 4);
      if (headerLen < 0x29 || headerLen > 0x100) {
        return no(`header length ${headerLen} leaves no room for a board id, or far too much`);
      }
      const idLen = headerLen - 0x28 - 1;
      if (!printableAscii(buf, off + 0x28, off + 0x28 + idLen)) {
        return no('the board id region is not printable ASCII');
      }
      if (u32be(buf, off + 0x18) === 0) return no('declared kernel length is zero');
      return at(
        'consistent',
        `board id "${String.fromCharCode(...buf.subarray(off + 0x28, off + 0x28 + idLen))}" fills the declared ${headerLen}-byte header`,
      );
    },
  },
  {
    id: 'netgear-dni',
    description: 'Netgear DNI firmware header (text)',
    category: 'container',
    // Seven printable characters that occur in ordinary prose and config files — `low` on purpose. The rule
    // exists only because the structural check below makes it actionable.
    confidence: 'low',
    magic: ascii('device:'),
    verify: (buf, off) => {
      if (!containsAt(buf, ascii('version:'), off, off + 256)) {
        return no('no `version:` key within 256 bytes — a DNI header always carries one');
      }
      const run = asciiRun(buf, off + 7, 40);
      if (run < 3) return no('the device name after `device:` is not printable ASCII');
      return at('consistent', 'both the device: and version: keys sit within one 256-byte DNI header block');
    },
  },
  {
    id: 'ubnt-fw-ubnt',
    description: 'Ubiquiti firmware image (UBNT)',
    category: 'container',
    confidence: 'high',
    magic: ascii('UBNT'),
    verify: ubntVerify,
  },
  {
    id: 'ubnt-fw-open',
    description: 'Ubiquiti-format firmware image (OPEN)',
    category: 'container',
    confidence: 'high',
    magic: ascii('OPEN'),
    verify: ubntVerify,
  },
  {
    id: 'ubnt-fw-geos',
    description: 'Ubiquiti-format firmware image (GEOS)',
    category: 'container',
    confidence: 'high',
    magic: ascii('GEOS'),
    verify: ubntVerify,
  },
  {
    id: 'trx-v2',
    description: 'TRX firmware container, v2 (HDR1 — Broadcom-derived, reused by several vendors)',
    category: 'container',
    confidence: 'high',
    magic: ascii('HDR1'),
    decode: (buf, off) => ({ totalSize: u32le(buf, off + 4) }),
    verify: trxVerify,
  },
  {
    id: 'cfe',
    description: 'Broadcom CFE bootloader',
    category: 'bootloader',
    confidence: 'high',
    // Eight bytes with a repeating structure — specific enough to stand on its own, which is exactly what the
    // `structural` base tier means for a rule with no verify.
    magic: ascii('CFE1CFE1'),
  },
  {
    id: 'tplink-safeloader',
    description: 'TP-Link safeloader partition table (fwup-ptn)',
    category: 'container',
    confidence: 'high',
    magic: ascii('fwup-ptn'),
    // Entries are text: `fwup-ptn <base> <size>\r\n`. A space followed by a decimal digit is the cheapest
    // check that separates the real table from the same string appearing in a tool's own strings section.
    verify: (buf, off) => {
      const sep = buf[off + 8];
      const digit = buf[off + 9] ?? 0;
      if (sep !== 0x20) return no('no space after the fwup-ptn keyword');
      if (digit < 0x30 || digit > 0x39) return no('the field after fwup-ptn does not start with a decimal digit');
      return at('consistent', 'fwup-ptn followed by a space and a decimal base offset, as the table format requires');
    },
  },
  {
    id: 'imagewty',
    description: 'Allwinner IMAGEWTY firmware package',
    category: 'container',
    confidence: 'high',
    magic: ascii('IMAGEWTY'),
  },
  {
    id: 'rkfw',
    description: 'Rockchip RKFW update image',
    category: 'container',
    confidence: 'high',
    magic: ascii('RKFW'),
    // An RKFW wrapper always carries the RKAF update payload behind its (small) header. Requiring the
    // cross-reference is what makes four common ASCII letters a container identification.
    verify: (buf, off) =>
      containsAt(buf, ascii('RKAF'), off, off + 0x4000)
        ? at('consistent', 'the RKAF update payload it wraps is present within 16 KB')
        : no('no RKAF payload within 16 KB — an RKFW header always wraps one'),
  },
  {
    id: 'rkaf',
    description: 'Rockchip RKAF update payload',
    category: 'container',
    confidence: 'high',
    magic: ascii('RKAF'),
    // The header carries the model / id / manufacturer as fixed-width ASCII strings right behind the magic.
    verify: (buf, off) =>
      asciiRun(buf, off + 8, 0x38) >= 4
        ? at('consistent', 'the model string field behind the magic holds printable ASCII')
        : no('the model string field behind the magic is not printable ASCII'),
  },
  {
    id: 'imx-ivt',
    description: 'NXP i.MX Image Vector Table (boot header)',
    category: 'bootloader',
    // Three bytes. It is here only because the IVT declares two reserved words that must be zero and two
    // pointers that must not be — four independent constraints a coincidence does not satisfy.
    confidence: 'low',
    magic: [0xd1, 0x00, 0x20],
    verify: (buf, off) => {
      const version = buf[off + 3] ?? 0;
      if (version < 0x40 || version > 0x4f) return no(`IVT version byte 0x${version.toString(16)} out of range`);
      if (u32le(buf, off + 8) !== 0) return no('reserved1 is non-zero');
      if (u32le(buf, off + 0x1c) !== 0) return no('reserved2 is non-zero');
      const entry = u32le(buf, off + 4);
      const self = u32le(buf, off + 0x14);
      if (entry === 0) return no('entry pointer is null');
      if (self === 0) return no('self pointer is null');
      return at(
        'consistent',
        `IVT v0x${version.toString(16)}: reserved words zero, entry 0x${entry.toString(16)}, self 0x${self.toString(16)}`,
      );
    },
  },
  {
    id: 'bflt',
    description: 'uClinux bFLT flat executable',
    category: 'executable',
    confidence: 'high',
    magic: ascii('bFLT'),
    verify: (buf, off) => {
      const rev = u32be(buf, off + 4);
      if (rev !== 2 && rev !== 4) return no(`bFLT revision ${rev} is neither 2 nor 4`);
      return at('consistent', `bFLT revision ${rev}`);
    },
  },
  {
    id: 'android-vendor-boot',
    description: 'Android vendor_boot image',
    category: 'container',
    confidence: 'high',
    magic: ascii('VNDRBOOT'),
  },
  {
    id: 'avb-vbmeta',
    description: 'Android Verified Boot vbmeta block',
    category: 'crypto',
    confidence: 'high',
    magic: ascii('AVB0'),
    // The header opens with the required libavb version as two big-endian u32s. avbtool has never emitted a
    // major above 1; allowing 2 leaves headroom without accepting arbitrary bytes.
    verify: (buf, off) => {
      const major = u32be(buf, off + 4);
      const minor = u32be(buf, off + 8);
      if (major > 2) return no(`required libavb major version ${major} is not a version avbtool emits`);
      if (minor > 64) return no(`required libavb minor version ${minor} is implausible`);
      return at('consistent', `declares required libavb ${major}.${minor}`);
    },
  },
  {
    id: 'android-dt-table',
    description: 'Android DTB/DTBO table',
    category: 'kernel',
    confidence: 'high',
    magic: [0xd7, 0xb7, 0xab, 0x1e],
    // dt_table_header: magic @0, total_size @4, header_size @8 (always 32), dt_entry_size @12, count, offset…
    verify: (buf, off) => {
      const headerSize = u32be(buf, off + 8);
      if (headerSize !== 32) return no(`header_size ${headerSize} is not the fixed 32 the format defines`);
      const total = u32be(buf, off + 4);
      if (total < 32) return no(`total_size ${total} is smaller than the header it contains`);
      return at('consistent', `header_size 32 as defined, total_size ${total}`);
    },
  },
  {
    id: 'fmap',
    description: 'Flashmap (FMAP) region table',
    category: 'bootloader',
    confidence: 'high',
    magic: ascii('__FMAP__'),
    verify: (buf, off) => {
      const major = buf[off + 8] ?? 0;
      if (major !== 1) return no(`FMAP major version ${major} is not 1`);
      return at('consistent', 'FMAP version 1 header');
    },
  },
  {
    id: 'cbfs',
    description: 'coreboot CBFS file header',
    category: 'bootloader',
    confidence: 'high',
    magic: ascii('LARCHIVE'),
  },
  {
    id: 'intel-flash-descriptor',
    description: 'Intel flash descriptor (FLVALSIG)',
    category: 'bootloader',
    confidence: 'high',
    // The descriptor signature lives at a fixed 0x10 in the SPI image — the anchor IS the evidence here.
    magic: [0x5a, 0xa5, 0xf0, 0x0f],
    atOffset: 0x10,
  },
  {
    id: 'intel-fpt',
    description: 'Intel ME flash partition table ($FPT)',
    category: 'bootloader',
    confidence: 'high',
    magic: ascii('$FPT'),
    verify: (buf, off) => {
      const entries = u32le(buf, off + 4);
      if (entries < 1 || entries > 128) return no(`entry count ${entries} outside the 1..128 a partition table holds`);
      return at('consistent', `declares ${entries} partition entries`);
    },
  },
];

/**
 * Ubiquiti firmware layout: a 0x100-byte `fw_header` followed immediately by the first `part_header`, whose own
 * magic is `PART`. The leading magic is four printable ASCII bytes — `OPEN` and `GEOS` in particular occur in
 * ordinary text — so the `PART` cross-reference at a fixed relative offset is what does the identifying.
 */
function ubntVerify(buf: Uint8Array, off: number): SignatureVerdict {
  if (!matchesAt(buf, off + 0x100, ascii('PART'))) {
    return no('no PART header at +0x100, where the Ubiquiti layout puts the first partition');
  }
  return at('consistent', 'the first PART header sits at +0x100 as the Ubiquiti layout requires');
}

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
/**
 * A signature scan and the bound that shaped its list.
 *
 * The distinction that matters: `hits` is a bounded LIST, `distinctIds` is a complete SET. `inferIdentity` reads
 * `new Set(hits.map(h => h.id))` and never a count, so the set is the part that must not be truncated — and it
 * is not.
 */
export interface SignatureScan {
  /** Bounded list, ascending by offset. Carries at least one hit for every rule that SURVIVED anywhere. */
  hits: SignatureHit[];
  /**
   * Every magic that matched in the whole buffer, before the rubric and before the listing bound. This is the
   * DENOMINATOR: `matched - rejected` survived, and of those the list shows `hits.length`. Reporting a hit count
   * without it is the pattern this codebase has paid for repeatedly — a number whose denominator is invisible
   * reads as an answer.
   */
  matched: number;
  /** Distinct rules with at least one surviving hit. Complete by construction, whatever the bound did. */
  distinctIds: number;
  /**
   * Magics that matched but whose structural check rejected them. OPTIONAL FOREVER — a scan persisted before
   * the rubric existed has no rejection count, and absent means "this build did not reject", not zero.
   */
  rejected?: number;
  /**
   * Rejections per rule id. Says WHICH rule the discarded matches belonged to, so "this image has no ELFs" can
   * be told apart from "every \x7fELF in it failed its e_ident check". Optional forever, same reason.
   */
  rejectedByRule?: Record<string, number>;
}

/**
 * Single linear scan of the buffer against all rules, bounded in what it LISTS but never in what it observes.
 *
 * The bound used to be `if (hits.length >= maxHits) return hits`, which ended the scan mid-buffer and therefore
 * truncated by file offset — arrival order, which makes the result an artifact of where the magics happen to sit.
 * That was not merely a short list. `inferIdentity` reads the SET of rule ids, so losing a rule TYPE changes a
 * persisted identity, and measured on the corpus it did: the 61.7 MB Obsbot image kept 5 000 of 32 372 matches,
 * lost `cramfs`, `lzop`, `lz4` and `trx` entirely, and was stored as `[squashfs, ubifs, ubi]` when the complete
 * scan says `[squashfs, cramfs, ubifs, ubi]` — a cramfs volume the workbench did not know existed. The Tenda
 * image lost `picobin`, which is one of the device-family landmarks the class ordering below exists precisely to
 * consult before a coincidental filesystem magic.
 *
 * So the scan now always runs to the end of the buffer, and the cap stops it ADDING to the list rather than
 * stopping it looking. Past the cap a match is still recorded when its rule id has not been seen yet, which keeps
 * the list within one entry per rule of its bound while making the id set exhaustive. `decode` runs only for hits
 * that are kept, so the work the cap was protecting against is still skipped.
 */
export function scanSignaturesDetailed(buf: Uint8Array, options: ScanOptions = {}): SignatureScan {
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
  const seenIds = new Set<string>();
  const rejectedByRule: Record<string, number> = {};
  let matched = 0;
  let rejected = 0;
  for (let off = 0; off < buf.length; off++) {
    const candidates = rulesByFirstByte.get(buf[off] ?? -1);
    if (!candidates) continue;
    for (const rule of candidates) {
      if (rule.atOffset !== undefined && rule.atOffset !== off) continue;
      if (!matchesAt(buf, off, rule.magic)) continue;
      matched++;
      // The rubric runs BEFORE the listing bound, and unconditionally. It has to: a rejection removes a rule
      // from the id set, and `inferIdentity` reads that set — so deciding it only for the matches that happen to
      // fit under the cap would make a persisted identity depend on the cap again. It is also cheap next to
      // `decode`, which still runs only for hits that are kept.
      const verdict = rule.verify?.(buf, off);
      if (verdict?.tier === 'rejected') {
        rejected++;
        rejectedByRule[rule.id] = (rejectedByRule[rule.id] ?? 0) + 1;
        continue;
      }
      // Past the bound only a rule nobody has seen yet may still be listed: the list stays short, the set stays
      // whole. Offsets are visited in ascending order and entries are only appended, so `hits` remains sorted.
      if (hits.length >= maxHits && seenIds.has(rule.id)) continue;
      seenIds.add(rule.id);
      const meta = rule.decode?.(buf, off);
      const tier = verdict ? (verdict.tier as SignatureTier) : baseTier(rule);
      hits.push({
        offset: off,
        id: rule.id,
        description: rule.description,
        category: rule.category,
        confidence: rule.confidence,
        tier,
        score: TIER_SCORE[tier],
        ...(verdict ? { rationale: verdict.why } : {}),
        ...(meta ? { meta } : {}),
      });
    }
  }
  return { hits, matched, distinctIds: seenIds.size, rejected, rejectedByRule };
}

/** Single linear scan of the buffer against all rules. See `scanSignaturesDetailed` for what the bound does. */
export function scanSignatures(buf: Uint8Array, options: ScanOptions = {}): SignatureHit[] {
  return scanSignaturesDetailed(buf, options).hits;
}
