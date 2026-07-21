/**
 * Turn raw signature hits + the entropy profile into a human-facing structure map and a best-effort image
 * identity. This is the deterministic backbone of the "binwalk graphical view" the workbench renders: a
 * ribbon of labeled, colored segments across the image, plus an inferred class/arch/endianness.
 */
import { parsePicobin } from './mcu.js';
import type {
  Architecture,
  Endianness,
  EntropyProfile,
  FirmwareClass,
  ImageIdentity,
  SignatureHit,
  StructureSegment,
} from './types.js';

/** ELF e_machine → architecture, for the common firmware targets. */
const ELF_MACHINE: Record<number, { arch: Architecture }> = {
  3: { arch: 'x86' },
  8: { arch: 'mips' },
  20: { arch: 'ppc' },
  40: { arch: 'arm' },
  62: { arch: 'x86_64' },
  183: { arch: 'arm64' },
  243: { arch: 'riscv' },
  2: { arch: 'sparc' },
};

/** U-Boot uImage `ih_arch` code → architecture (subset; see U-Boot image.h IH_ARCH_*). */
const UBOOT_ARCH: Record<number, Architecture> = {
  2: 'arm',
  3: 'x86',
  5: 'mips',
  6: 'mips64',
  7: 'ppc',
  10: 'sparc',
  22: 'arm64',
  24: 'x86_64',
  26: 'riscv',
};

/**
 * Resolve an ELF `e_machine` (+ endianness/bit-width) into a concrete architecture. Shared so both static
 * signature inference and post-extraction rootfs probing agree on the mapping. Returns `unknown` arch for
 * machines outside the firmware-common set.
 */
export function decodeElfArch(
  machine: number,
  endianBig: boolean,
  bits: number,
): {
  arch: Architecture;
  endianness: Endianness;
} {
  const endianness: Endianness = endianBig ? 'big' : 'little';
  let arch = ELF_MACHINE[machine]?.arch ?? 'unknown';
  if (arch === 'mips' && !endianBig) arch = 'mipsel';
  if (arch === 'x86_64' && bits === 32) arch = 'x86';
  return { arch, endianness };
}

/** Map a U-Boot uImage arch code to our architecture, or `unknown`. uImage carries no endianness. */
export function ubootArch(code: number): Architecture {
  return UBOOT_ARCH[code] ?? 'unknown';
}

/**
 * Build ordered, non-overlapping-ish segments from signature hits. Each high-confidence structural hit opens
 * a segment that runs until the next structural hit (or a decoded size when available). Entropy fills the
 * gaps with `padding` vs `high-entropy data` so the whole image is accounted for.
 */
export function buildStructureSegments(
  imageSize: number,
  hits: SignatureHit[],
  entropy: EntropyProfile | null,
): StructureSegment[] {
  // Only structural landmarks (not every gzip byte-coincidence) anchor segments.
  const anchors = hits
    .filter((h) => h.confidence !== 'low')
    .filter((h) => ['filesystem', 'bootloader', 'kernel', 'container', 'executable'].includes(h.category))
    .sort((a, b) => a.offset - b.offset);

  const segments: StructureSegment[] = [];
  for (let i = 0; i < anchors.length; i++) {
    const hit = anchors[i];
    if (!hit) continue;
    const next = anchors[i + 1];
    const declaredEnd = declaredSegmentEnd(hit, imageSize);
    const end = next ? Math.min(next.offset, declaredEnd) : declaredEnd;
    segments.push({
      start: hit.offset,
      end: Math.max(end, hit.offset + 1),
      label: hit.description,
      category: hit.category,
      confidence: hit.confidence,
      ...(hit.meta ? { meta: hit.meta } : {}),
    });
  }

  return fillGapsWithEntropy(imageSize, segments, entropy);
}

/** Use a decoded size field to bound a segment; else run to end-of-image (clamped later by the next anchor). */
function declaredSegmentEnd(hit: SignatureHit, imageSize: number): number {
  const sizeKeys = ['size', 'totalSize', 'dataSize', 'totalsize'];
  for (const key of sizeKeys) {
    const v = hit.meta?.[key];
    if (typeof v === 'number' && v > 0 && hit.offset + v <= imageSize) {
      return hit.offset + v;
    }
  }
  return imageSize;
}

/** Insert `padding` / `high-entropy data` segments into the gaps between structural segments. */
function fillGapsWithEntropy(
  imageSize: number,
  segments: StructureSegment[],
  entropy: EntropyProfile | null,
): StructureSegment[] {
  const filled: StructureSegment[] = [];
  let cursor = 0;
  const sorted = [...segments].sort((a, b) => a.start - b.start);

  function gapCategory(start: number, end: number): { label: string; category: StructureSegment['category'] } {
    if (!entropy || entropy.samples.length === 0) {
      return { label: 'unclassified', category: 'other' };
    }
    const mean = meanEntropyOver(entropy, start, end);
    if (mean >= 7.2) return { label: `high-entropy data (H≈${mean.toFixed(2)})`, category: 'compression' };
    if (mean <= 1.0) return { label: 'padding / empty', category: 'other' };
    return { label: `data (H≈${mean.toFixed(2)})`, category: 'other' };
  }

  for (const seg of sorted) {
    if (seg.start > cursor) {
      const gap = gapCategory(cursor, seg.start);
      filled.push({ start: cursor, end: seg.start, label: gap.label, category: gap.category, confidence: 'low' });
    }
    filled.push(seg);
    cursor = Math.max(cursor, seg.end);
  }
  if (cursor < imageSize) {
    const gap = gapCategory(cursor, imageSize);
    filled.push({ start: cursor, end: imageSize, label: gap.label, category: gap.category, confidence: 'low' });
  }
  return filled;
}

function meanEntropyOver(entropy: EntropyProfile, start: number, end: number): number {
  let sum = 0;
  let count = 0;
  for (const s of entropy.samples) {
    if (s.offset >= start && s.offset < end) {
      sum += s.entropy;
      count++;
    }
  }
  return count > 0 ? sum / count : entropy.mean;
}

/** High-confidence filesystem signatures — one of these is unambiguous proof of an extractable rootfs. */
const STRONG_FS_IDS = [
  'squashfs-le',
  'squashfs-be',
  'cramfs',
  'cramfs-be',
  'ubifs',
  'ubi',
  'romfs',
  'ext',
  'f2fs',
  'erofs',
];

/**
 * Valid JFFS2 node types — the 16-bit word that follows the 2-byte magic in every real node header. A genuine
 * JFFS2 image is a dense stream of these; a handful of coincidental 2-byte magic matches (the false-positive
 * that misclassified ESP32 SoC dumps and encrypted blobs as `embedded-linux`) will not have valid node types
 * behind them. See docs/AUTONOMOUS-WORKERS.md §3.1(1).
 */
const JFFS2_NODETYPES = new Set([0xe001, 0xe002, 0x2003, 0x2004, 0x2006, 0xe008, 0xe009]);

/** Count JFFS2 signature hits whose following 2 bytes form a valid node type (endianness matches the magic). */
function corroboratedJffs2Nodes(buf: Uint8Array, hits: SignatureHit[]): number {
  let count = 0;
  for (const h of hits) {
    if (h.id !== 'jffs2-le' && h.id !== 'jffs2-be') continue;
    const off = h.offset;
    if (off + 3 >= buf.length) continue;
    const nodetype =
      h.id === 'jffs2-le'
        ? (buf[off + 2] ?? 0) | ((buf[off + 3] ?? 0) << 8)
        : ((buf[off + 2] ?? 0) << 8) | (buf[off + 3] ?? 0);
    if (JFFS2_NODETYPES.has(nodetype)) count++;
  }
  return count;
}

/**
 * An OpenWrt-style FIT container wrapping a UBI image: a device-tree (FIT) header at (or very near) offset 0 and
 * a UBI magic somewhere after it. A single-pass extractor returns 0 files on these — the rootfs only appears
 * after a FIT→UBI→volume→SquashFS carve — so the class must be distinct from `embedded-linux` to route to W1.
 */
function isFitUbi(hits: SignatureHit[]): boolean {
  const dtb = hits.find((h) => h.id === 'dtb' && h.offset <= 4096);
  const ubi = hits.find((h) => h.id === 'ubi');
  return dtb !== undefined && ubi !== undefined && ubi.offset > dtb.offset;
}

/**
 * ESP chip-id → CPU arch, read from the image header (the authoritative source). The Xtensa classics (ESP32/-S2/
 * -S3) vs the RISC-V parts (C2/C3/C6/H2/P4) cannot be told apart by string-grep — a stock ESP-IDF build embeds
 * references to every target — so we read the actual `chip_id` from a bootloader/app `esp_image_header_t`.
 */
const ESP_CHIP_ARCH = new Map<number, Architecture>([
  [0x0000, 'xtensa'], // ESP32
  [0x0002, 'xtensa'], // ESP32-S2
  [0x0009, 'xtensa'], // ESP32-S3
  [0x0005, 'riscv'], // ESP32-C3
  [0x000c, 'riscv'], // ESP32-C2
  [0x000d, 'riscv'], // ESP32-C6
  [0x0010, 'riscv'], // ESP32-H2
  [0x0012, 'riscv'], // ESP32-P4
]);

/**
 * Read the ESP SoC arch from an image header: `esp_image_header_t` is `magic(0xE9) @0 … chip_id(u16 LE) @12`.
 * Probe the canonical bootloader offsets (ESP32 @ 0x1000, newer parts @ 0x0); the chip id is authoritative for
 * Xtensa-vs-RISC-V. Returns `unknown` honestly when no header is found (precise arch is refined later by W6).
 */
function espArch(buf: Uint8Array): { arch: Architecture; endianness: Endianness } {
  for (const base of [0x1000, 0x0]) {
    if (buf[base] === 0xe9) {
      const chipId = (buf[base + 12] ?? 0) | ((buf[base + 13] ?? 0) << 8);
      const arch = ESP_CHIP_ARCH.get(chipId);
      if (arch) return { arch, endianness: 'little' };
    }
  }
  return { arch: 'unknown', endianness: 'little' };
}

/**
 * Best-effort image identity from the signature hits + entropy. The class decision is ordered so that a
 * device-family landmark (ESP partition table, PICOBIN block, UEFI volume, FIT/UBI container) wins over a
 * coincidental short filesystem magic, and the whole-image encrypted gate is consulted before a weak (2-byte)
 * JFFS2 magic may assert a Linux rootfs. This is what stops ESP32 / RP2350 / encrypted-OTA / FIT-UBI images all
 * collapsing to `embedded-linux` / `jffs2` (docs/AUTONOMOUS-WORKERS.md §3.1). `entropy` is optional; when
 * omitted the encrypted gate is simply skipped.
 */
export function inferIdentity(buf: Uint8Array, hits: SignatureHit[], entropy?: EntropyProfile | null): ImageIdentity {
  const ids = new Set(hits.map((h) => h.id));
  const strongFs = STRONG_FS_IDS.filter((f) => ids.has(f));
  const jffs2Nodes = corroboratedJffs2Nodes(buf, hits);
  const picobin = parsePicobin(buf);

  let firmwareClass: FirmwareClass = 'unknown';
  let classRationale: string | undefined;
  let arch: Architecture;
  let endianness: Endianness;
  // Whether the resolved class is a genuine filesystem-bearing image (so the detected fs list is meaningful).
  let filesystemClass = false;

  if (ids.has('esp-parttable')) {
    firmwareClass = 'esp-soc';
    ({ arch, endianness } = espArch(buf));
    classRationale =
      'ESP SoC flash dump (partition table @ 0x8000). Not a Linux image — the rootfs pipeline does not apply; ' +
      'analyze the partition table, app images and the NVS key/value store (worker W6).';
  } else if (picobin) {
    firmwareClass = 'baremetal';
    arch = picobin.cpu === 'riscv' ? 'riscv' : picobin.cpu === 'arm' ? 'arm' : 'unknown';
    endianness = arch === 'unknown' ? 'unknown' : 'little';
    const cpuLabel = picobin.cpu === 'riscv' ? 'RISC-V' : picobin.cpu === 'arm' ? 'Arm Cortex-M' : 'an undeclared CPU';
    const chipLabel = picobin.chip ? `${picobin.chip.toUpperCase()} ` : '';
    classRationale = `Bare-metal ${chipLabel}image (PICOBIN, ${cpuLabel}). No filesystem; disassembly must target the declared ISA — reading RISC-V as Arm (or vice-versa) yields garbage (worker W7).`;
  } else if (ids.has('uefi-fv')) {
    firmwareClass = 'uefi-bios';
    ({ arch, endianness } = inferArch(buf, hits));
    classRationale = 'UEFI/BIOS platform firmware (firmware volumes) — analyzed offline by chipsec, not emulated.';
  } else if (isFitUbi(hits)) {
    firmwareClass = 'openwrt-fit-ubi';
    ({ arch, endianness } = inferArch(buf, hits));
    filesystemClass = true;
    classRationale =
      'OpenWrt-style FIT container wrapping a UBI image. A single-pass extractor returns 0 files here — a rootfs ' +
      'only appears after the FIT→UBI→volume→SquashFS carve (worker W1).';
  } else if (strongFs.length > 0) {
    firmwareClass = 'embedded-linux';
    filesystemClass = true;
    ({ arch, endianness } = inferArch(buf, hits));
  } else if (ids.has('uimage') || ids.has('trx') || ids.has('android-boot')) {
    firmwareClass = 'embedded-linux';
    filesystemClass = true;
    ({ arch, endianness } = inferArch(buf, hits));
  } else if (entropy?.likelyEncrypted) {
    firmwareClass = 'encrypted';
    ({ arch, endianness } = inferArch(buf, hits));
    classRationale = `Whole-image high entropy (mean ${entropy.mean.toFixed(2)} bits/byte) with no recognizable container header — the image is likely encrypted and cannot be extracted without the key (worker W8).`;
  } else if (jffs2Nodes >= 4) {
    firmwareClass = 'embedded-linux';
    filesystemClass = true;
    ({ arch, endianness } = inferArch(buf, hits));
  } else if (ids.has('arm-zimage') || ids.has('elf')) {
    firmwareClass = 'rtos';
    ({ arch, endianness } = inferArch(buf, hits));
  } else {
    ({ arch, endianness } = inferArch(buf, hits));
  }

  // Only report a filesystem inventory for classes that actually carry one — never surface the coincidental
  // JFFS2 magics that led an ESP/encrypted/bare-metal blob to look like a Linux rootfs.
  const filesystems: string[] = [];
  if (filesystemClass) {
    for (const f of strongFs) filesystems.push(f.replace(/-(le|be)$/, ''));
    if (jffs2Nodes >= 4) filesystems.push('jffs2');
    if (ids.has('yaffs2')) filesystems.push('yaffs2');
  }

  const bootloader = ids.has('uimage') ? 'U-Boot (uImage)' : undefined;

  return {
    firmwareClass,
    arch,
    endianness,
    filesystems: [...new Set(filesystems)],
    ...(bootloader ? { bootloader } : {}),
    ...(classRationale ? { classRationale } : {}),
  };
}

/**
 * Derive arch + endianness statically: prefer a decoded ELF header (authoritative on both fields), else fall
 * back to a U-Boot uImage `ih_arch` code (arch only — uImage carries no endianness). Post-extraction probing
 * of the rootfs (see the API extract provider) can refine this further.
 */
function inferArch(_buf: Uint8Array, hits: SignatureHit[]): { arch: Architecture; endianness: Endianness } {
  const elf = hits.find((h) => h.id === 'elf' && h.meta);
  if (elf?.meta) {
    return decodeElfArch(Number(elf.meta.machine), elf.meta.endian === 'big', Number(elf.meta.bits) || 32);
  }
  const uimage = hits.find((h) => h.id === 'uimage' && h.meta);
  if (uimage?.meta && typeof uimage.meta.archCode === 'number') {
    const arch = ubootArch(uimage.meta.archCode);
    if (arch !== 'unknown') return { arch, endianness: 'unknown' };
  }
  return { arch: 'unknown', endianness: 'unknown' };
}
