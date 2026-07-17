/**
 * Turn raw signature hits + the entropy profile into a human-facing structure map and a best-effort image
 * identity. This is the deterministic backbone of the "binwalk graphical view" the workbench renders: a
 * ribbon of labeled, colored segments across the image, plus an inferred class/arch/endianness.
 */
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

/**
 * Best-effort image identity from the signature hits. Deliberately cautious: we only assert a class when the
 * evidence is unambiguous (a real filesystem/bootloader/UEFI-volume), else `unknown`.
 */
export function inferIdentity(buf: Uint8Array, hits: SignatureHit[]): ImageIdentity {
  const ids = new Set(hits.map((h) => h.id));
  const filesystems: string[] = [];
  for (const fs of [
    'squashfs-le',
    'squashfs-be',
    'jffs2-le',
    'jffs2-be',
    'cramfs',
    'ubifs',
    'ubi',
    'yaffs2',
    'romfs',
  ]) {
    if (ids.has(fs)) filesystems.push(fs.replace(/-(le|be)$/, ''));
  }

  let firmwareClass: FirmwareClass = 'unknown';
  if (ids.has('uefi-fv')) firmwareClass = 'uefi-bios';
  else if (filesystems.length > 0) firmwareClass = 'embedded-linux';
  else if (ids.has('uimage') || ids.has('trx') || ids.has('android-boot')) firmwareClass = 'embedded-linux';
  else if (ids.has('arm-zimage') || (ids.has('elf') && !filesystems.length)) firmwareClass = 'rtos';

  const { arch, endianness } = inferArch(buf, hits);
  const bootloader = ids.has('uimage') ? 'U-Boot (uImage)' : undefined;

  return {
    firmwareClass,
    arch,
    endianness,
    filesystems: [...new Set(filesystems)],
    ...(bootloader ? { bootloader } : {}),
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
