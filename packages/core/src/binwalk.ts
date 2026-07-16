/**
 * Parse the textual output of `binwalk` (v2 signature scan and v3) into structured signature hits, so the
 * API can fold real binwalk results into the same structure map the built-in scanner produces. binwalk stays
 * an optional enhancement: when the firmware Docker image is built it runs and its richer, format-aware
 * output wins; without it the built-in scanner still yields a usable map.
 */
import type { SignatureCategory, SignatureHit } from './types.js';

/**
 * binwalk signature-scan lines look like:
 *
 *   DECIMAL       HEXADECIMAL     DESCRIPTION
 *   --------------------------------------------------------------------------------
 *   0             0x0             uImage header, header size: 64 bytes, ...
 *   64            0x40            LZMA compressed data, properties: 0x5D, ...
 *   1114112       0x110000        Squashfs filesystem, little endian, version 4.0, ...
 *
 * v3 output is column-compatible for the fields we need (decimal offset + description).
 */
const ROW_RE = /^\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.*\S)\s*$/;

/** Map a binwalk description to our category taxonomy by keyword. */
function categorize(description: string): { category: SignatureCategory; id: string } {
  const d = description.toLowerCase();
  if (d.includes('squashfs')) return { category: 'filesystem', id: 'squashfs' };
  if (d.includes('jffs2')) return { category: 'filesystem', id: 'jffs2' };
  if (d.includes('cramfs')) return { category: 'filesystem', id: 'cramfs' };
  if (d.includes('ubifs') || d.includes('ubi ')) return { category: 'filesystem', id: 'ubifs' };
  if (d.includes('yaffs')) return { category: 'filesystem', id: 'yaffs' };
  if (d.includes('romfs')) return { category: 'filesystem', id: 'romfs' };
  if (d.includes('uimage') || d.includes('u-boot')) return { category: 'bootloader', id: 'uimage' };
  if (d.includes('device tree') || d.includes('flattened')) return { category: 'kernel', id: 'dtb' };
  if (d.includes('linux kernel') || d.includes('zimage')) return { category: 'kernel', id: 'kernel' };
  if (d.includes('elf')) return { category: 'executable', id: 'elf' };
  if (d.includes('lzma')) return { category: 'compression', id: 'lzma' };
  if (d.includes('gzip')) return { category: 'compression', id: 'gzip' };
  if (d.includes('xz compressed')) return { category: 'compression', id: 'xz' };
  if (d.includes('bzip2')) return { category: 'compression', id: 'bzip2' };
  if (d.includes('zstandard') || d.includes('zstd')) return { category: 'compression', id: 'zstd' };
  if (d.includes('lz4')) return { category: 'compression', id: 'lz4' };
  if (d.includes('certificate') || d.includes('private key') || d.includes('public key')) {
    return { category: 'certificate', id: 'cert' };
  }
  if (d.includes('cpio')) return { category: 'container', id: 'cpio' };
  if (d.includes('android')) return { category: 'container', id: 'android-boot' };
  if (d.includes('uefi') || d.includes('firmware volume')) return { category: 'bootloader', id: 'uefi-fv' };
  return { category: 'other', id: 'binwalk' };
}

/** Parse binwalk stdout into signature hits. Header/separator/blank lines are ignored. */
export function parseBinwalkOutput(stdout: string): SignatureHit[] {
  const hits: SignatureHit[] = [];
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    if (/^\s*DECIMAL\b/.test(line)) continue;
    if (/^\s*-{3,}/.test(line)) continue;
    const m = ROW_RE.exec(line);
    if (!m) continue;
    const offset = Number.parseInt(m[1] ?? '', 10);
    const description = (m[2] ?? '').trim();
    if (!Number.isFinite(offset) || !description) continue;
    const { category, id } = categorize(description);
    hits.push({
      offset,
      id,
      description,
      category,
      confidence: 'high',
      meta: { source: 'binwalk' },
    });
  }
  return hits;
}

/**
 * Merge built-in-scanner hits with binwalk hits, preferring binwalk at any offset it also found (its
 * format-aware descriptions are richer). Offsets within `tolerance` bytes are treated as the same landmark.
 */
export function mergeSignatureSources(builtin: SignatureHit[], binwalk: SignatureHit[], tolerance = 4): SignatureHit[] {
  const merged: SignatureHit[] = [...binwalk];
  for (const b of builtin) {
    const dup = binwalk.some((w) => Math.abs(w.offset - b.offset) <= tolerance);
    if (!dup) merged.push(b);
  }
  return merged.sort((a, b) => a.offset - b.offset);
}
