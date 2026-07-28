/**
 * Data retention for the local data volume. Uploaded images and their carved rootfs can be large, and the
 * store only removes them on an explicit DELETE — so without a sweep the `firmlab-data` volume grows without
 * bound. This module enforces an optional age cap and total-size quota (both off by default) and reports usage.
 *
 *   FIRMLAB_MAX_IMAGE_AGE_DAYS  delete images older than N days   (0/unset = no age limit)
 *   FIRMLAB_MAX_DATA_BYTES      keep total images+extracts under N bytes, evicting oldest first (0/unset = off)
 *   FIRMLAB_RETENTION_SWEEP_MS  sweep interval (default 6h); a sweep also runs once at startup
 *
 * The research advisory cache under the same data root has its own two caps and its own reasons for them (it keeps
 * expired entries on purpose — see `research/cache.ts`), so it is swept on this schedule but decided over there:
 * the selection logic is pure and unit-tested, which it could not be in this module, since a test cannot load
 * anything that imports `store.js`. The two sets of limits are independent — either sweep runs with the other off.
 */
import fs from 'node:fs';
import path from 'node:path';
import { EXTRACT_DIR, IMAGES_DIR } from './paths.js';
import { measureResearchCache, sweepResearchCache } from './research/cache.js';
import { deleteImage, imagesWithActiveSessions, listImages } from './store.js';

const MAX_AGE_DAYS = Math.max(0, Number(process.env.FIRMLAB_MAX_IMAGE_AGE_DAYS ?? 0));
const MAX_DATA_BYTES = Math.max(0, Number(process.env.FIRMLAB_MAX_DATA_BYTES ?? 0));
export const SWEEP_INTERVAL_MS = Math.max(60_000, Number(process.env.FIRMLAB_RETENTION_SWEEP_MS ?? 6 * 3600 * 1000));

/** Recursively sum file sizes under a directory, bounded so a pathological tree can't stall the sweep. */
function dirSize(dir: string, budget = 500_000): number {
  let total = 0;
  const stack = [dir];
  let visited = 0;
  while (stack.length > 0 && visited < budget) {
    const cur = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      visited++;
      const abs = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(abs);
      else if (e.isFile()) {
        try {
          total += fs.statSync(abs).size;
        } catch {
          // vanished mid-sweep — ignore
        }
      }
    }
  }
  return total;
}

export interface StorageUsage {
  imageCount: number;
  imagesBytes: number;
  extractsBytes: number;
  /** Images + extracts. This, and only this, is what `FIRMLAB_MAX_DATA_BYTES` governs — see the note below. */
  totalBytes: number;
  quotaBytes: number;
  maxAgeDays: number;
  /**
   * The advisory cache, reported BESIDE the image quota rather than inside it. Every field below is optional
   * forever: a client compiled against an older shape must not assert they exist, and a payload that predates
   * them must not become a crash.
   */
  researchCacheBytes?: number;
  researchCacheEntries?: number;
  /** True when the cache walk hit its budget: the two numbers above are then a floor, not the total. */
  researchCacheTruncated?: boolean;
  /** The sentence that carries the two numbers and, when they are a floor, says so. */
  researchCacheNote?: string;
}

/**
 * What the data root currently holds. The research advisory cache is measured too — it is the one directory here
 * that grows without an image behind it, which is why it has caps of its own, and it was invisible in usage until
 * now.
 *
 * It is reported separately and is NOT added into `totalBytes`, because `totalBytes` is the number
 * `sweepRetention` compares against `FIRMLAB_MAX_DATA_BYTES` and that quota evicts IMAGES. Folding cache growth
 * into it would make the image sweep delete firmware to compensate for a directory it does not control, under a
 * cap that was never about it. The cache has its own two knobs; this states what it costs.
 *
 * Measuring never sweeps: `measureResearchCache` walks and sums, and deletes nothing whatever the caps say.
 */
export function storageUsage(): StorageUsage {
  const imagesBytes = dirSize(IMAGES_DIR);
  const extractsBytes = dirSize(EXTRACT_DIR);
  const cache = measureResearchCache();
  return {
    imageCount: listImages().length,
    imagesBytes,
    extractsBytes,
    totalBytes: imagesBytes + extractsBytes,
    quotaBytes: MAX_DATA_BYTES,
    maxAgeDays: MAX_AGE_DAYS,
    researchCacheBytes: cache.bytes,
    researchCacheEntries: cache.entryCount,
    researchCacheTruncated: cache.truncated,
    researchCacheNote: cache.note,
  };
}

/** Remove an image's DB row and its on-disk image + extract directories. */
function purge(id: string): void {
  deleteImage(id);
  fs.rmSync(path.join(IMAGES_DIR, id), { recursive: true, force: true });
  fs.rmSync(path.join(EXTRACT_DIR, id), { recursive: true, force: true });
}

/**
 * Enforce the configured age cap, then the size quota (evicting oldest-first until under). No-op when neither
 * limit is set. Returns the ids it removed — image ids only: the research cache is swept here too, but it evicts
 * files, not images, and conflating the two would put paths in a list of ids every caller reads as images.
 * Safe to call repeatedly.
 */
export function sweepRetention(log: (line: string) => void = () => {}): string[] {
  // Before the early return below: the advisory cache's caps are configured separately, so it must be swept even
  // when the image limits are off. With its own caps unset it walks the directory and deletes nothing.
  sweepResearchCache({ log });

  if (MAX_AGE_DAYS === 0 && MAX_DATA_BYTES === 0) return [];
  const removed: string[] = [];
  // An image with a live agent session is pinned: evicting it would pull the ground truth out from under a
  // running/awaiting-approval session and break its (auditable, resumable) transcript. Skip these entirely.
  const pinned = imagesWithActiveSessions();

  if (MAX_AGE_DAYS > 0) {
    const cutoff = Date.now() - MAX_AGE_DAYS * 24 * 3600 * 1000;
    for (const img of listImages()) {
      if (img.uploadedAt < cutoff && !pinned.has(img.id)) {
        purge(img.id);
        removed.push(img.id);
        log(`retention: pruned ${img.id} (${img.filename}) — older than ${MAX_AGE_DAYS}d`);
      }
    }
  }

  if (MAX_DATA_BYTES > 0) {
    let total = storageUsage().totalBytes;
    // Oldest first (listImages is newest-first).
    const oldestFirst = [...listImages()].sort((a, b) => a.uploadedAt - b.uploadedAt);
    for (const img of oldestFirst) {
      if (total <= MAX_DATA_BYTES) break;
      if (pinned.has(img.id)) continue; // pinned by an active session — never evict
      const before = dirSize(path.join(IMAGES_DIR, img.id)) + dirSize(path.join(EXTRACT_DIR, img.id));
      purge(img.id);
      removed.push(img.id);
      total -= before;
      log(`retention: evicted ${img.id} (${img.filename}) — over ${MAX_DATA_BYTES}B quota`);
    }
  }

  return removed;
}
