/**
 * Data retention for the local data volume. Uploaded images and their carved rootfs can be large, and the
 * store only removes them on an explicit DELETE — so without a sweep the `firmlab-data` volume grows without
 * bound. This module enforces an optional age cap and total-size quota (both off by default) and reports usage.
 *
 *   FIRMLAB_MAX_IMAGE_AGE_DAYS  delete images older than N days   (0/unset = no age limit)
 *   FIRMLAB_MAX_DATA_BYTES      keep total images+extracts under N bytes, evicting oldest first (0/unset = off)
 *   FIRMLAB_RETENTION_SWEEP_MS  sweep interval (default 6h); a sweep also runs once at startup
 */
import fs from 'node:fs';
import path from 'node:path';
import { EXTRACT_DIR, IMAGES_DIR } from './paths.js';
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
  totalBytes: number;
  quotaBytes: number;
  maxAgeDays: number;
}

export function storageUsage(): StorageUsage {
  const imagesBytes = dirSize(IMAGES_DIR);
  const extractsBytes = dirSize(EXTRACT_DIR);
  return {
    imageCount: listImages().length,
    imagesBytes,
    extractsBytes,
    totalBytes: imagesBytes + extractsBytes,
    quotaBytes: MAX_DATA_BYTES,
    maxAgeDays: MAX_AGE_DAYS,
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
 * limit is set. Returns the ids it removed. Safe to call repeatedly.
 */
export function sweepRetention(log: (line: string) => void = () => {}): string[] {
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
