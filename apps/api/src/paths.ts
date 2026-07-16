/**
 * Filesystem layout for the API. Everything the workbench persists lives under a single data root so a local
 * Docker deployment can bind-mount one directory. Overridable with FIRMLAB_DATA_DIR.
 */
import fs from 'node:fs';
import path from 'node:path';

export const DATA_DIR = process.env.FIRMLAB_DATA_DIR
  ? path.resolve(process.env.FIRMLAB_DATA_DIR)
  : path.resolve(process.cwd(), 'data');

/** Uploaded firmware images, one directory per image id. */
export const IMAGES_DIR = path.join(DATA_DIR, 'images');

/** Extracted rootfs / carve output, one directory per image id. */
export const EXTRACT_DIR = path.join(DATA_DIR, 'extract');

/** SQLite database file. */
export const DB_PATH = path.join(DATA_DIR, 'firmlab.db');

/** Directory holding the built web UI (served in production). */
export const WEB_DIST_DIR = process.env.FIRMLAB_WEB_DIST
  ? path.resolve(process.env.FIRMLAB_WEB_DIST)
  : path.resolve(process.cwd(), '../web/dist');

export function ensureDataDirs(): void {
  for (const dir of [DATA_DIR, IMAGES_DIR, EXTRACT_DIR]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}
