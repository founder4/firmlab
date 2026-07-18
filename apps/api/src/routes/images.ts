/**
 * Image intake + lifecycle routes. Upload stores the firmware under a fresh id, runs the deterministic static
 * analysis synchronously (fast, no external tool), and persists identity + analysis for instant view loads.
 */
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import type { FastifyInstance } from 'fastify';
import { analyzeImageBuffer } from '../analysis.js';
import { flagKnownCredentials, recordCredentials } from '../corpus.js';
import { normalizeSecrets, syncFindings } from '../findings.js';
import { EXTRACT_DIR, IMAGES_DIR } from '../paths.js';
import { sweepRetention } from '../retention.js';
import { deleteImage, getImage, insertImage, listImages, updateImageAnalysis, updateImageTags } from '../store.js';

const ALLOWED_EXT = new Set([
  '.bin',
  '.img',
  '.trx',
  '.chk',
  '.dlf',
  '.pkg',
  '.fw',
  '.hex',
  '.axf',
  '.elf',
  '.cap',
  '.rom',
  '.squashfs',
  '.ubi',
  '.ubifs',
  '.jffs2',
  '.cramfs',
  '.dtb',
  '.uimage',
  '.zip',
  '.tar',
  '.gz',
]);

/** Public image summary (never leaks absolute host paths beyond what the UI needs). */
function toSummary(row: ReturnType<typeof getImage>): unknown {
  if (!row) return null;
  return {
    id: row.id,
    filename: row.filename,
    size: row.size,
    sha256: row.sha256,
    uploadedAt: row.uploadedAt,
    status: row.status,
    identity: row.identityJson ? JSON.parse(row.identityJson) : null,
    tags: row.tags ? (JSON.parse(row.tags) as string[]) : [],
  };
}

export async function imageRoutes(app: FastifyInstance): Promise<void> {
  app.get('/images', async () => {
    return { images: listImages().map((row) => toSummary(row)) };
  });

  app.get('/images/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    return { image: toSummary(row) };
  });

  app.post('/images', async (req, reply) => {
    const file = await req.file();
    if (!file) return reply.status(400).send({ error: 'No file uploaded (multipart form with a firmware image)' });

    const safeName = path.basename(file.filename || 'firmware.bin').replace(/[^a-zA-Z0-9._-]+/g, '_');
    const ext = path.extname(safeName).toLowerCase();
    if (ext && !ALLOWED_EXT.has(ext)) {
      return reply.status(400).send({ error: `Unsupported extension ${ext}. Allowed: ${[...ALLOWED_EXT].join(' ')}` });
    }

    const id = randomUUID().slice(0, 8);
    const dir = path.join(IMAGES_DIR, id);
    fs.mkdirSync(dir, { recursive: true });
    const dest = path.join(dir, safeName);

    try {
      await pipeline(file.file, fs.createWriteStream(dest));
    } catch (err) {
      fs.rmSync(dir, { recursive: true, force: true });
      return reply.status(500).send({ error: `Failed to store upload: ${String(err)}` });
    }
    if (file.file.truncated) {
      fs.rmSync(dir, { recursive: true, force: true });
      return reply.status(413).send({ error: 'File exceeds the upload limit' });
    }

    const buf = fs.readFileSync(dest);
    const sha256 = createHash('sha256').update(buf).digest('hex');
    const now = Date.now();

    insertImage({
      id,
      filename: safeName,
      path: dest,
      size: buf.length,
      sha256,
      uploadedAt: now,
      status: 'analyzing',
      identityJson: null,
      analysisJson: null,
      tags: null,
    });

    try {
      const analysis = analyzeImageBuffer(buf);
      updateImageAnalysis(id, 'ready', JSON.stringify(analysis.identity), JSON.stringify(analysis));
      // Seed the findings ledger from the static secret hits (extraction-backed sources sync later, per job).
      syncFindings(id, 'secrets', normalizeSecrets(analysis.secrets));
      // Feed the corpus: classified secrets become cross-image credential occurrences.
      recordCredentials(
        id,
        analysis.secrets
          .filter((s) => s.secretKind)
          .map((s) => ({ value: s.value, kind: s.secretKind ?? null, severity: s.severity ?? null })),
      );
      // Level 1: elevate any secret that matches the known-bad credential watchlist.
      const flagged = flagKnownCredentials(id);
      if (flagged > 0) req.log.info(`Elevated ${flagged} finding(s) via the credential watchlist`);
    } catch (err) {
      req.log.error({ err }, 'static analysis failed');
      updateImageAnalysis(id, 'error', null, null);
    }

    // Enforce the size quota as data grows (no-op unless FIRMLAB_MAX_DATA_BYTES is set); never evicts this
    // upload since eviction is oldest-first.
    sweepRetention((line) => req.log.info(line));

    return reply.status(201).send({ image: toSummary(getImage(id)) });
  });

  app.delete('/images/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    purgeImage(id);
    return { deleted: id };
  });

  // Set the tag list for an image (replaces existing tags).
  app.post('/images/:id/tags', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const body = (req.body ?? {}) as { tags?: unknown };
    const tags = Array.isArray(body.tags)
      ? [...new Set(body.tags.map((t) => String(t).trim()).filter(Boolean))].slice(0, 32)
      : [];
    updateImageTags(id, tags.length > 0 ? JSON.stringify(tags) : null);
    return { image: toSummary(getImage(id)) };
  });

  // Bulk delete.
  app.post('/images/delete', async (req) => {
    const body = (req.body ?? {}) as { ids?: unknown };
    const ids = Array.isArray(body.ids) ? body.ids.map(String) : [];
    const deleted: string[] = [];
    for (const id of ids) {
      if (getImage(id)) {
        purgeImage(id);
        deleted.push(id);
      }
    }
    return { deleted };
  });
}

/** Remove an image row and its on-disk image + extract directories. */
function purgeImage(id: string): void {
  fs.rmSync(path.join(IMAGES_DIR, id), { recursive: true, force: true });
  fs.rmSync(path.join(EXTRACT_DIR, id), { recursive: true, force: true });
  deleteImage(id);
}
