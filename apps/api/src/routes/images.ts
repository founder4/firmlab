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
import { EXTRACT_DIR, IMAGES_DIR } from '../paths.js';
import { sweepRetention } from '../retention.js';
import { deleteImage, getImage, insertImage, listImages, updateImageAnalysis } from '../store.js';

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
    });

    try {
      const analysis = analyzeImageBuffer(buf);
      updateImageAnalysis(id, 'ready', JSON.stringify(analysis.identity), JSON.stringify(analysis));
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
    fs.rmSync(path.join(IMAGES_DIR, id), { recursive: true, force: true });
    fs.rmSync(path.join(EXTRACT_DIR, id), { recursive: true, force: true });
    deleteImage(id);
    return { deleted: id };
  });
}
