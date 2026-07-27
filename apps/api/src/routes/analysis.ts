/**
 * Read-only analysis views over the cached static analysis: identity, entropy profile, structure map,
 * signatures, and secrets. These back the workbench tabs (Entropy, Structure/binwalk map, Secrets). All data
 * is served from the persisted analysis JSON, so these routes are cheap and never re-read the image.
 */
import fs from 'node:fs';
import type { ImageIdentity, StaticAnalysis } from '@firmlab/core';
import type { FastifyInstance } from 'fastify';
import { analyzeImageBuffer } from '../analysis.js';
import { rowToFinding } from '../findings.js';
import { getImage, listFindings, listImages, updateImageAnalysis } from '../store.js';

function loadAnalysis(id: string): StaticAnalysis | null {
  const row = getImage(id);
  if (!row?.analysisJson) return null;
  return JSON.parse(row.analysisJson) as StaticAnalysis;
}

export async function analysisRoutes(app: FastifyInstance): Promise<void> {
  /**
   * Re-run the intake analysis over an image's stored bytes.
   *
   * `identityJson` is written once, at upload, and never refreshed — so every image ingested before a W0
   * classification improvement keeps the class it was given then. On this deployment that meant all 16 corpus
   * images still reported `embedded-linux` long after eCos→`rtos`, ESP→`esp-soc`, `encrypted` and
   * `openwrt-fit-ubi` landed, and BOTH `specsForClass` (W9's plan) and the coverage banner route off that stale
   * class — so they were planning and reporting against the wrong device class. Re-uploading was the only
   * workaround, which also discards the image's findings and job history.
   *
   * The bytes are re-read from disk, so this is a pure recomputation: nothing else about the image changes.
   */
  app.post('/images/:id/analysis', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const before = row.identityJson ? (JSON.parse(row.identityJson) as ImageIdentity).firmwareClass : null;
    try {
      const analysis = analyzeImageBuffer(fs.readFileSync(row.path));
      updateImageAnalysis(id, 'ready', JSON.stringify(analysis.identity), JSON.stringify(analysis));
      return {
        id,
        before,
        after: analysis.identity.firmwareClass,
        changed: before !== analysis.identity.firmwareClass,
        identity: analysis.identity,
      };
    } catch (err) {
      // Leave the stored analysis alone on failure: a stale class is bad, but replacing it with nothing while
      // reporting success would be worse.
      return reply
        .status(500)
        .send({ error: `Re-analysis failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  });

  /**
   * Re-analyze the whole corpus. Answers "which of my images are planning off a class that predates the current
   * classifier?" in one call, and reports each change rather than silently rewriting the bench.
   */
  app.post('/analysis/reanalyze-all', async () => {
    const results: { id: string; filename: string; before: string | null; after: string | null; error?: string }[] = [];
    for (const row of listImages()) {
      const before = row.identityJson ? (JSON.parse(row.identityJson) as ImageIdentity).firmwareClass : null;
      try {
        const analysis = analyzeImageBuffer(fs.readFileSync(row.path));
        updateImageAnalysis(row.id, 'ready', JSON.stringify(analysis.identity), JSON.stringify(analysis));
        results.push({ id: row.id, filename: row.filename, before, after: analysis.identity.firmwareClass });
      } catch (err) {
        results.push({
          id: row.id,
          filename: row.filename,
          before,
          after: before,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    const changed = results.filter((r) => !r.error && r.before !== r.after);
    return {
      total: results.length,
      changed: changed.length,
      failed: results.filter((r) => r.error).length,
      results,
    };
  });

  app.get('/images/:id/analysis', async (req, reply) => {
    const { id } = req.params as { id: string };
    const analysis = loadAnalysis(id);
    if (!analysis) return reply.status(404).send({ error: 'No analysis for this image' });
    return { analysis };
  });

  app.get('/images/:id/entropy', async (req, reply) => {
    const { id } = req.params as { id: string };
    const analysis = loadAnalysis(id);
    if (!analysis) return reply.status(404).send({ error: 'No analysis for this image' });
    return { size: analysis.size, entropy: analysis.entropy };
  });

  app.get('/images/:id/structure', async (req, reply) => {
    const { id } = req.params as { id: string };
    const analysis = loadAnalysis(id);
    if (!analysis) return reply.status(404).send({ error: 'No analysis for this image' });
    return { size: analysis.size, structure: analysis.structure, signatures: analysis.signatures };
  });

  app.get('/images/:id/secrets', async (req, reply) => {
    const { id } = req.params as { id: string };
    const analysis = loadAnalysis(id);
    if (!analysis) return reply.status(404).send({ error: 'No analysis for this image' });
    return { secrets: analysis.secrets };
  });

  // The normalized findings ledger across all providers, each carrying an explicit proof state.
  app.get('/images/:id/findings', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    return { findings: listFindings(id).map(rowToFinding) };
  });
}
