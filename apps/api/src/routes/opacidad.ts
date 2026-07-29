/**
 * Opacidad (W9) routes — the autonomous-scan orchestrator. POST plans + runs the class-routed worker chain as a
 * job (it invokes multiple providers, so it is slow); GET returns the latest run. The LLM narrative is optional:
 * with the agent off, opacidad still runs and composes a deterministic narrative, so this route is never gated
 * behind an API key — only the *phrasing* of the report changes when a model is configured.
 */
import type { ImageIdentity } from '@firmlab/core';
import type { FastifyInstance } from 'fastify';
import { rowToFinding } from '../findings.js';
import { type Locale, resolveLocale } from '../i18n/index.js';
import { loadLlmConfig } from '../llm.js';
import type { OpacidadStep } from '../opacidad-narrative.js';
import { specsForClass } from '../opacidad-plan.js';
import { runOpacidad } from '../opacidad.js';
import { partitionByProvenance } from '../operator-findings.js';
import { type CoverageReport, buildCoverage } from '../providers/coverage.js';
import { startJob } from '../providers/jobs.js';
import { type ImageRow, getImage, listFindings, listImages, listJobs } from '../store.js';

export async function opacidadRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/opacidad', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    if (!row.identityJson) {
      return reply
        .status(400)
        .send({ error: 'No analysis yet — the image must be analyzed before an autonomous scan' });
    }
    const cfg = loadLlmConfig();
    const jobId = startJob(id, 'opacidad', { narrative: cfg ? cfg.provider : 'deterministic' }, async (handle) => {
      handle.log('Autonomous scan (opacidad) starting…');
      const result = await runOpacidad(id, row.path, handle, cfg);
      handle.log(`Autonomous scan complete: ${result.steps.length} workers, ${result.findings.total} findings.`);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/opacidad', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'opacidad' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });

  /**
   * Analysis coverage — what this image's class routes to, what actually executed, and what its finding count does
   * and does not cover. Served next to opacidad because it reads the same class plan and the same run outcomes;
   * computing it here (rather than in the UI) keeps the banner from ever disagreeing with the autonomous scan.
   * Answers before any scan has run too — that is precisely the case the banner exists for.
   *
   * `?lang` picks the language of the verdict sentence. Nothing else about the report moves: the stage ids, the
   * statuses and every number are identifiers and data, and the counts a Spanish reader gets are the same counts.
   * Absent or unrecognised, it is English.
   */
  app.get('/images/:id/coverage', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    return coverageFor(row, resolveLocale((req.query as { lang?: unknown }).lang));
  });

  /**
   * Corpus-wide coverage — the same report, one row per image, so "what has actually been examined?" is answerable
   * without opening sixteen images one at a time. That question is the whole point of the banner: a dashboard that
   * lists images with no coverage column silently presents an unscanned image and a fully-scanned one identically,
   * which is the exact conflation the per-image banner exists to prevent. Same `buildCoverage`, so a row and the
   * image's own banner can never disagree.
   */
  app.get('/coverage', async (req) => {
    const locale = resolveLocale((req.query as { lang?: unknown }).lang);
    return {
      images: listImages().map((row) => {
        const c = coverageFor(row, locale);
        return {
          imageId: row.id,
          filename: row.filename,
          firmwareClass: c.firmwareClass,
          applicable: c.applicable,
          executed: c.executed,
          findingCount: c.findingCount,
          operatorAssertions: c.operatorAssertions,
          ambiguous: c.ambiguous,
          verdict: c.verdict,
        };
      }),
    };
  });
}

/** Build one image's coverage report from its stored identity, its last opacidad run and its finding count. */
function coverageFor(row: ImageRow, locale: Locale = 'en'): CoverageReport {
  let identity: ImageIdentity | null = null;
  try {
    identity = row.identityJson ? (JSON.parse(row.identityJson) as ImageIdentity) : null;
  } catch {
    identity = null;
  }
  const firmwareClass = identity?.firmwareClass ?? 'unknown';

  const done = listJobs(row.id).find((j) => j.kind === 'opacidad' && j.status === 'done' && j.resultJson);
  let steps: OpacidadStep[] | null = null;
  try {
    steps = done?.resultJson ? ((JSON.parse(done.resultJson) as { steps?: OpacidadStep[] }).steps ?? null) : null;
  } catch {
    steps = null;
  }

  // Split before counting. `findingCount` is the stage arithmetic's input, so an assertion reaching it would make
  // a hand-written row read as something a stage produced — the one conflation this whole report exists to stop.
  const { measured, asserted } = partitionByProvenance(listFindings(row.id).map(rowToFinding));

  return buildCoverage({
    firmwareClass,
    ...(identity?.classRationale ? { classRationale: identity.classRationale } : {}),
    specs: specsForClass(firmwareClass),
    steps,
    findingCount: measured.length,
    operatorAssertions: asserted.length,
    locale,
  });
}
