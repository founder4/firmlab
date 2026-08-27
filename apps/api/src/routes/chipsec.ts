/**
 * chipsec routes — the UEFI/BIOS analysis track. chipsec is an opt-in offline layer (parses firmware volumes,
 * carves EFI modules); with it absent the job degrades honestly (available:false / blocked_by_platform). A
 * successful decode is `static_confirmed` — a fact about the image bytes, never a device claim — and its UEFI
 * findings (module inventory, IOC matches, embedded-application leads) are synced into the findings ledger.
 */
import type { FastifyInstance } from 'fastify';
import { type FindingDraft, syncFindings } from '../findings.js';
import { type ChipsecResult, detectChipsec, runChipsec } from '../providers/chipsec.js';
import {
  DEFAULT_TIMEOUT_MS,
  hasActiveFwHuntJob,
  hasActiveOpacidadJob,
  latestFwHuntResult,
  nextModuleBatch,
  runFwHunt,
} from '../providers/fwhunt.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

/** Map the provider's UEFI findings onto finding drafts for the ledger (idempotent re-sync per image). */
function syncChipsecFindings(imageId: string, result: ChipsecResult): void {
  const drafts: FindingDraft[] = result.findings.map((f) => ({
    kind: f.kind,
    title: f.title,
    severity: f.severity,
    proofState: f.proofState,
    evidence: f.evidence,
    rationale: f.rationale,
  }));
  syncFindings(imageId, 'chipsec', drafts);
}

export async function chipsecRoutes(app: FastifyInstance): Promise<void> {
  app.get('/chipsec/status', async () => ({ available: await detectChipsec() }));

  app.post('/images/:id/chipsec', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const body = (req.body ?? {}) as { seconds?: number };
    const opts: { seconds?: number } = {};
    if (body.seconds) opts.seconds = Math.min(180, Math.max(5, Number(body.seconds)));
    const jobId = startJob(id, 'chipsec', {}, async () => {
      const result = await runChipsec(row.path, opts);
      syncChipsecFindings(id, result);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/chipsec', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'chipsec' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });

  /**
   * FwHunt implant scan. Served next to chipsec because it answers the question chipsec's module inventory raises
   * and cannot settle — "is any of this a known implant?" — using the upstream rule corpus rather than a GUID list
   * FirmLab would have had to invent.
   */
  app.post('/images/:id/fwhunt', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const jobs = listJobs(id);
    if (hasActiveFwHuntJob(jobs) || hasActiveOpacidadJob(jobs)) {
      return reply
        .status(409)
        .send({ error: 'FwHunt is already owned by a queued/running FwHunt or autonomous job for this image' });
    }

    const body = (req.body ?? {}) as { moduleBatch?: unknown; restart?: unknown };
    if (
      body.moduleBatch !== undefined &&
      (typeof body.moduleBatch !== 'number' || !Number.isSafeInteger(body.moduleBatch) || body.moduleBatch < 0)
    ) {
      return reply.status(400).send({ error: 'moduleBatch must be a non-negative integer (zero-based)' });
    }
    if (body.restart !== undefined && typeof body.restart !== 'boolean') {
      return reply.status(400).send({ error: 'restart must be a boolean' });
    }
    if (body.restart === true && body.moduleBatch !== undefined) {
      return reply.status(400).send({ error: 'restart and moduleBatch cannot be supplied together' });
    }
    // An unavailable/no-carve attempt carries no resumable evidence. The shared lookup keeps this route and the
    // autonomous orchestrator on the same newest durable campaign; the provider still fingerprint-checks it.
    const previous = latestFwHuntResult(jobs);
    if (
      typeof body.moduleBatch === 'number' &&
      previous?.modulePass &&
      previous.modulePass.batchCount > 0 &&
      body.moduleBatch >= previous.modulePass.batchCount
    ) {
      return reply.status(400).send({
        error: `moduleBatch ${body.moduleBatch} is outside the known zero-based range 0-${previous.modulePass.batchCount - 1}`,
      });
    }
    const restarting = body.restart === true;
    const moduleBatch = restarting ? 0 : (body.moduleBatch ?? nextModuleBatch(previous?.modulePass));
    if (moduleBatch === null) {
      return reply.status(409).send({ error: 'All FwHunt module batches are already complete for this image' });
    }

    const jobId = startJob(id, 'fwhunt', { moduleBatch, restart: restarting }, async (handle) => {
      const result = await runFwHunt(row.path, handle, DEFAULT_TIMEOUT_MS, {
        moduleBatch,
        previousModulePass: restarting ? null : (previous?.modulePass ?? null),
      });
      syncFindings(id, 'fwhunt', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/fwhunt', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'fwhunt' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
