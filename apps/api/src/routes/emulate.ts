/**
 * Emulation menu + execution. GET serves the ranked recipe menu for an image (arch/class-aware, augmented
 * with the latest extraction's rootfs + suggested binary). POST runs a user-mode QEMU recipe as a job.
 */
import type { ImageIdentity } from '@firmlab/core';
import type { FastifyInstance } from 'fastify';
import { runChrootService, runFullSystem } from '../providers/emulate-system.js';
import { type PlanContext, planEmulation, runUserModeEmulation } from '../providers/emulate.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { computeRuntimeCapabilities } from '../providers/preflight.js';
import { getImage, listJobs } from '../store.js';

/** Find the most recent successful extraction result for an image, if any. */
function latestExtract(imageId: string): ExtractResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as ExtractResult;
}

function identityOf(imageId: string): ImageIdentity | null {
  const row = getImage(imageId);
  if (!row?.identityJson) return null;
  return JSON.parse(row.identityJson) as ImageIdentity;
}

export async function emulateRoutes(app: FastifyInstance): Promise<void> {
  app.get('/images/:id/emulation', async (req, reply) => {
    const { id } = req.params as { id: string };
    const identity = identityOf(id);
    if (!identity) return reply.status(404).send({ error: 'No analysis for this image' });

    const extract = latestExtract(id);
    const ctx: PlanContext = { identity };
    if (extract?.rootfsPath) ctx.rootfsPath = extract.rootfsPath;
    if (extract?.suggestedBinary) ctx.suggestedBinary = extract.suggestedBinary;

    const recipes = await planEmulation(ctx);
    return {
      identity,
      rootfsReady: Boolean(extract?.rootfsPath),
      suggestedBinary: extract?.suggestedBinary ?? null,
      recipes,
      capabilities: await computeRuntimeCapabilities(id),
    };
  });

  // The deterministic runtime-capability preflight on its own — the honest floor for the proof-state machine.
  app.get('/images/:id/runtime-capabilities', async (req, reply) => {
    const { id } = req.params as { id: string };
    const caps = await computeRuntimeCapabilities(id);
    if (!caps) return reply.status(404).send({ error: 'No analysis for this image' });
    return { capabilities: caps };
  });

  app.post('/images/:id/emulate', async (req, reply) => {
    const { id } = req.params as { id: string };
    const identity = identityOf(id);
    if (!identity) return reply.status(404).send({ error: 'No analysis for this image' });

    const body = (req.body ?? {}) as { binary?: string; args?: string[] };
    const extract = latestExtract(id);
    if (!extract?.rootfsPath) {
      return reply.status(400).send({ error: 'Run extraction first — user-mode emulation needs an extracted rootfs' });
    }
    const target = body.binary ?? extract.suggestedBinary;
    if (!target) {
      return reply.status(400).send({ error: 'No target binary specified and none could be suggested' });
    }

    const rootfsPath = extract.rootfsPath;
    const args = Array.isArray(body.args) ? body.args.map(String) : [];
    const jobId = startJob(id, 'emulate', { binary: target, args }, (handle) =>
      runUserModeEmulation(identity.arch, rootfsPath, target, handle, args),
    );
    return reply.status(202).send({ jobId });
  });

  // Deeper emulation rungs (chroot service / full-system). Asset-gated: the runner returns a blocked result
  // when the libnvram shim / firmadyne kernels aren't baked in (see Dockerfile.firmware), never a half boot.
  app.post('/images/:id/emulate-system', async (req, reply) => {
    const { id } = req.params as { id: string };
    const identity = identityOf(id);
    if (!identity) return reply.status(404).send({ error: 'No analysis for this image' });
    const extract = latestExtract(id);
    if (!extract?.rootfsPath) {
      return reply.status(400).send({ error: 'Run extraction first — system emulation needs an extracted rootfs' });
    }
    const rootfsPath = extract.rootfsPath;
    const body = (req.body ?? {}) as { rung?: string; binary?: string };

    if (body.rung === 'full-system') {
      const jobId = startJob(id, 'emulate', { rung: 'full-system' }, (handle) =>
        runFullSystem(identity.arch, `${rootfsPath}.img`, 8080, handle),
      );
      return reply.status(202).send({ jobId });
    }

    const service = body.binary ?? extract.suggestedBinary;
    if (!service) return reply.status(400).send({ error: 'No target service specified and none could be suggested' });
    const jobId = startJob(id, 'emulate', { rung: 'chroot-service', binary: service }, (handle) =>
      runChrootService(identity.arch, rootfsPath, service, handle),
    );
    return reply.status(202).send({ jobId });
  });
}
