/**
 * AFL++ fuzzing routes (Phase 4 debt #1) — coverage-guided fuzzing of one rootfs binary under the isolation
 * sandbox. AFL++ is an opt-in layer (not baked into the shipped image, like Ghidra), so with it absent the job
 * returns available:false honestly. A reproduced crash is real dynamic evidence.
 */
import type { FastifyInstance } from 'fastify';
import { type FindingDraft, syncFindings } from '../findings.js';
import type { ExtractResult } from '../providers/extract.js';
import { detectFuzzing, runFuzz } from '../providers/fuzz.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

function latestRootfs(imageId: string): string | null {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return job?.resultJson ? ((JSON.parse(job.resultJson) as ExtractResult).rootfsPath ?? null) : null;
}

export async function fuzzRoutes(app: FastifyInstance): Promise<void> {
  app.get('/fuzz/status', async () => ({ available: await detectFuzzing() }));

  app.post('/images/:id/fuzz', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfs = latestRootfs(id);
    if (!rootfs) return reply.status(400).send({ error: 'Run extraction first — fuzzing needs an extracted rootfs' });
    const body = (req.body ?? {}) as { binary?: string; seconds?: number; harness?: string };
    if (!body.binary) return reply.status(400).send({ error: 'No target binary specified' });
    const seconds = Math.min(600, Math.max(10, Number(body.seconds ?? 60)));
    const binary = body.binary;
    const HARNESSES = ['auto', 'file', 'stdin', 'network'] as const;
    const harness = (HARNESSES as readonly string[]).includes(body.harness ?? '')
      ? (body.harness as (typeof HARNESSES)[number])
      : 'auto';
    const jobId = startJob(id, 'fuzz', { binary, seconds, harness }, async (h) => {
      const result = await runFuzz(rootfs, binary, h, { seconds, harness });
      // A reproduced crash is real dynamic evidence — record it as a confirmed finding tied to the binary.
      if (result.crashes > 0) {
        const draft: FindingDraft = {
          kind: 'fuzz-crash',
          title: `Fuzzing crashed ${binary} (${result.crashes} unique crash${result.crashes === 1 ? '' : 'es'})`,
          severity: 'high',
          proofState: 'confirmed_in_emulation',
          evidence: { binary, crashes: result.crashes, samples: result.crashSamples },
          rationale:
            'AFL++ reproduced a crash under isolation — memory-unsafety confirmed in the sandbox (not the device).',
        };
        syncFindings(id, `fuzz:${binary}`, [draft]);
      }
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/fuzz', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'fuzz' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
