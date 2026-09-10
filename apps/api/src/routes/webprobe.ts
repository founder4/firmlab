/**
 * Active web-probe routes (FSTM-7) — drive a booted firmware service for command injection / path traversal. The
 * target URL is a loopback service supplied by the operator. Because this route cannot prove that the service is
 * attached to FirmLab's active emulator, its observations remain `needs_runtime_reproduction`; only the in-session
 * emulation caller can create `confirmed_in_emulation` evidence.
 */
import type { FastifyInstance } from 'fastify';
import { type FindingDraft, syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { isLocalTarget } from '../providers/webprobe-transport.js';
import { runWebProbe } from '../providers/webprobe.js';
import { getImage, listJobs } from '../store.js';

export async function webprobeRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/webprobe', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const body = (req.body ?? {}) as { url?: string; maxRequests?: number };
    const url = typeof body.url === 'string' ? body.url.trim() : '';
    // Only loopback: QEMU forwards the image's service there, and this cannot become a LAN-side request primitive.
    if (!isLocalTarget(url)) {
      return reply.status(400).send({
        error: 'Provide a loopback URL for your booted emulated service (localhost / 127.0.0.1 / ::1).',
      });
    }
    const requested = body.maxRequests === undefined ? 200 : Number(body.maxRequests);
    if (!Number.isFinite(requested) || requested < 1) {
      return reply.status(400).send({ error: 'maxRequests must be a positive finite number.' });
    }
    const maxRequests = Math.min(500, Math.max(10, Math.floor(requested)));
    const jobId = startJob(id, 'webprobe', { url, maxRequests }, async () => {
      const result = await runWebProbe(url, maxRequests ? { maxRequests } : {});
      const drafts: FindingDraft[] = result.findings.map((f) => ({
        kind: f.kind,
        title: f.title,
        severity: f.severity,
        proofState: f.proofState,
        ...(f.evidenceChannel ? { evidenceChannel: f.evidenceChannel } : {}),
        evidence: f.evidence,
        rationale: f.rationale,
      }));
      syncFindings(id, 'webprobe', drafts);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/webprobe', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'webprobe' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}

export { isLocalTarget } from '../providers/webprobe-transport.js';
