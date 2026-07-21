/**
 * Active web-probe routes (FSTM-7) — drive a booted firmware service for command injection / path traversal. The
 * target URL is the operator's own emulated service (e.g. the port a full-system boot forwards). A reproduced hit
 * is real dynamic evidence and is synced into the findings ledger as `confirmed_in_emulation`.
 */
import type { FastifyInstance } from 'fastify';
import { type FindingDraft, syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { runWebProbe } from '../providers/webprobe.js';
import { getImage, listJobs } from '../store.js';

export async function webprobeRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/webprobe', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const body = (req.body ?? {}) as { url?: string; maxRequests?: number };
    const url = (body.url ?? '').trim();
    // Only loopback / private targets: this drives YOUR emulated service, never a third party on the internet.
    if (!isLocalTarget(url)) {
      return reply.status(400).send({
        error: 'Provide the URL of your booted emulated service (localhost / 127.0.0.1 / a private LAN address)',
      });
    }
    const maxRequests = body.maxRequests ? Math.min(500, Math.max(10, Number(body.maxRequests))) : undefined;
    const jobId = startJob(id, 'webprobe', { url, maxRequests }, async () => {
      const result = await runWebProbe(url, maxRequests ? { maxRequests } : {});
      const drafts: FindingDraft[] = result.findings.map((f) => ({
        kind: f.kind,
        title: f.title,
        severity: f.severity,
        proofState: f.proofState,
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

/** Guard: only loopback or RFC-1918 private targets — the probe drives your own sandboxed service, not the internet. */
export function isLocalTarget(url: string): boolean {
  try {
    const h = new URL(url).hostname;
    if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return true;
    if (/^10\./.test(h) || /^192\.168\./.test(h)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
    return false;
  } catch {
    return false;
  }
}
