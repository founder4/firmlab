/**
 * Export-reachability routes — the way to ask a library or a kernel module a question at all.
 *
 * `symreach` refuses these targets for a good reason: it explores from an entry point and neither has one. This
 * route takes the same kind of target and asks the question they DO admit — is a sink on a control-flow path
 * from an exported function? — so an operator staring at a vendor `.so` or a proprietary `.ko` is no longer
 * holding a prover they cannot point at anything.
 *
 * Findings sync under `exportreach:<path>`, its own source, deliberately NOT shared with `symreach:<path>`. The
 * two make different claims about the same file and merging their sources would let a weaker row silently
 * replace a stronger one on the next run — the deletion bug this ledger has already paid for once.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { isElfFile } from '../providers/binvuln.js';
import { resolveInsideRootfs } from '../providers/decompile.js';
import { runExportReach, sinksFor } from '../providers/exportreach.js';
import { startJob } from '../providers/jobs.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { validateSinkNames } from '../providers/symreach.js';
import { getImage, listJobs } from '../store.js';

const STAGE: RootfsStage = {
  stage: 'exportreach',
  needs: 'export reachability',
  note: 'No object was examined, which is not the same as no object carrying a reachable sink.',
};

/** The stable source string. One per target, so two objects never clobber each other's rows. */
export function exportReachSource(binary: string): string {
  return `exportreach:${binary}`;
}

export async function exportReachRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/exportreach', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });

    const gate = gateOnRootfs(STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const rootfsPath = gate.rootfsPath;

    const body = (req.body ?? {}) as { binary?: string; sinks?: unknown; budgetSeconds?: unknown };
    const binary = typeof body.binary === 'string' ? body.binary.trim() : '';
    if (!binary) return reply.status(400).send({ error: 'No target object specified' });

    const abs = resolveInsideRootfs(rootfsPath, binary);
    if (!abs) return reply.status(400).send({ error: `'${binary}' is not a file inside the extracted rootfs` });
    if (!isElfFile(abs)) {
      return reply.status(400).send({ error: `'${binary}' is not an ELF — this probe recovers a control-flow graph` });
    }

    const rawSinks = Array.isArray(body.sinks) ? body.sinks.filter((s): s is string => typeof s === 'string') : [];
    const { valid, rejected } = validateSinkNames(rawSinks);
    if (rejected.length > 0) {
      return reply.status(400).send({
        error: `Not symbol names: ${rejected.join(', ')} — a sink is a function symbol, e.g. strcpy, __kmalloc`,
      });
    }
    // Blank sinks default by target class rather than refusing: unlike the symbolic prober, an absent symbol here
    // costs microseconds to answer, so a sensible default set is cheaper than making the operator guess.
    const sinks = valid.length > 0 ? valid : [...sinksFor(binary)];

    const budgetSeconds =
      typeof body.budgetSeconds === 'number' && Number.isFinite(body.budgetSeconds)
        ? Math.round(body.budgetSeconds)
        : undefined;

    const jobId = startJob(id, 'exportreach', { binary, sinks, budgetSeconds }, async (handle) => {
      const result = await runExportReach(abs, binary, {
        sinks,
        ...(budgetSeconds ? { budgetSeconds } : {}),
      });
      handle.log(result.reason);
      syncFindings(id, exportReachSource(binary), result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/exportreach', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id)
      .filter((j) => j.kind === 'exportreach' && j.status === 'done' && j.resultJson)
      .map((j) => JSON.parse(j.resultJson as string));
    return { results: done };
  });
}
