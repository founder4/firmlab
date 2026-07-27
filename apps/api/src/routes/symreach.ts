/**
 * Symbolic-reachability routes — the manual way in to angr.
 *
 * Until now the prober had exactly one caller: W9 handed it the top few `binary-pwnable-candidate` leads that the
 * W5 sweep happened to flag, capped per run. That is a fine default and a terrible ceiling — it means the operator
 * owns a working symbolic prover they cannot ask anything. The interesting question is usually NOT "is strcpy
 * reachable in some ELF the sweep noticed"; it is "is `system` reachable in *this* CGI I am staring at", and the
 * sweep never poses it because `system` is not an unbounded copy and the CGI may well have a canary.
 *
 * So POST takes any rootfs binary and any sink names. The provider stays the judge of what it can answer: a symbol
 * the binary does not import comes back `absent`, a bounded search that runs out stays `needs_runtime_reproduction`,
 * and angr missing is `blocked_by_platform`. Findings sync under the SAME `symreach:<path>` source W9 uses, so a
 * manual probe and an autonomous one re-sync the same rows instead of duplicating them.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { assessBinaryFile, isElfFile } from '../providers/binvuln.js';
import { resolveInsideRootfs } from '../providers/decompile.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import {
  MAX_BUDGET_SECONDS,
  MIN_BUDGET_SECONDS,
  type SymReachResult,
  runSymReach,
  validateSinkNames,
} from '../providers/symreach.js';
import { getImage, listJobs } from '../store.js';

/** The most recent successful extraction's rootfs, if any — the probe needs a real file to load. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

export async function symreachRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/symreach', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });

    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply
        .status(400)
        .send({ error: 'Run extraction first — symbolic reachability needs an extracted rootfs' });
    }

    const body = (req.body ?? {}) as { binary?: string; sinks?: unknown; budgetSeconds?: unknown };
    const binary = typeof body.binary === 'string' ? body.binary.trim() : '';
    if (!binary) return reply.status(400).send({ error: 'No target binary specified' });

    const abs = resolveInsideRootfs(rootfsPath, binary);
    if (!abs) return reply.status(400).send({ error: `'${binary}' is not a file inside the extracted rootfs` });
    // angr loads executables. A shell script named as the target is a real mistake worth naming, not a crash later.
    if (!isElfFile(abs)) {
      return reply.status(400).send({ error: `'${binary}' is not an ELF — the symbolic prober loads executables` });
    }

    const rawSinks = Array.isArray(body.sinks) ? body.sinks.filter((s): s is string => typeof s === 'string') : [];
    const { valid: sinks, rejected } = validateSinkNames(rawSinks);
    if (rejected.length > 0) {
      return reply
        .status(400)
        .send({ error: `Not symbol names: ${rejected.join(', ')} — a sink is a function symbol, e.g. strcpy, system` });
    }

    const budgetSeconds =
      typeof body.budgetSeconds === 'number' && Number.isFinite(body.budgetSeconds)
        ? Math.min(MAX_BUDGET_SECONDS, Math.max(MIN_BUDGET_SECONDS, Math.round(body.budgetSeconds)))
        : undefined;

    // No sinks named and nothing unsafe imported: refuse up front WITH the symbol facts, so the operator can name a
    // sink themselves instead of reading "nothing to ask about" and concluding the binary is uninteresting.
    if (sinks.length === 0) {
      const a = assessBinaryFile(abs, binary);
      if (a.unsafeCopy.length === 0) {
        const hint = a.cmdExec.length
          ? ` It does import ${a.cmdExec.join(', ')} — command-exec sinks worth asking about.`
          : ' Nothing obviously dangerous is imported, but any symbol this binary calls can still be asked about.';
        return reply.status(400).send({
          error: `${binary} imports no unbounded-copy function — name the sink you want asked about.${hint}`,
          execImports: a.cmdExec,
        });
      }
    }

    const jobId = startJob(id, 'symreach', { binary, sinks, budgetSeconds }, async (handle) => {
      const result = await runSymReach(rootfsPath, binary, sinks, handle, {
        policy: 'as-given',
        ...(budgetSeconds ? { budgetSeconds } : {}),
      });
      // Same idempotent per-binary source as W9's re-planned probe — re-asking re-syncs rather than duplicating.
      syncFindings(id, `symreach:${binary}`, result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  /** The latest completed probe for this image (whichever binary it asked about). */
  app.get('/images/:id/symreach', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'symreach' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? (JSON.parse(done.resultJson) as SymReachResult) : null };
  });
}
