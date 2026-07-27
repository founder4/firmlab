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
import type { Architecture, ImageIdentity } from '@firmlab/core';
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { assessBinaryFile, isElfFile } from '../providers/binvuln.js';
import { resolveInsideRootfs } from '../providers/decompile.js';
import { runDynProbe } from '../providers/dynprobe-run.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import {
  MAX_BUDGET_SECONDS,
  MIN_BUDGET_SECONDS,
  type SymReachResult,
  manualSource,
  runSymReach,
  validateSinkNames,
} from '../providers/symreach.js';
import { getImage, listJobs } from '../store.js';

/** The most recent successful extraction, if any. */
function latestExtract(imageId: string): ExtractResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return done?.resultJson ? (JSON.parse(done.resultJson) as ExtractResult) : null;
}

/** The most recent successful extraction's rootfs, if any — the probe needs a real file to load. */
function latestRootfs(imageId: string): string | null {
  return latestExtract(imageId)?.rootfsPath ?? null;
}

/**
 * The architecture to emulate a ROOTFS BINARY with.
 *
 * The image-level `identity.arch` is a guess made from the raw firmware bytes and is routinely `unknown` — DVRF's
 * is. Extraction, by contrast, reads the ELF headers of the very binaries about to be run and takes the modal
 * answer (`mipsel` there, across 218 of them). Preferring the guess over the measurement was backwards, and it
 * refused a probe that had everything it needed.
 */
export function rootfsArch(imageId: string, identity: ImageIdentity | null): Architecture | null {
  const detected = latestExtract(imageId)?.detectedArch;
  if (detected && detected !== 'unknown') return detected;
  const fromIdentity = identity?.arch;
  return fromIdentity && fromIdentity !== 'unknown' ? fromIdentity : null;
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
        // Deliberately "mentions", not "imports": the sweep reads symbol tokens out of the binary's printable
        // strings, which is a SUPERSET of the real imports. Validating over MCP, `sbin/chkntfs` was suggested for
        // `system` on that basis and angr then resolved no PLT/symbol entry at all — an honest `absent`, but the
        // suggestion had promised more than the evidence carries.
        const hint = a.cmdExec.length
          ? ` Its symbols mention ${a.cmdExec.join(', ')} — command-exec sinks worth asking about (read from the binary's strings, so a mention is not proof of a real import).`
          : ' Nothing obviously dangerous is mentioned, but any symbol this binary calls can still be asked about.';
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
      syncFindings(id, manualSource(binary, sinks), result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  /**
   * Dynamic reproduction. `symreach` proves a sink is reachable and stops at a static claim; this runs the binary
   * under qemu-user with a cyclic input and a breakpoint on that exact call site, so the lead can finally be
   * settled instead of staying a lead. Addresses default to the ones the symreach run already recorded.
   */
  app.post('/images/:id/dynprobe', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply.status(400).send({ error: 'Run extraction first — dynamic reproduction needs an extracted rootfs' });
    }
    const body = (req.body ?? {}) as {
      binary?: string;
      sink?: string;
      addresses?: unknown;
      patternLength?: unknown;
    };
    const binary = typeof body.binary === 'string' ? body.binary.trim() : '';
    const sink = typeof body.sink === 'string' ? body.sink.trim() : '';
    if (!binary || !sink) return reply.status(400).send({ error: 'Body must include { binary, sink }' });

    const addresses = Array.isArray(body.addresses)
      ? body.addresses.filter((a): a is string => typeof a === 'string' && /^0x[0-9a-fA-F]+$/.test(a))
      : [];
    if (addresses.length === 0) {
      return reply.status(400).send({
        error: `No sink address to break on. Run POST /images/${id}/symreach on ${binary} first — its result carries the addresses — or pass { addresses: ["0x…"] }.`,
      });
    }
    const identity = row.identityJson ? (JSON.parse(row.identityJson) as ImageIdentity) : null;
    const arch = rootfsArch(id, identity);
    if (!arch) {
      return reply.status(400).send({
        error:
          'No architecture is known for this rootfs — neither the extraction nor the image identity resolved one, so no user-mode emulator can be chosen.',
      });
    }
    const patternLength =
      typeof body.patternLength === 'number' && Number.isFinite(body.patternLength)
        ? Math.round(body.patternLength)
        : undefined;

    const jobId = startJob(id, 'dynprobe', { binary, sink, addresses, patternLength }, async (handle) => {
      const result = await runDynProbe(rootfsPath, binary, sink, addresses, arch, handle, patternLength);
      // Keyed per binary+sink so probing a different sink adds rows rather than replacing the previous answer.
      syncFindings(id, `dynprobe:${binary}#${sink}`, result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/dynprobe', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'dynprobe' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });

  /** The latest completed probe for this image (whichever binary it asked about). */
  app.get('/images/:id/symreach', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'symreach' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? (JSON.parse(done.resultJson) as SymReachResult) : null };
  });
}
