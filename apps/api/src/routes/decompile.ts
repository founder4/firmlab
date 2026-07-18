/**
 * Binary triage intake. POST runs radare2 over a chosen binary from the latest extracted rootfs as a job; GET
 * returns the most recent completed triage. Needs a prior successful extraction to supply the rootfs.
 */
import type { FastifyInstance } from 'fastify';
import { normalizeBinaryHardening, syncFindings } from '../findings.js';
import { type DecompileResult, runDecompile } from '../providers/decompile.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listBinaries, listJobs, upsertBinaryTriage } from '../store.js';

/** Imports worth surfacing in the binaries table — command exec, unsafe string/mem ops. */
const DANGEROUS_IMPORTS = new Set([
  'system',
  'popen',
  'execl',
  'execlp',
  'execle',
  'execv',
  'execvp',
  'execve',
  'strcpy',
  'strcat',
  'sprintf',
  'gets',
  'memcpy',
  'scanf',
]);

const boolToInt = (b: boolean | undefined): number | null => (b === undefined ? null : b ? 1 : 0);

/** Fold a radare2 triage result into the binaries table (hardening flags + a dangerous-imports summary). */
function persistTriage(imageId: string, binary: string, r: DecompileResult): void {
  if (!r.available) return;
  const dangerous = r.imports.map((i) => i.name).filter((n) => DANGEROUS_IMPORTS.has(n));
  upsertBinaryTriage({
    imageId,
    path: binary,
    arch: r.info.arch ?? null,
    bits: r.info.bits ?? null,
    endianness: r.info.endian ?? null,
    nx: boolToInt(r.info.nx),
    canary: boolToInt(r.info.canary),
    pic: boolToInt(r.info.pic),
    importsSummary: dangerous.length > 0 ? [...new Set(dangerous)].join(', ') : null,
  });
}

/** Find the most recent successful extraction rootfs for an image, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

function latestDecompile(imageId: string): DecompileResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'decompile' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as DecompileResult;
}

export async function decompileRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/decompile', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply.status(400).send({ error: 'Run extraction first — binary triage needs an extracted rootfs' });
    }
    const body = (req.body ?? {}) as { binary?: string };
    const binary = typeof body.binary === 'string' ? body.binary : '';
    if (!binary) return reply.status(400).send({ error: 'No target binary specified' });

    const jobId = startJob(id, 'decompile', { binary }, (handle) =>
      runDecompile(rootfsPath, binary, handle).then((r) => {
        syncFindings(id, `binary:${binary}`, normalizeBinaryHardening(r));
        persistTriage(id, binary, r);
        return r;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/decompile', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestDecompile(id) };
  });

  // First-class binaries table for the image: every ELF from the rootfs, with arch + hardening + triage state.
  app.get('/images/:id/binaries', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    return { binaries: listBinaries(id) };
  });
}
