/**
 * RTOS / bare-metal routes — the raw ARM Cortex-M analysis track. Pure, tool-free static analysis of a raw `.bin`
 * blob: recover the Cortex-M vector table + flash/RAM memory map from the bytes and detect the RTOS kernel. A
 * successful parse is `static_confirmed` — a fact about the image bytes, never a device claim — and its findings
 * (vector table, RTOS kernel, bare-metal lead) are synced into the findings ledger. A non-Cortex-M blob degrades
 * honestly (isCortexM:false) rather than fabricating a memory map.
 *
 * `/rtos/tasks` walks an operator-supplied FreeRTOS RAM snapshot (see `providers/rtos-tasks.ts`). The contract is
 * validated before a job is created — a snapshot with an undeclared layout is refused, never defaulted — and the
 * result stays a `needs_runtime_reproduction` lead with per-lane coverage; it syncs no findings.
 *
 * `/rtos/elf-symbols` reads the FreeRTOS kernel addresses out of the image's own ELF symbol table (see
 * `providers/rtos-elf-symbols.ts`) so the snapshot form can be pre-filled. A link-time address is not runtime proof,
 * so it syncs no findings either; a raw or stripped image is reported as a reason, never as "no FreeRTOS".
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { runRtosElfSymbols } from '../providers/rtos-elf-symbols.js';
import { runRtosTaskSnapshot, validateRtosTaskSnapshot } from '../providers/rtos-tasks.js';
import { runRtosAnalysis } from '../providers/rtos.js';
import { getImage, listJobs } from '../store.js';

export async function rtosRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/rtos', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const jobId = startJob(id, 'rtos', {}, async () => {
      const result = runRtosAnalysis(row.path);
      syncFindings(id, 'rtos', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/rtos', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'rtos' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });

  app.post('/images/:id/rtos/tasks', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const checked = validateRtosTaskSnapshot(req.body);
    if (!checked.ok) return reply.status(400).send({ error: 'Invalid RTOS snapshot', details: checked.errors });
    const { base, layout, buf } = checked.snapshot;
    const jobId = startJob(id, 'rtos-tasks', { base, ...layout, bytes: buf.length }, async (handle) => {
      const result = runRtosTaskSnapshot(checked.snapshot);
      handle.log(result.summary);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/rtos/tasks', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'rtos-tasks' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });

  app.post('/images/:id/rtos/elf-symbols', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const jobId = startJob(id, 'rtos-elf-symbols', {}, async (handle) => {
      const result = runRtosElfSymbols(row.path);
      handle.log(result.summary);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/rtos/elf-symbols', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'rtos-elf-symbols' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
