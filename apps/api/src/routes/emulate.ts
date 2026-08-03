/**
 * Emulation menu + execution. GET serves the ranked recipe menu for an image (arch/class-aware, augmented
 * with the latest extraction's rootfs + suggested binary). POST runs a user-mode QEMU recipe as a job.
 */
import type { ImageIdentity } from '@firmlab/core';
import type { FastifyInstance } from 'fastify';
import { deviceFamilyKey, recordReachabilityPrior } from '../corpus.js';
import { syncFindings } from '../findings.js';
import {
  type SystemEmulationResult,
  buildSystemEmulationFindings,
  runChrootService,
  runFullSystem,
} from '../providers/emulate-system.js';
import {
  type PlanContext,
  buildUserEmulationFindings,
  planEmulation,
  runUserModeEmulation,
} from '../providers/emulate.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { computeRuntimeCapabilities } from '../providers/preflight.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { ensureRootfsImage } from '../providers/rootfs-image.js';
import { getImage, listJobs, updateBinaryEmulationStatus } from '../store.js';
import { rootfsArch } from './symreach.js';

// Both emulation rungs need a rootfs, and both used to refuse with "Run extraction first" whatever the ledger
// actually said — the same conflation `rootfs-gate.ts` was written for. The two stages are named separately so the
// refusal says which rung could not run.
const USER_STAGE: RootfsStage = { stage: 'emulate', needs: 'user-mode emulation' };
const SYSTEM_STAGE: RootfsStage = { stage: 'emulate-system', needs: 'system emulation' };

/** Find the most recent successful extraction result for an image, if any. */
function latestExtract(imageId: string): ExtractResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as ExtractResult;
}

/**
 * Record what a system-emulation run earned: the reachability prior when it confirmed something, and — since
 * 2026-08-03 — a row in the findings ledger on EVERY outcome.
 *
 * The two halves are deliberately gated differently. A prior is a claim that this device family can be shown to
 * do something, so only a confirmation may write one. A finding is the record of a question having been asked,
 * so a blocked rung and an unconfirmed boot write one too: for as long as this function only spoke on
 * confirmation, seven full-system boots and three `confirmed_full_system` verdicts left the ledger completely
 * silent, and a missing arch map key read as an honest platform limit because nothing in the dossier contradicted
 * it.
 *
 * The source key is per rung, not per run: every full-system boot of an image asks the identical question, so
 * `emulate-system` is image-wide and each boot replaces the last verdict (which is what makes re-running
 * idempotent). A chroot service is a different question per service, so its key carries the service path.
 */
function onSystemEmulationResult(
  imageId: string,
  identity: ImageIdentity,
  subject: string,
  r: SystemEmulationResult,
): SystemEmulationResult {
  if (r.proofState === 'confirmed_in_emulation' || r.proofState === 'confirmed_full_system') {
    recordReachabilityPrior(deviceFamilyKey(identity), subject, r.proofState, imageId);
    updateBinaryEmulationStatus(imageId, subject, r.proofState);
  }
  const source = r.strategy === 'full-system' ? 'emulate-system' : `emulate-chroot:${subject}`;
  syncFindings(imageId, source, buildSystemEmulationFindings(subject, r));
  return r;
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
    const gate = gateOnRootfs(USER_STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const extract = latestExtract(id);
    const target = body.binary ?? extract?.suggestedBinary;
    if (!target) {
      return reply.status(400).send({ error: 'No target binary specified and none could be suggested' });
    }

    const rootfsPath = gate.rootfsPath;
    const args = Array.isArray(body.args) ? body.args.map(String) : [];
    // The MEASURED architecture, like the deeper rungs below. This rung was still consulting `identity.arch` —
    // a guess from the raw image bytes, `unknown` on plenty of real images — while extraction had already read
    // the answer out of the ELF headers of every binary in this rootfs. The comment below records the same fix
    // being made for the system rungs and never carried across; this is the carry-across.
    const userArch = rootfsArch(id, identity) ?? identity.arch;
    const jobId = startJob(id, 'emulate', { binary: target, args }, (handle) =>
      runUserModeEmulation(userArch, rootfsPath, target, handle, args).then((r) => {
        // A different binary is a different question, so the source carries it — otherwise emulating a second
        // binary would delete the first one's row (the deletion bug the manual reachability probe already paid
        // for), and the ledger would only ever remember the most recently emulated binary on the image.
        syncFindings(id, `emulate:${target}`, buildUserEmulationFindings(target, r));
        return r;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  // Deeper emulation rungs (chroot service / full-system). Asset-gated: the runner returns a blocked result
  // when the libnvram shim / firmadyne kernels aren't baked in (see Dockerfile.firmware), never a half boot.
  app.post('/images/:id/emulate-system', async (req, reply) => {
    const { id } = req.params as { id: string };
    const identity = identityOf(id);
    if (!identity) return reply.status(404).send({ error: 'No analysis for this image' });
    const sysGate = gateOnRootfs(SYSTEM_STAGE, listJobs(id));
    if (!sysGate.ok) return reply.status(sysGate.status).send(rootfsGateBody(sysGate));
    const rootfsPath = sysGate.rootfsPath;
    const extract = latestExtract(id);
    const body = (req.body ?? {}) as { rung?: string; binary?: string };
    // Prefer the MEASURED architecture over the guessed one. `identity.arch` is inferred from the raw image bytes
    // and is `unknown` for plenty of real images (DVRF among them) while extraction has already read it out of the
    // ELF headers of every binary in the rootfs — so this rung refused to run on an image whose architecture was
    // known, just not in the field being consulted. Exactly the defect fixed once for the dynamic probe and never
    // carried across to here.
    const arch = rootfsArch(id, identity) ?? identity.arch;

    if (body.rung === 'full-system') {
      const jobId = startJob(id, 'emulate', { rung: 'full-system' }, async (handle) => {
        // Assemble the disk image first. Nothing used to: the rung was handed `${rootfsPath}.img` and every run
        // died on a file no code path created, which the guided recipe expected an operator to build by hand.
        const image = await ensureRootfsImage(rootfsPath, arch, handle);
        if (!image.available || !image.imagePath) {
          const blocked: SystemEmulationResult = {
            ran: false,
            strategy: 'full-system',
            proofState: 'blocked_by_platform',
            reason: image.reason,
            command: '',
            stdout: '',
            stderr: '',
            timedOut: false,
          };
          return onSystemEmulationResult(id, identity, 'system-boot', blocked);
        }
        // `image.repair` rather than re-deriving it: only the builder knows what it appended, and a verdict that
        // cannot say whether the firewall was torn down for this boot is a claim about a different artefact.
        //
        // And the image's PRIOR full-system boots, read here because only the route can: three causal claims were
        // drawn from single boots of this rung and all three were wrong, so a verdict now travels with how many
        // boots stand behind it. Stored results are data written by older builds, so every field is read
        // defensively — a row that carries no `open` array is counted as a boot with zero open ports rather than
        // dropped, because dropping it would understate `n` and understating `n` is what produced the retractions.
        const priorBoots = listJobs(id)
          .filter((j) => j.kind === 'emulate' && j.status === 'done' && j.resultJson)
          .map((j) => {
            try {
              return JSON.parse(j.resultJson as string) as Record<string, unknown>;
            } catch {
              return null;
            }
          })
          .filter((res): res is Record<string, unknown> => res?.strategy === 'full-system')
          .map((res) => ({
            verdict: typeof res.proofState === 'string' ? res.proofState : 'unknown',
            openPorts: Array.isArray(res.open) ? res.open.length : 0,
            panic: typeof res.stdout === 'string' && res.stdout.includes('Kernel panic'),
            // Absent on every row stored before boots recorded it, which the verdict counts as incomparable rather
            // than as a repeat — the same rule as the image's build stamp.
            buildRev: typeof res.buildRev === 'string' ? res.buildRev : undefined,
          }));
        const r = await runFullSystem(arch, image.imagePath, 8080, handle, rootfsPath, image.repair, priorBoots);
        return onSystemEmulationResult(id, identity, 'system-boot', r);
      });
      return reply.status(202).send({ jobId });
    }

    const service = body.binary ?? extract?.suggestedBinary;
    if (!service) return reply.status(400).send({ error: 'No target service specified and none could be suggested' });
    const jobId = startJob(id, 'emulate', { rung: 'chroot-service', binary: service }, (handle) =>
      runChrootService(arch, rootfsPath, service, handle).then((r) =>
        onSystemEmulationResult(id, identity, service, r),
      ),
    );
    return reply.status(202).send({ jobId });
  });
}
