/**
 * FirmLab API server.
 *
 * Local-first by design: binds to 127.0.0.1 unless FIRMLAB_HOST is set explicitly, so a default `docker run`
 * or `node dist/index.js` never exposes the workbench (or the firmware images it holds) to the network. Serves
 * the built web UI from the same origin in production.
 */
import fs from 'node:fs';
import fastifyMultipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import Fastify from 'fastify';
import { reconcileSessions } from './agent/session.js';
import { WEB_DIST_DIR, ensureDataDirs } from './paths.js';
import { SWEEP_INTERVAL_MS, sweepRetention } from './retention.js';
import { agentRoutes } from './routes/agent.js';
import { analysisRoutes } from './routes/analysis.js';
import { certsRoutes } from './routes/certs.js';
import { chipsecRoutes } from './routes/chipsec.js';
import { compmapRoutes } from './routes/compmap.js';
import { copilotRoutes } from './routes/copilot.js';
import { corpusRoutes } from './routes/corpus.js';
import { decompileRoutes } from './routes/decompile.js';
import { diffRoutes } from './routes/diff.js';
import { emulateRoutes } from './routes/emulate.js';
import { fccRoutes } from './routes/fcc.js';
import { fsauditRoutes } from './routes/fsaudit.js';
import { fuzzRoutes } from './routes/fuzz.js';
import { ghidraRoutes } from './routes/ghidra.js';
import { gitleaksRoutes } from './routes/gitleaks.js';
import { imageRoutes } from './routes/images.js';
import { jobRoutes } from './routes/jobs.js';
import { presetsRoutes } from './routes/presets.js';
import { renodeRoutes } from './routes/renode.js';
import { reportRoutes } from './routes/report.js';
import { researchRoutes } from './routes/research.js';
import { rtosRoutes } from './routes/rtos.js';
import { sbomRoutes } from './routes/sbom.js';
import { servicemapRoutes } from './routes/servicemap.js';
import { storageRoutes } from './routes/storage.js';
import { toolRoutes } from './routes/tools.js';
import { ubootRoutes } from './routes/uboot.js';
import { webprobeRoutes } from './routes/webprobe.js';
import { registerSecurity } from './security.js';
import { getDb } from './store.js';

const HOST = process.env.FIRMLAB_HOST ?? '127.0.0.1';
const PORT = Number(process.env.FIRMLAB_PORT ?? 8799);
const MAX_UPLOAD_BYTES = Number(process.env.FIRMLAB_MAX_UPLOAD ?? 500 * 1024 * 1024);

async function main(): Promise<void> {
  ensureDataDirs();
  getDb(); // initialize schema early so a bad data dir fails fast

  // Any agent session left 'running' by a previous process was interrupted — mark it errored so the transcript
  // stays honest (awaiting_approval sessions are a legitimate durable pause and survive the restart).
  reconcileSessions();

  // Enforce data-retention limits at startup and on a timer (no-op unless a limit is configured).
  sweepRetention((line) => console.log(line));
  setInterval(() => sweepRetention((line) => console.log(line)), SWEEP_INTERVAL_MS).unref();

  const app = Fastify({
    logger: { level: process.env.LOG_LEVEL ?? 'info' },
    bodyLimit: 8 * 1024 * 1024,
  });

  registerSecurity(app);

  await app.register(fastifyMultipart, { limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 } });

  // In Docker the server must bind 0.0.0.0 for port publishing to work; the host-side publish (compose binds
  // 127.0.0.1) is what actually controls exposure. FIRMLAB_LOOPBACK_PUBLISH=1 asserts that loopback publish so
  // the UI's local-only indicator stays accurate inside a container.
  const loopbackPublish = process.env.FIRMLAB_LOOPBACK_PUBLISH === '1';
  const boundLocally = HOST === '127.0.0.1' || HOST === 'localhost';
  // FIRMLAB_TRUSTED_PROXY=1 asserts the workbench sits behind an authenticating reverse proxy (e.g. Traefik +
  // forward-auth). It's still not loopback, but reaching it requires passing that proxy's auth — so the UI shows
  // an "auth-gated" state instead of the bare "exposed to network" warning.
  const trustedProxy = process.env.FIRMLAB_TRUSTED_PROXY === '1';
  app.get('/health', async () => {
    return {
      status: 'ok',
      host: HOST,
      port: PORT,
      // The git commit this image was built from (FIRMLAB_BUILD, baked at image build) — lets a deploy confirm it
      // is serving the latest build rather than a stale container.
      build: process.env.FIRMLAB_BUILD ?? 'dev',
      exposedToNetwork: !boundLocally && !loopbackPublish,
      trustedProxy,
    };
  });

  // API surface under /api.
  await app.register(
    async (api) => {
      await api.register(imageRoutes);
      await api.register(analysisRoutes);
      await api.register(jobRoutes);
      await api.register(emulateRoutes);
      await api.register(sbomRoutes);
      await api.register(decompileRoutes);
      await api.register(gitleaksRoutes);
      await api.register(ghidraRoutes);
      await api.register(diffRoutes);
      await api.register(corpusRoutes);
      await api.register(copilotRoutes);
      await api.register(agentRoutes);
      await api.register(fuzzRoutes);
      await api.register(renodeRoutes);
      await api.register(chipsecRoutes);
      await api.register(webprobeRoutes);
      await api.register(ubootRoutes);
      await api.register(fsauditRoutes);
      await api.register(certsRoutes);
      await api.register(rtosRoutes);
      await api.register(compmapRoutes);
      await api.register(servicemapRoutes);
      await api.register(fccRoutes);
      await api.register(presetsRoutes);
      await api.register(researchRoutes);
      await api.register(reportRoutes);
      await api.register(storageRoutes);
      await api.register(toolRoutes);
    },
    { prefix: '/api' },
  );

  // Serve the built web UI when present (production single-origin deploy).
  if (fs.existsSync(WEB_DIST_DIR)) {
    await app.register(fastifyStatic, { root: WEB_DIST_DIR });
    app.setNotFoundHandler((req, reply) => {
      // SPA fallback for non-API GETs.
      if (req.method === 'GET' && !req.url.startsWith('/api') && !req.url.startsWith('/health')) {
        return reply.sendFile('index.html');
      }
      return reply.status(404).send({ error: 'Not found' });
    });
  }

  await app.listen({ host: HOST, port: PORT });
  const exposed = !boundLocally && !loopbackPublish;
  app.log.info(`FirmLab API on http://${HOST}:${PORT}${exposed ? '  [WARNING: bound to a non-local host]' : ''}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
