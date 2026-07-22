/**
 * Capture-lane routes (Phase 6.0, design §14). The second network-touching lane, gated by `FIRMLAB_CAPTURE`.
 * Backend detection is a harmless read-only probe (runs regardless of the flag, parity with `/tools`); actually
 * arming a scan requires both the flag AND a per-request operator acknowledgement, and is bounded + observational.
 */
import type { FastifyInstance } from 'fastify';
import { availableTransports, detectCaptureBackends } from '../capture/backends.js';
import { loadCaptureConfig } from '../capture/config.js';
import { startDiscoveryScan } from '../capture/scan.js';
import { getCaptureSession, listDevices } from '../store.js';

export async function captureRoutes(app: FastifyInstance): Promise<void> {
  // Is the capture lane enabled? (parity with /agent/status, /research/status — never leaks secrets.)
  app.get('/capture/status', async () => {
    const cfg = loadCaptureConfig();
    if (!cfg) return { enabled: false };
    return { enabled: true, gatewayDeclared: cfg.gatewayDeclared, defaultSubnet: cfg.defaultSubnet };
  });

  // Detected capture backends + the transports the current mix can carry (parity with /tools). Read-only.
  app.get('/capture/backends', async (req) => {
    const force = (req.query as { refresh?: string }).refresh === '1';
    const backends = detectCaptureBackends(force);
    const cfg = loadCaptureConfig();
    return { enabled: cfg !== null, backends, transports: availableTransports(backends) };
  });

  // The persistent LAN device inventory (the radar table), freshest first.
  app.get('/capture/devices', async () => {
    return { devices: listDevices() };
  });

  // Arm + run a passive discovery scan. Gated by the flag AND a per-request operator acknowledgement.
  app.post('/capture/discover', async (req, reply) => {
    const cfg = loadCaptureConfig();
    if (!cfg) {
      return reply.status(400).send({ error: 'Capture disabled — set FIRMLAB_CAPTURE=1 to enable the capture lane' });
    }
    const body = (req.body ?? {}) as { subnet?: string; acknowledged?: boolean };
    if (body.acknowledged !== true) {
      return reply.status(400).send({
        error:
          'Operator acknowledgement required — confirm these are devices/networks you own or are authorized to test',
      });
    }
    const subnet = body.subnet?.trim() || cfg.defaultSubnet;
    const scanId = startDiscoveryScan(subnet ?? null);
    return reply.status(202).send({ scanId });
  });

  // Poll a discovery scan: its session status + transcript, plus the current inventory.
  app.get('/capture/discover/:scanId', async (req, reply) => {
    const { scanId } = req.params as { scanId: string };
    const session = getCaptureSession(scanId);
    if (!session) return reply.status(404).send({ error: 'Scan not found' });
    return { session, devices: listDevices() };
  });
}
