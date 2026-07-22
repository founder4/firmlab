/**
 * Capture-lane routes (Phase 6.0/6.1, design §14). The second network-touching lane, gated by `FIRMLAB_CAPTURE`.
 * Backend detection is a harmless read-only probe (runs regardless of the flag, parity with `/tools`); arming a
 * scan or a capture requires both the flag AND a per-request operator acknowledgement, and is bounded + honest.
 */
import type { FastifyInstance } from 'fastify';
import { type AgentFlowInput, createAgentSession, ingestAgentFlow, loadAgentToken, tokenOk } from '../capture/agent.js';
import { availableTransports, detectCaptureBackends } from '../capture/backends.js';
import { loadCaptureConfig } from '../capture/config.js';
import { FRIDA_UNPIN } from '../capture/frida.js';
import { planCapture, realizedCeiling } from '../capture/preflight.js';
import { ingestFlow, refreshCaptureFlows, startCaptureSession, teardownCaptureSession } from '../capture/proxy.js';
import { startDiscoveryScan } from '../capture/scan.js';
import { getCaptureSession, getDevice, listDevices } from '../store.js';

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

  // Capturability preflight for a chosen target: the ranked strategy ladder + the honest acquisition ceiling.
  app.get('/capture/preflight/:deviceId', async (req, reply) => {
    const { deviceId } = req.params as { deviceId: string };
    const device = getDevice(deviceId);
    if (!device) return reply.status(404).send({ error: 'Device not found' });
    const plan = planCapture(
      { typeGuess: device.typeGuess, mdnsIdentity: device.mdnsIdentity },
      detectCaptureBackends(),
    );
    return { device, plan };
  });

  // The Frida TLS-unpinning template (operator runs it on a rooted phone when a device pins). Plain-text download.
  app.get('/capture/frida-unpin', async (_req, reply) => {
    return reply
      .header('content-type', 'text/plain; charset=utf-8')
      .header('content-disposition', 'attachment; filename="firmlab-unpin.js"')
      .send(FRIDA_UNPIN);
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

  // === Phase 6.1: interception sessions ===

  // Arm a capture session for a chosen target: spawn the on-path proxy, watch for the OTA. Flag + operator ack.
  app.post('/capture/session', async (req, reply) => {
    const cfg = loadCaptureConfig();
    if (!cfg) {
      return reply.status(400).send({ error: 'Capture disabled — set FIRMLAB_CAPTURE=1 to enable the capture lane' });
    }
    const body = (req.body ?? {}) as { deviceId?: string; acknowledged?: boolean };
    if (body.acknowledged !== true) {
      return reply.status(400).send({
        error:
          'Operator acknowledgement required — confirm these are devices/networks you own or are authorized to test',
      });
    }
    const result = startCaptureSession(body.deviceId ?? null);
    return reply.status(202).send(result);
  });

  // Poll a capture session: status + transcript + the live (re-scored) flow feed + the realized acquisition ceiling.
  app.get('/capture/session/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const session = getCaptureSession(id);
    if (!session) return reply.status(404).send({ error: 'Session not found' });
    const flows = refreshCaptureFlows(id);
    return { session: getCaptureSession(id) ?? session, flows, ceiling: realizedCeiling(flows) };
  });

  // Ingest a carved firmware candidate into the workbench (→ a normal image + capture provenance).
  app.post('/capture/session/:id/ingest', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getCaptureSession(id)) return reply.status(404).send({ error: 'Session not found' });
    const { flowId } = (req.body ?? {}) as { flowId?: string };
    if (!flowId) return reply.status(400).send({ error: 'flowId is required' });
    try {
      const result = ingestFlow(id, flowId);
      return reply.status(201).send(result);
    } catch (e) {
      return reply.status(400).send({ error: e instanceof Error ? e.message : String(e) });
    }
  });

  // Explicit teardown (also runs automatically on the time-box). Restores positioning, stops the proxy.
  app.post('/capture/session/:id/teardown', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getCaptureSession(id)) return reply.status(404).send({ error: 'Session not found' });
    teardownCaptureSession(id);
    return { session: getCaptureSession(id) };
  });

  // === Phase 6.2: remote LAN capture agent (the Docker answer). Token-authed; off unless a token is configured. ===

  app.get('/capture/agent/status', async () => {
    return { enabled: loadAgentToken() !== null };
  });

  // A remote agent opens a session it will stream carved flows into.
  app.post('/capture/agent/session', async (req, reply) => {
    const token = (req.headers['x-capture-token'] as string | undefined) ?? (req.body as { token?: string })?.token;
    if (!tokenOk(token)) return reply.status(401).send({ error: 'Invalid or missing capture-agent token' });
    const { agentId } = (req.body ?? {}) as { agentId?: string };
    const sessionId = createAgentSession(agentId ?? 'agent');
    return reply.status(201).send({ sessionId });
  });

  // A remote agent streams one carved flow (metadata + optional base64 body) into its session.
  app.post('/capture/agent/flow', async (req, reply) => {
    const token = (req.headers['x-capture-token'] as string | undefined) ?? (req.body as { token?: string })?.token;
    if (!tokenOk(token)) return reply.status(401).send({ error: 'Invalid or missing capture-agent token' });
    const body = (req.body ?? {}) as { sessionId?: string; flow?: AgentFlowInput; bodyBase64?: string };
    if (!body.sessionId || !body.flow?.url) {
      return reply.status(400).send({ error: 'sessionId and flow.url are required' });
    }
    const blob = body.bodyBase64 ? Buffer.from(body.bodyBase64, 'base64') : null;
    try {
      const result = ingestAgentFlow(body.sessionId, body.flow, blob);
      return reply.status(201).send(result);
    } catch (e) {
      return reply.status(400).send({ error: e instanceof Error ? e.message : String(e) });
    }
  });
}
