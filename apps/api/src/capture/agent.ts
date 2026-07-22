/**
 * Remote LAN capture agent — the robust answer to Docker (Phase 6.2, design §5c). A NAT-bridged container can't
 * ARP-spoof or transparently proxy the LAN, so the durable shape is a small agent that sits on the LAN with the
 * privileges, does the positioning + interception locally, and streams the flows/blobs it carves back to the
 * workbench over a simple token-authenticated channel. This module is the WORKBENCH side of that channel: it
 * authenticates the agent, lands each streamed flow as a scored capture_flow (saving carved bodies where the 6.1
 * ingest can find them), so a remotely-captured blob ingests through the exact same path as a local capture.
 *
 * The reference agent is `apps/api/scripts/capture-agent.mjs`. Auth is a shared token (FIRMLAB_CAPTURE_AGENT_TOKEN);
 * with it unset the agent lane is off (endpoints refuse). Bodies stream as base64 in JSON, so the workbench's 8 MB
 * body limit caps a single agent-posted blob — larger images are a documented follow-up (raw/chunked streaming).
 */
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { CAPTURE_DIR } from '../paths.js';
import { type FlowMeta, type TlsPosture, scoreFirmwareFlow } from '../providers/flowscore.js';
import { getCaptureSession, insertCaptureSession, upsertCaptureFlow } from '../store.js';

/** The shared agent token, or null when the agent lane is off (no token configured). */
export function loadAgentToken(env: NodeJS.ProcessEnv = process.env): string | null {
  return env.FIRMLAB_CAPTURE_AGENT_TOKEN?.trim() || null;
}

/** Pure: does a presented token match the configured one? False when no token is configured (lane off). */
export function tokenOk(provided: string | undefined | null): boolean {
  const t = loadAgentToken();
  return t !== null && typeof provided === 'string' && provided === t;
}

/** Create a capture session that a remote agent streams into. Its target id is `agent:<agentId>`. */
export function createAgentSession(agentId: string): string {
  const id = randomUUID().slice(0, 12);
  const now = Date.now();
  fs.mkdirSync(path.join(CAPTURE_DIR, id, 'bodies'), { recursive: true });
  insertCaptureSession({
    id,
    status: 'watching',
    subnet: null,
    targetDeviceId: `agent:${agentId}`,
    strategyJson: JSON.stringify({ agent: { id: agentId } }),
    transcript: `[armed] remote capture agent ${agentId} streaming to the workbench\n`,
    deviceCount: 0,
    error: null,
    createdAt: now,
    updatedAt: now,
  });
  return id;
}

export interface AgentFlowInput {
  id?: string;
  host?: string | null;
  url: string;
  method?: string;
  contentType?: string | null;
  contentLength?: number;
  tls?: TlsPosture;
}

/** Land a streamed flow into an agent session: score it, save the body if it's a carved candidate. */
export function ingestAgentFlow(
  sessionId: string,
  flow: AgentFlowInput,
  body: Buffer | null,
): { flowId: string; firmwareScore: number; carved: boolean } {
  const session = getCaptureSession(sessionId);
  if (!session) throw new Error('Unknown capture session');
  const flowId = flow.id || randomUUID().slice(0, 12);
  const meta: FlowMeta = {
    url: flow.url,
    method: flow.method || 'GET',
    contentType: flow.contentType ?? null,
    contentLength: flow.contentLength ?? (body ? body.length : 0),
    tls: flow.tls ?? null,
  };
  const score = scoreFirmwareFlow(meta, body ?? new Uint8Array(0));
  const carved = score.isFirmwareCandidate && body ? 1 : 0;
  let bodyPath: string | null = null;
  if (carved && body) {
    bodyPath = path.join(CAPTURE_DIR, sessionId, 'bodies', `${flowId}.bin`);
    fs.writeFileSync(bodyPath, body);
  }
  upsertCaptureFlow({
    id: flowId,
    sessionId,
    host: flow.host ?? null,
    url: flow.url,
    method: flow.method || 'GET',
    contentType: flow.contentType ?? null,
    size: meta.contentLength,
    tlsPosture: flow.tls ?? null,
    firmwareScore: score.score,
    carved,
    bodyPath: carved ? bodyPath : null,
    createdAt: Date.now(),
  });
  return { flowId, firmwareScore: score.score, carved: carved === 1 };
}
