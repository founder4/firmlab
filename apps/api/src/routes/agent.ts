/**
 * Agent-session routes (Phase 3) — the conscious-autonomy decision loop, flag-gated like the copilot. With the
 * agent off (no FIRMLAB_AGENT / no key) every route reports disabled and nothing touches the network. A session
 * is started, its auditable transcript is polled, and any proposed emulation is gated behind an explicit human
 * approve/decline. GET /agent/config surfaces the governor budget so the UI can show the leash.
 */
import type { FastifyInstance } from 'fastify';
import { loadGovernorBudget } from '../agent/governor.js';
import { approveEmulation, declineEmulation, startAgentSession } from '../agent/session.js';
import { loadLlmConfig } from '../llm.js';
import { type AgentSessionRow, type AgentStepRow, getImage, getSession, latestSession, listSteps } from '../store.js';

function sessionView(row: AgentSessionRow): unknown {
  return {
    id: row.id,
    imageId: row.imageId,
    status: row.status,
    goal: row.goal,
    budget: JSON.parse(row.budgetJson),
    consumed: JSON.parse(row.consumedJson),
    haltReason: row.haltReason,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function stepView(row: AgentStepRow): unknown {
  return {
    seq: row.seq,
    node: row.node,
    status: row.status,
    input: row.inputJson ? JSON.parse(row.inputJson) : null,
    output: row.outputJson ? JSON.parse(row.outputJson) : null,
    rationale: row.rationale,
    model: row.model,
    inputTokens: row.inputTokens,
    outputTokens: row.outputTokens,
    createdAt: row.createdAt,
  };
}

function withSteps(row: AgentSessionRow): unknown {
  return { session: sessionView(row), steps: listSteps(row.id).map(stepView) };
}

export async function agentRoutes(app: FastifyInstance): Promise<void> {
  // The governor budget (and whether the agent is enabled) — lets the UI render the leash.
  app.get('/agent/config', async () => {
    const cfg = loadLlmConfig();
    if (!cfg) return { enabled: false };
    return { enabled: true, provider: cfg.provider, model: cfg.model, budget: loadGovernorBudget() };
  });

  // Start a conscious-autonomy session over an image.
  app.post('/images/:id/agent/session', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const cfg = loadLlmConfig();
    if (!cfg) return reply.status(400).send({ error: 'Agent disabled — set FIRMLAB_AGENT=1 and an LLM API key' });
    const goal = ((req.body ?? {}) as { goal?: string }).goal ?? null;
    try {
      const session = startAgentSession(id, cfg, goal);
      return reply.status(202).send({ session: sessionView(session) });
    } catch (err) {
      return reply.status(409).send({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  // Latest session for an image + its transcript (poll this while it runs).
  app.get('/images/:id/agent/session', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const row = latestSession(id);
    if (!row) return { session: null, steps: [] };
    return withSteps(row);
  });

  // A specific session by id.
  app.get('/agent/sessions/:sid', async (req, reply) => {
    const { sid } = req.params as { sid: string };
    const row = getSession(sid);
    if (!row) return reply.status(404).send({ error: 'Session not found' });
    return withSteps(row);
  });

  // Human-in-the-loop approval: run the proposed emulation deterministically.
  app.post('/agent/sessions/:sid/approve', async (req, reply) => {
    const { sid } = req.params as { sid: string };
    const binary = ((req.body ?? {}) as { binary?: string }).binary ?? null;
    try {
      const session = await approveEmulation(sid, binary);
      return withSteps(session);
    } catch (err) {
      return reply.status(400).send({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  // Decline the proposed emulation — the session closes with nothing run.
  app.post('/agent/sessions/:sid/decline', async (req, reply) => {
    const { sid } = req.params as { sid: string };
    try {
      const session = declineEmulation(sid);
      return withSteps(session);
    } catch (err) {
      return reply.status(400).send({ error: err instanceof Error ? err.message : String(err) });
    }
  });
}
