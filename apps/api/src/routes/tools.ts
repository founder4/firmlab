/**
 * Capability introspection: which external tools this deployment has, grouped by what they unlock. Backs the
 * UI "Capabilities" panel so a user immediately sees whether they're on the full firmware image or the
 * static-only base.
 */
import type { FastifyInstance } from 'fastify';
import { detectTools } from '../tools.js';

export async function toolRoutes(app: FastifyInstance): Promise<void> {
  app.get('/tools', async (req) => {
    const force = (req.query as { refresh?: string }).refresh === '1';
    const tools = await detectTools(force);
    const groups: Record<string, { available: number; total: number }> = {};
    for (const t of tools) {
      if (!groups[t.group]) groups[t.group] = { available: 0, total: 0 };
      const g = groups[t.group] as { available: number; total: number };
      g.total++;
      if (t.available) g.available++;
    }
    return { tools, groups };
  });
}
