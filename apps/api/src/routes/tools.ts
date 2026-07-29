/**
 * Capability introspection: which external tools this deployment has, grouped by what they unlock. Backs the
 * UI "Capabilities" panel so a user immediately sees whether they're on the full firmware image or the
 * static-only base.
 *
 * `?lang` selects the language of the per-tool gloss only. The ids, the binary names and the version line each
 * tool printed are identifiers and come back identical either way; what is probed does not depend on the locale,
 * so the cache is shared and the answer to "is it installed?" is the same answer in both languages. Absent or
 * unrecognised, `?lang` is English — the answer every caller before this got.
 */
import type { FastifyInstance } from 'fastify';
import { resolveLocale } from '../i18n/index.js';
import { detectTools } from '../tools.js';

export async function toolRoutes(app: FastifyInstance): Promise<void> {
  app.get('/tools', async (req) => {
    const query = req.query as { refresh?: string; lang?: unknown };
    const force = query.refresh === '1';
    const tools = await detectTools(force, resolveLocale(query.lang));
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
