/**
 * Cross-image corpus routes — its priors and its overview. Everything here is a *reference* into other
 * images (occurrences), never a new asserted finding: the corpus enriches, it does not conclude.
 */
import type { FastifyInstance } from 'fastify';
import { corpusOverview, corpusRefs, deleteRule, listRules, promoteRule, reindexCorpus } from '../corpus.js';
import { messages, resolveLocale } from '../i18n/index.js';
import { getImage } from '../store.js';

export async function corpusRoutes(app: FastifyInstance): Promise<void> {
  // The corpus as a whole: credential reuse, component prevalence, device families.
  app.get('/corpus/overview', async () => {
    return { overview: corpusOverview() };
  });

  // For one image: which of its credentials / components / binaries also appear in other images.
  app.get('/images/:id/corpus-refs', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    return { refs: corpusRefs(id) };
  });

  // Level 1: the human-curated rule watchlist (e.g. known-bad credentials).
  app.get('/corpus/rules', async (req) => {
    const { type } = (req.query ?? {}) as { type?: string };
    return { rules: listRules(type) };
  });

  app.post('/corpus/rules', async (req, reply) => {
    const body = (req.body ?? {}) as { type?: string; key?: string; label?: string; note?: string };
    const type = typeof body.type === 'string' ? body.type : '';
    const key = typeof body.key === 'string' ? body.key.trim() : '';
    const label = typeof body.label === 'string' ? body.label.trim() : '';
    if (!type || !key || !label) {
      return reply.status(400).send({ error: 'type, key and label are required' });
    }
    return { rule: promoteRule(type, key, label, typeof body.note === 'string' ? body.note : null) };
  });

  /**
   * Reconcile the corpus against every image already on the bench.
   *
   * POST because it writes, and idempotent because every insert is `INSERT OR IGNORE` over immutable data — so a
   * second call is free and reports zero inserted, which is the honest answer and not a failure. It runs no tool,
   * opens no socket and re-reads no firmware bytes: recording used to happen only at the instant a provider ran,
   * which made the corpus a record of WHEN each image was uploaded rather than of what the bench holds.
   *
   * The two tables it cannot rebuild are named in the response instead of being left out of it. `reachability_prior`
   * is written only when a live run confirms a subject; `corpus_rule` is promoted by a person. A reader who saw
   * neither mentioned would take their size for a measurement of the bench, which is the one reading a
   * reconciliation must not enable.
   */
  app.post('/corpus/reindex', async (req) => {
    const m = messages(resolveLocale((req.query as { lang?: unknown } | undefined)?.lang)).corpusReindex;
    const report = reindexCorpus(
      {
        verdict: m.verdict,
        boundedNote: m.boundedNote,
        unrecordedNote: m.unrecordedNote,
        unstampedNote: m.unstampedNote,
      },
      [
        { table: 'reachability_prior', reason: m.reachabilityPrior },
        { table: 'corpus_rule', reason: m.corpusRule },
      ],
    );
    return { report };
  });

  app.delete('/corpus/rules/:id', async (req) => {
    const { id } = req.params as { id: string };
    deleteRule(id);
    return { deleted: id };
  });
}
