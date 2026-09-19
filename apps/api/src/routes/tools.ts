/**
 * Capability introspection: which external tools this deployment has, grouped by what they unlock. Backs the
 * UI "Capabilities" panel so a user immediately sees whether they're on the full firmware image or the
 * static-only base.
 *
 * `?lang` selects the language of the per-tool gloss only. The ids, the binary names and the version line each
 * tool printed are identifiers and come back identical either way; what is probed does not depend on the locale,
 * so the cache is shared and the answer to "is it installed?" is the same answer in both languages. Absent or
 * unrecognised, `?lang` is English — the answer every caller before this got.
 *
 * **Why a tool's dataset is read here and not in `probe`.** `detectTools` answers "is the binary there?" and
 * caches it for the process lifetime, which is right for a binary and wrong for the DATA a binary needs: grype
 * runs perfectly well with no vulnerability database and then refuses every CVE question, and provisioning that
 * database is an operator action that happens while the server is up. Caching it would keep denying a database
 * that is now on disk until someone restarted the API. So it is probed per request, off to the side, and only
 * for the tools that have one — `dataset` absent on a row means that tool needs no dataset, never that its
 * dataset is fine.
 */
import type { FastifyInstance } from 'fastify';
import { type Locale, messages, resolveLocale } from '../i18n/index.js';
import { anchoreEnv, grypeDatasetFact, grypeDbDir, readGrypeDbStatus } from '../providers/sbom-db.js';
import { type ToolDataset, type ToolStatus, detectTools } from '../tools.js';

/**
 * The grype row's data dependency, in the reader's language.
 *
 * `readGrypeDbStatus` never throws: a grype that ran and reported no database, and a `grype db status` that
 * could not be run at all, both come back as `present: false` with the reason in `error`. Those are genuinely
 * different claims, and what keeps the page from conflating them is that the sentence interpolates grype's own
 * error text rather than asserting "no database" on its own authority. This is only reached when the `version`
 * probe already succeeded, so the second case is a harness failure and reads as one.
 */
async function grypeDataset(locale: Locale): Promise<ToolDataset> {
  const text = messages(locale).tools.dataset;
  const fact = grypeDatasetFact(await readGrypeDbStatus(anchoreEnv()), grypeDbDir());
  return fact.ready
    ? {
        ready: true,
        detail: text.grypeReady({
          built: fact.built,
          ageDays: fact.ageDays,
          stale: fact.stale,
          schema: fact.schemaVersion,
        }),
      }
    : { ready: false, detail: text.grypeAbsent({ dbDir: fact.dbDir, error: fact.error }) };
}

export async function toolRoutes(app: FastifyInstance): Promise<void> {
  app.get('/tools', async (req) => {
    const query = req.query as { refresh?: string; lang?: unknown };
    const force = query.refresh === '1';
    const locale = resolveLocale(query.lang);
    const probed = await detectTools(force, locale);

    // Only asked when the binary answered: `grype db status` on a box with no grype is a second way of learning
    // what the probe already reported, and it would spend a 30 s timeout to learn it.
    const grypeAvailable = probed.some((t) => t.id === 'grype' && t.available);
    const dataset = grypeAvailable ? await grypeDataset(locale) : undefined;
    const tools: ToolStatus[] = probed.map((t) => (t.id === 'grype' && dataset !== undefined ? { ...t, dataset } : t));

    const groups: Record<string, { available: number; total: number; notReady: number }> = {};
    for (const t of tools) {
      if (!groups[t.group]) groups[t.group] = { available: 0, total: 0, notReady: 0 };
      const g = groups[t.group] as { available: number; total: number; notReady: number };
      g.total++;
      if (t.available) g.available++;
      // Counted apart from `available`, never subtracted from it. The binary IS here; what it cannot do is the
      // one question its dataset backs, and a counter that hid it would reproduce the overstatement this fixes.
      if (t.available && t.dataset?.ready === false) g.notReady++;
    }
    return { tools, groups };
  });
}
