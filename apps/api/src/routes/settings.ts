/**
 * Settings routes — read every lane flag with the reason it is where it is, and flip the ones that can be flipped.
 *
 * The GET deliberately returns more than a boolean per flag. A toggle whose only output is on/off invites the
 * question this endpoint exists to answer in advance: *why* is the lane off when compose says `=1`, and what
 * exactly starts happening if I turn it on? So each entry carries what it enables, what leaves the machine, where
 * its current value came from, and whether it is on-but-inert because the lane it depends on is off.
 *
 * That prose is what `?lang` selects. It is resolved on every read and it describes this deployment, so it is
 * interface copy rather than a record — while the flag NAME, the source (`override` / `environment` / `default`)
 * and every boolean are identifiers and come back identical in both languages. The write endpoints take it too:
 * they answer with the whole resolved set, and a lane switched from a Spanish UI must not come back in English.
 */
import type { FastifyInstance } from 'fastify';
import { TOGGLEABLE_FLAGS, resolveFlags } from '../flags.js';
import { resolveLocale } from '../i18n/index.js';
import { clearFlagOverride, getFlagOverrides, listFlagOverrides, setFlagOverride } from '../settings.js';

export async function settingsRoutes(app: FastifyInstance): Promise<void> {
  app.get('/settings/flags', async (req) => {
    const locale = resolveLocale((req.query as { lang?: unknown }).lang);
    const overrides = getFlagOverrides();
    const stamps = new Map(listFlagOverrides().map((s) => [s.key, s.updatedAt]));
    return {
      flags: resolveFlags(process.env, overrides, locale).map((f) => ({
        ...f,
        ...(stamps.has(f.name) ? { overriddenAt: stamps.get(f.name) } : {}),
      })),
      // Stated so the UI can say it rather than imply it: these take effect immediately because every lane reads
      // its config per run, not once at boot.
      appliesImmediately: true,
    };
  });

  app.put('/settings/flags/:name', async (req, reply) => {
    const { name } = req.params as { name: string };
    const locale = resolveLocale((req.query as { lang?: unknown }).lang);
    const body = (req.body ?? {}) as { enabled?: unknown };
    if (typeof body.enabled !== 'boolean') {
      return reply.status(400).send({ error: 'body must be { "enabled": true | false }' });
    }
    if (!setFlagOverride(name, body.enabled)) {
      return reply
        .status(400)
        .send({ error: `${name} is not a runtime-toggleable flag`, toggleable: TOGGLEABLE_FLAGS.map((f) => f.name) });
    }
    app.log.info(`settings: ${name} overridden to ${body.enabled ? '1' : '0'}`);
    return { flags: resolveFlags(process.env, getFlagOverrides(), locale) };
  });

  /** Drop the override so the flag follows the environment again — a distinct state from pinning the same value. */
  app.delete('/settings/flags/:name', async (req, reply) => {
    const { name } = req.params as { name: string };
    const locale = resolveLocale((req.query as { lang?: unknown }).lang);
    if (!clearFlagOverride(name)) return reply.status(400).send({ error: `${name} is not a runtime-toggleable flag` });
    app.log.info(`settings: ${name} override cleared — following the environment again`);
    return { flags: resolveFlags(process.env, getFlagOverrides(), locale) };
  });
}
