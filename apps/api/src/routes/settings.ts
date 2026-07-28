/**
 * Settings routes — read every lane flag with the reason it is where it is, and flip the ones that can be flipped.
 *
 * The GET deliberately returns more than a boolean per flag. A toggle whose only output is on/off invites the
 * question this endpoint exists to answer in advance: *why* is the lane off when compose says `=1`, and what
 * exactly starts happening if I turn it on? So each entry carries what it enables, what leaves the machine, where
 * its current value came from, and whether it is on-but-inert because the lane it depends on is off.
 */
import type { FastifyInstance } from 'fastify';
import { TOGGLEABLE_FLAGS, resolveFlags } from '../flags.js';
import { clearFlagOverride, getFlagOverrides, listFlagOverrides, setFlagOverride } from '../settings.js';

export async function settingsRoutes(app: FastifyInstance): Promise<void> {
  app.get('/settings/flags', async () => {
    const overrides = getFlagOverrides();
    const stamps = new Map(listFlagOverrides().map((s) => [s.key, s.updatedAt]));
    return {
      flags: resolveFlags(process.env, overrides).map((f) => ({
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
    return { flags: resolveFlags(process.env, getFlagOverrides()) };
  });

  /** Drop the override so the flag follows the environment again — a distinct state from pinning the same value. */
  app.delete('/settings/flags/:name', async (req, reply) => {
    const { name } = req.params as { name: string };
    if (!clearFlagOverride(name)) return reply.status(400).send({ error: `${name} is not a runtime-toggleable flag` });
    app.log.info(`settings: ${name} override cleared — following the environment again`);
    return { flags: resolveFlags(process.env, getFlagOverrides()) };
  });
}
