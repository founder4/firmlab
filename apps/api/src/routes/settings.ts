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
import { resolveAgentApproval } from '../agent/approval.js';
import { TOGGLEABLE_FLAGS, resolveFlags } from '../flags.js';
import { resolveLocale } from '../i18n/index.js';
import { LLM_SETTING_KEYS, describeLlm, isLlmSettingKey, validateLlmSetting } from '../llm-settings.js';
import {
  clearAgentPreapproval,
  clearFlagOverride,
  clearLlmSetting,
  getAgentPreapprovalOverride,
  getFlagOverrides,
  getLlmOverrides,
  listFlagOverrides,
  listLlmSettingTimes,
  setAgentPreapproval,
  setFlagOverride,
  setLlmSetting,
} from '../settings.js';

export async function settingsRoutes(app: FastifyInstance): Promise<void> {
  const approvalState = () => resolveAgentApproval(process.env, getAgentPreapprovalOverride());

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

  /**
   * The model provider, described and never disclosed.
   *
   * Every field says whether the ENVIRONMENT or an OVERRIDE won, the same contract the flags have, because an
   * operator who set `FIRMLAB_LLM_MODEL` in compose and sees another model here deserves to be told why. The API
   * KEY is the exception to "return what you store": this reports only that one is present and its last four
   * characters — enough to tell two keys apart, useless as a credential. A settings endpoint that echoed a key
   * back would turn one authenticated reader into an exfiltration path.
   */
  app.get('/settings/llm', async () => {
    const stamps = new Map(listLlmSettingTimes().map((s) => [s.key, s.updatedAt]));
    const state = describeLlm(process.env, getLlmOverrides(), process.env.FIRMLAB_AGENT === '1');
    return { llm: state, updatedAt: Object.fromEntries(stamps) };
  });

  app.put('/settings/llm/:key', async (req, reply) => {
    const { key } = req.params as { key: string };
    const body = (req.body ?? {}) as { value?: unknown };
    if (!isLlmSettingKey(key)) {
      return reply.status(400).send({ error: `${key} is not a model setting`, settable: LLM_SETTING_KEYS });
    }
    if (typeof body.value !== 'string') return reply.status(400).send({ error: 'body must be { "value": "…" }' });
    const check = validateLlmSetting(key, body.value);
    if (!check.ok) return reply.status(400).send({ error: check.error });
    setLlmSetting(key, body.value);
    // The value is never echoed, not even the one just written — an endpoint that returns a key on write is the
    // same hole as one that returns it on read.
    app.log.info(`settings: ${key} set (${body.value.length} chars)`);
    return { llm: describeLlm(process.env, getLlmOverrides(), process.env.FIRMLAB_AGENT === '1') };
  });

  /** Drop one field so it follows the environment again — a distinct state from pinning the same value by hand. */
  app.delete('/settings/llm/:key', async (req, reply) => {
    const { key } = req.params as { key: string };
    if (!clearLlmSetting(key)) return reply.status(400).send({ error: `${key} is not a model setting` });
    app.log.info(`settings: ${key} cleared — following the environment again`);
    return { llm: describeLlm(process.env, getLlmOverrides(), process.env.FIRMLAB_AGENT === '1') };
  });

  /** Persistent pre-authorisation for future agent sessions. Manual approval remains the default. */
  app.get('/settings/agent-approval', async () => ({ approval: approvalState() }));

  app.put('/settings/agent-approval', async (req, reply) => {
    const body = (req.body ?? {}) as { preapproveAll?: unknown };
    if (typeof body.preapproveAll !== 'boolean') {
      return reply.status(400).send({ error: 'body must be { "preapproveAll": true | false }' });
    }
    setAgentPreapproval(body.preapproveAll);
    app.log.info(`settings: agent emulation pre-approval set to ${body.preapproveAll ? '1' : '0'}`);
    return { approval: approvalState() };
  });

  app.delete('/settings/agent-approval', async () => {
    clearAgentPreapproval();
    app.log.info('settings: agent emulation pre-approval cleared — following the environment again');
    return { approval: approvalState() };
  });
}
