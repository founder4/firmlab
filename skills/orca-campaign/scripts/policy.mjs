/**
 * Pure, zero-dependency policy engine for Orca campaigns.
 *
 * Code, never a model, assigns proof states and decides capacity availability.
 * A campaign policy tracks durable quota, rate-limit, and availability boundaries
 * across providers, models, and shared domains so workers are not launched into
 * known capacity exhaustion.
 *
 * Core invariants:
 * - A blocked/unavailable provider-scope entry excludes every model of that provider.
 * - A blocked model-scope entry excludes that specific model only (other models permitted
 *   if no provider-scope block exists).
 * - Elapsed resetAt never auto-recovers: positive canary evidence (recoveredBy) is required.
 * - Unknown capacity (no entry) is not exhaustion and is allowed (reason 'no_recorded_block').
 * - Fresh terminals and handles never bypass capacity decisions.
 * - Explicit --capacity-domain is accounting metadata only and cannot bypass provider/model blocks.
 *
 * Identities fail closed. Every rule above matches on an entry's provider, scope and model, so an identity the
 * matcher cannot recognise is not a narrower block but NO block: a provider-scope entry written as "Anthropic"
 * used to parse cleanly and then match nothing, allowing every Claude launch as 'no_recorded_block'. So a
 * registry entry is canonicalised (provider trimmed and lowercased, then required to be a known provider) or
 * refused outright, and a refused registry refuses every launch (`policy_invalid` in the launcher):
 * - scope 'model' must name a non-empty model; scope 'provider' must name none. A provider-scope entry naming a
 *   model is rejected rather than silently narrowed or widened, because nobody can tell which was meant.
 * - A domain using a reserved prefix (`provider:` / `model:`) must equal the key its identity implies, so that
 *   `provider:anthropic` can never be an entry the provider rule does not read. Any other domain string is an
 *   explicit shared capacity domain and stays free-form.
 *
 * A handoff records the reason it happened, and new records must carry the evidence for it (the limit screen,
 * the context exhaustion, the unavailability, or the user's opt-in for forced_test): a reason with nothing
 * observed behind it is a rotation, which the campaign forbids. Entries written before that rule parse without
 * it, because a stored registry is data an older build wrote.
 */

export class PolicyValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyValidationError';
  }
}

const VALID_SCOPES = new Set(['provider', 'model']);
const VALID_STATUSES = new Set(['blocked', 'unavailable', 'recovered']);
const VALID_HANDOFF_REASONS = new Set(['capacity_exhausted', 'context_exhausted', 'unavailable', 'forced_test']);
const RESERVED_DOMAIN_PREFIX = /^(provider|model):/i;

export const KNOWN_PROVIDERS = Object.freeze(['anthropic', 'openai', 'google']);

/**
 * Canonical provider identity: trimmed and lowercased, then required to be a known provider. Returns null for
 * anything else, which every caller treats as invalid rather than as an unknown-but-harmless provider.
 */
export function canonicalProvider(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return KNOWN_PROVIDERS.includes(normalized) ? normalized : null;
}

/** The domain key an identity implies: `provider:<p>` or `model:<p>/<m>`. */
export function identityDomain(scope, provider, model) {
  return scope === 'model' ? `model:${provider}/${model}` : `provider:${provider}`;
}

/**
 * Maps known agent identifiers to their underlying capacity provider.
 * Unknown agents return null and are refused launch.
 */
export function providerOf(agent) {
  if (typeof agent !== 'string') return null;
  const normalized = agent.trim().toLowerCase();
  switch (normalized) {
    case 'claude':
      return 'anthropic';
    case 'codex':
      return 'openai';
    case 'antigravity':
      return 'google';
    default:
      return null;
  }
}

/**
 * Resolves the capacity domain key for a given agent, model, or explicit domain.
 * An explicit capacityDomain takes precedence. Otherwise model-scoped or provider-wide.
 */
export function capacityDomain({ agent, model, capacityDomain: explicitDomain } = {}) {
  if (explicitDomain && typeof explicitDomain === 'string' && explicitDomain.trim()) {
    return explicitDomain.trim();
  }
  const provider = providerOf(agent);
  if (!provider) return null;
  if (model && typeof model === 'string' && model.trim()) {
    return `model:${provider}/${model.trim()}`;
  }
  return `provider:${provider}`;
}

export function validateDomainEntry(entry, index) {
  const prefix = index !== undefined ? `Domain entry [${index}]: ` : 'Domain entry: ';
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new PolicyValidationError(`${prefix}must be an object`);
  }
  if (typeof entry.domain !== 'string' || !entry.domain.trim()) {
    throw new PolicyValidationError(`${prefix}domain must be a non-empty string`);
  }
  if (!VALID_SCOPES.has(entry.scope)) {
    throw new PolicyValidationError(`${prefix}scope must be 'provider' or 'model'`);
  }
  const provider = canonicalProvider(entry.provider);
  if (!provider) {
    throw new PolicyValidationError(
      `${prefix}provider must be one of ${KNOWN_PROVIDERS.map((p) => `'${p}'`).join(', ')} (after trim and lowercase), got ${JSON.stringify(entry.provider)}`,
    );
  }
  if (entry.model !== null && entry.model !== undefined && typeof entry.model !== 'string') {
    throw new PolicyValidationError(`${prefix}model must be string, null, or undefined`);
  }
  const model = typeof entry.model === 'string' ? entry.model.trim() : null;
  if (entry.scope === 'model' && !model) {
    throw new PolicyValidationError(`${prefix}scope 'model' requires a non-empty model`);
  }
  if (entry.scope === 'provider' && entry.model !== null && entry.model !== undefined) {
    throw new PolicyValidationError(
      `${prefix}scope 'provider' must not name a model (got ${JSON.stringify(entry.model)}); record a model-scope entry instead`,
    );
  }
  const domain = entry.domain.trim();
  if (RESERVED_DOMAIN_PREFIX.test(domain) && domain !== identityDomain(entry.scope, provider, model)) {
    throw new PolicyValidationError(
      `${prefix}domain '${domain}' uses a reserved prefix but does not match its identity '${identityDomain(entry.scope, provider, model)}'`,
    );
  }
  if (!VALID_STATUSES.has(entry.status)) {
    throw new PolicyValidationError(`${prefix}status must be 'blocked', 'unavailable', or 'recovered'`);
  }
  if (typeof entry.reason !== 'string' || !entry.reason.trim()) {
    throw new PolicyValidationError(`${prefix}reason must be a non-empty string`);
  }
  if (typeof entry.evidence !== 'string' || !entry.evidence.trim()) {
    throw new PolicyValidationError(`${prefix}evidence must be a non-empty string`);
  }
  if (typeof entry.observedAt !== 'string' || !Number.isFinite(Date.parse(entry.observedAt))) {
    throw new PolicyValidationError(`${prefix}observedAt must be a valid ISO date string`);
  }
  if (
    entry.resetAt !== null &&
    entry.resetAt !== undefined &&
    (typeof entry.resetAt !== 'string' || !Number.isFinite(Date.parse(entry.resetAt)))
  ) {
    throw new PolicyValidationError(`${prefix}resetAt must be null or a valid ISO date string`);
  }
  if (entry.status === 'recovered') {
    if (typeof entry.recoveredBy !== 'string' || !entry.recoveredBy.trim()) {
      throw new PolicyValidationError(`${prefix}recoveredBy (canary evidence) is required when status is 'recovered'`);
    }
  } else if (entry.recoveredBy !== undefined && entry.recoveredBy !== null && typeof entry.recoveredBy !== 'string') {
    throw new PolicyValidationError(`${prefix}recoveredBy must be a string if provided`);
  }
}

/** The canonical form of an entry validateDomainEntry accepted. */
function normalizeDomainEntry(d) {
  return {
    domain: d.domain.trim(),
    scope: d.scope,
    provider: canonicalProvider(d.provider),
    model: d.scope === 'model' ? d.model.trim() : null,
    status: d.status,
    reason: d.reason,
    evidence: d.evidence,
    observedAt: d.observedAt,
    resetAt: d.resetAt ?? null,
    ...(d.recoveredBy ? { recoveredBy: d.recoveredBy } : {}),
  };
}

/**
 * `requireEvidence` is set for records being written now; a parsed registry may hold handoffs written before
 * evidence was required, and those stay readable. Evidence that IS present must be a non-empty string either way.
 */
export function validateHandoffEntry(entry, index, { requireEvidence = false } = {}) {
  const prefix = index !== undefined ? `Handoff entry [${index}]: ` : 'Handoff entry: ';
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new PolicyValidationError(`${prefix}must be an object`);
  }
  if (typeof entry.fromHandle !== 'string' || !entry.fromHandle.trim()) {
    throw new PolicyValidationError(`${prefix}fromHandle must be a non-empty string`);
  }
  if (typeof entry.toHandle !== 'string' || !entry.toHandle.trim()) {
    throw new PolicyValidationError(`${prefix}toHandle must be a non-empty string`);
  }
  if (!Number.isInteger(entry.generation) || entry.generation < 0) {
    throw new PolicyValidationError(`${prefix}generation must be a non-negative integer`);
  }
  if (!VALID_HANDOFF_REASONS.has(entry.reason)) {
    throw new PolicyValidationError(
      `${prefix}reason must be one of 'capacity_exhausted', 'context_exhausted', 'unavailable', 'forced_test'`,
    );
  }
  if (entry.reason === 'forced_test' && entry.explicitUserOptIn !== true) {
    throw new PolicyValidationError(`${prefix}forced_test requires explicitUserOptIn === true`);
  }
  if (typeof entry.at !== 'string' || !Number.isFinite(Date.parse(entry.at))) {
    throw new PolicyValidationError(`${prefix}at must be a valid ISO date string`);
  }
  if (entry.explicitUserOptIn !== undefined && typeof entry.explicitUserOptIn !== 'boolean') {
    throw new PolicyValidationError(`${prefix}explicitUserOptIn must be a boolean`);
  }
  if (entry.evidence === undefined ? requireEvidence : typeof entry.evidence !== 'string' || !entry.evidence.trim()) {
    throw new PolicyValidationError(
      `${prefix}evidence must be a non-empty string naming what was observed (limit screen, context exhaustion, unavailability, or the user's opt-in for forced_test)`,
    );
  }
}

export function parsePolicy(text) {
  if (typeof text !== 'string') {
    throw new PolicyValidationError('Policy text must be a string');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new PolicyValidationError(`Invalid JSON in policy: ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new PolicyValidationError('Policy root must be an object');
  }
  if (parsed.version !== 1) {
    throw new PolicyValidationError(`Unsupported policy version: ${parsed.version}`);
  }
  if (
    parsed.currentProvider !== null &&
    parsed.currentProvider !== undefined &&
    typeof parsed.currentProvider !== 'string'
  ) {
    throw new PolicyValidationError('currentProvider must be string, null, or undefined');
  }
  if (!Array.isArray(parsed.domains)) {
    throw new PolicyValidationError('domains must be an array');
  }
  for (let i = 0; i < parsed.domains.length; i++) {
    validateDomainEntry(parsed.domains[i], i);
  }
  if (parsed.handoffs !== undefined && !Array.isArray(parsed.handoffs)) {
    throw new PolicyValidationError('handoffs must be an array');
  }
  const handoffs = parsed.handoffs ?? [];
  for (let i = 0; i < handoffs.length; i++) {
    validateHandoffEntry(handoffs[i], i);
  }
  return {
    version: 1,
    currentProvider: parsed.currentProvider ?? null,
    domains: parsed.domains.map(normalizeDomainEntry),
    handoffs: handoffs.map((h) => ({
      fromHandle: h.fromHandle,
      toHandle: h.toHandle,
      generation: h.generation,
      reason: h.reason,
      at: h.at,
      ...(h.explicitUserOptIn !== undefined ? { explicitUserOptIn: h.explicitUserOptIn } : {}),
      ...(h.evidence !== undefined ? { evidence: h.evidence } : {}),
    })),
  };
}

export function serializePolicy(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new PolicyValidationError('Policy must be an object');
  }
  return `${JSON.stringify(policy, null, 2)}\n`;
}

export function createEmptyPolicy({ currentProvider = null } = {}) {
  return {
    version: 1,
    currentProvider,
    domains: [],
    handoffs: [],
  };
}

export function setCurrentProvider(policy, provider) {
  if (provider !== null && typeof provider !== 'string') {
    throw new PolicyValidationError('provider must be a string or null');
  }
  return {
    ...policy,
    currentProvider: provider,
  };
}

export function recordBlock(policy, entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new PolicyValidationError('Block entry must be an object');
  }
  const candidate = {
    domain: typeof entry.domain === 'string' ? entry.domain.trim() : entry.domain,
    scope: entry.scope,
    provider: entry.provider,
    model: entry.model ?? null,
    status: entry.status ?? 'blocked',
    reason: typeof entry.reason === 'string' ? entry.reason.trim() : entry.reason,
    evidence: typeof entry.evidence === 'string' ? entry.evidence.trim() : entry.evidence,
    observedAt: entry.observedAt ?? new Date().toISOString(),
    resetAt: entry.resetAt ?? null,
  };
  validateDomainEntry(candidate);
  return {
    ...policy,
    domains: [...(policy.domains ?? []), normalizeDomainEntry(candidate)],
  };
}

export function recordRecovery(policy, { domain, recoveredBy, observedAt, reason, evidence } = {}) {
  if (!domain || typeof domain !== 'string' || !domain.trim()) {
    throw new PolicyValidationError('domain is required for recovery');
  }
  if (!recoveredBy || typeof recoveredBy !== 'string' || !recoveredBy.trim()) {
    throw new PolicyValidationError('Canary evidence (recoveredBy) is required for recovery');
  }
  const cleanDomain = domain.trim();
  const cleanEvidence = recoveredBy.trim();

  const prior = [...(policy.domains ?? [])].reverse().find((d) => d.domain === cleanDomain);
  let scope = prior?.scope;
  let provider = prior?.provider;
  let model = prior?.model ?? null;

  if (!scope || !provider) {
    if (cleanDomain.startsWith('provider:')) {
      scope = 'provider';
      provider = cleanDomain.slice(9);
    } else if (cleanDomain.startsWith('model:')) {
      scope = 'model';
      const parts = cleanDomain.slice(6).split('/');
      provider = parts[0];
      model = parts.slice(1).join('/');
    } else {
      // A shared domain's identity cannot be read from its name, and guessing one would record a recovery the
      // provider and model rules then apply to the wrong thing.
      throw new PolicyValidationError(
        `Recovery for shared domain '${cleanDomain}' needs a prior recorded entry to take its identity from`,
      );
    }
  }

  const recoveryEntry = {
    domain: cleanDomain,
    scope,
    provider,
    model,
    status: 'recovered',
    reason: reason ?? 'recovered_by_canary',
    evidence: evidence ?? cleanEvidence,
    observedAt: observedAt ?? new Date().toISOString(),
    resetAt: null,
    recoveredBy: cleanEvidence,
  };
  validateDomainEntry(recoveryEntry);
  return {
    ...policy,
    domains: [...(policy.domains ?? []), normalizeDomainEntry(recoveryEntry)],
  };
}

export function recordHandoff(
  policy,
  { fromHandle, toHandle, generation, reason, at, explicitUserOptIn, evidence } = {},
) {
  const handoff = {
    fromHandle,
    toHandle,
    generation,
    reason,
    at: at ?? new Date().toISOString(),
    ...(explicitUserOptIn !== undefined ? { explicitUserOptIn } : {}),
    evidence: typeof evidence === 'string' ? evidence.trim() : evidence,
  };
  validateHandoffEntry(handoff, undefined, { requireEvidence: true });
  return {
    ...policy,
    handoffs: [...(policy.handoffs ?? []), handoff],
  };
}

/**
 * Deterministically collects the latest authoritative entry per domain.
 * Ordering tie-breaker: Date.parse(observedAt) -> localeCompare -> array index.
 */
function getLatestDomainEntries(domains) {
  const byDomain = new Map();
  for (let idx = 0; idx < domains.length; idx++) {
    const entry = domains[idx];
    const existing = byDomain.get(entry.domain);
    if (!existing) {
      byDomain.set(entry.domain, { entry, idx });
    } else {
      const existingTime = Date.parse(existing.entry.observedAt);
      const entryTime = Date.parse(entry.observedAt);
      if (
        entryTime > existingTime ||
        (entryTime === existingTime && entry.observedAt.localeCompare(existing.entry.observedAt) > 0) ||
        (entryTime === existingTime && entry.observedAt === existing.entry.observedAt && idx > existing.idx)
      ) {
        byDomain.set(entry.domain, { entry, idx });
      }
    }
  }
  const result = new Map();
  for (const [d, { entry }] of byDomain.entries()) {
    result.set(d, entry);
  }
  return result;
}

/**
 * The authoritative entry for one domain under the same rule `evaluateLaunch` applies (latest `observedAt`, then
 * array order), so every reader of the registry agrees on whether a domain is blocked.
 */
export function latestDomainEntry(policy, domain) {
  return getLatestDomainEntries(policy?.domains ?? []).get(domain) ?? null;
}

/**
 * Evaluates whether launching a worker for the given agent and model is permitted under policy.
 *
 * Rules:
 * (a) A blocked/unavailable provider-scope entry blocks every model of that provider.
 * (b) A blocked model-scope entry blocks that model only; another model of the same provider
 *     is allowed if no provider-scope entry blocks it.
 * (c) Terminal handle is never considered in the decision.
 * (d) Unknown capacity (no recorded block) is allowed with reason 'no_recorded_block'.
 * (e) Elapsed resetAt never auto-recovers; only an entry with status 'recovered' and
 *     canary evidence lifts it.
 * (f) The latest entry per domain (by observedAt) is authoritative.
 * (g) Explicit capacityDomain is accounting metadata only; it cannot bypass provider/model blocks.
 * (h) A launch that names no model is refused while any model of its provider is blocked: the provider default
 *     may be the blocked model, and nothing here can tell.
 */
export function evaluateLaunch(policy, { agent, model, capacityDomain: explicitDomain } = {}, now = Date.now()) {
  const provider = providerOf(agent);
  if (!provider) {
    return {
      allowed: false,
      reason: 'unknown_provider',
      domain: explicitDomain ?? null,
    };
  }

  if (!policy || typeof policy !== 'object' || !Array.isArray(policy.domains)) {
    throw new PolicyValidationError('Invalid policy structure passed to evaluateLaunch');
  }

  const latestByDomain = getLatestDomainEntries(policy.domains);

  function checkEntry(entry) {
    if (!entry) return null;
    if (entry.status === 'blocked' || entry.status === 'unavailable') {
      if (entry.resetAt) {
        const resetTime = Date.parse(entry.resetAt);
        if (Number.isFinite(resetTime) && resetTime <= now) {
          return {
            blocked: true,
            reason: 'reset_elapsed_requires_viable_canary',
            domain: entry.domain,
            matched: entry,
          };
        }
      }
      return {
        blocked: true,
        reason: entry.reason,
        domain: entry.domain,
        matched: entry,
      };
    }
    if (entry.status === 'recovered') {
      if (entry.recoveredBy && entry.recoveredBy.trim().length > 0) {
        return {
          blocked: false,
          recovered: true,
          domain: entry.domain,
          matched: entry,
        };
      }
      return {
        blocked: true,
        reason: 'reset_elapsed_requires_viable_canary',
        domain: entry.domain,
        matched: entry,
      };
    }
    return null;
  }

  // 1. Provider-level block check (rule a).
  // Provider-wide exclusion applies to all models of this provider.
  let matchedProviderEntry = null;
  for (const entry of latestByDomain.values()) {
    if (canonicalProvider(entry.provider) === provider && entry.scope === 'provider') {
      const check = checkEntry(entry);
      if (check?.blocked) {
        return {
          allowed: false,
          reason: check.reason,
          domain: check.domain,
          matched: check.matched,
        };
      }
      if (check?.recovered) {
        matchedProviderEntry = check.matched;
      }
    }
  }

  // 2a. An unnamed model is the provider's default, which may be exactly the blocked model: refuse rather than guess.
  if (!(model && typeof model === 'string' && model.trim())) {
    for (const entry of latestByDomain.values()) {
      if (canonicalProvider(entry.provider) !== provider || entry.scope !== 'model') continue;
      const check = checkEntry(entry);
      if (check?.blocked) {
        return {
          allowed: false,
          reason: 'model_unspecified_with_model_block',
          domain: check.domain,
          matched: check.matched,
        };
      }
    }
  }

  // 2. Model-level block check (rule b).
  let matchedModelEntry = null;
  if (model && typeof model === 'string' && model.trim()) {
    const cleanModel = model.trim();
    const modelDomainKey = `model:${provider}/${cleanModel}`;
    const entry = latestByDomain.get(modelDomainKey);
    if (entry) {
      const check = checkEntry(entry);
      if (check?.blocked) {
        return {
          allowed: false,
          reason: check.reason,
          domain: check.domain,
          matched: check.matched,
        };
      }
      if (check?.recovered) {
        matchedModelEntry = check.matched;
      }
    } else {
      for (const e of latestByDomain.values()) {
        if (e.scope === 'model' && canonicalProvider(e.provider) === provider && e.model === cleanModel) {
          const check = checkEntry(e);
          if (check?.blocked) {
            return {
              allowed: false,
              reason: check.reason,
              domain: check.domain,
              matched: check.matched,
            };
          }
          if (check?.recovered) {
            matchedModelEntry = check.matched;
          }
        }
      }
    }
  }

  // 3. Explicit capacity domain check.
  let matchedCapacityEntry = null;
  if (explicitDomain && typeof explicitDomain === 'string' && explicitDomain.trim()) {
    const cleanExplicit = explicitDomain.trim();
    const entry = latestByDomain.get(cleanExplicit);
    if (entry) {
      const check = checkEntry(entry);
      if (check?.blocked) {
        return {
          allowed: false,
          reason: check.reason,
          domain: check.domain,
          matched: check.matched,
        };
      }
      if (check?.recovered) {
        matchedCapacityEntry = check.matched;
      }
    }
  }

  const targetDomain = capacityDomain({ agent, model, capacityDomain: explicitDomain });

  const recoveredMatch = matchedCapacityEntry ?? matchedModelEntry ?? matchedProviderEntry;
  if (recoveredMatch) {
    return {
      allowed: true,
      reason: 'recovered',
      domain: targetDomain,
      matched: recoveredMatch,
    };
  }

  return {
    allowed: true,
    reason: 'no_recorded_block',
    domain: targetDomain,
  };
}
