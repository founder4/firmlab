/**
 * Agent-emulation approval policy.
 *
 * Manual approval remains the safe default. A deployment may explicitly pre-authorise every emulation target
 * proposed by future agent sessions, either through the environment or through the persisted Settings override.
 * This policy never widens what the agent may execute: it only settles the existing emulation gate for targets
 * already clamped by deterministic preflight.
 */

export const AGENT_PREAPPROVE_KEY = 'FIRMLAB_AGENT_PREAPPROVE' as const;

export type AgentApprovalSource = 'override' | 'environment' | 'default';

export interface AgentApprovalState {
  key: typeof AGENT_PREAPPROVE_KEY;
  preapproveAll: boolean;
  source: AgentApprovalSource;
  environmentValue: boolean;
}

const enabled = (value: string | undefined): boolean => /^(1|true|yes|on)$/i.test(value?.trim() ?? '');

/** Resolve the effective policy while preserving where it came from for the Settings screen. */
export function resolveAgentApproval(env: NodeJS.ProcessEnv, override?: string): AgentApprovalState {
  const environmentValue = enabled(env[AGENT_PREAPPROVE_KEY]);
  return {
    key: AGENT_PREAPPROVE_KEY,
    preapproveAll: override === undefined ? environmentValue : enabled(override),
    source: override === undefined ? (env[AGENT_PREAPPROVE_KEY] === undefined ? 'default' : 'environment') : 'override',
    environmentValue,
  };
}

/**
 * Resolve one approval click into an execution list. `all` preserves proposal order and removes duplicate binary
 * targets so a model repeating one target cannot make a single approval run it twice.
 */
export function approvedTargets<T extends { binary: string }>(
  plan: readonly T[],
  choice: { binary?: string | null; all?: boolean },
): T[] {
  if (!choice.all) {
    const selected = choice.binary ? plan.find((entry) => entry.binary === choice.binary) : plan[0];
    return selected ? [selected] : [];
  }
  const seen = new Set<string>();
  return plan.filter((entry) => {
    if (seen.has(entry.binary)) return false;
    seen.add(entry.binary);
    return true;
  });
}
