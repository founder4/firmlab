/**
 * proofState — the human gloss for each proof state, and for severity. English source of truth.
 *
 * **The codes themselves are never translated.** `static_confirmed`, `blocked_by_platform` and the rest cross the
 * API and are stored in SQLite; they are identifiers, not prose, and rendering `confirmado_estático` anywhere would
 * be inventing a value the workbench does not use. What is localised is the short label a reader sees and the
 * sentence explaining what the state does and does not claim.
 *
 * The meanings are load-bearing and must not be softened in translation. `blocked_by_*` means the question WAS
 * asked and could not be answered — it is not a negative, and a Spanish rendering that reads like "sin problemas"
 * would invert the workbench's central claim.
 */
export const proofState = {
  label: {
    confirmed_full_system: 'confirmed (full-system)',
    confirmed_in_emulation: 'confirmed (emulated)',
    static_confirmed: 'static-confirmed',
    needs_runtime_reproduction: 'needs reproduction',
    blocked_by_platform: 'blocked (platform)',
    blocked_by_security: 'blocked (control)',
    false_positive: 'false positive',
    operator_assertion: 'asserted · not measured',
  },
  meaning: {
    confirmed_full_system: 'Reproduced under full-system emulation.',
    confirmed_in_emulation: 'Reproduced against a booted image. This proves the sandbox, never the physical device.',
    static_confirmed: 'The property is literally present in the bytes. It states the fact, not its exploitability.',
    needs_runtime_reproduction:
      'A lead. A precondition was observed and nothing was proven — never report it as a bug.',
    blocked_by_platform:
      'The question was asked and this deployment could not answer it. This is NOT a negative result.',
    blocked_by_security: 'A control — encryption, secure boot — stopped the analysis. This is NOT a negative result.',
    false_positive: 'Checked and dismissed.',
    operator_assertion:
      'A person or an agent asserted this; FirmLab did not measure it. It carries no proof state and counts towards no analysis stage.',
  },
  severity: {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    info: 'info',
  },
};
