/**
 * The kernel command line audit, shared by every provider that can find one.
 *
 * "The kernel boots to a root shell" and "a serial console is on the kernel command line" are facts about a
 * *command line*, not about U-Boot. They were first implemented in `uboot.ts` because the U-Boot environment was
 * the first place this workbench could read one; the flattened device tree's `/chosen` node carries the same
 * string, and a second set of finding codes for the same fact would split the ledger into two dialects — a
 * consumer filtering for "does this image drop to a root shell" would have to know every provider that can answer.
 *
 * So the codes stay exactly as `uboot.ts` minted them (`uboot-root-shell`, `uboot-serial-console`) and only the
 * PROVENANCE varies: `origin` says where the string was read from, in the finding's rationale and its evidence.
 * The ledger's own `source` column already separates the providers; `kind` is the class of fact, and the class is
 * the same one. Renaming the codes to be provider-neutral would be tidier and is deliberately not done — it would
 * silently reclassify every finding already stored under the old codes.
 *
 * Proof states are unchanged and deliberately split: a root-shell command line is a LEAD
 * (`needs_runtime_reproduction`) because only a real boot proves the device honours it, while an exposed console
 * directive is `static_confirmed` because the directive is literally in the bytes.
 */
import type { FindingDraft } from '../findings-normalize.js';

/** Where a command line was read from, so the finding can say so without inventing a new finding code. */
export interface CmdlineOrigin {
  /** Human phrase completing "…is present in {where}", e.g. 'the stored U-Boot environment'. */
  where: string;
  /** Provenance fields merged into every finding's evidence (the variable name, the device-tree path, …). */
  evidence: Record<string, unknown>;
}

/** Truncate a value for evidence so a huge command line cannot bloat the finding. */
export function truncate(s: string, n = 200): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/**
 * Pure: audit one kernel command line. Returns the root-shell finding (when the line hands PID 1 or an
 * interactive shell to whoever powers the board on) and the serial-console finding (when it names a console).
 * Every finding quotes the offending string and asserts only what the string actually contains.
 */
export function auditKernelCommandLine(cmdline: string, origin: CmdlineOrigin): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  if (!cmdline) return drafts;

  const markers: string[] = [];
  if (/\binit=\/bin\/sh\b/.test(cmdline)) markers.push('init=/bin/sh');
  if (/\brdinit=/.test(cmdline)) markers.push('rdinit=');
  if (/(?:^|\s)single(?:\s|$)/.test(cmdline)) markers.push('single');
  if (markers.length > 0) {
    drafts.push({
      kind: 'uboot-root-shell',
      title: 'Kernel command line drops to an unauthenticated root shell',
      severity: 'high',
      proofState: 'needs_runtime_reproduction',
      evidence: { ...origin.evidence, value: truncate(cmdline), markers },
      rationale: [
        `The kernel command line in ${origin.where} hands PID 1 / an interactive shell to whoever powers the`,
        'device on (no authentication). Confirmed by a real boot — hence needs_runtime_reproduction, not',
        'asserted device compromise.',
      ].join(' '),
    });
  }

  const cm = /\bconsole=(\S+)/.exec(cmdline);
  if (cm) {
    drafts.push({
      kind: 'uboot-serial-console',
      title: `Kernel serial console exposed (console=${truncate(cm[1] ?? '', 32)})`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { ...origin.evidence, value: truncate(cmdline), console: cm[1] },
      rationale: [
        'A serial console on the kernel command line means physical UART access yields boot logs and, combined',
        `with a command-line shell, an interactive session. The console= directive is present in ${origin.where}.`,
      ].join(' '),
    });
  }

  return drafts;
}
