/**
 * W9 (opacidad) class-routed plan — pure data, no store/provider imports, so the routing is unit-testable in
 * isolation. `specsForClass` maps W0's device class to the ordered list of workers to run; the concrete executor
 * for each `provider` tag lives in opacidad.ts (which binds the store + provider runners). A worker whose deep
 * implementation does not exist yet is `built: false` (no provider tag) — reported honestly, never omitted.
 *
 * **Why the "why this stage" line is not in the table below.** A seed spec's `reason` is the sentence the coverage
 * report prints beside the stage — "what could this even tell me". It is recomposed from this routing on every
 * request, it describes THE PLAN this deployment would run and never a firmware image, and nothing about it is
 * written at measurement time. So it follows the same rule as `tools.ts`'s `unlocks`: the table holds a stable
 * `reasonId`, the prose lives in `i18n/` keyed by that id, and `specsForClass` takes the locale as a parameter.
 * The routing itself — order, providers, `needsRootfs`, `built` — is data and does not move between languages.
 *
 * The locale DEFAULTS to English, deliberately. `opacidad.ts` stores its plan on the job row, and a stored plan is
 * a record of what was run: it stays in the language that produced it, exactly like a finding's title. Only the
 * read-side callers (the coverage route) pass a locale.
 *
 * A `replan` spec's reason is the opposite case again — it is the LEAD that scheduled it, composed by a worker
 * mid-run and recorded in the trace, so it is carried through verbatim in either language.
 *
 * The i18n import is type-safe in both directions: `i18n/en.ts` imports `PlanReasonId` with `import type`, which
 * is erased, so there is no runtime cycle and this module stays store-free and unit-testable.
 */
import { type Locale, messages } from './i18n/index.js';
import type { OpacidadPlanEntry } from './opacidad-narrative.js';

/** Executor tags — each maps to a concrete provider runner in opacidad.ts's registry. */
export type ProviderId =
  | 'extract'
  | 'fsaudit'
  | 'auxsecrets'
  | 'sbom'
  | 'compcve'
  | 'kernel'
  | 'servicemap'
  | 'certs'
  | 'compmap'
  | 'uboot'
  | 'updatepath'
  | 'devicetree'
  | 'bootcmdline'
  | 'nvram'
  | 'fcc'
  | 'rtos'
  | 'chipsec'
  | 'fwhunt'
  | 'esp'
  | 'encrypted'
  | 'webtaint'
  | 'binvuln'
  | 'kmod'
  | 'symreach'
  | 'dynprobe'
  | 'decompile';

/**
 * The stable id of a seed stage's "why this stage" line. It keys the catalogue and never reaches a screen, so a
 * routing change that needs new prose is a compile error in `i18n/en.ts` until the sentence exists — the same
 * guarantee `ToolId` gives the Capabilities table.
 *
 * Two pairs look redundant and are not: `certificates`/`certificatesRaw` and `ubootEnv`/`ubootEnvRaw` are the same
 * provider reached from the Linux chain and from the rootfs-free recon group, and the recon wording says outright
 * that it reads the raw image. Collapsing them would drop that clause from the class where it is the whole point.
 */
export type PlanReasonId =
  | 'extract'
  | 'credentials'
  | 'auxSecrets'
  | 'sbom'
  | 'componentFingerprint'
  | 'kernelPosture'
  | 'serviceEnumeration'
  | 'certificates'
  | 'certificatesRaw'
  | 'componentMap'
  | 'ubootEnv'
  | 'ubootEnvRaw'
  | 'deviceTree'
  | 'bootCmdlineCrosscheck'
  | 'fccId'
  | 'nvram'
  | 'webTaint'
  | 'binaryVulnSweep'
  | 'kernelModules'
  | 'updatePath'
  | 'chipsec'
  | 'fwhunt'
  | 'rtos'
  | 'esp'
  | 'encrypted';

/** Every reason id the routing can produce, so a test can check none of them is unglossed. */
export const PLAN_REASON_IDS: readonly PlanReasonId[] = [
  'extract',
  'credentials',
  'auxSecrets',
  'sbom',
  'componentFingerprint',
  'kernelPosture',
  'serviceEnumeration',
  'certificates',
  'certificatesRaw',
  'componentMap',
  'ubootEnv',
  'ubootEnvRaw',
  'deviceTree',
  'bootCmdlineCrosscheck',
  'fccId',
  'nvram',
  'webTaint',
  'binaryVulnSweep',
  'kernelModules',
  'updatePath',
  'chipsec',
  'fwhunt',
  'rtos',
  'esp',
  'encrypted',
];

export interface PlanSpec {
  worker: string;
  reason: string;
  needsRootfs: boolean;
  built: boolean;
  provider?: ProviderId;
  note?: string;
  /** A concrete target for the executor (e.g. the rootfs-relative binary path for a `decompile` spec). */
  target?: string;
  /** For a `symreach` spec: the sinks to ask about inside `target`. */
  sinks?: string[];
  /**
   * Which QUESTION a `symreach` spec is asking about `target`, when it is not the default one.
   *
   * One binary can carry two independent reachability questions — "is an unbounded copy on a live path" and "is a
   * command-exec call on a live path" — and 40 of this corpus's 80 askable command-exec binaries are ALSO
   * stack-overflow candidates. Both `specKey` and the findings source are derived from this, so the second question
   * cannot dedup away the first, and its answer cannot delete the first's rows. That deletion has been paid for
   * once already, on the manual route, whose source string carries its sink set for exactly this reason.
   */
  sinkClass?: 'cmdexec';
  /** For a `dynprobe` spec: the single sink to reproduce and the call-site addresses to break on. */
  sink?: string;
  addresses?: string[];
  /** `replan` = dynamically scheduled by W9 in response to a lead (vs a seed spec from the class DAG). */
  origin?: 'replan';
  /** The lead that caused this spec to be scheduled (shown in the trace). */
  trigger?: string;
}

/**
 * A lead a worker surfaces mid-run that should re-plan the agenda — the thing that turns W9's fixed per-class DAG
 * into a dynamic worklist. Two kinds today: "decompile this specific binary" (a network daemon a scan found, or the
 * httpd that serves a tainted handler), and "prove whether this binary's unsafe sinks are actually reachable" (a
 * binvuln candidate, whose imports-plus-no-canary precondition is exactly the thing symbolic execution can settle).
 */
export type Lead =
  | {
      kind: 'decompile-binary';
      /** The rootfs-relative binary to analyze. */
      target: string;
      reason: string;
    }
  | {
      kind: 'reproduce-crash';
      /** The rootfs-relative binary whose sink was proven reachable. */
      target: string;
      reason: string;
      /** The one sink to reproduce, and the call-site addresses symreach already resolved for it. */
      sink: string;
      addresses: string[];
    }
  | {
      kind: 'prove-reachability';
      /** The rootfs-relative binary whose sinks are in question. */
      target: string;
      reason: string;
      /** The unbounded-copy functions this binary imports — the sinks to ask angr about. */
      sinks: string[];
    }
  | {
      /**
       * The same question, asked about a command-execution sink instead of an unbounded copy.
       *
       * Its own kind rather than a flag on the one above, because it schedules under its own key, its own cap and
       * its own findings source — and because the two must be able to coexist on one binary.
       */
      kind: 'prove-cmdexec-reachability';
      target: string;
      reason: string;
      /** The command-exec functions this binary IMPORTS — never the ones merely named in its strings. */
      sinks: string[];
    };

/**
 * A seed stage as the routing table declares it: everything a `PlanSpec` has except the prose, which the locale
 * supplies. Nothing is cached here that a second language would have to un-say.
 */
type SeedSpec = Omit<PlanSpec, 'reason'> & { reasonId: PlanReasonId };

const EXTRACT: SeedSpec = {
  worker: 'W1 · Extraction',
  reasonId: 'extract',
  needsRootfs: false,
  built: true,
  provider: 'extract',
};

/**
 * The one boot question neither provider can answer alone: the tree's `/chosen` line says what the build expects,
 * the environment says what the board would pass, and only something holding both can notice they differ.
 *
 * It is a STAGE rather than a clause folded into the two steps that feed it, because `coverage.ts` reads this plan
 * to answer "was this question asked" — a check with no row of its own is one an operator cannot see going
 * unasked, which is the conflation that report exists to prevent. It must be ordered AFTER both halves; the
 * executor still verifies both ran and degrades honestly when one did not, so the ordering is an intention here
 * and not a load-bearing assumption (a comment that was true when written is a trap this codebase has paid for).
 */
const BOOT_CMDLINE_CROSSCHECK: SeedSpec = {
  worker: 'Cross-check · Kernel command line',
  reasonId: 'bootCmdlineCrosscheck',
  needsRootfs: false,
  built: true,
  provider: 'bootcmdline',
};

/** The provider chain for a standard Linux rootfs (also the FIT/UBI class, after W1 recovers its rootfs). */
const LINUX_CHAIN: SeedSpec[] = [
  EXTRACT,
  {
    worker: 'W3 · Credentials & secrets',
    reasonId: 'credentials',
    needsRootfs: true,
    built: true,
    provider: 'fsaudit',
  },
  {
    worker: 'W3 · Auxiliary-partition secrets',
    reasonId: 'auxSecrets',
    needsRootfs: false,
    built: true,
    provider: 'auxsecrets',
  },
  {
    worker: 'W2 · SBOM / CVE',
    reasonId: 'sbom',
    needsRootfs: true,
    built: true,
    provider: 'sbom',
  },
  {
    worker: 'W2 · Component fingerprint (bundled n-days)',
    reasonId: 'componentFingerprint',
    needsRootfs: true,
    built: true,
    provider: 'compcve',
  },
  {
    // Deliberately `needsRootfs: false` even though the rootfs is what makes it strong. The kernel banner lives in a
    // carved blob or the raw image, so this stage still answers the version question when extraction produced no
    // rootfs — and a version with an explicitly undetermined posture is strictly more than a skipped stage.
    worker: 'W2 · Kernel posture',
    reasonId: 'kernelPosture',
    needsRootfs: false,
    built: true,
    provider: 'kernel',
  },
  {
    worker: 'Recon · Service enumeration',
    reasonId: 'serviceEnumeration',
    needsRootfs: true,
    built: true,
    provider: 'servicemap',
  },
  {
    worker: 'Static · Certificates',
    reasonId: 'certificates',
    needsRootfs: false,
    built: true,
    provider: 'certs',
  },
  {
    worker: 'Static · Component map',
    reasonId: 'componentMap',
    needsRootfs: true,
    built: true,
    provider: 'compmap',
  },
  {
    worker: 'Static · U-Boot env',
    reasonId: 'ubootEnv',
    needsRootfs: false,
    built: true,
    provider: 'uboot',
  },
  {
    worker: 'Static · Device tree',
    reasonId: 'deviceTree',
    needsRootfs: false,
    built: true,
    provider: 'devicetree',
  },
  BOOT_CMDLINE_CROSSCHECK,
  { worker: 'Recon · FCC-ID', reasonId: 'fccId', needsRootfs: false, built: true, provider: 'fcc' },
  {
    // Listed here as well as in RECON_ANY_CLASS: the Linux chain enumerates its rootfs-free workers explicitly so
    // the shared group does not duplicate them, which means an addition there does not reach this chain.
    worker: 'W3 · NVRAM store',
    reasonId: 'nvram',
    needsRootfs: false,
    built: true,
    provider: 'nvram',
  },
  {
    worker: 'W4 · Web attack-surface (taint)',
    reasonId: 'webTaint',
    needsRootfs: true,
    built: true,
    provider: 'webtaint',
  },
  {
    worker: 'W5 · Binary-vuln sweep',
    reasonId: 'binaryVulnSweep',
    needsRootfs: true,
    built: true,
    provider: 'binvuln',
  },
  {
    // Runs AFTER the userland sweep on purpose. `binvuln` excludes ET_REL objects by construction and counts
    // them (`relocatableSkipped`), so this stage is the other half of that exclusion rather than a competitor
    // for it — and reading its reason next to binvuln's is what makes the split legible in the coverage table.
    worker: 'W5 · Kernel-module surface',
    reasonId: 'kernelModules',
    needsRootfs: true,
    built: true,
    provider: 'kmod',
  },
  {
    // Deliberately `needsRootfs: false`: half the question (what integrity metadata the shipped image carries) is
    // answerable from the raw bytes, and skipping the stage for want of a rootfs would turn "we never looked" into
    // a silent absence on precisely the images where the answer matters. The provider records the updater half as
    // blocked when there is no rootfs to search.
    worker: 'ISTG-FW · Update-path integrity',
    reasonId: 'updatePath',
    needsRootfs: false,
    built: true,
    provider: 'updatepath',
  },
];

/**
 * Recon workers that read the RAW IMAGE and need no rootfs, so they apply to every device class.
 *
 * They used to hang off the Linux chain alone, which made them unreachable for an `rtos`, `baremetal`, `esp-soc`
 * or `encrypted` image — classes whose plan is one worker wide. The third experimental pass caught it: driving
 * the providers directly over Xiaomi-Repeater_2018 (an eCos monolith, `rtos`), the U-Boot worker parsed 6
 * environment variables and flagged `bootcmd` booting over **tftp** — a real network-boot exposure that the fixed
 * class plan structurally could not reach, on an image its own coverage report was calling fully covered.
 *
 * They are cheap and they degrade to nothing honestly (no U-Boot env / no X.509 / no FCC ID each report zero),
 * and a stage that ran and found nothing is strictly more information than a stage that was never planned.
 */
const RECON_ANY_CLASS: SeedSpec[] = [
  {
    worker: 'Static · Certificates',
    reasonId: 'certificatesRaw',
    needsRootfs: false,
    built: true,
    provider: 'certs',
  },
  {
    worker: 'Static · U-Boot env',
    reasonId: 'ubootEnvRaw',
    needsRootfs: false,
    built: true,
    provider: 'uboot',
  },
  {
    // Reads the RAW image (and the FIT/UBI carve chain inside it), so it needs no rootfs and belongs to every
    // class. It also degrades to nothing honestly: an image with no FDT reports `blocked_by_platform` naming
    // where it looked, which is strictly more information than a stage that was never planned.
    worker: 'Static · Device tree',
    reasonId: 'deviceTree',
    needsRootfs: false,
    built: true,
    provider: 'devicetree',
  },
  BOOT_CMDLINE_CROSSCHECK,
  { worker: 'Recon · FCC-ID', reasonId: 'fccId', needsRootfs: false, built: true, provider: 'fcc' },
  {
    // Every other W3 stage walks extraction output, which is why no provider had ever seen one of these: the
    // stores live in the RAW upload's flash environment partition, not in the rootfs. Nine of the sixteen images
    // in the corpus carry one — routers, cameras and both eCos Xiaomis — so it belongs to every class, and it can
    // never be skipped for want of a rootfs.
    worker: 'W3 · NVRAM store',
    reasonId: 'nvram',
    needsRootfs: false,
    built: true,
    provider: 'nvram',
  },
];

/** Given W0's class, the ordered routing — ids only, no prose. Pure, and the shape the tests pin. */
function seedsForClass(cls: string): SeedSpec[] {
  switch (cls) {
    case 'embedded-linux':
    case 'openwrt-fit-ubi':
      return LINUX_CHAIN;
    case 'uefi-bios':
      return [
        {
          worker: 'UEFI · chipsec',
          reasonId: 'chipsec',
          needsRootfs: false,
          built: true,
          provider: 'chipsec',
        },
        {
          worker: 'UEFI · FwHunt implant scan',
          reasonId: 'fwhunt',
          needsRootfs: false,
          built: true,
          provider: 'fwhunt',
        },
        ...RECON_ANY_CLASS,
      ];
    case 'baremetal':
    case 'rtos':
      return [
        {
          worker: 'W7 · Bare-metal / RTOS',
          reasonId: 'rtos',
          needsRootfs: false,
          built: true,
          provider: 'rtos',
        },
        ...RECON_ANY_CLASS,
      ];
    case 'esp-soc':
      return [
        {
          worker: 'W6 · ESP / IoT-SoC',
          reasonId: 'esp',
          needsRootfs: false,
          built: true,
          provider: 'esp',
        },
        ...RECON_ANY_CLASS,
      ];
    case 'encrypted':
      return [
        {
          worker: 'W8 · Encrypted-blob',
          reasonId: 'encrypted',
          needsRootfs: false,
          built: true,
          provider: 'encrypted',
        },
        ...RECON_ANY_CLASS,
      ];
    default:
      return [EXTRACT, ...RECON_ANY_CLASS];
  }
}

/**
 * Pure: dress one seed in a language. The worker id, the provider tag and every boolean pass through untouched —
 * they are what the scan, the coverage table and the stored run all key on, and a reader comparing the plan
 * against the table underneath it must find the same strings in both languages.
 */
function dress(seed: SeedSpec, locale: Locale): PlanSpec {
  const { reasonId, ...rest } = seed;
  return { ...rest, reason: messages(locale).plan.reason[reasonId] };
}

/**
 * Given W0's class, the ordered plan of workers. Pure — the routing itself is unit-tested.
 *
 * The locale defaults to English, so a caller that predates it — and every stored plan — is byte-for-byte
 * unaffected. Only the "why this stage" line moves; the routing does not.
 */
export function specsForClass(cls: string, locale: Locale = 'en'): PlanSpec[] {
  return seedsForClass(cls).map((seed) => dress(seed, locale));
}

/** Turn a plan into the pre-execution plan list shown to the operator. */
export function planEntries(specs: PlanSpec[]): OpacidadPlanEntry[] {
  return specs.map((s) => ({ worker: s.worker, reason: s.reason }));
}

/** The base name of a rootfs-relative path (no `node:path` dependency in this pure module). */
function baseName(p: string): string {
  const parts = p.split('/');
  return parts[parts.length - 1] || p;
}

/**
 * A spec's stable dedup key: a `decompile` spec keys on its target binary (so the same daemon is scheduled once),
 * every other spec keys on its provider tag or worker name. Used to seed the "already planned" set and to keep
 * re-planning idempotent.
 */
export function specKey(spec: PlanSpec): string {
  if (spec.provider === 'decompile' && spec.target) return `decompile:${spec.target}`;
  // The suffix is only ever ADDED, never applied to the existing question: a key that changed shape would stop
  // matching the `symreach:<path>` rows every prior run wrote, and `syncFindings` would leave them orphaned beside
  // the new ones instead of replacing them.
  if (spec.provider === 'symreach' && spec.target) {
    return spec.sinkClass === 'cmdexec' ? `symreach:${spec.target}#cmdexec` : `symreach:${spec.target}`;
  }
  if (spec.provider === 'dynprobe' && spec.target) return `dynprobe:${spec.target}#${spec.sink ?? ''}`;
  return spec.provider ?? spec.worker;
}

/**
 * Pure: map one lead to the follow-up spec(s) to schedule. A `decompile-binary` lead becomes a W5 targeted
 * binary-vuln spec; a `prove-reachability` lead becomes a W5 symbolic-reachability spec over that binary's sinks.
 * Both carry origin `replan`, and both are dropped when the same target is already planned (idempotent).
 */
export function replan(lead: Lead, planned: ReadonlySet<string>): PlanSpec[] {
  if (lead.kind === 'reproduce-crash') {
    const spec: PlanSpec = {
      worker: `W5 · Reproduce (${baseName(lead.target)}:${lead.sink})`,
      reason: lead.reason,
      needsRootfs: true,
      built: true,
      provider: 'dynprobe',
      target: lead.target,
      sink: lead.sink,
      addresses: lead.addresses,
      origin: 'replan',
      trigger: lead.reason,
    };
    return planned.has(specKey(spec)) ? [] : [spec];
  }
  if (lead.kind === 'prove-cmdexec-reachability') {
    const spec: PlanSpec = {
      worker: `W5 · Cmd-exec reachability (${baseName(lead.target)})`,
      reason: lead.reason,
      needsRootfs: true,
      built: true,
      provider: 'symreach',
      target: lead.target,
      sinks: lead.sinks,
      sinkClass: 'cmdexec',
      origin: 'replan',
      trigger: lead.reason,
    };
    return planned.has(specKey(spec)) ? [] : [spec];
  }
  const spec: PlanSpec =
    lead.kind === 'decompile-binary'
      ? {
          worker: `W5 · Binary-vuln (${baseName(lead.target)})`,
          reason: lead.reason,
          needsRootfs: true,
          built: true,
          provider: 'decompile',
          target: lead.target,
          origin: 'replan',
          trigger: lead.reason,
        }
      : {
          worker: `W5 · Reachability (${baseName(lead.target)})`,
          reason: lead.reason,
          needsRootfs: true,
          built: true,
          provider: 'symreach',
          target: lead.target,
          sinks: lead.sinks,
          origin: 'replan',
          trigger: lead.reason,
        };
  return planned.has(specKey(spec)) ? [] : [spec];
}

/**
 * How many symbolic-reachability probes are already on the agenda. The angr budget is a PER-RUN cost (tens of
 * seconds of wall-clock each), so it has to be counted globally rather than per lead source — otherwise W4 and the
 * binvuln sweep would each spend the full cap and a scan would quietly take twice as long as designed.
 */
export function countReachabilityProbes(planned: ReadonlySet<string>): number {
  let n = 0;
  // Command-exec probes are EXCLUDED, and this exclusion is the whole point of them having their own cap. Counting
  // them here would make adding the new question silently shrink the unbounded-copy allowance from 3 to 1 on any
  // image carrying both — a budget cut nobody asked for, delivered by a feature that reads like an addition.
  for (const key of planned) if (key.startsWith('symreach:') && !key.endsWith('#cmdexec')) n++;
  return n;
}

/** …and how many command-exec probes are on it. Its own counter, against its own cap, for the reason above. */
export function countCmdexecProbes(planned: ReadonlySet<string>): number {
  let n = 0;
  for (const key of planned) if (key.startsWith('symreach:') && key.endsWith('#cmdexec')) n++;
  return n;
}

/** Mutable bookkeeping for dynamic scheduling across a run: what's planned, how many dynamic steps, how many capped. */
export interface ScheduleState {
  planned: Set<string>;
  dynamicCount: number;
  capped: number;
  /**
   * How many were dropped, BY LEAD KIND. The total alone was reported as "N further daemon lead(s) not
   * scheduled" whatever had actually overflowed, so a run that dropped three crash reproductions told the
   * operator to go triage daemons. A bound that misnames what it dropped sends the reader to the wrong place —
   * the count was honest and the sentence was not.
   */
  cappedByKind?: Partial<Record<Lead['kind'], number>>;
}

/** How a lead kind reads in a sentence written for an operator. */
export const LEAD_KIND_LABEL: Record<Lead['kind'], string> = {
  'decompile-binary': 'daemon/handler decompile',
  'reproduce-crash': 'crash reproduction',
  'prove-reachability': 'reachability probe',
  'prove-cmdexec-reachability': 'command-exec reachability probe',
};

/**
 * Pure (given the state it mutates): turn a batch of leads into the new specs to append to the agenda, respecting
 * the already-planned set and a hard cap on dynamically-scheduled steps (so re-planning can never loop). Leads
 * beyond the cap are counted in `state.capped` and surfaced honestly as a gap — never silently dropped.
 */
export function scheduleLeads(leads: Lead[], state: ScheduleState, cap: number): PlanSpec[] {
  const added: PlanSpec[] = [];
  for (const lead of leads) {
    for (const spec of replan(lead, state.planned)) {
      const key = specKey(spec);
      if (state.dynamicCount >= cap) {
        if (!state.planned.has(key)) {
          state.planned.add(key);
          state.capped++;
          state.cappedByKind ??= {};
          state.cappedByKind[lead.kind] = (state.cappedByKind[lead.kind] ?? 0) + 1;
        }
        continue;
      }
      state.planned.add(key);
      state.dynamicCount++;
      added.push(spec);
    }
  }
  return added;
}
