/**
 * W9 (opacidad) class-routed plan — pure data, no store/provider imports, so the routing is unit-testable in
 * isolation. `specsForClass` maps W0's device class to the ordered list of workers to run; the concrete executor
 * for each `provider` tag lives in opacidad.ts (which binds the store + provider runners). A worker whose deep
 * implementation does not exist yet is `built: false` (no provider tag) — reported honestly, never omitted.
 */
import type { OpacidadPlanEntry } from './opacidad-narrative.js';

/** Executor tags — each maps to a concrete provider runner in opacidad.ts's registry. */
export type ProviderId =
  | 'extract'
  | 'fsaudit'
  | 'auxsecrets'
  | 'sbom'
  | 'compcve'
  | 'servicemap'
  | 'certs'
  | 'compmap'
  | 'uboot'
  | 'updatepath'
  | 'nvram'
  | 'fcc'
  | 'rtos'
  | 'chipsec'
  | 'fwhunt'
  | 'esp'
  | 'encrypted'
  | 'webtaint'
  | 'binvuln'
  | 'symreach'
  | 'dynprobe'
  | 'decompile';

export interface PlanSpec {
  worker: string;
  reason: string;
  needsRootfs: boolean;
  built: boolean;
  provider?: ProviderId;
  note?: string;
  /** A concrete target for the executor (e.g. the rootfs-relative binary path for a `decompile` spec). */
  target?: string;
  /** For a `symreach` spec: the unbounded-copy sinks to ask about inside `target`. */
  sinks?: string[];
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
    };

const EXTRACT: PlanSpec = {
  worker: 'W1 · Extraction',
  reason: 'recover the rootfs (recursive FIT→UBI→SquashFS carve when the container needs it)',
  needsRootfs: false,
  built: true,
  provider: 'extract',
};

/** The provider chain for a standard Linux rootfs (also the FIT/UBI class, after W1 recovers its rootfs). */
const LINUX_CHAIN: PlanSpec[] = [
  EXTRACT,
  {
    worker: 'W3 · Credentials & secrets',
    reason: 'weak/empty creds, root shells, key material',
    needsRootfs: true,
    built: true,
    provider: 'fsaudit',
  },
  {
    worker: 'W3 · Auxiliary-partition secrets',
    reason: 'embedded private keys in sibling (non-rootfs) partitions the rootfs audit never sees',
    needsRootfs: false,
    built: true,
    provider: 'auxsecrets',
  },
  {
    worker: 'W2 · SBOM / CVE',
    reason: 'components → known CVEs (the n-day surface)',
    needsRootfs: true,
    built: true,
    provider: 'sbom',
  },
  {
    worker: 'W2 · Component fingerprint (bundled n-days)',
    reason: 'bundled binaries (pppd, openssl) → CVEs a manifest-only SBOM misses',
    needsRootfs: true,
    built: true,
    provider: 'compcve',
  },
  {
    worker: 'Recon · Service enumeration',
    reason: 'boot-time network daemons = attack surface',
    needsRootfs: true,
    built: true,
    provider: 'servicemap',
  },
  {
    worker: 'Static · Certificates',
    reason: 'embedded X.509 posture',
    needsRootfs: false,
    built: true,
    provider: 'certs',
  },
  {
    worker: 'Static · Component map',
    reason: 'rootfs ELF → dependency graph',
    needsRootfs: true,
    built: true,
    provider: 'compmap',
  },
  {
    worker: 'Static · U-Boot env',
    reason: 'boot posture (init=/bin/sh, interruptible autoboot, console)',
    needsRootfs: false,
    built: true,
    provider: 'uboot',
  },
  { worker: 'Recon · FCC-ID', reason: 'FCC IDs → public filings', needsRootfs: false, built: true, provider: 'fcc' },
  {
    // Listed here as well as in RECON_ANY_CLASS: the Linux chain enumerates its rootfs-free workers explicitly so
    // the shared group does not duplicate them, which means an addition there does not reach this chain.
    worker: 'W3 · NVRAM store',
    reason: 'flash key-value store in the raw image — credentials and wifi keys no rootfs scan can reach',
    needsRootfs: false,
    built: true,
    provider: 'nvram',
  },
  {
    worker: 'W4 · Web attack-surface (taint)',
    reason: 'web-param → uci → os.execute/io.popen sinks (the GL.iNet Tor root-RCE class)',
    needsRootfs: true,
    built: true,
    provider: 'webtaint',
  },
  {
    worker: 'W5 · Binary-vuln sweep',
    reason: 'rootfs ELFs → unbounded-copy + no-canary stack-overflow candidates (DVRF pwnables)',
    needsRootfs: true,
    built: true,
    provider: 'binvuln',
  },
  {
    // Deliberately `needsRootfs: false`: half the question (what integrity metadata the shipped image carries) is
    // answerable from the raw bytes, and skipping the stage for want of a rootfs would turn "we never looked" into
    // a silent absence on precisely the images where the answer matters. The provider records the updater half as
    // blocked when there is no rootfs to search.
    worker: 'ISTG-FW · Update-path integrity',
    reason: 'is the image signed, does the updater verify anything, is a downgrade bounded',
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
const RECON_ANY_CLASS: PlanSpec[] = [
  {
    worker: 'Static · Certificates',
    reason: 'embedded X.509 posture (reads the raw image — no rootfs needed)',
    needsRootfs: false,
    built: true,
    provider: 'certs',
  },
  {
    worker: 'Static · U-Boot env',
    reason: 'boot posture (init=/bin/sh, interruptible autoboot, net-boot, console)',
    needsRootfs: false,
    built: true,
    provider: 'uboot',
  },
  { worker: 'Recon · FCC-ID', reason: 'FCC IDs → public filings', needsRootfs: false, built: true, provider: 'fcc' },
  {
    // Every other W3 stage walks extraction output, which is why no provider had ever seen one of these: the
    // stores live in the RAW upload's flash environment partition, not in the rootfs. Nine of the sixteen images
    // in the corpus carry one — routers, cameras and both eCos Xiaomis — so it belongs to every class, and it can
    // never be skipped for want of a rootfs.
    worker: 'W3 · NVRAM store',
    reason: 'flash key-value store in the raw image — credentials and wifi keys no rootfs scan can reach',
    needsRootfs: false,
    built: true,
    provider: 'nvram',
  },
];

/** Given W0's class, the ordered plan of workers. Pure — the routing itself is unit-tested. */
export function specsForClass(cls: string): PlanSpec[] {
  switch (cls) {
    case 'embedded-linux':
    case 'openwrt-fit-ubi':
      return LINUX_CHAIN;
    case 'uefi-bios':
      return [
        {
          worker: 'UEFI · chipsec',
          reason: 'offline firmware-volume decode + Secure Boot / NVRAM posture',
          needsRootfs: false,
          built: true,
          provider: 'chipsec',
        },
        {
          worker: 'UEFI · FwHunt implant scan',
          reason: 'upstream FwHunt code-pattern rules → known implant / vulnerable-module families',
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
          reason: 'vector table + memory map + RTOS/decode-routine detection',
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
          reason: 'partition table + NVS key store (signing keys!) + Flash-Enc/Secure-Boot posture',
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
          reason: 'identify cipher/mode/IV and name the key-recovery path (honest verdict, never a silent empty)',
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
  if (spec.provider === 'symreach' && spec.target) return `symreach:${spec.target}`;
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
  for (const key of planned) if (key.startsWith('symreach:')) n++;
  return n;
}

/** Mutable bookkeeping for dynamic scheduling across a run: what's planned, how many dynamic steps, how many capped. */
export interface ScheduleState {
  planned: Set<string>;
  dynamicCount: number;
  capped: number;
}

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
