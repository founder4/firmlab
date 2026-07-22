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
  | 'sbom'
  | 'compcve'
  | 'servicemap'
  | 'certs'
  | 'compmap'
  | 'uboot'
  | 'fcc'
  | 'rtos'
  | 'chipsec'
  | 'esp'
  | 'encrypted'
  | 'webtaint'
  | 'binvuln'
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
  /** `replan` = dynamically scheduled by W9 in response to a lead (vs a seed spec from the class DAG). */
  origin?: 'replan';
  /** The lead that caused this spec to be scheduled (shown in the trace). */
  trigger?: string;
}

/**
 * A lead a worker surfaces mid-run that should re-plan the agenda — the thing that turns W9's fixed per-class DAG
 * into a dynamic worklist. Today the one kind is "decompile this specific binary" (a network daemon a scan found,
 * or the httpd that serves a tainted handler).
 */
export interface Lead {
  kind: 'decompile-binary';
  /** The rootfs-relative binary to analyze. */
  target: string;
  reason: string;
}

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
      ];
    default:
      return [EXTRACT];
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
  return spec.provider ?? spec.worker;
}

/**
 * Pure: map one lead to the follow-up spec(s) to schedule. A `decompile-binary` lead becomes a W5 targeted
 * binary-vuln spec (origin `replan`), unless that binary is already planned — then it is dropped (idempotent).
 */
export function replan(lead: Lead, planned: ReadonlySet<string>): PlanSpec[] {
  if (lead.kind === 'decompile-binary') {
    const spec: PlanSpec = {
      worker: `W5 · Binary-vuln (${baseName(lead.target)})`,
      reason: lead.reason,
      needsRootfs: true,
      built: true,
      provider: 'decompile',
      target: lead.target,
      origin: 'replan',
      trigger: lead.reason,
    };
    return planned.has(specKey(spec)) ? [] : [spec];
  }
  return [];
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
