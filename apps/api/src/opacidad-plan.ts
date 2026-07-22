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
  | 'servicemap'
  | 'certs'
  | 'compmap'
  | 'uboot'
  | 'fcc'
  | 'rtos'
  | 'chipsec'
  | 'esp'
  | 'encrypted'
  | 'webtaint';

export interface PlanSpec {
  worker: string;
  reason: string;
  needsRootfs: boolean;
  built: boolean;
  provider?: ProviderId;
  note?: string;
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
