/**
 * RTOS / bare-metal blob provider — the raw ARM Cortex-M rung of static analysis. A `rtos` image that is a raw
 * `.bin` (not an ELF, not a Linux rootfs) carries its own identity in the first bytes: an ARM Cortex-M vector
 * table (word[0] = initial SP → SRAM, word[1] = reset handler → a Thumb address in flash), from which the
 * flash/RAM memory map is recovered deterministically. Its printable strings then name the RTOS kernel
 * (FreeRTOS, Zephyr, ThreadX …) when one is linked in. This provider reads BOTH from the REAL bytes — pure
 * functions, no tool dependency — and emits honest `static_confirmed` facts (never a device claim). When the
 * blob is not a raw Cortex-M image (an ELF, a Linux image, random bytes) it degrades HONESTLY to
 * isCortexM:false rather than inventing a vector table. The dynamic follow-up (actually booting the MCU) is
 * Renode's job; a bare-metal blob with no RTOS strings is surfaced as a lead pointing there.
 *
 * The parse (vector table, base-address recovery, memory map, kernel detection) is PURE and unit-tested; the
 * runner only reads a bounded prefix of the image and composes them.
 */
import fs from 'node:fs';
import { fingerprintMcu } from '@firmlab/core';
import type { FindingDraft } from '../findings.js';

/** Format a 32-bit address as zero-padded, 0x-prefixed hex (e.g. 0x08000000) for titles and evidence. */
function hex(n: number): string {
  return `0x${(n >>> 0).toString(16).padStart(8, '0')}`;
}

/** Read a little-endian 32-bit word at `o`, tolerating a short buffer (missing bytes read as 0). */
function u32le(b: Uint8Array, o: number): number {
  return ((b[o] ?? 0) | ((b[o + 1] ?? 0) << 8) | ((b[o + 2] ?? 0) << 16) | ((b[o + 3] ?? 0) << 24)) >>> 0;
}

/**
 * Is `addr` in a plausible Cortex-M SRAM window for an initial stack pointer? Two conventional regions: the
 * TCM/CCM-style 0x10000000 band and the classic 0x20000000 SRAM band.
 */
function looksLikeSram(addr: number): boolean {
  return (addr >= 0x1000_0000 && addr <= 0x1004_0000) || (addr >= 0x2000_0000 && addr <= 0x2010_0000);
}

/**
 * Pure: read the ARM Cortex-M reset vector from offset 0 — word[0] the initial stack pointer, word[1] the reset
 * handler. Valid iff the SP lands in a plausible SRAM window AND the reset handler is odd (Thumb bit set) and
 * non-zero. An ELF (0x7F 'E' 'L' 'F') is deliberately rejected here — a real ELF is fingerprinted/booted on the
 * ELF path (Renode), not treated as a raw baremetal blob. Returns null when the bytes are not a Cortex-M table.
 */
export function parseVectorTable(buf: Uint8Array): { initialSP: number; resetHandler: number } | null {
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return null;
  if (buf.length < 8) return null;
  const initialSP = u32le(buf, 0);
  const resetHandler = u32le(buf, 4);
  const spOk = looksLikeSram(initialSP);
  const resetOk = (resetHandler & 1) === 1 && resetHandler !== 0;
  if (!spOk || !resetOk) return null;
  return { initialSP, resetHandler };
}

/**
 * Pure: infer the flash base address from a reset handler by masking it to its region. An 0x0800_xxxx reset →
 * 0x0800_0000 (the STM32 flash alias); an 0x0000_xxxx reset → 0x0000_0000; anything else masks to its top 12
 * bits (`resetHandler & 0xFFF00000`).
 */
export function recoverBaseAddress(resetHandler: number): number {
  const region = (resetHandler & 0xfff0_0000) >>> 0;
  if (region === 0x0800_0000) return 0x0800_0000; // STM32 flash alias
  if (region === 0x0000_0000) return 0x0000_0000; // reset from the 0x0 region
  return region;
}

/**
 * Pure: derive the flash/RAM memory map from the vector table. Flash base is recovered from the reset handler;
 * RAM base is the initial SP masked to its 0xFFFF0000 region (the SP conventionally sits atop SRAM).
 */
export function inferMemoryMap(initialSP: number, resetHandler: number): { flashBase: number; ramBase: number } {
  return {
    flashBase: recoverBaseAddress(resetHandler),
    ramBase: (initialSP & 0xffff_0000) >>> 0,
  };
}

/** Cap the string scan — MCU firmware is small; this bounds work if a large image is ever mis-routed here. */
const SCAN_CAP = 16 * 1024 * 1024;

/** Decode a bounded prefix of the image as latin1 (byte == code point), lowercased, for marker matching. */
function decodeAscii(buf: Uint8Array): string {
  const end = Math.min(buf.length, SCAN_CAP);
  let out = '';
  for (let i = 0; i < end; i += 0x8000) {
    out += String.fromCharCode(...buf.subarray(i, Math.min(end, i + 0x8000)));
  }
  return out.toLowerCase();
}

/** RTOS kernel markers → canonical display name. Ordered most-specific first; the first hit wins. */
const KERNEL_MARKERS: { name: string; markers: string[] }[] = [
  { name: 'FreeRTOS', markers: ['freertos', 'tsktcb', 'pxcurrenttcb', 'vtaskdelay'] },
  { name: 'Zephyr', markers: ['zephyr', 'k_thread'] },
  { name: 'ThreadX', markers: ['threadx', '_tx_thread'] },
  { name: 'Contiki', markers: ['contiki-ng', 'contiki'] },
  { name: 'RIOT', markers: ['riot-os', 'riot'] },
  { name: 'mbed', markers: ['mbed-os', 'mbed'] },
  { name: 'ChibiOS', markers: ['chibios'] },
  { name: 'NuttX', markers: ['nuttx'] },
];

/** Map the shared MCU fingerprint's lowercase RTOS banner onto our canonical display name. */
const FP_RTOS_DISPLAY: Record<string, string> = {
  freertos: 'FreeRTOS',
  zephyr: 'Zephyr',
  threadx: 'ThreadX',
  contiki: 'Contiki',
  riot: 'RIOT',
  mbed: 'mbed',
  nuttx: 'NuttX',
  chibios: 'ChibiOS',
  mynewt: 'Mynewt',
};

/**
 * Pure: identify the RTOS kernel from the image's printable strings. Scans for kernel-specific markers (task
 * control blocks, scheduler symbols, banners) and, failing a direct hit, corroborates with the shared
 * `fingerprintMcu` RTOS banner (broader vendor-SDK string coverage). Returns the canonical kernel name, or null
 * for a bare-metal blob with no recognizable kernel.
 */
export function detectRtosKernel(bytes: Uint8Array): string | null {
  const text = decodeAscii(bytes);
  for (const k of KERNEL_MARKERS) {
    if (k.markers.some((m) => text.includes(m))) return k.name;
  }
  const fp = fingerprintMcu(bytes);
  if (fp.rtos) return FP_RTOS_DISPLAY[fp.rtos] ?? fp.rtos;
  return null;
}

/**
 * Pure: detect an eCos RTOS monolith and pull out what the bytes disclose — the kernel version (`eCos 3.6.10`),
 * whether a RedBoot bootloader is bundled, and the vendor application name (e.g. `zxrouter`). eCos images are
 * routinely repacked inside a U-Boot uImage whose OS byte still says Linux, so W0 classifies them by these same
 * markers (see structure.ts); this surfaces the concrete version/posture as a finding. Returns null when the
 * image carries no eCos markers.
 */
export function detectEcos(buf: Uint8Array): { version: string | null; redboot: boolean; app: string | null } | null {
  const text = decodeAscii(buf); // lowercased
  const hasMarker = ['cyg_scheduler', 'cyg_thread', 'cyg_kernel', 'ecos_hal', 'redboot', 'zxrouter', '<<< ecos'].some(
    (m) => text.includes(m),
  );
  if (!hasMarker) return null;
  const version = text.match(/ecos[\s-]?v?(\d+\.\d+(?:\.\d+)?)/)?.[1] ?? null;
  const redboot = text.includes('redboot');
  const app = text.includes('zxrouter') ? 'zxrouter' : null;
  return { version: version ? `eCos ${version}` : null, redboot, app };
}

/**
 * A CTF/flag-format token literally present in the bytes: `flag{…}`, `CTF{…}`, `key{…}`. Bare-metal challenge
 * firmware often carries the flag (or a plaintext UART credential) in cleartext; when it does, extracting it is
 * the headline. A flag hidden behind a decode routine will NOT appear here — that needs manual reversing, which
 * this provider states honestly rather than pretending the image is flag-free.
 */
const FLAG_RE = /\b(?:flag|ctf|key)\{[\x20-\x7e]{3,80}?\}/gi;

/** Pure: extract plaintext flag-format tokens from the (case-preserving) ASCII of a bare-metal image. */
export function extractFlags(buf: Uint8Array): string[] {
  const end = Math.min(buf.length, SCAN_CAP);
  let text = '';
  for (let i = 0; i < end; i += 0x8000) {
    text += String.fromCharCode(...buf.subarray(i, Math.min(end, i + 0x8000)));
  }
  const out = new Set<string>();
  for (const m of text.matchAll(FLAG_RE)) out.add(m[0]);
  return [...out].slice(0, 20);
}

export interface RtosAnalysis {
  isCortexM: boolean;
  vectorTable: { initialSP: number; resetHandler: number } | null;
  memoryMap: { flashBase: number; ramBase: number } | null;
  rtosKernel: string | null;
  ecos: { version: string | null; redboot: boolean; app: string | null } | null;
  flags: string[];
  findings: FindingDraft[];
}

/**
 * Pure: compose the vector-table parse, memory-map recovery and kernel detection into an honest analysis of a
 * raw baremetal blob. Emits `info` / `static_confirmed` facts about the bytes — the Cortex-M vector table (with
 * the recovered flash base) and any detected RTOS kernel — plus, when a vector table is found with NO RTOS
 * strings, an `info` lead noting that a dynamic run needs Renode with a matching platform.
 */
export function analyzeRtos(buf: Uint8Array): RtosAnalysis {
  const vectorTable = parseVectorTable(buf);
  const rtosKernel = detectRtosKernel(buf);
  const isCortexM = vectorTable !== null;
  const memoryMap = vectorTable ? inferMemoryMap(vectorTable.initialSP, vectorTable.resetHandler) : null;
  const ecos = detectEcos(buf);
  const flags = extractFlags(buf);
  const findings: FindingDraft[] = [];

  if (vectorTable && memoryMap) {
    findings.push({
      kind: 'rtos-vector-table',
      title: `Cortex-M vector table found: SP=${hex(vectorTable.initialSP)}, reset=${hex(vectorTable.resetHandler)}, inferred flash base ${hex(memoryMap.flashBase)}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: {
        initialSP: hex(vectorTable.initialSP),
        resetHandler: hex(vectorTable.resetHandler),
        flashBase: hex(memoryMap.flashBase),
        ramBase: hex(memoryMap.ramBase),
      },
      rationale:
        'The first two little-endian words at offset 0 are a valid ARM Cortex-M reset vector (initial SP in ' +
        'SRAM, reset handler an odd/Thumb address in flash) — a fact about the image bytes, from which the ' +
        'flash/RAM base map is derived. Proves image layout, not device behavior.',
    });
  }

  if (rtosKernel) {
    findings.push({
      kind: 'rtos-kernel',
      title: `RTOS kernel detected: ${rtosKernel}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { kernel: rtosKernel },
      rationale: `Kernel marker strings for ${rtosKernel} are literally present in the image bytes — identifies the RTOS this firmware links against.`,
    });
  }

  if (vectorTable && !rtosKernel) {
    findings.push({
      kind: 'rtos-baremetal',
      title: 'bare-metal (no RTOS strings) — dynamic analysis needs Renode with a matching platform',
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      evidence: {
        flashBase: memoryMap ? hex(memoryMap.flashBase) : null,
        ramBase: memoryMap ? hex(memoryMap.ramBase) : null,
      },
      rationale:
        'A valid Cortex-M vector table with no recognizable RTOS kernel strings indicates a bare-metal firmware. ' +
        'Confirming its behavior needs Renode booting a matching per-MCU platform (.repl); this is a lead for ' +
        'that runtime step, not a verdict.',
    });
  }

  // eCos monolith (MIPS/ARM, no Cortex-M vector table) — surface its version + posture so the non-Cortex path
  // is not a silent empty. This is the finding W0 routes both Xiaomi repeaters here to produce.
  if (ecos) {
    const parts = [
      ecos.version ?? 'eCos RTOS',
      ecos.app ? `app "${ecos.app}"` : null,
      ecos.redboot ? 'RedBoot bootloader' : null,
    ].filter(Boolean);
    findings.push({
      kind: 'rtos-ecos',
      title: `eCos RTOS monolith: ${parts.join(', ')}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { version: ecos.version, app: ecos.app, redboot: ecos.redboot },
      rationale:
        'eCos kernel/RedBoot markers are literally present in the image — this is a standalone RTOS, NOT embedded ' +
        'Linux (the uImage OS byte often lies). There is no rootfs; analyze it as a monolith. A static fact about the bytes.',
    });
  }

  // Plaintext CTF/flag tokens (bare-metal challenge firmware) — the headline when the flag is not obfuscated.
  for (const flag of flags) {
    findings.push({
      kind: 'baremetal-flag',
      title: `Plaintext flag/credential token in image: ${flag}`,
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { token: flag },
      rationale:
        'A flag-format token is present in cleartext in the firmware bytes — recoverable without running the ' +
        'device. Flags hidden behind an on-device decode routine will not appear here and need manual reversing.',
    });
  }

  return { isCortexM, vectorTable, memoryMap, rtosKernel, ecos, flags, findings };
}

export interface RtosResult {
  available: boolean;
  isCortexM: boolean;
  vectorTable: { initialSP: number; resetHandler: number } | null;
  memoryMap: { flashBase: number; ramBase: number } | null;
  rtosKernel: string | null;
  findings: FindingDraft[];
  reason: string;
}

const FIRMWARE_READ_CAP = 16 * 1024 * 1024;

/** Read a bounded prefix of the firmware — MCU blobs are tiny; this caps a mis-routed image. */
function readFirmwareBounded(p: string, cap = FIRMWARE_READ_CAP): Uint8Array {
  const fd = fs.openSync(p, 'r');
  try {
    const len = Math.min(fs.fstatSync(fd).size, cap);
    const b = Buffer.allocUnsafe(len);
    fs.readSync(fd, b, 0, len, 0);
    return b;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Analyze a raw baremetal / RTOS blob from disk — honest and tool-free. Always `available` (pure analysis, no
 * external tool to be absent); when the bytes are not a raw Cortex-M vector table it returns isCortexM:false
 * with an honest reason rather than fabricating a memory map. A recognized image yields `static_confirmed`
 * findings about the layout and any RTOS kernel.
 */
export function runRtosAnalysis(imagePath: string): RtosResult {
  let buf: Uint8Array;
  try {
    buf = readFirmwareBounded(imagePath);
  } catch (err) {
    return {
      available: true,
      isCortexM: false,
      vectorTable: null,
      memoryMap: null,
      rtosKernel: null,
      findings: [],
      reason: `Could not read image bytes: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const a = analyzeRtos(buf);
  if (!a.isCortexM) {
    const ecosNote = a.ecos ? ` eCos monolith detected (${a.ecos.version ?? 'version unknown'}).` : '';
    const flagNote = a.flags.length ? ` ${a.flags.length} plaintext flag/credential token(s) recovered.` : '';
    return {
      available: true,
      isCortexM: false,
      vectorTable: null,
      memoryMap: null,
      rtosKernel: a.rtosKernel,
      findings: a.findings,
      reason:
        `No ARM Cortex-M vector table at offset 0 (not a raw Cortex-M image).${ecosNote}${flagNote}` +
        (a.findings.length ? '' : ' No eCos/flag markers either — static analysis found nothing to assert.'),
    };
  }

  const map = a.memoryMap;
  const mapNote = map ? ` Recovered map: flash ${hex(map.flashBase)}, RAM ${hex(map.ramBase)}.` : '';
  const kernelNote = a.rtosKernel ? ` RTOS kernel: ${a.rtosKernel}.` : ' No RTOS strings — bare-metal.';
  return {
    available: true,
    isCortexM: true,
    vectorTable: a.vectorTable,
    memoryMap: a.memoryMap,
    rtosKernel: a.rtosKernel,
    findings: a.findings,
    reason: `ARM Cortex-M vector table at offset 0.${mapNote}${kernelNote} Static analysis of the image bytes — proves layout, not device behavior.`,
  };
}
