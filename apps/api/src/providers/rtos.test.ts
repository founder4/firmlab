import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  analyzeRtos,
  detectEcos,
  detectRtosKernel,
  extractFlags,
  inferMemoryMap,
  parseVectorTable,
  recoverBaseAddress,
  runRtosAnalysis,
} from './rtos.js';

/** Little-endian 4-byte encoding of a 32-bit word. */
function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

// A synthetic raw Cortex-M blob: initial SP 0x20010000, reset handler 0x08000135 (odd/Thumb), then FreeRTOS
// kernel marker strings somewhere further in — exactly the shape a raw STM32 .bin with FreeRTOS carries.
const INITIAL_SP = 0x20010000;
const RESET_HANDLER = 0x08000135;
function baremetalBlob(): Uint8Array {
  const head = Buffer.from([...u32le(INITIAL_SP), ...u32le(RESET_HANDLER)]);
  const body = Buffer.from('FreeRTOS Kernel V10.4.3 ... tskTCB pxCurrentTCB vTaskDelay', 'latin1');
  return Buffer.concat([head, Buffer.alloc(128), body]);
}

/** Realistic two-block RP2350/RISC-V PICOBIN loop without embedding any corpus payload or challenge secret. */
function picobinBlob(): Uint8Array {
  const buf = new Uint8Array(0x70);
  const dv = new DataView(buf.buffer);
  const first = 0x14;
  const tail = 0x50;
  dv.setUint32(first, 0xffff_ded3, true);
  dv.setUint32(first + 4, 0x1101_0142, true);
  dv.setUint32(first + 8, 0x0000_0344, true);
  dv.setUint32(first + 12, 0x1000_0036, true);
  dv.setUint32(first + 16, 0x2008_2000, true);
  dv.setUint32(first + 20, 0x0000_04ff, true);
  dv.setInt32(first + 24, tail - first, true);
  dv.setUint32(first + 28, 0xab12_3579, true);
  dv.setUint32(tail, 0xffff_ded3, true);
  dv.setUint32(tail + 4, 0x0000_01fe, true);
  dv.setUint32(tail + 8, 0x0000_01ff, true);
  dv.setInt32(tail + 12, first - tail, true);
  dv.setUint32(tail + 16, 0xab12_3579, true);
  return buf;
}

describe('parseVectorTable', () => {
  it('reads the initial SP and reset handler from a valid Cortex-M table', () => {
    expect(parseVectorTable(baremetalBlob())).toEqual({ initialSP: INITIAL_SP, resetHandler: RESET_HANDLER });
  });

  it('returns null for an ELF (magic 0x7F ELF) — handled on the ELF path, not as a raw blob', () => {
    const elf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, ...u32le(INITIAL_SP)]);
    expect(parseVectorTable(elf)).toBeNull();
  });

  it('returns null for random bytes (SP not in SRAM / reset not Thumb)', () => {
    expect(parseVectorTable(Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]))).toBeNull();
  });

  it('returns null when the reset handler is even (Thumb bit clear)', () => {
    const blob = Buffer.from([...u32le(INITIAL_SP), ...u32le(0x08000134)]);
    expect(parseVectorTable(blob)).toBeNull();
  });

  it('returns null for a too-short buffer', () => {
    expect(parseVectorTable(Buffer.from([0x00, 0x00, 0x01, 0x20]))).toBeNull();
  });
});

describe('recoverBaseAddress', () => {
  it('maps an STM32 reset handler to the 0x08000000 flash alias', () => {
    expect(recoverBaseAddress(RESET_HANDLER)).toBe(0x08000000);
  });
  it('maps a 0x0000_xxxx reset to base 0x00000000', () => {
    expect(recoverBaseAddress(0x00000135)).toBe(0x00000000);
  });
  it('masks any other reset handler to its top 12 bits', () => {
    expect(recoverBaseAddress(0x1fff0201)).toBe(0x1ff00000);
  });
});

describe('inferMemoryMap', () => {
  it('recovers the flash base from the reset handler and the RAM region from the SP', () => {
    expect(inferMemoryMap(INITIAL_SP, RESET_HANDLER)).toEqual({ flashBase: 0x08000000, ramBase: 0x20010000 });
  });
});

describe('detectRtosKernel', () => {
  it('finds FreeRTOS from its marker strings', () => {
    expect(detectRtosKernel(baremetalBlob())).toBe('FreeRTOS');
  });
  it('finds Zephyr from a k_thread marker', () => {
    expect(detectRtosKernel(Buffer.from('...k_thread_create...', 'latin1'))).toBe('Zephyr');
  });
  it('finds RIOT and mbed only from runtime-specific markers', () => {
    expect(detectRtosKernel(Buffer.from('...RIOT_VERSION=2026.10...', 'latin1'))).toBe('RIOT');
    expect(detectRtosKernel(Buffer.from('...mbed_error_status...', 'latin1'))).toBe('mbed');
  });
  it('does not promote incidental Linux/U-Boot substrings to RTOS findings', () => {
    expect(detectRtosKernel(Buffer.from('...random /riot bytes...', 'latin1'))).toBeNull();
    expect(detectRtosKernel(Buffer.from('...CONFIG_OF_EMBED...', 'latin1'))).toBeNull();
  });
  it('returns null when no kernel strings are present', () => {
    expect(detectRtosKernel(Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))).toBeNull();
  });
});

describe('analyzeRtos', () => {
  const a = analyzeRtos(baremetalBlob());

  it('marks a valid blob as Cortex-M with a recovered memory map', () => {
    expect(a.isCortexM).toBe(true);
    expect(a.vectorTable).toEqual({ initialSP: INITIAL_SP, resetHandler: RESET_HANDLER });
    expect(a.memoryMap).toEqual({ flashBase: 0x08000000, ramBase: 0x20010000 });
    expect(a.rtosKernel).toBe('FreeRTOS');
  });

  it('emits static_confirmed vector-table and RTOS-kernel findings with 0x-prefixed hex', () => {
    const kinds = a.findings.map((f) => f.kind);
    expect(kinds).toContain('rtos-vector-table');
    expect(kinds).toContain('rtos-kernel');
    // Kernel detected → no bare-metal lead.
    expect(kinds).not.toContain('rtos-baremetal');
    const vt = a.findings.find((f) => f.kind === 'rtos-vector-table');
    expect(vt?.proofState).toBe('static_confirmed');
    expect(vt?.severity).toBe('info');
    expect(vt?.title).toContain('0x20010000');
    expect(vt?.title).toContain('0x08000135');
    expect(vt?.title).toContain('inferred flash base 0x08000000');
    const rtos = a.findings.find((f) => f.kind === 'rtos-kernel');
    expect(rtos?.title).toBe('RTOS kernel detected: FreeRTOS');
    expect(rtos?.proofState).toBe('static_confirmed');
  });

  it('surfaces a bare-metal lead when a vector table has no RTOS strings', () => {
    const bare = analyzeRtos(Buffer.from([...u32le(INITIAL_SP), ...u32le(RESET_HANDLER), 0, 0, 0, 0]));
    expect(bare.rtosKernel).toBeNull();
    const lead = bare.findings.find((f) => f.kind === 'rtos-baremetal');
    expect(lead?.severity).toBe('info');
    expect(lead?.proofState).toBe('needs_runtime_reproduction');
    expect(lead?.title).toMatch(/needs Renode/i);
    expect((lead?.evidence as { markerScanCoverage: { complete: boolean } }).markerScanCoverage.complete).toBe(true);
  });

  it('produces no findings for a non-Cortex-M blob with no eCos/flag markers', () => {
    expect(analyzeRtos(Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00])).findings).toHaveLength(0);
  });

  it('surfaces a structurally validated RP2350/RISC-V PICOBIN declaration', () => {
    const parsed = analyzeRtos(picobinBlob());
    expect(parsed.isCortexM).toBe(false);
    expect(parsed.picobin).toMatchObject({
      chip: 'rp2350',
      cpu: 'riscv',
      cpuMode: 'riscv',
      entryPoint: 0x1000_0036,
      initialSP: 0x2008_2000,
      blockOffsets: [0x14, 0x50],
      loopComplete: true,
    });
    const finding = parsed.findings.find((f) => f.kind === 'rtos-picobin');
    expect(finding?.proofState).toBe('static_confirmed');
    expect(finding?.title).toContain('RP2350 PICOBIN executable declares RISC-V');
    expect(finding?.title).toContain('2-block loop validated');
  });
});

describe('detectEcos + extractFlags (non-Cortex-M RTOS / bare-metal lens)', () => {
  it('detects an eCos monolith with version, RedBoot and the vendor app', () => {
    const buf = Buffer.from('boot: RedBoot(tm) ... eCos 3.6.10 ... cyg_scheduler_start ... zxrouter main', 'latin1');
    const e = detectEcos(buf);
    expect(e).not.toBeNull();
    expect(e?.version).toBe('eCos 3.6.10');
    expect(e?.redboot).toBe(true);
    expect(e?.app).toBe('zxrouter');
  });

  it('returns null for an image with no eCos markers', () => {
    expect(detectEcos(Buffer.from('just some linux busybox strings', 'latin1'))).toBeNull();
  });

  it('analyzeRtos emits an rtos-ecos finding for a non-Cortex-M eCos image (not a silent empty)', () => {
    const a = analyzeRtos(Buffer.from('cyg_thread_create eCos 3.6.10 zxrouter', 'latin1'));
    expect(a.isCortexM).toBe(false);
    const f = a.findings.find((x) => x.kind === 'rtos-ecos');
    expect(f?.proofState).toBe('static_confirmed');
    expect(f?.title).toMatch(/eCos 3\.6\.10/);
  });

  it('extracts plaintext flag-format tokens and emits a static_confirmed finding', () => {
    const buf = Buffer.from('...garbage...flag{cR4p_1n_pl41nt3xt}...more...CTF{second_one}...', 'latin1');
    const flags = extractFlags(buf);
    expect(flags).toContain('flag{cR4p_1n_pl41nt3xt}');
    expect(flags).toContain('CTF{second_one}');
    const a = analyzeRtos(buf);
    const ff = a.findings.filter((x) => x.kind === 'baremetal-flag');
    expect(ff.length).toBe(2);
    expect(ff[0]?.proofState).toBe('static_confirmed');
  });

  it('finds no flags in an image without flag-format tokens', () => {
    expect(extractFlags(Buffer.from('nothing here but ordinary strings', 'latin1'))).toHaveLength(0);
  });
});

describe('runRtosAnalysis', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-rtos-test-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('analyzes a raw Cortex-M blob on disk into static_confirmed findings', () => {
    const p = path.join(tmp, 'blob.bin');
    fs.writeFileSync(p, baremetalBlob());
    const res = runRtosAnalysis(p);
    expect(res.available).toBe(true);
    expect(res.isCortexM).toBe(true);
    expect(res.vectorTable).toEqual({ initialSP: INITIAL_SP, resetHandler: RESET_HANDLER });
    expect(res.rtosKernel).toBe('FreeRTOS');
    expect(res.coverage).toEqual({
      scannedBytes: baremetalBlob().length,
      fileBytes: baremetalBlob().length,
      complete: true,
    });
    expect(res.findings.length).toBeGreaterThan(0);
  });

  it('degrades honestly for a non-baremetal blob', () => {
    const p = path.join(tmp, 'random.bin');
    fs.writeFileSync(p, Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00]));
    const res = runRtosAnalysis(p);
    expect(res.available).toBe(true);
    expect(res.isCortexM).toBe(false);
    expect(res.vectorTable).toBeNull();
    expect(res.reason).toContain('No ARM Cortex-M vector table at offset 0');
    expect(res.reason).toContain('complete 8-byte image');
  });

  it('reports PICOBIN metadata for a non-Cortex-M-at-offset-zero image instead of a silent empty', () => {
    const p = path.join(tmp, 'rp2350-riscv.bin');
    fs.writeFileSync(p, picobinBlob());
    const res = runRtosAnalysis(p);
    expect(res.isCortexM).toBe(false);
    expect(res.findings.some((f) => f.kind === 'rtos-picobin')).toBe(true);
    expect(res.reason).toContain('PICOBIN declares RP2350 riscv; block loop validated.');
    expect(res.reason).toMatch(/Entrypoint disassembly (completed|unavailable)/);
    expect(res.reason).not.toContain('static analysis found nothing to assert');
  });

  // Scanning a real 16 MiB buffer synchronously takes ~4s on its own, which already eats most of vitest's 5s
  // default under the full parallel suite's CPU contention — this raises the test's own budget, not the code's.
  it('bounds negative marker claims when the file exceeds the 16 MiB scan cap', () => {
    const p = path.join(tmp, 'large-random.bin');
    const cap = 16 * 1024 * 1024;
    const lateMarker = Buffer.from('eCos 3.6.10 cyg_scheduler', 'latin1');
    const fd = fs.openSync(p, 'w');
    try {
      fs.writeSync(fd, Buffer.from([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]), 0, 8, 0);
      fs.writeSync(fd, lateMarker, 0, lateMarker.length, cap + 32);
    } finally {
      fs.closeSync(fd);
    }

    const res = runRtosAnalysis(p);
    expect(res.findings).toHaveLength(0);
    expect(res.coverage).toEqual({
      scannedBytes: cap,
      fileBytes: cap + 32 + lateMarker.length,
      complete: false,
    });
    expect(res.reason).toContain(`first ${cap} of ${cap + 32 + lateMarker.length} image bytes`);
    expect(res.reason).toContain('within that scope');
    expect(res.reason).not.toContain('static analysis found nothing to assert.');
  }, 20000);
});
