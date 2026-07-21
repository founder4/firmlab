/**
 * Deterministic MCU fingerprint for the RTOS / bare-metal emulation rung.
 *
 * Renode boots a microcontroller firmware only when given the right per-MCU platform description (.repl). Picking
 * that platform needs to know WHICH microcontroller the blob targets — and the evidence is already in the bytes,
 * in two places static analysis never mined before:
 *
 *   1. The memory layout. An ELF's load addresses (its flash LMA + SRAM region), or — for a raw `.bin` — the ARM
 *      Cortex-M vector table (word[0] = initial stack pointer → SRAM base, word[1] = reset handler → flash base),
 *      pin down the address map, which is a strong family discriminator (STM32 flash @ 0x08000000, nRF @ 0x0, …).
 *   2. The plain strings. Vendor SDK banners and CMSIS device names ("STM32F407", "nRF5 SDK", "EFR32MG", "ESP-IDF",
 *      "SiFive FE310"), the CPU core ("Cortex-M4"), and the RTOS ("Zephyr", "Contiki", "FreeRTOS") — none of which
 *      is a *secret*, so the credential-oriented string scan drops them on the floor.
 *
 * This module reads both — bytes in, a structured fingerprint out — with no I/O and no tool dependency, so it is
 * fully unit-testable and shared by every caller (the /renode route, the emulation ladder, the agent executor).
 * It asserts no more than the evidence supports: an unrecognized MCU yields a family-less fingerprint so the
 * platform selector degrades honestly to `blocked_by_platform` rather than booting a wrong guess.
 */

/** CPU family an MCU fingerprint can resolve — a superset of the Linux-oriented `Architecture` (adds Xtensa/MSP430). */
export type McuArch = 'arm' | 'riscv' | 'xtensa' | 'mips' | 'msp430' | 'unknown';

export interface McuFingerprint {
  /** CPU architecture from the ELF `e_machine`, the vector table, or a string marker. */
  arch: McuArch;
  /** ARM Cortex-M core when a string named it, normalized (e.g. `cortex-m4`, `cortex-m0plus`, `cortex-m33`). */
  cortexM: string | null;
  /** Canonical vendor family token, e.g. `stm32f4`, `nrf52`, `efr32mg`, `cc2538`, `esp32`, `fe310`. */
  family: string | null;
  /** Most-specific part token seen in the strings, e.g. `stm32f407`, `nrf52840`, `efr32mg12`. */
  part: string | null;
  /** The bare STM32 part core with the `stm32` prefix stripped (e.g. `h753`, `f429`) — matches boards that drop it. */
  partCore: string | null;
  /** Silicon vendor, e.g. `st`, `nordic`, `silabs`, `ti`, `nxp`, `microchip`, `espressif`, `sifive`. */
  vendor: string | null;
  /** RTOS / SDK banner when present, e.g. `zephyr`, `freertos`, `contiki`, `riot`, `mbed`, `nuttx`. */
  rtos: string | null;
  /** Flash / code base address (ELF min load LMA, or the vector table's reset-target region), when derivable. */
  flashBase: number | null;
  /** SRAM base (ELF RAM region, or the vector table's initial-SP region), when derivable. */
  ramBase: number | null;
  /** True if the buffer parsed as an ELF; false if it was fingerprinted as a raw Cortex-M image. */
  isElf: boolean;
  /** The concrete markers that fired, for the honest "why this platform" audit trail. */
  evidence: string[];
  /** Lowercased search tokens (part / family / vendor / core / rtos) for catalog matching. */
  tokens: string[];
}

/** ELF `e_machine` → MCU arch, for the machines that show up in microcontroller firmware. */
const ELF_MACHINE_MCU: Record<number, McuArch> = {
  8: 'mips', // PIC32 and friends
  40: 'arm',
  94: 'xtensa', // ESP32 / ESP8266
  243: 'riscv',
};

/** Cap the string scan: MCU firmware is small, and this bounds work if a large image is ever mis-routed here. */
const MARKER_SCAN_CAP = 4 * 1024 * 1024;

function u16(b: Uint8Array, o: number, le: boolean): number {
  if (o < 0 || o + 1 >= b.length) return 0;
  const a = b[o] ?? 0;
  const c = b[o + 1] ?? 0;
  return le ? a | (c << 8) : (a << 8) | c;
}

function u32(b: Uint8Array, o: number, le: boolean): number {
  if (o < 0 || o + 3 >= b.length) return 0;
  const x0 = b[o] ?? 0;
  const x1 = b[o + 1] ?? 0;
  const x2 = b[o + 2] ?? 0;
  const x3 = b[o + 3] ?? 0;
  return (le ? x0 | (x1 << 8) | (x2 << 16) | (x3 << 24) : (x0 << 24) | (x1 << 16) | (x2 << 8) | x3) >>> 0;
}

interface Layout {
  isElf: boolean;
  arch: McuArch;
  flashBase: number | null;
  ramBase: number | null;
}

/** Is an address in a plausible Cortex-M SRAM window? (SRAM is conventionally based at 0x20000000.) */
function looksLikeSram(addr: number): boolean {
  return addr >= 0x2000_0000 && addr < 0x2020_0000;
}

/**
 * Parse an ELF just far enough to read the CPU and the load map: `e_machine`, and the PT_LOAD program headers'
 * physical (flash LMA) and virtual (run) addresses. Handles 32- and 64-bit, both endiannesses. Never throws —
 * a truncated or non-ELF buffer returns `isElf: false`.
 */
function parseElfLayout(buf: Uint8Array): Layout {
  const notElf: Layout = { isElf: false, arch: 'unknown', flashBase: null, ramBase: null };
  if (buf.length < 20 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) return notElf;
  const is64 = buf[4] === 2;
  const le = buf[5] !== 2; // EI_DATA: 1 = little, 2 = big
  const arch = ELF_MACHINE_MCU[u16(buf, 18, le)] ?? 'unknown';

  const phoff = is64 ? u32(buf, 32, le) : u32(buf, 28, le); // low 32 bits of e_phoff (MCU images are small)
  const phentsize = is64 ? u16(buf, 54, le) : u16(buf, 42, le);
  const phnum = Math.min(is64 ? u16(buf, 56, le) : u16(buf, 44, le), 64);

  const flashCandidates: number[] = [];
  const ramCandidates: number[] = [];
  for (let i = 0; i < phnum; i++) {
    const ph = phoff + i * phentsize;
    if (u32(buf, ph, le) !== 1) continue; // PT_LOAD
    const vaddr = is64 ? u32(buf, ph + 16, le) : u32(buf, ph + 8, le);
    const paddr = is64 ? u32(buf, ph + 24, le) : u32(buf, ph + 12, le);
    const filesz = is64 ? u32(buf, ph + 32, le) : u32(buf, ph + 16, le);
    if (filesz > 0) flashCandidates.push(paddr); // the LMA is where the segment lives in flash
    if (looksLikeSram(vaddr) || (vaddr !== paddr && vaddr !== 0)) ramCandidates.push(vaddr);
  }
  return {
    isElf: true,
    arch,
    flashBase: flashCandidates.length ? Math.min(...flashCandidates) : null,
    ramBase: ramCandidates.length ? Math.min(...ramCandidates) : null,
  };
}

/**
 * Fingerprint a raw (non-ELF) image as an ARM Cortex-M firmware from its vector table: word[0] is the initial
 * stack pointer (must land in SRAM), word[1] the reset handler (a Thumb address in flash — bit 0 set). If both
 * hold, the two region bases are the memory map; otherwise this is not a recognizable Cortex-M image.
 */
function parseVectorTable(buf: Uint8Array): Layout | null {
  if (buf.length < 8) return null;
  const sp = u32(buf, 0, true);
  const reset = u32(buf, 4, true);
  const spOk = looksLikeSram(sp);
  const resetOk = (reset & 1) === 1 && reset > 0 && reset < 0x1000_0000;
  if (!spOk || !resetOk) return null;
  return { isElf: false, arch: 'arm', flashBase: reset & 0xfff0_0000, ramBase: sp & 0xfff0_0000 };
}

/** Decode a bounded prefix of the image as latin1 (byte == code point), lowercased, for marker matching. */
function decodeAscii(buf: Uint8Array): string {
  const end = Math.min(buf.length, MARKER_SCAN_CAP);
  let out = '';
  for (let i = 0; i < end; i += 0x8000) {
    // Chunked to stay well under argument-count limits on String.fromCharCode.
    out += String.fromCharCode(...buf.subarray(i, Math.min(end, i + 0x8000)));
  }
  return out.toLowerCase();
}

/**
 * Vendor-family detectors. The high-value families use a captured regex so a single rule covers every
 * sub-family without enumerating parts (e.g. one STM32 rule spans f0…f7, g0/g4, h7, l0…l5, wb/wl, u5). `family`
 * is either a literal or derived from the match — deriving keeps the fingerprint specific enough that catalog
 * matching lands on the right board. Ordered most-specific first; the first hit wins.
 */
interface FamilyRule {
  re: RegExp;
  vendor: string;
  arch: McuArch;
  family: (m: RegExpMatchArray) => string;
}
const FAMILY_RULES: FamilyRule[] = [
  { re: /stm32([fghlwu])(\d)\w*/, vendor: 'st', arch: 'arm', family: (m) => `stm32${m[1]}${m[2]}` },
  { re: /nrf(\d{2})\d{2,3}/, vendor: 'nordic', arch: 'arm', family: (m) => `nrf${m[1]}` },
  { re: /(ef[rm]32)([a-z]{2})?\w*/, vendor: 'silabs', arch: 'arm', family: (m) => `${m[1]}${m[2] ?? ''}` },
  { re: /cc(13|26|25|32)(\d{2})\w*/, vendor: 'ti', arch: 'arm', family: (m) => `cc${m[1]}${m[2]}` },
  { re: /(atsam|sam)([de]\d{2}|3[xnu]|4[elsn])\w*/, vendor: 'microchip', arch: 'arm', family: (m) => `sam${m[2]}` },
  { re: /imxrt(\d{3,4})/, vendor: 'nxp', arch: 'arm', family: (m) => `imxrt${m[1]}` },
  { re: /\bmk[levw]?(\d{2})\w*/, vendor: 'nxp', arch: 'arm', family: () => 'kinetis' },
  { re: /lpc(\d{2})\d{1,2}\w*/, vendor: 'nxp', arch: 'arm', family: (m) => `lpc${m[1]}` },
  { re: /gd32v\w*/, vendor: 'gigadevice', arch: 'riscv', family: () => 'gd32v' },
  { re: /gd32([a-z])\w*/, vendor: 'gigadevice', arch: 'arm', family: (m) => `gd32${m[1]}` },
  { re: /ch32v\w*/, vendor: 'wch', arch: 'riscv', family: () => 'ch32v' },
  { re: /esp32-?([csh]\d)/, vendor: 'espressif', arch: 'riscv', family: (m) => `esp32${m[1]}` }, // -C/-H are RISC-V
  { re: /esp32/, vendor: 'espressif', arch: 'xtensa', family: () => 'esp32' },
  { re: /esp8266/, vendor: 'espressif', arch: 'xtensa', family: () => 'esp8266' },
  { re: /(fe310|hifive|sifive|e310)/, vendor: 'sifive', arch: 'riscv', family: () => 'fe310' },
  { re: /pic32([a-z]{2})\w*/, vendor: 'microchip', arch: 'mips', family: (m) => `pic32${m[1]}` },
  { re: /msp430\w*/, vendor: 'ti', arch: 'msp430', family: () => 'msp430' },
];

/** Specific part tokens to lift out verbatim for catalog fuzzy-matching (longest wins as `part`). */
const PART_RES: RegExp[] = [
  /stm32[fghlwu]\d{2,3}[a-z0-9]{0,4}/g,
  /nrf\d{4,5}/g,
  /ef[rm]32[a-z]{2}\d{1,2}[a-z0-9]{0,4}/g,
  /cc\d{4}[a-z0-9]{0,3}/g,
  /atsam[de]\d{2}[a-z0-9]{0,4}/g,
  /samd\d{2}[a-z0-9]{0,4}/g,
  /imxrt\d{3,4}/g,
  /lpc\d{3,4}[a-z0-9]{0,2}/g,
  /gd32[a-z]?\d{2,3}[a-z0-9]{0,3}/g,
  /ch32[a-z]\d{2,3}[a-z0-9]{0,3}/g,
  /esp32-?[a-z]?\d?/g,
  /fe310[a-z0-9]{0,4}/g,
  /pic32[a-z]{2}\w{0,6}/g,
];

const RTOS_RULES: { re: RegExp; name: string }[] = [
  { re: /contiki-?ng|contiki/, name: 'contiki' },
  { re: /zephyr/, name: 'zephyr' },
  { re: /freertos/, name: 'freertos' },
  { re: /\briot\b|riot-os/, name: 'riot' },
  { re: /mbed[ -]?os|mbed/, name: 'mbed' },
  { re: /nuttx/, name: 'nuttx' },
  { re: /mynewt/, name: 'mynewt' },
  { re: /threadx|azure rtos/, name: 'threadx' },
  { re: /chibios/, name: 'chibios' },
];

/** Normalize a Cortex-M core string to a canonical token. */
const CORE_RE = /cortex-?m(0\+|0plus|23|33|55|85|0|1|3|4|7)/;
function normalizeCore(sub: string): string {
  const s = sub === '0+' || sub === '0plus' ? '0plus' : sub;
  return `cortex-m${s}`;
}

/** The RP2350 PICOBIN block start marker (u32 0xFFFFDED3, stored little-endian → D3 DE FF FF). */
const PICOBIN_START_MARKER = [0xd3, 0xde, 0xff, 0xff];
/** PICOBIN item type that declares the image kind + CPU + chip (see the RP2350 datasheet §5.9.5). */
const PICOBIN_IMAGE_TYPE_ITEM = 0x42;

export interface PicobinInfo {
  /** Offset of the start marker in the buffer. */
  markerOffset: number;
  /** CPU the image was built for — the field that decides Arm-vs-RISC-V disassembly. `varmulet` runs Arm code. */
  cpu: McuArch;
  /** Target chip token when the IMAGE_TYPE item declared it. */
  chip: 'rp2040' | 'rp2350' | null;
  /** Whether the block declares an executable image (vs a data/packaged image). */
  isExecutable: boolean;
}

/**
 * Detect and decode an RP2350 PICOBIN boot block. Bare-metal RP2350 images are the one class where guessing the
 * ISA by chip *name* is catastrophic: the RP2350 ships both an Arm Cortex-M33 and a RISC-V Hazard3 core, and the
 * only authoritative source of which one a given image targets is the IMAGE_TYPE item's CPU field. We walk the
 * block's TLV items to read it, so the classifier picks `riscv` vs `arm` from the bytes, never from a label.
 *
 * Returns null when no PICOBIN block is present. Pure; scans a bounded prefix (boot blocks live near the start).
 */
export function parsePicobin(buf: Uint8Array): PicobinInfo | null {
  const scanEnd = Math.min(buf.length - 4, 256 * 1024);
  let markerOffset = -1;
  for (let o = 0; o <= scanEnd; o++) {
    if (
      buf[o] === PICOBIN_START_MARKER[0] &&
      buf[o + 1] === PICOBIN_START_MARKER[1] &&
      buf[o + 2] === PICOBIN_START_MARKER[2] &&
      buf[o + 3] === PICOBIN_START_MARKER[3]
    ) {
      markerOffset = o;
      break;
    }
  }
  if (markerOffset < 0) return null;

  // Walk the block's items (each item's byte 1 carries its size in 32-bit words) until IMAGE_TYPE or the end.
  let cpu: McuArch = 'unknown';
  let chip: PicobinInfo['chip'] = null;
  let isExecutable = false;
  let pos = markerOffset + 4;
  for (let n = 0; n < 32 && pos + 4 <= buf.length; n++) {
    const itemType = buf[pos] ?? 0;
    if (itemType === 0) break;
    if (itemType === PICOBIN_IMAGE_TYPE_ITEM) {
      const flags = u16(buf, pos + 2, true);
      isExecutable = (flags & 0x000f) === 0x1; // IMAGE_TYPE_EXE
      cpu =
        ((flags >> 8) & 0x7) === 0x1
          ? 'riscv'
          : ((flags >> 8) & 0x7) === 0x0
            ? 'arm'
            : ((flags >> 8) & 0x7) === 0x2
              ? 'arm' // varmulet: emulated Arm code running on the RISC-V core → the image is Arm
              : 'unknown';
      chip = ((flags >> 12) & 0x7) === 0x1 ? 'rp2350' : ((flags >> 12) & 0x7) === 0x0 ? 'rp2040' : null;
      break;
    }
    const sizeWords = buf[pos + 1] ?? 0;
    if (sizeWords <= 0) break;
    pos += sizeWords * 4;
  }
  return { markerOffset, cpu, chip, isExecutable };
}

/** Build the fingerprint. `buf` should be the firmware bytes (the caller may cap very large buffers). */
export function fingerprintMcu(buf: Uint8Array): McuFingerprint {
  const layout = parseElfLayout(buf);
  const map = layout.isElf ? layout : (parseVectorTable(buf) ?? layout);
  const text = decodeAscii(buf);
  const evidence: string[] = [];

  let family: string | null = null;
  let vendor: string | null = null;
  let markerArch: McuArch = 'unknown';
  for (const rule of FAMILY_RULES) {
    const m = text.match(rule.re);
    if (m) {
      family = rule.family(m);
      vendor = rule.vendor;
      markerArch = rule.arch;
      evidence.push(`family marker "${m[0]}" → ${family} (${vendor})`);
      break;
    }
  }

  // Most-specific literal part token, for catalog matching against real .repl filenames.
  let part: string | null = null;
  for (const re of PART_RES) {
    for (const m of text.matchAll(re)) {
      if (!part || m[0].length > part.length) part = m[0];
    }
  }
  if (part) evidence.push(`part token "${part}"`);

  const coreMatch = text.match(CORE_RE);
  const cortexM = coreMatch ? normalizeCore(coreMatch[1] ?? '') : null;
  if (cortexM) evidence.push(`core "${cortexM}"`);

  let rtos: string | null = null;
  for (const r of RTOS_RULES) {
    if (r.re.test(text)) {
      rtos = r.name;
      evidence.push(`rtos banner "${rtos}"`);
      break;
    }
  }

  // Arch precedence: an ELF `e_machine` is authoritative; else a memory-map/vector-table read; else the marker.
  let arch: McuArch = map.arch;
  if (arch === 'unknown') arch = markerArch;
  if (arch === 'unknown' && cortexM) arch = 'arm';

  // The flash base is corroborating evidence. The STM32-characteristic 0x08000000 confirms an ARM Cortex-M map,
  // but we do NOT fabricate a concrete vendor family from it alone — without a string, that would be a guess;
  // arch=arm lets the selector fall back to a generic core honestly instead of naming a specific board.
  if (map.flashBase !== null) evidence.push(`flash base 0x${map.flashBase.toString(16)}`);
  if (map.flashBase === 0x0800_0000 && arch === 'unknown') arch = 'arm';

  // STM32 boards name themselves inconsistently — `stm32f4_discovery` keeps the prefix, `nucleo_h753zi` drops it —
  // so expose the bare core (letter + digits, e.g. `h753`, `f429`) as a token too, to match either style of board.
  const partCore = part?.match(/stm32([a-z]\d{2,3})/)?.[1] ?? null;

  const tokens = [...new Set([part, partCore, family, vendor, cortexM, rtos].filter((t): t is string => !!t))];
  return {
    arch,
    cortexM,
    family,
    part,
    partCore,
    vendor,
    rtos,
    flashBase: map.flashBase,
    ramBase: map.ramBase,
    isElf: layout.isElf,
    evidence,
    tokens,
  };
}
