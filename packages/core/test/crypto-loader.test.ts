import { describe, expect, it } from 'vitest';
import { detectLoaderDerivedKey, detectLoaderDerivedKeyInBytes } from '../src/crypto-loader.js';
import { extractStrings } from '../src/strings.js';

/** Build a buffer of NUL-separated strings, so extractStrings recovers each with a real offset. */
function loaderBytes(...s: string[]): Uint8Array {
  return new TextEncoder().encode(`${s.join('\0')}\0`);
}

// The recipe as it appears verbatim in the NexoCam NX-820 U-Boot partition (`flash_p1`): a decrypt anchor, the
// key-derivation help line (which itself carries the AES primitive), the `sha256` primitive, the two factory
// constants the real key is `SHA256("NX820-boot"||"Tarlogic-HW-2026")[:16]`, and the bootcmd that invokes it.
const NX820_LOADER = loaderBytes(
  'U-Boot 2023.10 (Sep 02 2026) NexoCam NX-820',
  'nx_decrypt: bad magic at 0x%lx (not an ENC1 partition)',
  'decrypt an ENC1 firmware partition in place',
  '    - derive the factory AES-128 key and decrypt the ENC1',
  'sha256',
  'NX820-boot',
  'Tarlogic-HW-2026',
  'bootcmd=sf probe 0; sf read 0x81000000 0x100000 0x400000; nx_decrypt kernel 0x81000000; nx_decrypt rootfs 0x84000000; bootm',
);

// The AES-128 key the real derivation produces. The detector must NEVER emit it — it reports the recipe, not the key.
const REAL_DERIVED_KEY_HEX = '2210be562c902f9d89049062ddcd8244';

describe('detectLoaderDerivedKey', () => {
  it('fires on the NX-820 loader: anchor + primitive + factory constants', () => {
    const r = detectLoaderDerivedKeyInBytes(NX820_LOADER);
    expect(r).not.toBeNull();
    expect(r?.primitive).toMatch(/sha|aes/i);
    expect(r?.anchors.length).toBeGreaterThan(0);
    expect(r?.anchors.some((a) => /ENC1|derive|decrypt/i.test(a.value))).toBe(true);
    const consts = r?.candidateConstants.map((c) => c.value) ?? [];
    expect(consts).toContain('NX820-boot');
    expect(consts).toContain('Tarlogic-HW-2026');
    expect(r?.confidence).toBe('high');
  });

  it('never emits or invents a key — only verbatim input strings', () => {
    const r = detectLoaderDerivedKeyInBytes(NX820_LOADER);
    // The derived key is nowhere in the output; the module does no derivation.
    expect(JSON.stringify(r)).not.toContain(REAL_DERIVED_KEY_HEX);
    // Every candidate constant is a string that was literally in the input, with its real offset.
    const inputValues = new Set(extractStrings(NX820_LOADER, { minLength: 4 }).map((h) => h.value));
    for (const c of r?.candidateConstants ?? []) {
      expect(inputValues.has(c.value)).toBe(true);
    }
  });

  it('returns null on a benign bootloader (no crypto primitive, no decrypt anchor)', () => {
    const benign = loaderBytes('bootcmd=bootm 0x8000', 'bootdelay=2', 'console=ttyS0,115200', 'ipaddr=192.168.1.1');
    expect(detectLoaderDerivedKeyInBytes(benign)).toBeNull();
  });

  it('requires co-occurrence: an anchor with no primitive does not fire', () => {
    const anchorOnly = loaderBytes('flash_key_region', 'decrypt the ENC1 partition here', 'NX820-boot');
    expect(detectLoaderDerivedKeyInBytes(anchorOnly)).toBeNull();
  });

  it('requires co-occurrence: a primitive with no decrypt anchor does not fire', () => {
    const primitiveOnly = loaderBytes('sha256 self-test ok', 'aes-128 cbc test vectors', 'bootdelay=2');
    expect(detectLoaderDerivedKeyInBytes(primitiveOnly)).toBeNull();
  });

  it('does not join an anchor to an unrelated primitive three MiB away', () => {
    expect(
      detectLoaderDerivedKey([
        { value: 'aes_decrypt', offset: 0 },
        { value: 'sha256 self-test', offset: 0x300000 },
        { value: 'Vendor-Seed', offset: 0x300010 },
      ]),
    ).toBeNull();
  });

  it('chooses the nearby hash rather than the first unrelated cipher primitive', () => {
    const r = detectLoaderDerivedKey([
      { value: 'md5 self-test', offset: 0 },
      { value: 'derive flash key', offset: 1000 },
      { value: 'sha256', offset: 1001 },
      { value: 'Vendor-Seed', offset: 1002 },
    ]);
    expect(r?.primitive).toMatch(/sha256/i);
  });

  it('reports how many ranked candidates its cap omitted', () => {
    const constants = Array.from({ length: 30 }, (_, i) => ({ value: `Vendor-${i}-Seed`, offset: 20 + i }));
    const r = detectLoaderDerivedKey([
      { value: 'derive flash key', offset: 0 },
      { value: 'sha256', offset: 1 },
      ...constants,
    ]);
    expect(r?.candidateConstants).toHaveLength(24);
    expect(r?.candidateTotal).toBe(30);
    expect(r?.candidateDropped).toBe(6);
  });

  it('drops medium confidence when the recipe co-occurs but no constant is near it', () => {
    const noConst = loaderBytes('derive the AES-128 key and decrypt the ENC1 partition', 'sha256');
    const r = detectLoaderDerivedKey(extractStrings(noConst, { minLength: 4 }));
    expect(r).not.toBeNull();
    expect(r?.confidence).toBe('medium');
    expect(r?.candidateConstants.length).toBe(0);
  });
});
