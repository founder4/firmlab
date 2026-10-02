import { describe, expect, it } from 'vitest';
import {
  SPI_DESCRIPTOR_PARSE_CAP_BYTES,
  SPI_DESCRIPTOR_SCAN_CAP_BYTES,
  analyzeSpiDescriptor,
  assessHostMeWrite,
} from './spi-descriptor.js';

const DESCRIPTOR_SIGNATURE = 0x0ff0a55a;

function buildDescriptor(regions: number[], { offset = 0, size = 0x10000, regionBaseUnits = 6 } = {}): Buffer {
  const bytes = Buffer.alloc(size);
  bytes.writeUInt32LE(DESCRIPTOR_SIGNATURE, offset + 0x10);
  const map0 = (regionBaseUnits << 16) | ((regions.length - 1) << 24);
  bytes.writeUInt32LE(map0, offset + 0x14);
  regions.forEach((raw, index) => bytes.writeUInt32LE(raw, offset + regionBaseUnits * 16 + index * 4));
  return bytes;
}

function region(baseUnits: number, limitUnits: number): number {
  return ((limitUnits & 0x7fff) << 16) | (baseUnits & 0x7fff);
}

describe('analyzeSpiDescriptor', () => {
  it('parses static flash regions, overlaps, gaps, and keeps runtime registers unknown', () => {
    const image = buildDescriptor([
      region(0, 0), // Flash descriptor: [0x0000, 0x1000)
      region(0, 2), // BIOS: overlaps the descriptor region
      region(4, 4), // Intel ME: gap after BIOS
      region(5, 4), // GbE disabled because base > limit
      region(6, 6), // Platform data: another gap after ME
    ]);

    const result = analyzeSpiDescriptor(image);

    expect(result.status).toBe('parsed');
    expect(result.descriptorOffset).toBe(0);
    expect(result.regions[1]).toMatchObject({
      name: 'BIOS',
      enabled: true,
      startBytes: 0,
      endBytesExclusive: 0x3000,
    });
    expect(result.regions[3]).toMatchObject({ name: 'GbE', enabled: false, startBytes: null });
    expect(result.overlaps).toEqual([
      { firstRegion: 'Flash Descriptor', secondRegion: 'BIOS', startBytes: 0, endBytesExclusive: 0x1000 },
    ]);
    expect(result.gaps).toEqual([
      { firstRegion: 'BIOS', secondRegion: 'Intel ME', startBytes: 0x3000, endBytesExclusive: 0x4000 },
      { firstRegion: 'Intel ME', secondRegion: 'Platform Data', startBytes: 0x5000, endBytesExclusive: 0x6000 },
    ]);
    expect(result.runtimeRegisterPosture.state).toBe('unknown');
    expect(result.runtimeRegisterPosture.reason).toContain('live register dump');
    expect(result.findings.map((finding) => finding.proofState)).toEqual([
      'static_confirmed',
      'static_confirmed',
      'static_confirmed',
    ]);
    expect(result.findings.map((finding) => finding.kind)).toEqual([
      'spi-descriptor-map',
      'spi-descriptor-overlap',
      'spi-descriptor-gap',
    ]);
    expect(result.coverage).toMatchObject({
      imageBytes: image.byteLength,
      scannedBytes: image.byteLength,
      scanLimitBytes: SPI_DESCRIPTOR_SCAN_CAP_BYTES,
      parsedBytes: 0x74,
      parseLimitBytes: SPI_DESCRIPTOR_PARSE_CAP_BYTES,
      parsedStartBytes: 0,
      parsedEndBytesExclusive: 0x74,
    });
  });

  it('leaves an absent descriptor unknown without a clean or negative finding', () => {
    const result = analyzeSpiDescriptor(Buffer.alloc(64));

    expect(result.status).toBe('unknown');
    expect(result.reason).toContain('No aligned Intel flash descriptor signature');
    expect(result.coverage).toMatchObject({ imageBytes: 64, scannedBytes: 64, parsedBytes: 0 });
    expect(result.findings).toEqual([]);
  });

  it('leaves a truncated descriptor map unknown and reports the partial parse bounds', () => {
    const image = Buffer.alloc(0x200);
    image.writeUInt32LE(DESCRIPTOR_SIGNATURE, 0x10);
    image.writeUInt32LE((0x7f << 16) | (1 << 24), 0x14);

    const result = analyzeSpiDescriptor(image);

    expect(result.status).toBe('unknown');
    expect(result.reason).toContain('region map is truncated');
    expect(result.descriptorOffset).toBe(0);
    expect(result.coverage).toMatchObject({ parsedBytes: 0x18, parsedStartBytes: 0, parsedEndBytesExclusive: 0x18 });
    expect(result.findings).toEqual([]);
  });

  it('reports explicit scan bounds when the descriptor lies beyond the scanned prefix', () => {
    const image = buildDescriptor([region(0, 0)], { offset: 0x100, size: 0x10000 });

    const result = analyzeSpiDescriptor(image, { scanLimitBytes: 0x100 });

    expect(result.status).toBe('unknown');
    expect(result.coverage).toMatchObject({ imageBytes: image.byteLength, scannedBytes: 0x100, scanLimitBytes: 0x100 });
  });

  it('leaves ranges extending beyond the source image unknown', () => {
    const image = buildDescriptor([region(0, 0x7fff)], { size: 0x10000 });

    const result = analyzeSpiDescriptor(image);

    expect(result.status).toBe('unknown');
    expect(result.reason).toContain('ends beyond the');
    expect(result.findings).toEqual([]);
  });
});

/**
 * A descriptor whose FLMAP1 points the master section at `masterBaseUnits * 16`, holding `flmstr1`, and declares
 * `masterCount` masters in NM (bits 8..).
 */
function withMaster(
  flmstr1: number,
  { masterBaseUnits = 8, masterCount = 2, size = 0x10000, regions = [region(0, 0), region(1, 15)] } = {},
): Buffer {
  const bytes = buildDescriptor(regions, { size });
  bytes.writeUInt32LE(masterBaseUnits | (masterCount << 8), 0x18);
  // A pointer into the header is left unwritten: writing there would clobber the signature under test.
  if (masterBaseUnits * 16 >= 0x20 && masterBaseUnits * 16 + 4 <= size)
    bytes.writeUInt32LE(flmstr1 >>> 0, masterBaseUnits * 16);
  return bytes;
}

describe('analyzeSpiDescriptor — host master access', () => {
  it('reports a descriptor-write grant only when every chipsec FLMSTR layout agrees', () => {
    // The fully unlocked value: write bits set under both the 8-bit (24..31) and 12-bit (20..31) layouts.
    const result = analyzeSpiDescriptor(withMaster(0xffff0000));
    expect(result.hostMasterAccess).toMatchObject({ status: 'read', flmstr1Offset: 0x80, descriptorWrite: 'granted' });
    expect(result.hostMasterAccess?.layouts.map((l) => [l.layout, l.writeMask])).toEqual([
      ['ich-8bit', 0xff],
      ['pch-12bit', 0xfff],
    ]);
    expect(result.hostMasterAccess?.masterCount?.map((f) => f.value)).toEqual([2, 2]);
    const finding = result.findings.find((f) => f.kind === 'spi-descriptor-host-write');
    expect(finding).toMatchObject({ severity: 'medium', proofState: 'static_confirmed' });
    expect(finding?.rationale).toMatch(/FRAP register .* was not read/);
  });

  it('counts the FLMSTR1 read in the parse coverage', () => {
    // Region map ends at 0x68; FLMSTR1 sits at 0x80.
    const result = analyzeSpiDescriptor(withMaster(0xffff0000));
    expect(result.coverage).toMatchObject({ parsedStartBytes: 0, parsedBytes: 0x84, parsedEndBytesExclusive: 0x84 });
    const map = result.findings.find((f) => f.kind === 'spi-descriptor-map');
    expect(map?.evidence.coverage).toBe(result.coverage);
  });

  it('leaves master access unknown when FLMAP1 NM is 0, recording NM and making no host-write claim', () => {
    const result = analyzeSpiDescriptor(withMaster(0xffff0000, { masterCount: 0 }));
    expect(result.status).toBe('parsed');
    expect(result.hostMasterAccess).toMatchObject({
      status: 'unknown',
      flmstr1Offset: 0x80,
      rawValue: null,
      descriptorWrite: 'unknown',
      meWrite: 'unknown',
      masterCount: [
        { source: 'chipsec cfg/8086/common.xml', width: 2, value: 0 },
        { source: 'chipsec cfg/8086/pch_1xx.xml', width: 3, value: 0 },
      ],
    });
    expect(result.hostMasterAccess?.reason).toMatch(/NM = 0 as no master records/);
    expect(result.hostMasterAccess?.reason).toMatch(/cannot establish whether NM is zero-based/);
    expect(result.findings.some((f) => f.kind.startsWith('spi-descriptor-host'))).toBe(false);
    // FLMSTR1 (0x80) was not read, so it is not counted; the coverage ends at FLREG2, read beyond NR at 0x68.
    expect(result.coverage.parsedEndBytesExclusive).toBe(0x6c);
  });

  it('leaves master access unknown when the NM readings disagree on a zero count', () => {
    // Bit 10 alone: NM = 0 under the 2-bit common.xml field, 4 under the 3-bit pch_1xx.xml field.
    const result = analyzeSpiDescriptor(withMaster(0xffff0000, { masterCount: 4 }));
    expect(result.hostMasterAccess?.masterCount?.map((f) => f.value)).toEqual([0, 4]);
    expect(result.hostMasterAccess?.descriptorWrite).toBe('unknown');
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-write')).toBe(false);
  });

  it('records a denied grant without a finding', () => {
    // CPU/BIOS master: read descriptor+BIOS, write BIOS only, under both layouts.
    const result = analyzeSpiDescriptor(withMaster((0x2 << 24) | (0x3 << 16)));
    expect(result.hostMasterAccess?.descriptorWrite).toBe('denied');
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-write')).toBe(false);
  });

  it('refuses to pick a layout when the two disagree', () => {
    // Bit 20 is the descriptor write bit in the 12-bit layout and a read bit (region 4) in the 8-bit one.
    const result = analyzeSpiDescriptor(withMaster(1 << 20));
    expect(result.hostMasterAccess?.descriptorWrite).toBe('layout-dependent');
    expect(result.hostMasterAccess?.reason).toMatch(/under pch-12bit only; .* undetermined/);
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-write')).toBe(false);
  });

  it('leaves master access unknown when FLMAP1 has no master section, points into the header, or runs out', () => {
    expect(analyzeSpiDescriptor(withMaster(0xffff0000, { masterBaseUnits: 0 })).hostMasterAccess).toMatchObject({
      status: 'unknown',
      descriptorWrite: 'unknown',
    });
    expect(analyzeSpiDescriptor(withMaster(0xffff0000, { masterBaseUnits: 1 })).hostMasterAccess?.reason).toMatch(
      /inside the descriptor header/,
    );
    const outOfBound = analyzeSpiDescriptor(withMaster(0xffff0000, { masterBaseUnits: 0xff }), {
      parseLimitBytes: 0x200,
    });
    expect(outOfBound.status).toBe('parsed');
    expect(outOfBound.hostMasterAccess?.reason).toMatch(/FLMSTR1 is truncated or exceeds the parse bound/);
    expect(outOfBound.findings.some((f) => f.kind === 'spi-descriptor-host-write')).toBe(false);
  });
});

describe('analyzeSpiDescriptor — host master Intel ME write', () => {
  // Descriptor, BIOS, and an enabled Intel ME region at [0x8000, 0x10000).
  const withMe = [region(0, 0), region(1, 7), region(8, 15)];
  // ME is region 2: write bit 24+2 under the 8-bit layout, 20+2 under the 12-bit one. Neither sets descriptor write.
  const meGrantedBoth = (1 << 26) | (1 << 22);

  it('flags an ME write grant when both layouts agree and the region map enables the ME region', () => {
    const result = analyzeSpiDescriptor(withMaster(meGrantedBoth, { regions: withMe }));
    expect(result.hostMasterAccess).toMatchObject({ meWrite: 'granted', descriptorWrite: 'denied' });
    expect(result.hostMasterAccess?.layouts.map((l) => l.meWritable)).toEqual([true, true]);
    const finding = result.findings.find((f) => f.kind === 'spi-descriptor-host-me-write');
    expect(finding).toMatchObject({
      title: 'SPI descriptor grants the CPU/BIOS master write access to the Intel ME region',
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { meRegion: { index: 2, name: 'Intel ME', enabled: true, startBytes: 0x8000 } },
    });
    expect(finding?.evidence.hostMasterAccess).toBe(result.hostMasterAccess);
    expect(finding?.rationale).toMatch(/write the ME firmware region/);
    expect(finding?.rationale).toMatch(/FRAP register was not read/);
    expect(finding?.rationale).toMatch(/descriptor-override strap can change the runtime behavior/);
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-write')).toBe(false);
  });

  it('records a grant over a disabled ME region with its reason and no finding', () => {
    const disabledMe = [region(0, 0), region(1, 7), region(9, 8)];
    const result = analyzeSpiDescriptor(withMaster(meGrantedBoth, { regions: disabledMe }));
    expect(result.hostMasterAccess?.meWrite).toBe('granted');
    expect(result.hostMasterAccess?.meWriteReason).toMatch(/Intel ME region disabled .* not flagged/);
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-me-write')).toBe(false);
  });

  it('refuses to flag a grant when the ME region is enabled under only one FLREG width', () => {
    // 13-bit reading: base 8 <= limit 0x1fff, enabled. 15-bit reading: base 0x6008 > limit 0x1fff, disabled.
    const result = analyzeSpiDescriptor(
      withMaster(meGrantedBoth, { regions: [region(0, 0), region(1, 7), 0x1fff6008] }),
    );
    expect(result.hostMasterAccess?.meWrite).toBe('granted');
    expect(result.hostMasterAccess?.meWriteReason).toMatch(
      /FLREG2 0x1fff6008 enables the Intel ME region under the 13-bit .* but not the 15-bit .* undetermined/,
    );
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-me-write')).toBe(false);
  });

  it('refuses to flag a grant when the 15-bit width enables the ME region and the 13-bit one does not', () => {
    // Base 0x1000 with limit 0x2001: 15-bit 0x1000 <= 0x2001; 13-bit 0x1000 > 0x0001.
    const raw = (0x2001 << 16) | 0x1000;
    const result = analyzeSpiDescriptor(withMaster(meGrantedBoth, { regions: [region(0, 0), region(1, 7), raw] }), {
      imageSizeBytes: 0x4000000,
    });
    expect(result.status).toBe('parsed');
    expect(result.hostMasterAccess?.meWriteReason).toMatch(/under the 15-bit .* but not the 13-bit/);
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-me-write')).toBe(false);
  });

  it('refuses to pick a layout when the ME write bit is set under only one', () => {
    // Bit 22 is the ME write bit in the 12-bit layout and a read bit (region 6) in the 8-bit one.
    const result = analyzeSpiDescriptor(withMaster(1 << 22, { regions: withMe }));
    expect(result.hostMasterAccess?.meWrite).toBe('layout-dependent');
    expect(result.hostMasterAccess?.meWriteReason).toMatch(/under pch-12bit only; .* undetermined/);
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-me-write')).toBe(false);
  });

  it('records a denied ME write without a finding', () => {
    const result = analyzeSpiDescriptor(withMaster((0x2 << 24) | (0x3 << 16), { regions: withMe }));
    expect(result.hostMasterAccess?.meWrite).toBe('denied');
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-me-write')).toBe(false);
  });

  it('leaves the ME write unknown when master access is unknown', () => {
    const result = analyzeSpiDescriptor(withMaster(meGrantedBoth, { masterBaseUnits: 0, regions: withMe }));
    expect(result.hostMasterAccess).toMatchObject({ status: 'unknown', meWrite: 'unknown' });
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-me-write')).toBe(false);
  });
});

/**
 * A 12-bit-generation descriptor as chipsec's pch_1xx/skl definitions read it: FLMAP0 has no NR field, so bits
 * 24..26 are 0 and an NR-based reader sees one region. FLREG2 sits at FRBA + 8 regardless.
 */
function withNrZero(flreg2: number, flmstr1: number, { size = 0x10000 } = {}): Buffer {
  const bytes = withMaster(flmstr1, { regions: [region(0, 0)], size });
  bytes.writeUInt32LE(region(1, 7), 0x64);
  bytes.writeUInt32LE(flreg2 >>> 0, 0x68);
  return bytes;
}

describe('analyzeSpiDescriptor — Intel ME region beyond the NR count', () => {
  const meGrantedBoth = (1 << 26) | (1 << 22);

  it('reads FLREG2 beyond NR and reports the ME declaration as layout-dependent, never as undeclared', () => {
    const result = analyzeSpiDescriptor(withNrZero(region(8, 15), meGrantedBoth));
    expect(result.status).toBe('parsed');
    // The NR-based map is kept for the region list.
    expect(result.regions.map((r) => r.name)).toEqual(['Flash Descriptor']);
    expect(result.meRegionBeyondNr).toMatchObject({
      regionCountUnderNr: 1,
      flreg2Offset: 0x68,
      status: 'read',
      rawValue: region(8, 15),
      enabled: true,
      startBytes: 0x8000,
      endBytesExclusive: 0x10000,
    });
    const reason = result.hostMasterAccess?.meWriteReason ?? '';
    expect(reason).toMatch(/FLMAP0 NR covers 1 region under chipsec common.xml/);
    expect(reason).toMatch(/12-bit-generation definitions .* have no NR field/);
    expect(reason).toMatch(/FLREG2 at 0x68 reads enabled at \[0x8000, 0x10000\) there/);
    expect(reason).toMatch(/Intel ME declaration is therefore layout-dependent, so the grant is not flagged/);
    expect(reason).not.toMatch(/declares no Intel ME region/);
    expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-me-write')).toBe(false);
    // Coverage spans the FLREG2 read (0x6c) and FLMSTR1 (0x84).
    expect(result.coverage.parsedEndBytesExclusive).toBe(0x84);
  });

  it('says FLREG2 reads disabled there when it is disabled or chipsec-unused', () => {
    for (const flreg2 of [region(9, 8), 0xffffffff]) {
      const result = analyzeSpiDescriptor(withNrZero(flreg2, meGrantedBoth));
      expect(result.meRegionBeyondNr).toMatchObject({ status: 'read', enabled: false, startBytes: null });
      expect(result.hostMasterAccess?.meWriteReason).toMatch(
        /FLREG2 at 0x68 reads disabled there\. .* layout-dependent/,
      );
      expect(result.findings.some((f) => f.kind === 'spi-descriptor-host-me-write')).toBe(false);
    }
  });

  it('leaves the ME declaration unknown when FLREG2 lies beyond the parse bound', () => {
    // The parse bound ends at the one-region map (0x64), and FLMSTR1 is unreachable too.
    const result = analyzeSpiDescriptor(withNrZero(region(8, 15), meGrantedBoth), { parseLimitBytes: 0x64 });
    expect(result.status).toBe('parsed');
    expect(result.meRegionBeyondNr).toMatchObject({ status: 'unread', rawValue: null, enabled: null });
    expect(result.coverage.parsedEndBytesExclusive).toBe(0x64);
    expect(result.hostMasterAccess?.meWrite).toBe('unknown');
  });

  it('states the unread FLREG2 when the grant is agreed but FLREG2 is out of bounds', () => {
    const access = {
      status: 'read' as const,
      reason: 'r',
      flmstr1Offset: 0x80,
      rawValue: meGrantedBoth,
      layouts: [],
      descriptorWrite: 'denied' as const,
      meWrite: 'granted' as const,
      meWriteReason: 'Granted.',
    };
    const unread = analyzeSpiDescriptor(withNrZero(region(8, 15), meGrantedBoth), { parseLimitBytes: 0x64 });
    const { reason, flag } = assessHostMeWrite(access, unread.regions, unread.meRegionBeyondNr);
    expect(flag).toBe(false);
    expect(reason).toMatch(/FLREG2 at 0x68 lies beyond the available bytes or the parse bound and was not read/);
    expect(reason).toMatch(/Whether the descriptor declares an ME region is unknown/);
    expect(reason).not.toMatch(/declares no Intel ME region/);
    expect(assessHostMeWrite(access, []).reason).toMatch(
      /FLREG2 was not read, so whether the descriptor declares it is unknown/,
    );
  });
});
