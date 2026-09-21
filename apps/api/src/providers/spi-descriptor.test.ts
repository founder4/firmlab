import { describe, expect, it } from 'vitest';
import {
  SPI_DESCRIPTOR_PARSE_CAP_BYTES,
  SPI_DESCRIPTOR_SCAN_CAP_BYTES,
  analyzeSpiDescriptor,
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
