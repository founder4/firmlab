import { describe, expect, it } from 'vitest';
import { assessBleCompleteness, assessZigbeeCompleteness, findMissingSequences } from './reassembly-coverage.js';
import type { ZigbeeOtaHeader } from './zigbee-ota.js';

describe('findMissingSequences', () => {
  it('returns empty array when sequences array is empty', () => {
    expect(findMissingSequences([])).toEqual([]);
  });

  it('returns empty array when sequences are contiguous starting at 0', () => {
    expect(findMissingSequences([0, 1, 2, 3, 4])).toEqual([]);
  });

  it('detects missing sequences within the range', () => {
    expect(findMissingSequences([0, 1, 3, 5])).toEqual([2, 4]);
  });

  it('detects missing sequences from 0 when list starts above 0', () => {
    expect(findMissingSequences([2, 3, 4])).toEqual([0, 1]);
  });

  it('handles unordered sequences and duplicates', () => {
    expect(findMissingSequences([3, 0, 1, 1, 4])).toEqual([2]);
  });
});

describe('assessBleCompleteness', () => {
  // Legacy DFU init packet trailer: 4-byte little endian uint32
  const init100 = Uint8Array.from([0x00, 0x00, 100, 0x00, 0x00, 0x00]); // 100 bytes declared

  it('reports complete when received bytes match declared size and no missing sequences', () => {
    const res = assessBleCompleteness(100, init100);
    expect(res.status).toBe('complete');
    expect(res.receivedBytes).toBe(100);
    expect(res.expectedBytes).toBe(100);
    expect(res.missingBytes).toBeUndefined();
    expect(res.missingSequences).toBeUndefined();
  });

  it('reports incomplete with missing bytes when received < declared size', () => {
    const res = assessBleCompleteness(60, init100);
    expect(res.status).toBe('incomplete');
    expect(res.receivedBytes).toBe(60);
    expect(res.expectedBytes).toBe(100);
    expect(res.missingBytes).toBe(40);
    expect(res.missing?.bytes).toBe(40);
    expect(res.reason).toContain('missing 40 bytes');
  });

  it('reports incomplete when reassembled bytes exceed declared size', () => {
    const res = assessBleCompleteness(120, init100);
    expect(res.status).toBe('incomplete');
    expect(res.reason).toContain('exceeds declared size');
  });

  it('reports incomplete when chunk sequences have gaps even if init packet matches size', () => {
    const res = assessBleCompleteness(100, init100, [0, 1, 3]);
    expect(res.status).toBe('incomplete');
    expect(res.missingSequences).toEqual([2]);
    expect(res.missing?.sequences).toEqual([2]);
  });

  it('reports incomplete when chunk sequences have gaps without init packet', () => {
    const res = assessBleCompleteness(50, null, [0, 2]);
    expect(res.status).toBe('incomplete');
    expect(res.expectedBytes).toBeUndefined();
    expect(res.missingSequences).toEqual([1]);
  });

  it('reports unknown expected size when init packet is missing or unparseable and no gaps', () => {
    const res = assessBleCompleteness(50, null);
    expect(res.status).toBe('unknown');
    expect(res.expectedBytes).toBeUndefined();
    expect(res.reason).toContain('Expected size unknown');
  });

  it('reports unknown when init packet is too short to extract size structurally', () => {
    const shortInit = Uint8Array.from([1, 2]);
    const res = assessBleCompleteness(50, shortInit);
    expect(res.status).toBe('unknown');
  });
});

describe('assessZigbeeCompleteness', () => {
  const header: ZigbeeOtaHeader = {
    manufacturerCode: 0x1234,
    imageType: 0x0001,
    fileVersion: 1,
    headerString: 'Test',
    totalImageSize: 500,
    headerLength: 56,
  };

  it('reports complete when received bytes match totalImageSize, upgrade image present, no gaps', () => {
    const res = assessZigbeeCompleteness(500, header, true);
    expect(res.status).toBe('complete');
    expect(res.receivedBytes).toBe(500);
    expect(res.expectedBytes).toBe(500);
    expect(res.missingBytes).toBeUndefined();
  });

  it('reports incomplete when received bytes < totalImageSize (truncated OTA)', () => {
    const res = assessZigbeeCompleteness(350, header, true);
    expect(res.status).toBe('incomplete');
    expect(res.receivedBytes).toBe(350);
    expect(res.expectedBytes).toBe(500);
    expect(res.missingBytes).toBe(150);
    expect(res.missing?.bytes).toBe(150);
    expect(res.reason).toContain('missing 150 bytes');
  });

  it('reports incomplete when block sequences have missing gaps', () => {
    const res = assessZigbeeCompleteness(500, header, true, [0, 1, 3]);
    expect(res.status).toBe('incomplete');
    expect(res.missingSequences).toEqual([2]);
    expect(res.missing?.sequences).toEqual([2]);
  });

  it('reports incomplete when upgrade-image (tag 0x0000) is absent', () => {
    const res = assessZigbeeCompleteness(500, header, false);
    expect(res.status).toBe('incomplete');
    expect(res.reason).toContain('no complete upgrade-image');
  });

  it('reports incomplete when stream is shorter than minimum 56-byte header', () => {
    const res = assessZigbeeCompleteness(30, null, false);
    expect(res.status).toBe('incomplete');
    expect(res.reason).toContain('shorter than minimum 56-byte');
  });

  it('reports unknown when stream has 56+ bytes but missing 0x0BEEF11E magic', () => {
    const res = assessZigbeeCompleteness(100, null, false);
    expect(res.status).toBe('unknown');
    expect(res.reason).toContain('Missing Zigbee OTA header');
  });
});
