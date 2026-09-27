import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { captureRoutes } from '../routes/capture.js';

function buildOta(image: Uint8Array, declaredTotalSize?: number): Uint8Array {
  const HEADER = 56;
  const sub = 6 + image.length;
  const total = declaredTotalSize ?? HEADER + sub;
  const buf = new Uint8Array(HEADER + sub);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0x0beef11e, true);
  dv.setUint16(4, 0x0100, true);
  dv.setUint16(6, HEADER, true);
  dv.setUint16(8, 0, true);
  dv.setUint16(10, 0x1234, true);
  dv.setUint16(12, 0x0001, true);
  dv.setUint32(14, 0x00000003, true);
  dv.setUint16(18, 0x0002, true);
  for (let i = 0; i < 'TestFW'.length; i++) buf[20 + i] = 'TestFW'.charCodeAt(i);
  dv.setUint32(52, total, true);
  dv.setUint16(HEADER, 0x0000, true);
  dv.setUint32(HEADER + 2, image.length, true);
  buf.set(image, HEADER + 6);
  return buf;
}

describe('Capture Wireless Reassembly Routes', () => {
  const app = Fastify();

  beforeAll(async () => {
    process.env.FIRMLAB_CAPTURE = '1';
    await app.register(captureRoutes);
    await app.ready();
  });

  afterAll(async () => {
    // Assigning undefined stores the STRING 'undefined'; delete actually unsets it for the next test file.
    Reflect.deleteProperty(process.env, 'FIRMLAB_CAPTURE');
    await app.close();
  });

  describe('POST /capture/ble/dfu', () => {
    it('stages a complete DFU stream and marks carved when matching init packet size', async () => {
      const sessRes = await app.inject({
        method: 'POST',
        url: '/capture/ble/session',
        payload: { acknowledged: true },
      });
      expect(sessRes.statusCode).toBe(201);
      const { sessionId } = sessRes.json<{ sessionId: string }>();

      // Init packet declares 8 bytes (0x00000008 at the end)
      const initB64 = Buffer.from([0x00, 0x00, 0x08, 0x00, 0x00, 0x00]).toString('base64');
      const chunk1 = Buffer.from([1, 2, 3, 4]).toString('base64');
      const chunk2 = Buffer.from([5, 6, 7, 8]).toString('base64');

      const res = await app.inject({
        method: 'POST',
        url: '/capture/ble/dfu',
        payload: {
          sessionId,
          name: 'ble-complete.bin',
          chunks: [chunk1, chunk2],
          initPacket: initB64,
          chunkSeqs: [0, 1],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{
        flowId: string;
        size: number;
        carved: boolean;
        completeness: { status: string; receivedBytes: number; expectedBytes: number };
      }>();
      expect(body.size).toBe(8);
      expect(body.carved).toBe(true);
      expect(body.completeness.status).toBe('complete');
      expect(body.completeness.receivedBytes).toBe(8);
      expect(body.completeness.expectedBytes).toBe(8);
    });

    it('stages a DFU stream with a chunk-sequence gap as incomplete and carved=false', async () => {
      const sessRes = await app.inject({
        method: 'POST',
        url: '/capture/ble/session',
        payload: { acknowledged: true },
      });
      const { sessionId } = sessRes.json<{ sessionId: string }>();

      // Chunks 0 and 2 arrived; 1 did not. A sequence gap is evidence of missing bytes (an init size is not).
      const chunk1 = Buffer.from([1, 2, 3, 4]).toString('base64');

      const res = await app.inject({
        method: 'POST',
        url: '/capture/ble/dfu',
        payload: {
          sessionId,
          name: 'ble-incomplete.bin',
          chunks: [chunk1, chunk1],
          chunkSeqs: [0, 2],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{
        flowId: string;
        size: number;
        carved: boolean;
        completeness: { status: string; receivedBytes: number; missingSequences: number[] };
      }>();
      expect(body.size).toBe(8);
      expect(body.carved).toBe(false); // Incomplete MUST NOT be marked carved
      expect(body.completeness.status).toBe('incomplete');
      expect(body.completeness.missingSequences).toEqual([1]);
    });

    it('reports status unknown when no init packet is provided', async () => {
      const sessRes = await app.inject({
        method: 'POST',
        url: '/capture/ble/session',
        payload: { acknowledged: true },
      });
      const { sessionId } = sessRes.json<{ sessionId: string }>();

      const chunk = Buffer.from([1, 2, 3]).toString('base64');
      const res = await app.inject({
        method: 'POST',
        url: '/capture/ble/dfu',
        payload: {
          sessionId,
          chunks: [chunk],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{
        flowId: string;
        size: number;
        carved: boolean;
        completeness: { status: string };
      }>();
      expect(body.carved).toBe(true);
      expect(body.completeness.status).toBe('unknown');
    });
  });

  describe('POST /capture/zigbee/ota', () => {
    it('stages a complete Zigbee OTA file and marks carved=true', async () => {
      const sessRes = await app.inject({
        method: 'POST',
        url: '/capture/zigbee/session',
        payload: { acknowledged: true },
      });
      expect(sessRes.statusCode).toBe(201);
      const { sessionId } = sessRes.json<{ sessionId: string }>();

      const img = Uint8Array.from([10, 20, 30, 40]);
      const otaBuf = buildOta(img);
      const blockB64 = Buffer.from(otaBuf).toString('base64');

      const res = await app.inject({
        method: 'POST',
        url: '/capture/zigbee/ota',
        payload: {
          sessionId,
          name: 'zigbee-test.ota',
          blocks: [blockB64],
          blockSeqs: [0],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{
        flowId: string;
        size: number;
        carved: boolean;
        completeness: { status: string; receivedBytes: number; expectedBytes: number };
      }>();
      expect(body.size).toBe(4);
      expect(body.carved).toBe(true);
      expect(body.completeness.status).toBe('complete');
      expect(body.completeness.receivedBytes).toBe(otaBuf.length);
      expect(body.completeness.expectedBytes).toBe(otaBuf.length);
    });

    it('stages a truncated Zigbee OTA file with carved=false and reports missing bytes', async () => {
      const sessRes = await app.inject({
        method: 'POST',
        url: '/capture/zigbee/session',
        payload: { acknowledged: true },
      });
      const { sessionId } = sessRes.json<{ sessionId: string }>();

      const img = Uint8Array.from([10, 20, 30, 40]);
      // Declare totalImageSize as 500, but only provide 66 bytes (56 header + 10 sub-element)
      const otaBuf = buildOta(img, 500);
      const blockB64 = Buffer.from(otaBuf).toString('base64');

      const res = await app.inject({
        method: 'POST',
        url: '/capture/zigbee/ota',
        payload: {
          sessionId,
          blocks: [blockB64],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{
        flowId: string;
        size: number;
        carved: boolean;
        completeness: { status: string; receivedBytes: number; expectedBytes: number; missingBytes: number };
      }>();
      expect(body.carved).toBe(false); // Truncated MUST NOT be marked carved
      expect(body.completeness.status).toBe('incomplete');
      expect(body.completeness.receivedBytes).toBe(otaBuf.length);
      expect(body.completeness.expectedBytes).toBe(500);
      expect(body.completeness.missingBytes).toBe(500 - otaBuf.length);
    });
  });

  it('refuses sequence numbers that are not one non-negative integer per chunk, before staging anything', async () => {
    const sessRes = await app.inject({ method: 'POST', url: '/capture/ble/session', payload: { acknowledged: true } });
    const { sessionId } = sessRes.json<{ sessionId: string }>();
    const chunk = Buffer.from([1, 2]).toString('base64');
    for (const chunkSeqs of [[-1], [0.5], ['x'], [0, 1]]) {
      const res = await app.inject({
        method: 'POST',
        url: '/capture/ble/dfu',
        payload: { sessionId, chunks: [chunk], chunkSeqs },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json<{ error: string }>().error).toContain('chunkSeqs');
    }
  });
});
