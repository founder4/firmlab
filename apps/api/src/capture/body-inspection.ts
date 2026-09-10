/**
 * Bounded body reads for the capture lane. A captured OTA may be much larger than the amount it is safe to hold
 * in the API process, so scoring reads a prefix and carries the exact coverage beside the score. The file itself
 * stays intact on disk and remains ingestable when that bounded score identifies it as a candidate.
 */
import fs from 'node:fs';

export const CAPTURE_BODY_READ_CAP = 64 * 1024 * 1024;

export interface CapturedBodyInspection {
  body: Uint8Array;
  /** Exact size of the captured body on disk, or null when no body was retained/readable. */
  bodyBytes: number | null;
  /** Bytes supplied to scoreFirmwareFlow. */
  bodyBytesInspected: number;
  /** Whether every captured body byte was supplied to the scorer. */
  bodyInspectionComplete: boolean;
}

/** Read at most `cap` bytes without ever allocating from an untrusted Content-Length header. */
export function readCapturedBodyBounded(filePath: string, cap = CAPTURE_BODY_READ_CAP): CapturedBodyInspection {
  let fd: number | null = null;
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) throw new Error('capture body is not a regular file');
    const limit = Math.min(stat.size, Math.max(0, cap));
    const body = Buffer.allocUnsafe(limit);
    fd = fs.openSync(filePath, 'r');
    let offset = 0;
    while (offset < limit) {
      const read = fs.readSync(fd, body, offset, limit - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    const inspected = offset === limit ? body : body.subarray(0, offset);
    return {
      body: inspected,
      bodyBytes: stat.size,
      bodyBytesInspected: offset,
      bodyInspectionComplete: offset === stat.size,
    };
  } catch {
    return { body: new Uint8Array(0), bodyBytes: null, bodyBytesInspected: 0, bodyInspectionComplete: false };
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}
