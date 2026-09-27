/**
 * Transport-level wireless capture input decoding utilities.
 * Handles decoding uploaded files (JSON, base64/hex lines, or binary blobs)
 * into standardized base64 chunks/blocks for API transmission.
 * Analysis and completeness verification are exclusively performed by the backend.
 */

export function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  const CHUNK_SIZE = 0x8000;
  for (let i = 0; i < len; i += CHUNK_SIZE) {
    const sub = bytes.subarray(i, Math.min(i + CHUNK_SIZE, len));
    binary += String.fromCharCode(...sub);
  }
  return btoa(binary);
}

export function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function hexToUint8(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error('Invalid hex string length');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = Number.parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

export interface ParsedCaptureInput {
  name?: string | undefined;
  base64Items: string[];
  initPacketBase64?: string | undefined;
  sequences?: number[] | undefined;
  error?: string | undefined;
}

/**
 * Pure: parse uploaded content (JSON, text lines of base64/hex, or binary) into base64 items for API staging.
 * Does NOT perform domain completeness or format verification.
 */
export function parseCapturePayload(content: string | Uint8Array, filename: string): ParsedCaptureInput {
  if (content instanceof Uint8Array) {
    const b64 = uint8ToBase64(content);
    return {
      name: filename,
      base64Items: [b64],
    };
  }

  const text = content.trim();
  if (!text) {
    return {
      base64Items: [],
      error: 'Empty capture file',
    };
  }

  // Case 1: JSON payload
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      const parsed = JSON.parse(text);
      const name =
        typeof parsed === 'object' && parsed !== null && 'name' in parsed && typeof parsed.name === 'string'
          ? parsed.name
          : filename.replace(/\.json$/i, '.bin');

      let rawItems: unknown[] = [];
      if (Array.isArray(parsed)) {
        rawItems = parsed;
      } else if (parsed && typeof parsed === 'object') {
        if (Array.isArray(parsed.chunks)) rawItems = parsed.chunks;
        else if (Array.isArray(parsed.blocks)) rawItems = parsed.blocks;
        else if (Array.isArray(parsed.data)) rawItems = parsed.data;
      }

      const sequences: number[] = [];
      const base64Items: string[] = [];

      for (let i = 0; i < rawItems.length; i++) {
        const item = rawItems[i];
        if (typeof item === 'string') {
          base64Items.push(item.trim());
        } else if (item && typeof item === 'object') {
          const obj = item as Record<string, unknown>;
          if (typeof obj.seq === 'number') sequences.push(obj.seq);
          else if (typeof obj.index === 'number') sequences.push(obj.index);

          const payload = typeof obj.data === 'string' ? obj.data : typeof obj.chunk === 'string' ? obj.chunk : null;
          if (payload) {
            base64Items.push(payload.trim());
          }
        }
      }

      let initPacketBase64: string | undefined;
      if (parsed && typeof parsed === 'object' && 'initPacket' in parsed && typeof parsed.initPacket === 'string') {
        initPacketBase64 = parsed.initPacket.trim();
      }

      return {
        name,
        base64Items,
        initPacketBase64,
        sequences: sequences.length > 0 ? sequences : undefined,
      };
    } catch (e) {
      return {
        base64Items: [],
        error: `Invalid JSON capture: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  }

  // Case 2: Line-delimited base64 or hex
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));
  const base64Items: string[] = [];

  for (const line of lines) {
    if (/^[0-9a-fA-F]+$/.test(line) && line.length % 2 === 0) {
      const u8 = hexToUint8(line);
      base64Items.push(uint8ToBase64(u8));
    } else {
      try {
        // Validate base64 string
        base64ToUint8(line);
        base64Items.push(line);
      } catch {
        return {
          base64Items: [],
          error: `Unrecognized line format: ${line.slice(0, 32)}…`,
        };
      }
    }
  }

  return {
    name: filename.replace(/\.(txt|log|hex)$/i, '.bin'),
    base64Items,
  };
}
