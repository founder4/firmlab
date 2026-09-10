/**
 * Recover Linux's builtin compressed symbol-name table from a decompressed kernel image.
 *
 * This is a TypeScript port of the self-anchoring algorithm in nmatt0/mithril (MIT): locate the 256-entry token
 * index by its geometry, recover the NUL-terminated token table immediately before it, then cross-check either the
 * address-array/count anchor or the kallsyms markers before accepting names. Every structural check fails closed;
 * a missing result says only that this decoder could not recover a table.
 */

export interface DecodedKallsyms {
  /** Bare names with the leading kallsyms type character removed. */
  names: Set<string>;
  /** Number of encoded symbol rows (names may theoretically repeat). */
  symbolCount: number;
  /** Number of distinct bare names retained in `names`. */
  uniqueNameCount: number;
  /** Kernel word width selected by the validated table geometry. */
  wordBytes: 4 | 8;
  /** A successful result always consumed exactly the declared table. */
  complete: true;
}

interface TokenTables {
  tableStart: number;
  indexStart: number;
  index: number[];
}

interface DecodedSymbol {
  next: number;
  name: string;
}

interface Markers {
  namesEnd: number;
  firstSpan: bigint;
  count: number;
}

const CORE_SYMBOLS = ['commit_creds', 'prepare_kernel_cred', 'do_exit', 'kmalloc'];

function isIdentifierByte(byte: number): boolean {
  return (
    (byte >= 0x61 && byte <= 0x7a) ||
    (byte >= 0x41 && byte <= 0x5a) ||
    (byte >= 0x30 && byte <= 0x39) ||
    byte === 0x5f ||
    byte === 0x2e ||
    byte === 0x24
  );
}

function read16(data: Uint8Array, offset: number): number {
  return (data[offset] as number) | ((data[offset + 1] as number) << 8);
}

function readWord(data: Uint8Array, offset: number, wordBytes: 4 | 8): bigint {
  let value = 0n;
  for (let i = 0; i < wordBytes; i++) value |= BigInt(data[offset + i] as number) << BigInt(8 * i);
  return value;
}

function tryTokenTables(data: Uint8Array, indexStart: number): TokenTables | null {
  if (indexStart < 2 || indexStart + 512 > data.length) return null;
  const index: number[] = [];
  let previous = 0;
  for (let i = 0; i < 256; i++) {
    const value = read16(data, indexStart + i * 2);
    if ((i === 0 && value !== 0) || (i > 0 && (value <= previous || value - previous > 64))) return null;
    index.push(value);
    previous = value;
  }
  if (data[indexStart - 1] !== 0) return null;

  let tableStart = -1;
  const last = index[255] as number;
  for (let length = last + 2; length <= last + 66 && length <= indexStart; length++) {
    const candidate = indexStart - length;
    let valid = data[candidate] !== 0;
    for (let i = 1; i < 256 && valid; i++) {
      if (data[candidate + (index[i] as number) - 1] !== 0) valid = false;
    }
    if (valid) {
      tableStart = candidate;
      break;
    }
  }
  if (tableStart < 0) return null;
  const tableLength = indexStart - tableStart;
  if (index.some((offset) => offset >= tableLength)) return null;
  return { tableStart, indexStart, index };
}

function decodeSymbol(data: Uint8Array, tokens: TokenTables, position: number): DecodedSymbol | null {
  if (position >= data.length) return null;
  let cursor = position;
  let length = data[cursor++] as number;
  if (length & 0x80) {
    if (cursor >= data.length) return null;
    length = (length & 0x7f) | ((data[cursor++] as number) << 7);
  }
  if (length === 0 || length > 256 || cursor + length > data.length) return null;

  const expanded: number[] = [];
  const tableEnd = tokens.indexStart;
  for (let i = 0; i < length; i++) {
    const tokenIndex = data[cursor + i] as number;
    let tokenOffset = tokens.tableStart + (tokens.index[tokenIndex] as number);
    while (tokenOffset < tableEnd && data[tokenOffset] !== 0) expanded.push(data[tokenOffset++] as number);
  }
  cursor += length;
  if (expanded.length < 2) return null;
  const nameBytes = expanded.slice(1);
  if (nameBytes.some((byte) => !isIdentifierByte(byte))) return null;
  return { next: cursor, name: String.fromCharCode(...nameBytes) };
}

function hasCoreSymbol(names: ReadonlySet<string>): boolean {
  return CORE_SYMBOLS.some((symbol) => names.has(symbol));
}

function decodeDeclaredNames(
  data: Uint8Array,
  tokens: TokenTables,
  namesStart: number,
  symbolCount: number,
): { names: Set<string>; end: number } | null {
  const names = new Set<string>();
  let position = namesStart;
  for (let i = 0; i < symbolCount; i++) {
    const decoded = decodeSymbol(data, tokens, position);
    if (!decoded || decoded.next > tokens.tableStart) return null;
    names.add(decoded.name);
    position = decoded.next;
  }
  return { names, end: position };
}

function findAbsoluteAnchor(
  data: Uint8Array,
  tokens: TokenTables,
  wordBytes: 4 | 8,
): { names: Set<string>; symbolCount: number } | null {
  const highBit = 1n << BigInt(wordBytes * 8 - 1);
  let runStart = 0;
  let previous = 0n;
  let inRun = false;
  for (let offset = 0; offset + wordBytes <= tokens.tableStart; offset += wordBytes) {
    const value = readWord(data, offset, wordBytes);
    const address = (value & highBit) !== 0n;
    if (address && (!inRun || value >= previous)) {
      if (!inRun) runStart = offset;
      inRun = true;
      previous = value;
      continue;
    }
    if (inRun) {
      const runLength = (offset - runStart) / wordBytes;
      if (runLength >= 2000 && runLength <= 500000) {
        for (
          let countAt = offset;
          countAt + wordBytes <= tokens.tableStart && countAt <= offset + 8 * wordBytes;
          countAt += wordBytes
        ) {
          if (readWord(data, countAt, wordBytes) !== BigInt(runLength)) continue;
          let namesStart = countAt + wordBytes;
          while (namesStart < tokens.tableStart && data[namesStart] === 0 && namesStart < countAt + wordBytes + 32)
            namesStart++;
          if (namesStart >= tokens.tableStart || data[namesStart] === 0) break;
          const decoded = decodeDeclaredNames(data, tokens, namesStart, runLength);
          if (decoded && hasCoreSymbol(decoded.names)) return { names: decoded.names, symbolCount: runLength };
          break;
        }
      }
    }
    inRun = address;
    if (address) {
      runStart = offset;
      previous = value;
    }
  }
  return null;
}

function findMarkers(data: Uint8Array, tableStart: number, wordBytes: 4 | 8): Markers | null {
  if (tableStart < 64) return null;
  const lower = tableStart > 16 * 1024 * 1024 ? tableStart - 16 * 1024 * 1024 : 0;
  for (let start = tableStart - wordBytes; start >= lower + wordBytes; start -= wordBytes) {
    if (readWord(data, start, wordBytes) !== 0n) continue;
    let cursor = start;
    let previous = 0n;
    let count = 0;
    let first = true;
    while (cursor + wordBytes <= tableStart) {
      const value = readWord(data, cursor, wordBytes);
      if (!first && (value <= previous || value > 64n * 1024n * 1024n)) break;
      first = false;
      previous = value;
      count++;
      cursor += wordBytes;
    }
    if (count >= 2 && tableStart - cursor < 2 * wordBytes) {
      return { namesEnd: start, firstSpan: readWord(data, start + wordBytes, wordBytes), count };
    }
  }
  return null;
}

function decodeFromMarkers(
  data: Uint8Array,
  tokens: TokenTables,
  wordBytes: 4 | 8,
): { names: Set<string>; symbolCount: number } | null {
  const markers = findMarkers(data, tokens.tableStart, wordBytes);
  if (!markers || markers.firstSpan < 64n) return null;
  const padding = 2 * wordBytes;
  const windowLower = Math.max(wordBytes, markers.namesEnd - 8 * 1024 * 1024);
  const minimumSymbols = Math.max(0, (markers.count - 2) * 256);
  const maximumSymbols = (markers.count + 1) * 256;

  for (let start = markers.namesEnd - wordBytes; start >= windowLower; start -= wordBytes) {
    const first = decodeSymbol(data, tokens, start);
    if (!first || first.next > markers.namesEnd) continue;
    const declaredBig = readWord(data, start - wordBytes, wordBytes);
    if (declaredBig > 500000n) continue;
    const declared = Number(declaredBig);
    if (declared < 500 || declared <= minimumSymbols || declared > maximumSymbols) continue;

    let position = start;
    let valid = true;
    for (let i = 0; i < 256; i++) {
      const decoded = decodeSymbol(data, tokens, position);
      if (!decoded || decoded.next > markers.namesEnd) {
        valid = false;
        break;
      }
      position = decoded.next;
    }
    if (!valid || BigInt(position - start) !== markers.firstSpan) continue;

    position = start;
    let count = 0;
    while (position < markers.namesEnd) {
      if (
        markers.namesEnd - position <= padding &&
        position + wordBytes <= data.length &&
        readWord(data, position, wordBytes) === 0n
      )
        break;
      const decoded = decodeSymbol(data, tokens, position);
      if (!decoded || decoded.next > markers.namesEnd || ++count > declared) {
        valid = false;
        break;
      }
      position = decoded.next;
    }
    if (!valid || count !== declared || markers.namesEnd - position > padding) continue;
    const decoded = decodeDeclaredNames(data, tokens, start, count);
    if (decoded && hasCoreSymbol(decoded.names)) return { names: decoded.names, symbolCount: count };
  }
  return null;
}

/** Best-effort decode. Null means no fully self-consistent table was recovered; it is never an absence verdict. */
export function decodeKallsyms(data: Uint8Array): DecodedKallsyms | null {
  if (data.length < 4096) return null;
  for (let indexStart = 0; indexStart + 512 <= data.length; indexStart += 2) {
    if (data[indexStart] !== 0 || data[indexStart + 1] !== 0) continue;
    if (data[indexStart + 2] === 0 && data[indexStart + 3] === 0) continue;
    const tokens = tryTokenTables(data, indexStart);
    if (!tokens) continue;
    for (const wordBytes of [4, 8] as const) {
      const decoded = findAbsoluteAnchor(data, tokens, wordBytes) ?? decodeFromMarkers(data, tokens, wordBytes);
      if (decoded) return { ...decoded, uniqueNameCount: decoded.names.size, wordBytes, complete: true };
    }
  }
  return null;
}
