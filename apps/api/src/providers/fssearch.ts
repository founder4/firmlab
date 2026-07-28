/**
 * Content search across an extraction — "which file says this", the question the file browser cannot answer.
 *
 * `fsbrowse` answers "what does this file say" once you already know which file. The other direction is how an
 * analyst actually works: a certificate CN, a hardcoded host, a symbol name, an NVRAM key seen in one provider's
 * evidence, and the question is where else it appears. Without it every cross-reference is a guess.
 *
 * **The bound is the entire design problem, not the matching.** A grep over the GL.iNet's 6497 files is trivially
 * a `for` loop; what is hard is that the loop must decide, for every file, whether to open it — and each of those
 * decisions removes a file from the answer. Skip binaries and a string in `busybox` is invisible. Cap the file
 * size and the 15.7 MB blob is never searched. Stop at 200 hits and the 201st is silently the same as absent.
 * Every one of those makes a SHORT LIST look like a COMPLETE list, which is this codebase's oldest failure mode
 * (`selectFindings`, the NVD page presented as the set, the sweep that spent 94% of its budget on kernel modules).
 *
 * So the result is a `SearchCoverage` first and a hit list second: how many files were opened, how many were
 * skipped and under which rule, and whether the walk or the hit cap cut it short. A caller that reads only
 * `hits` gets a list; a caller that reads the object gets an answer it can trust. `formatCoverage` writes the
 * sentence so the API, the MCP surface and the UI cannot each invent their own wording for the same limits.
 *
 * Binary files are searched too, and that is deliberate: a firmware's most interesting strings live inside ELFs
 * and NVRAM blobs, so refusing to look inside them would answer the question "which TEXT file says this", which
 * is not what anyone asked. What binaries do NOT get is a line number — the match is reported at a byte offset,
 * because "line 4211 of busybox" is a fiction.
 */
import fs from 'node:fs';
import path from 'node:path';

/** Files above this are not opened: the search would dominate the request and the answer would still be partial. */
export const SEARCH_FILE_CAP = 8 * 1024 * 1024;
/** Total bytes read across one search, so a rootfs of many medium files cannot cost more than a few large ones. */
export const SEARCH_BYTE_BUDGET = 256 * 1024 * 1024;
/** Hits returned. Reaching it is reported, never silently truncating. */
export const SEARCH_HIT_CAP = 200;
/** Filesystem entries visited. */
export const SEARCH_WALK_CAP = 40000;
/** Bytes of context either side of a match in the excerpt. */
const CONTEXT = 48;

export interface SearchHit {
  /** Extraction-relative path. */
  path: string;
  /** Byte offset of the match within the file — always meaningful, unlike a line number in a binary. */
  offset: number;
  /** 1-based line number, present only for a file classified as text. */
  line?: number;
  /** The match with surrounding context, control bytes rendered as `.`, bounded. */
  excerpt: string;
  /** True when this file was classified as binary, so the caller can weight the hit. */
  binary: boolean;
}

/** Why a file present in the extraction was never opened. Each is a hole in the answer, counted separately. */
export interface SearchSkips {
  tooLarge: number;
  unreadable: number;
  /** Files not opened because the byte budget was already spent — the answer is partial from here on. */
  budgetExhausted: number;
}

export interface SearchCoverage {
  filesExamined: number;
  bytesRead: number;
  entriesWalked: number;
  skipped: SearchSkips;
  /** The walk stopped before visiting the whole extraction. */
  walkTruncated: boolean;
  /** The hit cap was reached, so matches beyond it exist and are not listed. */
  hitCapReached: boolean;
  /** The byte budget ran out, so files after that point were never opened. */
  budgetSpent: boolean;
}

export interface SearchResult {
  query: string;
  regex: boolean;
  hits: SearchHit[];
  coverage: SearchCoverage;
  /** The sentence stating what this answer does and does not cover. Never omitted, even on a clean full search. */
  verdict: string;
}

/**
 * Pure: the sentence a search result owes. Written here so the route, the MCP payload and the panel cannot drift
 * into three different accounts of the same bound — the coverage banner exists for exactly this reason one layer
 * up, and a search is the same shape of claim.
 */
export function formatCoverage(c: SearchCoverage, hitCount: number, deep = false): string {
  const holes: string[] = [];
  if (c.skipped.tooLarge > 0) {
    const capMb = Math.round((deep ? SEARCH_BYTE_BUDGET : SEARCH_FILE_CAP) / (1024 * 1024));
    holes.push(`${c.skipped.tooLarge} file(s) larger than ${capMb} MB`);
  }
  if (c.skipped.budgetExhausted > 0) holes.push(`${c.skipped.budgetExhausted} file(s) after the read budget ran out`);
  if (c.skipped.unreadable > 0) holes.push(`${c.skipped.unreadable} unreadable file(s)`);

  const parts = [`Searched ${c.filesExamined} file(s) of ${c.entriesWalked} walked; ${hitCount} match(es).`];
  if (holes.length > 0) {
    parts.push(`NOT searched: ${holes.join(', ')} — a term present only in those would not appear above.`);
  }
  if (c.walkTruncated) {
    parts.push(`The ${SEARCH_WALK_CAP}-entry walk bound was reached, so part of the extraction was never visited.`);
  }
  if (c.hitCapReached) {
    parts.push(`The ${SEARCH_HIT_CAP}-hit cap was reached: further matches exist and are not listed.`);
  }
  if (holes.length === 0 && !c.walkTruncated && !c.hitCapReached) {
    parts.push('Every file in the extraction was opened, so this list is complete for this term.');
  } else if (!deep && c.skipped.tooLarge > 0) {
    parts.push('Re-run with deep search to open those too.');
  }
  return parts.join(' ');
}

/** Render bytes as a single-line excerpt: printable ASCII kept, everything else a dot. */
export function excerptAt(buf: Uint8Array, at: number, matchLen: number): string {
  const from = Math.max(0, at - CONTEXT);
  const to = Math.min(buf.length, at + matchLen + CONTEXT);
  let out = '';
  for (let i = from; i < to; i++) {
    const b = buf[i] as number;
    out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
  }
  return (from > 0 ? '…' : '') + out + (to < buf.length ? '…' : '');
}

/**
 * Pure: build the matcher. A literal query is escaped, so a search for `a.out` does not also match `about` — the
 * silent-wrong-answer version of this feature. `regex: true` is opt-in and an invalid pattern is an error the
 * caller sees, never a search that quietly matches nothing.
 */
export function buildMatcher(query: string, regex: boolean): RegExp | { error: string } {
  if (query.length === 0) return { error: 'The search term is empty.' };
  try {
    const source = regex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(source, 'g');
  } catch (e) {
    return { error: `Not a valid regular expression: ${e instanceof Error ? e.message : String(e)}` };
  }
}

/** Count the newlines before `offset`, so a text hit can carry a line number that means something. */
function lineAt(text: string, offset: number): number {
  let n = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

/** A file is treated as binary when a NUL appears in its head — same rule the browser classifies with. */
function looksBinary(buf: Uint8Array): boolean {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

/**
 * Search every file under `root` for `query`. Reads with `latin1` so a byte offset in the decoded string is the
 * byte offset in the file — a UTF-8 decode would shift every offset past the first multi-byte character, which is
 * the sort of quietly-wrong coordinate that sends an analyst to the wrong place in a binary.
 */
export function searchExtraction(
  root: string,
  query: string,
  opts: { regex?: boolean; hitCap?: number; deep?: boolean } = {},
): SearchResult | { error: string } {
  const matcher = buildMatcher(query, opts.regex === true);
  if ('error' in matcher) return matcher;
  const hitCap = opts.hitCap ?? SEARCH_HIT_CAP;
  // `deep` lifts the per-file cap. It exists because the default makes a COMPLETE search impossible on the
  // corpus's richest image: the GL.iNet carve holds 10 files above 8 MB, so every query there — including one
  // that legitimately found nothing — carries a permanent hole. An operator who needs a real negative has to be
  // able to buy one, and the byte budget still bounds the cost.
  const fileCap = opts.deep === true ? SEARCH_BYTE_BUDGET : SEARCH_FILE_CAP;

  const hits: SearchHit[] = [];
  const skipped: SearchSkips = { tooLarge: 0, unreadable: 0, budgetExhausted: 0 };
  let filesExamined = 0;
  let bytesRead = 0;
  let entriesWalked = 0;
  let walkTruncated = false;
  let hitCapReached = false;
  let budgetSpent = false;

  const stack: string[] = [path.resolve(root)];
  while (stack.length > 0) {
    if (entriesWalked >= SEARCH_WALK_CAP) {
      walkTruncated = true;
      break;
    }
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    // Sorted so which files fit under the caps is a fact about the extraction, not about the disk that holds it.
    entries.sort((a, b) => a.name.localeCompare(b.name));
    const subdirs: string[] = [];
    for (const e of entries) {
      if (entriesWalked >= SEARCH_WALK_CAP) {
        walkTruncated = true;
        break;
      }
      entriesWalked++;
      const abs = path.join(dir, e.name);
      // A symlink is never followed: its target either lives inside the extraction and is walked on its own, or
      // lies outside it and does not belong in an answer about this firmware.
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        subdirs.push(abs);
        continue;
      }
      if (!e.isFile()) continue;

      let size = 0;
      try {
        size = fs.statSync(abs).size;
      } catch {
        skipped.unreadable++;
        continue;
      }
      if (size === 0) continue;
      if (size > fileCap) {
        skipped.tooLarge++;
        continue;
      }
      if (bytesRead + size > SEARCH_BYTE_BUDGET) {
        budgetSpent = true;
        skipped.budgetExhausted++;
        continue;
      }

      let buf: Buffer;
      try {
        buf = fs.readFileSync(abs);
      } catch {
        skipped.unreadable++;
        continue;
      }
      filesExamined++;
      bytesRead += buf.length;

      const text = buf.toString('latin1');
      const binary = looksBinary(buf);
      matcher.lastIndex = 0;
      let m: RegExpExecArray | null = matcher.exec(text);
      while (m !== null) {
        if (hits.length >= hitCap) {
          hitCapReached = true;
          break;
        }
        const hit: SearchHit = {
          path: path.relative(root, abs),
          offset: m.index,
          excerpt: excerptAt(buf, m.index, m[0].length).slice(0, 240),
          binary,
        };
        // A line number in a binary is a fiction — the byte offset is the coordinate that means something there.
        if (!binary) hit.line = lineAt(text, m.index);
        hits.push(hit);
        if (m[0].length === 0) matcher.lastIndex++; // a zero-width pattern must not spin forever
        m = matcher.exec(text);
      }
      if (hitCapReached) break;
    }
    if (hitCapReached) break;
    for (let i = subdirs.length - 1; i >= 0; i--) stack.push(subdirs[i] as string);
  }

  const coverage: SearchCoverage = {
    filesExamined,
    bytesRead,
    entriesWalked,
    skipped,
    walkTruncated,
    hitCapReached,
    budgetSpent,
  };
  return {
    query,
    regex: opts.regex === true,
    hits,
    coverage,
    verdict: formatCoverage(coverage, hits.length, opts.deep === true),
  };
}
