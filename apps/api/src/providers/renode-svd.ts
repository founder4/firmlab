/**
 * Locally provisioned register descriptions (SVD) for Renode platforms — used when, and only when, they verify.
 *
 * Several bundled platform descriptions apply an SVD over HTTPS on load (`ApplySVD @https://dl.antmicro.com/…`).
 * Every Renode process runs under `OFFLINE_RENODE_ENV`, so that download is refused and the run uses the platform
 * without it (see `renode.ts`). An operator may instead provision those files ahead of time with
 * `scripts/renode-svd-provision.mjs`, which stores the bytes and a manifest (url, sha256, size, fetchedAt,
 * referencedBy) under `$FIRMLAB_DATA_DIR/renode-svd/`. This module is the run-time half, and it never fetches:
 *
 *  - It walks the selected platform's include chain under the same rule the remote-resource scan uses, finds every
 *    `ApplySVD @http(s)://…`, and decides each URL against the manifest: `local` only when an entry exists, its file
 *    lies inside the SVD directory, and the file's sha256 is the one the manifest records; otherwise `missing`,
 *    `mismatch`, or `unusable` — and those keep today's behaviour exactly: the URL stays in the platform, Renode's
 *    attempt is refused offline, and the result names it.
 *  - For the `local` ones it writes a COPY of every chain file that has to change — the file holding the `ApplySVD`
 *    and each file on the include path above it — into the run's own work directory, with the URL replaced by a
 *    copy of the verified bytes in that same directory (so what Renode loads is what was hashed, not whatever the
 *    data directory holds a moment later) and every `using` rewritten to an absolute path, since a moved file can no
 *    longer resolve `./x` against its old directory. The bundled platforms are never edited.
 *
 * What it refuses to claim. A manifest sha256 pins the bytes the operator accepted at provisioning time; nothing
 * upstream publishes a digest for most of these files, so `local` means "the provisioned bytes, unaltered", not
 * "authentic". And `local` is about a reference in the chain, not about what Renode applied: a file that redefines
 * `sysbus: init:` replaces the init block of the file it includes, so an SVD referenced by an included file may be
 * served locally and still not be applied (measured on `cpus/stm32f429.repl`, which includes `stm32f4.repl`: Renode
 * applies only the F429x SVD). That is the same scope the refused-resource list has always had.
 *
 * Pure parsing/rewriting/decision functions are exported for the tests; the I/O is confined to reading the manifest,
 * hashing, and writing into the caller's work directory. No store import, so vitest can reach all of it.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** Subdirectory of the data root that holds the provisioned SVD files and their manifest. */
export const RENODE_SVD_DIRNAME = 'renode-svd';
export const RENODE_SVD_MANIFEST = 'manifest.json';
export const RENODE_SVD_MANIFEST_VERSION = 1;
/** Largest SVD the run time will hash and copy; matches the provisioning script's cap. */
export const RENODE_SVD_MAX_BYTES = 64 * 1024 * 1024;

/** Where the provisioned SVDs live: `<FIRMLAB_DATA_DIR or ./data>/renode-svd`, the same data-root rule as `paths.ts`. */
export function renodeSvdDir(env: NodeJS.ProcessEnv = process.env): string {
  const root = env.FIRMLAB_DATA_DIR ? path.resolve(env.FIRMLAB_DATA_DIR) : path.resolve(process.cwd(), 'data');
  return path.join(root, RENODE_SVD_DIRNAME);
}

// --- parsing & rewriting (pure) ------------------------------------------------------------------------------------

/**
 * Comments blanked to spaces with every offset and newline preserved, under the rule `stripReplComments` uses:
 * `/* … *\/` blocks and whole-line `//` comments. Matching against the mask and editing the original keeps a
 * commented-out `ApplySVD` from ever being rewritten or counted.
 */
export function maskReplComments(text: string): string {
  const blank = (s: string): string => s.replace(/[^\n]/g, ' ');
  return text.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/^[ \t]*\/\/.*$/gm, blank);
}

export interface ApplySvdRef {
  url: string;
  /** Offsets of the URL itself (after the `@`) in the ORIGINAL text. */
  start: number;
  end: number;
  /** 1-based line number, for messages. */
  line: number;
}

/** Pure: every `ApplySVD @http(s)://…` in a .repl/.resc text, in order, comments excluded. */
export function parseApplySvdRefs(text: string): ApplySvdRef[] {
  const out: ApplySvdRef[] = [];
  for (const m of maskReplComments(text).matchAll(/\bApplySVD[ \t]+@(https?:\/\/[^\s"'`;]+)/g)) {
    const url = m[1];
    if (!url || m.index === undefined) continue;
    const start = m.index + m[0].length - url.length;
    out.push({ url, start, end: start + url.length, line: text.slice(0, start).split('\n').length });
  }
  return out;
}

export interface UsingRef {
  /** The quoted include target exactly as written. */
  raw: string;
  /** Offsets of the quoted content (inside the quotes) in the ORIGINAL text. */
  start: number;
  end: number;
  /** Absolute path, resolved by the rule the scans use: `./x` against the file's directory, else the Renode root. */
  resolved: string;
}

/** Pure: the `using "…"` includes of one platform file, resolved the way `scanRemoteResources` resolves them. */
export function parseUsingRefs(text: string, filePath: string, renodeRoot: string): UsingRef[] {
  const out: UsingRef[] = [];
  for (const m of maskReplComments(text).matchAll(/^([ \t]*using[ \t]+")([^"]+)"/gm)) {
    const raw = m[2];
    const lead = m[1];
    if (!raw || lead === undefined || m.index === undefined) continue;
    const start = m.index + lead.length;
    const inc = raw.endsWith('.repl') ? raw : `${raw}.repl`;
    const resolved = inc.startsWith('.') ? path.resolve(path.dirname(filePath), inc) : path.resolve(renodeRoot, inc);
    out.push({ raw, start, end: start + raw.length, resolved });
  }
  return out;
}

/** Pure: apply non-overlapping `[start, end) → text` edits to a string (order-independent). */
export function applyEdits(text: string, edits: ReadonlyArray<{ start: number; end: number; text: string }>): string {
  let out = text;
  for (const e of [...edits].sort((a, b) => b.start - a.start)) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

/**
 * Pure: the text with each `ApplySVD @<url>` whose URL is in `local` pointed at the local path instead, and each
 * `using` target replaced by `usingTarget(ref)` when that returns a path. Anything not named stays byte-identical.
 */
export function rewritePlatformText(
  text: string,
  local: ReadonlyMap<string, string>,
  usingRefs: readonly UsingRef[] = [],
  usingTarget: (ref: UsingRef) => string | null = () => null,
): { text: string; rewritten: string[] } {
  const edits: { start: number; end: number; text: string }[] = [];
  const rewritten: string[] = [];
  for (const ref of parseApplySvdRefs(text)) {
    const to = local.get(ref.url);
    if (to === undefined) continue;
    edits.push({ start: ref.start, end: ref.end, text: to });
    rewritten.push(ref.url);
  }
  for (const ref of usingRefs) {
    const to = usingTarget(ref);
    if (to !== null) edits.push({ start: ref.start, end: ref.end, text: to });
  }
  return { text: applyEdits(text, edits), rewritten };
}

// --- manifest & decision (pure) ------------------------------------------------------------------------------------

export interface SvdManifestEntry {
  url: string;
  /** File name inside the SVD directory (a bare name — a path is refused). */
  file: string;
  sha256: string;
  size?: number;
  fetchedAt?: string;
  referencedBy?: string[];
}

export interface SvdManifest {
  version: number;
  entries: SvdManifestEntry[];
}

/**
 * Pure: a manifest from its JSON text, keeping only well-formed entries. A missing, unparsable or wrong-version
 * manifest is `null`, which makes every SVD `missing` — the same as never having provisioned.
 */
export function parseSvdManifest(json: string): SvdManifest | null {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;
  const m = raw as { version?: unknown; entries?: unknown };
  if (m.version !== RENODE_SVD_MANIFEST_VERSION || !Array.isArray(m.entries)) return null;
  const entries: SvdManifestEntry[] = [];
  for (const e of m.entries as unknown[]) {
    if (!e || typeof e !== 'object') continue;
    const x = e as Record<string, unknown>;
    if (typeof x.url !== 'string' || typeof x.file !== 'string' || typeof x.sha256 !== 'string') continue;
    if (!/^[0-9a-f]{64}$/.test(x.sha256)) continue;
    const entry: SvdManifestEntry = { url: x.url, file: x.file, sha256: x.sha256 };
    if (typeof x.size === 'number') entry.size = x.size;
    if (typeof x.fetchedAt === 'string') entry.fetchedAt = x.fetchedAt;
    if (Array.isArray(x.referencedBy)) entry.referencedBy = x.referencedBy.filter((r) => typeof r === 'string');
    entries.push(entry);
  }
  return { version: m.version, entries };
}

/** True when a manifest `file` is a bare, safe file name — never a path, never hidden, never `..`. */
export function isSafeSvdFileName(file: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(file) && !file.includes('..');
}

export type SvdLocalStatus = 'local' | 'missing' | 'mismatch' | 'unusable';

/**
 * How one remote SVD reference was served in a run. Persisted on the run result, so every field past `url` and
 * `status` is optional forever.
 */
export interface SvdResolution {
  url: string;
  /**
   * `local` — the verified provisioned copy was used, nothing was requested. `missing` — not provisioned (no
   * manifest, no entry, or the file is gone). `mismatch` — provisioned but the file no longer hashes to the
   * manifest's sha256. `unusable` — provisioned but could not be used (unsafe file name, too large, or a work path
   * Renode cannot take unquoted). Every status but `local` leaves the URL in place, refused offline as before.
   */
  status: SvdLocalStatus;
  reason?: string;
  /** The manifest's sha256 (when an entry exists). */
  expectedSha256?: string;
  /** What the provisioned file hashed to in this run (when it was read). */
  observedSha256?: string;
}

/** What the run observed about the provisioned file: null when absent/unreadable. */
export interface ObservedSvdFile {
  sha256: string;
  size: number;
}

/**
 * Pure: decide one URL. `local` requires all three — an entry, a safe file name, and an observed sha256 equal to
 * the recorded one. Never upgrades on partial evidence: an entry whose file cannot be read is `missing`, not trusted.
 */
export function decideSvd(
  url: string,
  entry: SvdManifestEntry | undefined,
  observed: ObservedSvdFile | null,
  maxBytes = RENODE_SVD_MAX_BYTES,
): SvdResolution {
  if (!entry) return { url, status: 'missing', reason: 'not provisioned (no manifest entry for this URL)' };
  const expectedSha256 = entry.sha256;
  if (!isSafeSvdFileName(entry.file)) {
    return {
      url,
      status: 'unusable',
      reason: `manifest file name is not a bare file name (${entry.file})`,
      expectedSha256,
    };
  }
  if (!observed) {
    return {
      url,
      status: 'missing',
      reason: `manifest names ${entry.file}, which is absent or unreadable`,
      expectedSha256,
    };
  }
  if (observed.size > maxBytes) {
    return {
      url,
      status: 'unusable',
      reason: `${entry.file} is ${observed.size} bytes (cap ${maxBytes})`,
      expectedSha256,
    };
  }
  if (observed.sha256 !== expectedSha256) {
    return {
      url,
      status: 'mismatch',
      reason: `${entry.file} hashes to ${observed.sha256}, not the manifest's ${expectedSha256}`,
      expectedSha256,
      observedSha256: observed.sha256,
    };
  }
  return { url, status: 'local', expectedSha256, observedSha256: observed.sha256 };
}

/** Pure: true when Renode can take `p` as an unquoted `@path` / inside a `using "…"` — no whitespace or quotes. */
export function isRenodeSafePath(p: string): boolean {
  return !/[\s"'`;]/.test(p);
}

// --- the overlay (reads the chain and the SVD dir; writes only into the run's work dir) ---------------------------

export interface SvdOverlay {
  /** The platform to load: the rewritten copy when anything was served locally, else the original path. */
  platformPath: string;
  /** One row per distinct remote `ApplySVD` URL found in the chain, in first-seen order. */
  resolutions: SvdResolution[];
  /** URLs actually rewritten to a local copy (a subset of the `local` resolutions' URLs). */
  servedLocally: string[];
}

interface ChainFile {
  abs: string;
  text: string;
  svd: ApplySvdRef[];
  usings: UsingRef[];
}

/** Read the include chain the scans read — inside `renodeRoot` only, cycles stopped, depth and file count bounded. */
function readChain(
  platformPath: string,
  renodeRoot: string,
  maxDepth: number,
  maxFiles: number,
): Map<string, ChainFile> {
  const root = path.resolve(renodeRoot);
  const files = new Map<string, ChainFile>();
  const seen = new Set<string>();
  const within = (p: string): boolean => {
    const rel = path.relative(root, p);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  };
  const visit = (file: string, depth: number): void => {
    const abs = path.resolve(file);
    if (seen.has(abs) || !within(abs) || depth > maxDepth || files.size >= maxFiles) return;
    seen.add(abs);
    let text: string;
    try {
      text = fs.readFileSync(abs, 'utf8');
    } catch {
      return;
    }
    const usings = parseUsingRefs(text, abs, root);
    files.set(abs, { abs, text, svd: parseApplySvdRefs(text), usings });
    for (const u of usings) visit(u.resolved, depth + 1);
  };
  visit(platformPath, 0);
  return files;
}

function hashFile(file: string, maxBytes: number): { observed: ObservedSvdFile | null; bytes: Buffer | null } {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return { observed: null, bytes: null };
    if (st.size > maxBytes) return { observed: { sha256: '', size: st.size }, bytes: null };
    const bytes = fs.readFileSync(file);
    return { observed: { sha256: crypto.createHash('sha256').update(bytes).digest('hex'), size: bytes.length }, bytes };
  } catch {
    return { observed: null, bytes: null };
  }
}

/**
 * Prepare the platform a run should load. Reads the chain and the manifest, hashes each provisioned file it needs,
 * and — only for URLs that verify — writes the verified bytes and the rewritten chain copies under
 * `<workDir>/svd-overlay/`. With nothing local (no manifest, nothing provisioned, a mismatch, a chain with no SVD),
 * it writes nothing and returns the original platform path, which is exactly today's behaviour. Never fetches.
 */
export function prepareSvdOverlay(
  platformPath: string,
  renodeRoot: string,
  workDir: string,
  opts: { svdDir?: string; maxDepth?: number; maxFiles?: number; maxBytes?: number } = {},
): SvdOverlay {
  const svdDir = opts.svdDir ?? renodeSvdDir();
  const maxBytes = opts.maxBytes ?? RENODE_SVD_MAX_BYTES;
  const chain = readChain(platformPath, renodeRoot, opts.maxDepth ?? 12, opts.maxFiles ?? 64);

  const urls: string[] = [];
  for (const f of chain.values()) for (const r of f.svd) if (!urls.includes(r.url)) urls.push(r.url);
  if (urls.length === 0) return { platformPath, resolutions: [], servedLocally: [] };

  let manifest: SvdManifest | null = null;
  try {
    manifest = parseSvdManifest(fs.readFileSync(path.join(svdDir, RENODE_SVD_MANIFEST), 'utf8'));
  } catch {
    manifest = null;
  }
  const byUrl = new Map((manifest?.entries ?? []).map((e) => [e.url, e]));

  const overlayDir = path.join(workDir, 'svd-overlay');
  const pathsOk = isRenodeSafePath(overlayDir);
  const local = new Map<string, string>();
  const resolutions: SvdResolution[] = [];
  for (const url of urls) {
    const entry = byUrl.get(url);
    const read = entry && isSafeSvdFileName(entry.file) ? hashFile(path.join(svdDir, entry.file), maxBytes) : null;
    let res = decideSvd(url, entry, read?.observed ?? null, maxBytes);
    if (res.status === 'local' && !pathsOk) {
      res = {
        ...res,
        status: 'unusable',
        reason: `the run's work path cannot be passed to Renode unquoted (${overlayDir})`,
      };
    }
    if (res.status === 'local' && entry && read?.bytes) {
      fs.mkdirSync(overlayDir, { recursive: true });
      const dest = path.join(overlayDir, `svd-${local.size}-${entry.file}`);
      fs.writeFileSync(dest, read.bytes);
      local.set(url, dest);
    }
    resolutions.push(res);
  }
  if (local.size === 0) return { platformPath, resolutions, servedLocally: [] };

  // Which chain files must be copied: those that hold a rewritten ApplySVD, and every file that includes one of them.
  const needs = new Map<string, boolean>();
  const mustCopy = (abs: string, stack: Set<string>): boolean => {
    const known = needs.get(abs);
    if (known !== undefined) return known;
    const f = chain.get(abs);
    if (!f || stack.has(abs)) return false;
    stack.add(abs);
    let r = f.svd.some((s) => local.has(s.url));
    for (const u of f.usings) if (mustCopy(u.resolved, stack)) r = true;
    stack.delete(abs);
    needs.set(abs, r);
    return r;
  };
  const top = path.resolve(platformPath);
  // `local` is a claim that the run used the copy, so a URL that ends up not rewritten must not keep it.
  const settle = (served: ReadonlySet<string>): SvdResolution[] =>
    resolutions.map((r) =>
      r.status === 'local' && !served.has(r.url)
        ? { ...r, status: 'unusable', reason: 'verified, but no rewritten copy of the include chain carried it' }
        : r,
    );
  if (!mustCopy(top, new Set())) return { platformPath, resolutions: settle(new Set()), servedLocally: [] };

  const copyName = new Map<string, string>();
  let i = 0;
  for (const [abs, need] of needs) {
    if (need) copyName.set(abs, path.join(overlayDir, `${i++}-${path.basename(abs)}`));
  }
  // A moved file can no longer resolve `./x`, so every include of a copy becomes absolute. If any of those targets
  // cannot be written unquoted, the copy would not load: give up on the overlay and keep today's behaviour.
  const target = (u: UsingRef): string => copyName.get(u.resolved) ?? u.resolved;
  for (const abs of copyName.keys()) {
    const bad = chain.get(abs)?.usings.find((u) => !isRenodeSafePath(target(u)));
    if (bad) {
      const reason = `an include of the rewritten platform cannot be passed to Renode unquoted (${target(bad)})`;
      return {
        platformPath,
        resolutions: resolutions.map((r) => (r.status === 'local' ? { ...r, status: 'unusable', reason } : r)),
        servedLocally: [],
      };
    }
  }
  const served = new Set<string>();
  for (const [abs, dest] of copyName) {
    const f = chain.get(abs);
    if (!f) continue;
    const { text, rewritten } = rewritePlatformText(f.text, local, f.usings, target);
    for (const u of rewritten) served.add(u);
    fs.writeFileSync(dest, text);
  }
  return { platformPath: copyName.get(top) ?? platformPath, resolutions: settle(served), servedLocally: [...served] };
}

/**
 * Pure: the sentence the run reason gains about provisioned SVDs, or '' when the chain referenced none. It states
 * what was served from the verified local copy and why each other one was not — never that the SVD was applied.
 */
export function describeSvdResolution(resolutions: readonly SvdResolution[]): string {
  if (resolutions.length === 0) return '';
  const local = resolutions.filter((r) => r.status === 'local');
  const other = resolutions.filter((r) => r.status !== 'local');
  const parts: string[] = [];
  if (local.length > 0) {
    parts.push(
      `${local.length} register description${local.length === 1 ? '' : 's'} (SVD) the platform references ${local.length === 1 ? 'was' : 'were'} served from the provisioned local copy after its sha256 matched the manifest (${local.map((r) => r.url).join(', ')}); nothing was requested for ${local.length === 1 ? 'it' : 'them'}.`,
    );
  }
  if (other.length > 0) {
    const shown = other
      .slice(0, 3)
      .map((r) => `${r.url}: ${r.status}${r.reason ? ` — ${r.reason}` : ''}`)
      .join('; ');
    parts.push(
      `${other.length} SVD reference${other.length === 1 ? ' was' : 's were'} not served from a local copy (${shown}${other.length > 3 ? `; and ${other.length - 3} more` : ''}).`,
    );
  }
  return parts.join(' ');
}

/**
 * Pure: the remote-resource scan minus the URLs the overlay served locally — what the run actually left to the
 * offline refusal. Everything else about the scan (files read, includes left unread) is carried over unchanged.
 */
export function withoutServedLocally<T extends { remote: string[] }>(scan: T, served: readonly string[]): T {
  if (served.length === 0) return scan;
  const s = new Set(served);
  return { ...scan, remote: scan.remote.filter((u) => !s.has(u)) };
}
