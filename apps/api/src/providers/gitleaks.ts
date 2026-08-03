/**
 * Deep secret-scan provider. Runs `gitleaks` over an extracted rootfs to find hardcoded credentials, keys, and
 * tokens in the recovered files — a filesystem-level complement to the core's raw-image string heuristic.
 * gitleaks is optional: with it absent the job returns a clear `available:false` result rather than throwing.
 *
 * gitleaks exits non-zero (1) precisely WHEN it finds leaks, so a non-zero exit with a valid JSON report is the
 * success path here, not a failure. Matched secrets are redacted before persistence so the DB never holds a full
 * credential.
 *
 * **This module gathers; it does not judge.** Whether a hit deserves `static_confirmed` or is only a lead is
 * decided in `findings-normalize.ts`, which is store-free and therefore reachable by a unit test. What this
 * module owes that decision is *context*, because a redacted match on its own cannot distinguish the upstream
 * public minisign key of a dnscrypt config from a live API token: both are 56 opaque characters. So alongside
 * the match it carries three things the tool already knows or the rootfs already says —
 *
 *   - `entropy`  — the Shannon score gitleaks itself computed for the secret, which is the entire basis of its
 *                  entropy-driven rules and therefore the honest statement of what was measured;
 *   - `context`  — the regex match with the secret scrubbed out, which keeps the *identifier that named the
 *                  value* (`minisign_key = …`, `private_key":"…`). That identifier is the strongest available
 *                  evidence of what the value is FOR, and it comes straight from gitleaks' own output;
 *   - `lineText` — the source line the match sits on, scrubbed and read back from the rootfs. gitleaks reports
 *                  `StartColumn` but never the line prefix, so a match on a commented-out line is indis-
 *                  tinguishable from one in live configuration unless the line is read. On the BE3600 corpus
 *                  five of twelve hits sat on commented-out lines.
 *
 * All three are **optional forever**: a result persisted by an older build has none of them, is re-read for as
 * long as the image exists, and must still normalize. Absent means "not measured", never "measured and clean".
 *
 * The context is scrubbed twice before it is stored — once for the secret gitleaks named, and once with a
 * generic net over any remaining long opaque token — because a line that holds one credential may hold two, and
 * this field must not become the place the DB finally keeps a full one.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

export interface GitleaksFinding {
  rule: string;
  description: string;
  file: string;
  line: number;
  match: string;
  /**
   * Shannon entropy gitleaks scored the secret at. Optional forever — results stored before this field existed
   * do not carry it, and an absent score must not be read as a low one.
   */
  entropy?: number;
  /** The regex match with the secret scrubbed out, keeping the identifier that named it. Optional forever. */
  context?: string;
  /** The source line the match sits on, scrubbed, read back from the rootfs. Best-effort; optional forever. */
  lineText?: string;
}

export interface GitleaksResult {
  available: boolean;
  reason?: string;
  target: string;
  findingCount: number;
  findings: GitleaksFinding[];
}

const FINDING_CAP = 500;
const MATCH_CAP = 120;
const CONTEXT_CAP = 200;
/** Files larger than this are not read back for line context; a hit in one still reports, just without it. */
const CONTEXT_FILE_CAP = 4 * 1024 * 1024;

/** Raw gitleaks report row (v8 JSON schema; fields are PascalCase). */
interface GitleaksRow {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Secret?: string;
  Match?: string;
  Entropy?: number;
}

/** Reads a rootfs file for line context. Injected so `mapFindings` stays pure and unit-testable. */
export type ContextFileReader = (absPath: string) => string | null;

function unavailable(target: string, reason: string): GitleaksResult {
  return { available: false, reason, target, findingCount: 0, findings: [] };
}

/**
 * Redact a matched secret for safe storage: collapse whitespace, and if it looks like real key material (long),
 * keep only a head/tail fingerprint. Never returns more than MATCH_CAP characters. Pure — unit-tested.
 */
export function redactMatch(raw: unknown): string {
  const s = String(raw ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  if (s.length <= 24) return s.slice(0, MATCH_CAP);
  const head = s.slice(0, 6);
  const tail = s.slice(-4);
  return `${head}…${tail} (${s.length} chars)`.slice(0, MATCH_CAP);
}

/** Any run of opaque token-alphabet characters this long is treated as key material and never stored. */
const OPAQUE_TOKEN = /[A-Za-z0-9+/=_-]{20,}/g;

/**
 * Scrub a piece of surrounding context so it is safe to persist: remove the secret gitleaks named, then remove
 * anything else that still looks like key material, then flatten control characters and whitespace.
 *
 * The second pass is not redundant. A line may carry two credentials and gitleaks names one per row; without the
 * net, the context field would be the place this database finally stored a whole one. It costs a mangled URL now
 * and then, which is an acceptable price for a field that exists only to say what the value was called.
 *
 * Leading whitespace is trimmed but the first non-space character is not, so a `#` or `//` marker survives —
 * that marker is the only reason the line is read at all. Pure — unit-tested.
 */
export function scrubContext(raw: unknown, secret: string): string {
  let s = String(raw ?? '');
  if (secret && secret.length >= 4) s = s.split(secret).join('…');
  // Control characters are flattened by code point rather than by a regex class: biome refuses control
  // characters inside a regex even when they are written as escapes, and writing them as literals is how this
  // file cost the repo two NUL bytes an hour ago. Codes, not literals.
  const printable = Array.from(s.replace(OPAQUE_TOKEN, '…'), (ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f ? ' ' : ch;
  }).join('');
  return printable.replace(/\s+/g, ' ').trim().slice(0, CONTEXT_CAP);
}

/**
 * Map a raw gitleaks report array to capped, redacted findings.
 *
 * `readFile` is optional and injected: with it, each hit also carries the (scrubbed) source line it sits on,
 * which is the only way to tell a commented-out match from live configuration — gitleaks reports the column but
 * never the prefix. Without it the field is simply absent, which downstream must read as "not measured". A
 * single-entry line cache is enough because gitleaks emits its rows in filesystem-walk order, so hits in the
 * same file arrive together. Pure — unit-tested with an injected reader.
 */
export function mapFindings(rows: GitleaksRow[], rootfsPath: string, readFile?: ContextFileReader): GitleaksFinding[] {
  const root = path.resolve(rootfsPath);
  let cachedPath: string | null = null;
  let cachedLines: string[] | null = null;
  const lineAt = (abs: string, line: number): string | undefined => {
    if (!readFile || !abs || line < 1) return undefined;
    if (abs !== cachedPath) {
      cachedPath = abs;
      const text = readFile(abs);
      cachedLines = text === null ? null : text.split('\n');
    }
    return cachedLines?.[line - 1];
  };

  return rows.slice(0, FINDING_CAP).map((r) => {
    const abs = r.File ?? '';
    let rel = abs;
    const resolved = path.resolve(abs);
    if (resolved === root) rel = '';
    else if (resolved.startsWith(root + path.sep)) rel = resolved.slice(root.length + 1);
    else rel = abs.replace(/^\/+/, '');
    const rule = String(r.RuleID ?? 'unknown');
    const line = Number(r.StartLine ?? 0);
    const secret = String(r.Secret ?? '');
    const context = scrubContext(r.Match, secret);
    const lineText = scrubContext(lineAt(abs, line) ?? '', secret);
    return {
      rule,
      description: String(r.Description ?? rule),
      file: rel,
      line,
      match: redactMatch(r.Secret ?? r.Match),
      ...(typeof r.Entropy === 'number' && Number.isFinite(r.Entropy) ? { entropy: r.Entropy } : {}),
      ...(context ? { context } : {}),
      ...(lineText ? { lineText } : {}),
    };
  });
}

/**
 * An fs-backed reader for line context, size-capped and never throwing.
 *
 * A read failure is not a finding failure: the hit still reports, minus the line. Anything over the cap, or that
 * turns out to be binary, returns null rather than dragging a multi-megabyte blob through the job for one line.
 */
export function rootfsContextReader(): ContextFileReader {
  return (absPath) => {
    try {
      const stat = fs.statSync(absPath);
      if (!stat.isFile() || stat.size > CONTEXT_FILE_CAP) return null;
      const text = fs.readFileSync(absPath, 'utf8');
      return text.includes('\u0000') ? null : text;
    } catch {
      return null;
    }
  };
}

export async function runGitleaks(rootfsPath: string, handle: JobHandle): Promise<GitleaksResult> {
  if (!(await isToolAvailable('gitleaks'))) {
    handle.log('gitleaks not available on PATH — build the firmware Docker image to enable the deep secret scan.');
    return unavailable(rootfsPath, 'gitleaks not installed');
  }

  const reportPath = path.join(os.tmpdir(), `firmlab-gitleaks-${Math.random().toString(36).slice(2)}.json`);
  // gitleaks v8: `dir` subcommand scans a directory; older builds use `detect --source --no-git`. Try both.
  const argSets: string[][] = [
    ['dir', rootfsPath, '--no-banner', '--report-format', 'json', '--report-path', reportPath],
    [
      'detect',
      '--source',
      rootfsPath,
      '--no-git',
      '--no-banner',
      '--report-format',
      'json',
      '--report-path',
      reportPath,
    ],
  ];

  try {
    let ran = false;
    for (const args of argSets) {
      handle.log(`Running: gitleaks ${args.join(' ')}`);
      try {
        await execFileAsync('gitleaks', args, { timeout: 10 * 60 * 1000, maxBuffer: 64 * 1024 * 1024 });
        ran = true;
        break; // exit 0: ran, no leaks
      } catch (err) {
        // Exit 1 = leaks found (normal); the report still exists → treat as success.
        if (fs.existsSync(reportPath)) {
          ran = true;
          break;
        }
        // Unknown subcommand / usage error: try the next arg set.
        const message = err instanceof Error ? err.message : String(err);
        handle.log(`gitleaks invocation failed, trying fallback: ${message}`);
      }
    }
    if (!ran) return unavailable(rootfsPath, 'gitleaks failed to run (no report produced)');

    if (!fs.existsSync(reportPath)) {
      // Ran clean with no findings and (some versions) wrote no file.
      handle.log('gitleaks reported no leaks.');
      return { available: true, target: rootfsPath, findingCount: 0, findings: [] };
    }
    const raw = fs.readFileSync(reportPath, 'utf8').trim();
    const rows = raw ? (JSON.parse(raw) as GitleaksRow[]) : [];
    const findings = mapFindings(Array.isArray(rows) ? rows : [], rootfsPath, rootfsContextReader());
    const withLine = findings.filter((f) => f.lineText).length;
    if (findings.length > 0) {
      handle.log(`Read line context for ${withLine}/${findings.length} hit(s); the rest report without it.`);
    }
    handle.log(`gitleaks found ${Array.isArray(rows) ? rows.length : 0} leak(s); reporting ${findings.length}.`);
    return { available: true, target: rootfsPath, findingCount: findings.length, findings };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    handle.log(`gitleaks report parse failed: ${message}`);
    return unavailable(rootfsPath, `gitleaks failed: ${message}`);
  } finally {
    try {
      fs.rmSync(reportPath, { force: true });
    } catch {
      // best-effort cleanup
    }
  }
}
