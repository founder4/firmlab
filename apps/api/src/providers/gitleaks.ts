/**
 * Deep secret-scan provider. Runs `gitleaks` over an extracted rootfs to find hardcoded credentials, keys, and
 * tokens in the recovered files — a filesystem-level complement to the core's raw-image string heuristic.
 * gitleaks is optional: with it absent the job returns a clear `available:false` result rather than throwing.
 *
 * gitleaks exits non-zero (1) precisely WHEN it finds leaks, so a non-zero exit with a valid JSON report is the
 * success path here, not a failure. Matched secrets are redacted before persistence so the DB never holds a full
 * credential.
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

/** Raw gitleaks report row (v8 JSON schema; fields are PascalCase). */
interface GitleaksRow {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Secret?: string;
  Match?: string;
}

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

/** Map a raw gitleaks report array to capped, redacted findings. Pure — unit-tested. */
export function mapFindings(rows: GitleaksRow[], rootfsPath: string): GitleaksFinding[] {
  const root = path.resolve(rootfsPath);
  return rows.slice(0, FINDING_CAP).map((r) => {
    const abs = r.File ?? '';
    let rel = abs;
    const resolved = path.resolve(abs);
    if (resolved === root) rel = '';
    else if (resolved.startsWith(root + path.sep)) rel = resolved.slice(root.length + 1);
    else rel = abs.replace(/^\/+/, '');
    const rule = String(r.RuleID ?? 'unknown');
    return {
      rule,
      description: String(r.Description ?? rule),
      file: rel,
      line: Number(r.StartLine ?? 0),
      match: redactMatch(r.Secret ?? r.Match),
    };
  });
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
    const findings = mapFindings(Array.isArray(rows) ? rows : [], rootfsPath);
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
