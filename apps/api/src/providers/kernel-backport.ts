/**
 * Read-only comparison of Linux CNA fix commits with an operator-provisioned local Git tree. A match proves only
 * source-tree state. `artifactBinding` is deliberately fixed to `unverified`: no result here changes ProofState.
 */
import { promisify } from 'node:util';
import { type Finding, type LinuxKernelCveRecord, parseLinuxKernelCveRecord } from '@firmlab/core';
import { execFile, spawn, terminateJobProcess } from '../job-process.js';

const execFileAsync = promisify(execFile);
const SHA1 = /^[0-9a-f]{40}$/;
export const MAX_KERNEL_BACKPORT_ATTACHMENTS = 128;

export interface KernelBackportLimits {
  maxCommits: number;
  timeoutMs: number;
  maxPatchBytes: number;
}

export interface KernelBackportMatch {
  upstreamCommit: string;
  method: 'exact_ancestor' | 'stable_patch_id' | 'not_found' | 'source_commit_missing' | 'error';
  vendorCommit?: string;
  patchId?: string;
  reason: string;
}

export interface KernelBackportEvidence {
  /** Optional forever: persisted results written before route integration do not carry the candidate identity. */
  cveId?: string;
  artifactBinding: 'unverified';
  repoPath: string;
  repoHead: string | null;
  shallow: boolean | null;
  filesExamined: string[];
  commitsExamined: number;
  matches: KernelBackportMatch[];
  coverage: 'complete' | 'partial' | 'none';
  limits: KernelBackportLimits;
  reason: string;
}

export interface KernelBackportRequest {
  repoPath: string;
  record: LinuxKernelCveRecord;
  limits: KernelBackportLimits;
}

export type KernelBackportRequestParse = { ok: true; value: KernelBackportRequest } | { ok: false; error: string };

const defaults: KernelBackportLimits = { maxCommits: 256, timeoutMs: 30_000, maxPatchBytes: 2 * 1024 * 1024 };

function boundedLimits(input: Partial<KernelBackportLimits>): KernelBackportLimits {
  return {
    maxCommits: Math.max(1, Math.min(1024, Math.floor(input.maxCommits ?? defaults.maxCommits))),
    timeoutMs: Math.max(1000, Math.min(120_000, Math.floor(input.timeoutMs ?? defaults.timeoutMs))),
    maxPatchBytes: Math.max(
      64 * 1024,
      Math.min(16 * 1024 * 1024, Math.floor(input.maxPatchBytes ?? defaults.maxPatchBytes)),
    ),
  };
}

const object = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;

/** Validate an operator-provisioned mirror request before a durable job is created. */
export function parseKernelBackportRequest(input: unknown): KernelBackportRequestParse {
  const body = object(input);
  if (!body) return { ok: false, error: 'body must be an object' };
  if (
    typeof body.repoPath !== 'string' ||
    !body.repoPath.startsWith('/') ||
    body.repoPath.length > 4096 ||
    body.repoPath.includes('\0')
  ) {
    return { ok: false, error: 'repoPath must be an absolute local path of at most 4096 characters' };
  }
  const parsedRecord = parseLinuxKernelCveRecord(body.record);
  if (!parsedRecord.ok) return { ok: false, error: `record rejected: ${parsedRecord.reason}` };

  const rawLimits = body.limits === undefined ? {} : object(body.limits);
  if (!rawLimits) return { ok: false, error: 'limits must be an object when supplied' };
  const requested: Partial<KernelBackportLimits> = {};
  for (const key of ['maxCommits', 'timeoutMs', 'maxPatchBytes'] as const) {
    const value = rawLimits[key];
    if (value === undefined) continue;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
      return { ok: false, error: `limits.${key} must be a positive safe integer` };
    }
    requested[key] = value;
  }
  return {
    ok: true,
    value: { repoPath: body.repoPath, record: parsedRecord.record, limits: boundedLimits(requested) },
  };
}

/** Rehydrate only the minimum shape that can be safely attached to a finding. Older results remain unattached. */
export function parseKernelBackportEvidence(input: unknown): KernelBackportEvidence | null {
  const value = object(input);
  if (
    !value ||
    typeof value.cveId !== 'string' ||
    !/^CVE-\d{4}-\d{4,}$/.test(value.cveId) ||
    value.artifactBinding !== 'unverified' ||
    !Array.isArray(value.matches)
  )
    return null;
  return value as unknown as KernelBackportEvidence;
}

/** Add source-tree context to matching kernel-CVE rows without changing severity, proof state or stored ownership. */
export function attachKernelBackportEvidence(findings: readonly Finding[], rawEvidence: unknown): Finding[] {
  const candidates = Array.isArray(rawEvidence) ? rawEvidence : [rawEvidence];
  const byCve = new Map<string, KernelBackportEvidence>();
  for (const candidate of candidates.slice(0, MAX_KERNEL_BACKPORT_ATTACHMENTS)) {
    const evidence = parseKernelBackportEvidence(candidate);
    if (evidence?.cveId && !byCve.has(evidence.cveId)) byCve.set(evidence.cveId, evidence);
  }
  if (byCve.size === 0) return [...findings];
  return findings.map((finding) => {
    if (finding.kind !== 'kernel-cve' && finding.kind !== 'kernel-cve-candidate') return finding;
    const evidenceId = typeof finding.evidence?.id === 'string' ? finding.evidence.id : null;
    const titleId = /^CVE-\d{4}-\d{4,}/.exec(finding.title)?.[0] ?? null;
    const backportEvidence = byCve.get(evidenceId ?? titleId ?? '');
    if (!backportEvidence) return finding;
    return { ...finding, evidence: { ...finding.evidence, backportEvidence } };
  });
}

const safeEnv = () => ({
  ...process.env,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
});

function errorText(error: unknown): string {
  const e = error as { code?: unknown; message?: unknown; stderr?: unknown };
  const stderr = typeof e.stderr === 'string' ? e.stderr.trim() : '';
  return (stderr || (typeof e.message === 'string' ? e.message : String(error))).slice(0, 500);
}

async function patchId(patch: string, timeoutMs: number, maxBytes: number): Promise<string> {
  if (Buffer.byteLength(patch) > maxBytes) throw new Error(`patch exceeds ${maxBytes}-byte bound`);
  return new Promise((resolve, reject) => {
    const child = spawn('git', ['patch-id', '--stable'], { env: safeEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else {
        const id = stdout.trim().split(/\s+/)[0] ?? '';
        if (!SHA1.test(id)) reject(new Error('git patch-id returned no stable SHA-1'));
        else resolve(id);
      }
    };
    const timer = setTimeout(() => {
      terminateJobProcess(child);
      finish(new Error(`git patch-id timed out after ${timeoutMs} ms`));
    }, timeoutMs);
    child.stdout?.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
      if (Buffer.byteLength(stdout) > 1024) {
        terminateJobProcess(child);
        finish(new Error('git patch-id output exceeded bound'));
      }
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
      if (Buffer.byteLength(stderr) > 4096) {
        terminateJobProcess(child);
        finish(new Error('git patch-id error output exceeded bound'));
      }
    });
    child.once('error', (error) => finish(error));
    child.once('close', (code) => finish(code === 0 ? undefined : new Error(stderr || `git patch-id exited ${code}`)));
    child.stdin?.end(patch);
  });
}

/** Inspect an explicit local repository. No clone, fetch, checkout, hooks or build commands are performed. */
export async function compareKernelBackports(
  repoPath: string,
  record: LinuxKernelCveRecord,
  options: Partial<KernelBackportLimits> = {},
): Promise<KernelBackportEvidence> {
  const limits = boundedLimits(options);
  const started = Date.now();
  const remaining = () => Math.max(1, limits.timeoutMs - (Date.now() - started));
  const run = async (args: string[], maxBuffer = 1024 * 1024) => {
    const result = await execFileAsync('git', ['-C', repoPath, ...args], {
      encoding: 'utf8',
      env: safeEnv(),
      timeout: remaining(),
      maxBuffer,
    });
    return String(result.stdout).trim();
  };
  const base = {
    cveId: record.cveId,
    artifactBinding: 'unverified' as const,
    repoPath,
    filesExamined: record.programFiles.slice(0, 128),
    limits,
  };
  if (!repoPath.startsWith('/'))
    return {
      ...base,
      repoHead: null,
      shallow: null,
      commitsExamined: 0,
      matches: [],
      coverage: 'none',
      reason: 'repoPath must be absolute',
    };

  let head: string;
  let shallow: boolean;
  try {
    await run(['rev-parse', '--git-dir']);
    head = await run(['rev-parse', 'HEAD']);
    if (!SHA1.test(head)) throw new Error('HEAD is not a full SHA-1 commit');
    shallow = (await run(['rev-parse', '--is-shallow-repository'])) === 'true';
    const bare = (await run(['rev-parse', '--is-bare-repository'])) === 'true';
    if (!bare && (await run(['status', '--porcelain', '--untracked-files=no'])) !== '') {
      return {
        ...base,
        repoHead: head,
        shallow,
        commitsExamined: 0,
        matches: [],
        coverage: 'none',
        reason: 'local source tree is dirty; comparison was not attempted',
      };
    }
  } catch (error) {
    return {
      ...base,
      repoHead: null,
      shallow: null,
      commitsExamined: 0,
      matches: [],
      coverage: 'none',
      reason: `local Git repository unavailable: ${errorText(error)}`,
    };
  }

  let candidates: string[] = [];
  try {
    const output = await run([
      'log',
      `--max-count=${limits.maxCommits}`,
      '--format=%H',
      'HEAD',
      '--',
      ...base.filesExamined,
    ]);
    candidates = output ? output.split('\n').filter((value) => SHA1.test(value)) : [];
  } catch (error) {
    return {
      ...base,
      repoHead: head,
      shallow,
      commitsExamined: 0,
      matches: [],
      coverage: 'none',
      reason: `commit census failed: ${errorText(error)}`,
    };
  }

  const candidatePatchIds = new Map<string, string>();
  const matches: KernelBackportMatch[] = [];
  for (const fix of record.fixCommits) {
    try {
      await run(['cat-file', '-e', `${fix}^{commit}`]);
    } catch {
      matches.push({
        upstreamCommit: fix,
        method: 'source_commit_missing',
        reason: 'fix object is absent from the local repository',
      });
      continue;
    }
    try {
      await run(['merge-base', '--is-ancestor', fix, 'HEAD']);
      matches.push({
        upstreamCommit: fix,
        method: 'exact_ancestor',
        vendorCommit: fix,
        reason: 'fix commit is an ancestor of the examined HEAD',
      });
      continue;
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      if (code !== 1) {
        matches.push({ upstreamCommit: fix, method: 'error', reason: `ancestry check failed: ${errorText(error)}` });
        continue;
      }
    }
    try {
      const upstreamPatch = await run(
        ['show', '--format=', '--no-ext-diff', '--no-renames', '--binary', fix, '--', ...base.filesExamined],
        limits.maxPatchBytes,
      );
      const upstreamPatchId = await patchId(upstreamPatch, remaining(), limits.maxPatchBytes);
      let equivalent: string | null = null;
      for (const candidate of candidates) {
        let id = candidatePatchIds.get(candidate);
        if (!id) {
          const patch = await run(
            ['show', '--format=', '--no-ext-diff', '--no-renames', '--binary', candidate, '--', ...base.filesExamined],
            limits.maxPatchBytes,
          );
          id = await patchId(patch, remaining(), limits.maxPatchBytes);
          candidatePatchIds.set(candidate, id);
        }
        if (id === upstreamPatchId) {
          equivalent = candidate;
          break;
        }
      }
      matches.push(
        equivalent
          ? {
              upstreamCommit: fix,
              method: 'stable_patch_id',
              vendorCommit: equivalent,
              patchId: upstreamPatchId,
              reason: 'a bounded local-history commit has the same stable patch-id',
            }
          : {
              upstreamCommit: fix,
              method: 'not_found',
              patchId: upstreamPatchId,
              reason: `no equivalent patch was found in the ${candidates.length}-commit bounded census`,
            },
      );
    } catch (error) {
      matches.push({ upstreamCommit: fix, method: 'error', reason: `patch comparison failed: ${errorText(error)}` });
    }
  }

  const completed = matches.filter(
    (match) => match.method !== 'error' && match.method !== 'source_commit_missing',
  ).length;
  const found = matches.filter(
    (match) => match.method === 'exact_ancestor' || match.method === 'stable_patch_id',
  ).length;
  return {
    ...base,
    repoHead: head,
    shallow,
    commitsExamined: candidates.length,
    matches,
    coverage: completed === matches.length && !shallow ? 'complete' : completed > 0 ? 'partial' : 'none',
    reason: `${found} of ${matches.length} fix commit(s) matched source-tree evidence; artifact binding remains unverified${
      shallow ? '; the local history is shallow' : ''
    }.`,
  };
}
