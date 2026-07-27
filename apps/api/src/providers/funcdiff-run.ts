/**
 * Function-diff runner — pairs binaries across two extracted rootfs and drives radare2 over the ones that differ.
 *
 * The comparison logic is pure and lives in funcdiff.ts; this only does I/O. Two bounds matter and both are
 * reported rather than silently applied:
 *
 *  - **Hash first.** Most of a firmware rootfs is byte-identical between two releases, and an identical binary
 *    needs no analysis at all. Skipping those is what makes this affordable, and the count of them is real
 *    information: "3 of 412 binaries changed" is the shape of a patch release.
 *  - **A per-run cap.** radare2's full analysis (`-A`) is seconds to minutes per binary, so a release that
 *    genuinely rewrote hundreds of binaries would run for hours. The cap stops that, and the number of pairs left
 *    unexamined is carried in the result — a truncated comparison must never read as a complete one.
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingDraft } from '../findings-normalize.js';
import { isToolAvailable } from '../tools.js';
import { type TextDiff, diffLines, renderUnified, summarizeTextDiff } from './funcdiff-text.js';
import { type BinaryDiff, buildFuncDiffFindings, classifyDiff, matchFunctions, parseFunctions } from './funcdiff.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

/** Binaries analyzed per run. Each is a full radare2 analysis pass, so this bounds a job to minutes. */
export const MAX_PAIRS = 20;
/** Changed functions decompiled per binary. Two radare2 runs each, so this stays small and deliberate. */
export const MAX_TEXT_FUNCS = 3;
const R2_TIMEOUT_MS = 180 * 1000;
const WALK_CAP = 20000;

/** A decompiled before/after for one changed function — the readable end of the localization chain. */
export interface FuncTextDiff {
  binary: string;
  function: string;
  /** Which reconstruction produced the text: `pdg` is r2ghidra's C, `pdc` radare2's pseudo-C. */
  decompiler: 'pdg' | 'pdc';
  headline: string;
  looksTargeted: boolean;
  unified: string;
  stats: Pick<TextDiff, 'added' | 'removed' | 'unchanged' | 'truncated'>;
}

export interface FuncDiffResult {
  available: boolean;
  reason: string;
  older: string;
  newer: string;
  /** Binaries present in both rootfs. */
  paired: number;
  /** Of those, how many are byte-identical (skipped, and a real result in themselves). */
  identical: number;
  /** Pairs that differ and were analyzed. */
  analyzed: number;
  /** Pairs that differ and were NOT analyzed because the per-run cap was reached. */
  notAnalyzed: number;
  diffs: BinaryDiff[];
  /** Before/after decompilation of the tightest changed functions, when `withText` was requested. */
  textDiffs: FuncTextDiff[];
  findings: FindingDraft[];
}

/** Is this file an ELF? Reads only the magic. */
function isElf(abs: string): boolean {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const b = Buffer.allocUnsafe(4);
      fs.readSync(fd, b, 0, 4, 0);
      return b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return false;
  }
}

function sha1(abs: string): string {
  try {
    return createHash('sha1').update(fs.readFileSync(abs)).digest('hex');
  } catch {
    return '';
  }
}

/** Every ELF under a rootfs, keyed by its rootfs-relative path — the identity two releases share. */
function listElves(root: string): Map<string, string> {
  const out = new Map<string, string>();
  const stack = [root];
  let walked = 0;
  while (stack.length && walked < WALK_CAP) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (walked++ >= WALK_CAP) break;
      if (e.isSymbolicLink()) continue;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) stack.push(abs);
      else if (e.isFile() && isElf(abs)) out.set(path.relative(root, abs), abs);
    }
  }
  return out;
}

/**
 * Which decompiler this radare2 has, cached per process.
 *
 * `pdg` (r2ghidra) produces real C and is the better read; stock radare2 ships only `pdc`, a pseudo-C rendering
 * inferred from the disassembly. Both are RECONSTRUCTIONS, and which one produced the text is carried into the
 * result — a reader comparing two `pdc` renderings is looking at something considerably further from source than
 * one comparing two Ghidra outputs, and should weight the hunks accordingly.
 */
let decompilerCmd: 'pdg' | 'pdc' | null = null;
async function detectDecompiler(sample: string): Promise<'pdg' | 'pdc'> {
  if (decompilerCmd) return decompilerCmd;
  try {
    const { stdout } = await execFileAsync('radare2', ['-q', '-2', '-c', 'pdg?', sample], { timeout: 20000 });
    decompilerCmd = /r2ghidra|need|install/i.test(stdout) ? 'pdc' : 'pdg';
  } catch {
    decompilerCmd = 'pdc';
  }
  return decompilerCmd;
}

/** Decompiled text for one function, or null. Colour is disabled so two renderings compare as text. */
async function decompileFunction(abs: string, fnName: string, cmd: 'pdg' | 'pdc'): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(
      'radare2',
      ['-q', '-2', '-A', '-e', 'scr.color=0', '-c', `s ${fnName}; ${cmd}`, abs],
      { timeout: 90 * 1000, maxBuffer: 8 * 1024 * 1024 },
    );
    const text = stdout.trim();
    return text || null;
  } catch {
    return null;
  }
}

/** radare2's function list for one binary, or null when it cannot analyze it. */
async function functionsOf(abs: string): Promise<ReturnType<typeof parseFunctions> | null> {
  try {
    const { stdout } = await execFileAsync('radare2', ['-q', '-2', '-A', '-c', 'aflj', abs], {
      timeout: R2_TIMEOUT_MS,
      maxBuffer: 64 * 1024 * 1024,
    });
    return parseFunctions(JSON.parse(stdout.trim() || '[]'));
  } catch {
    return null;
  }
}

/**
 * Diff two extracted rootfs at function granularity. Degrades honestly: radare2 absent, a missing rootfs, or a
 * binary radare2 cannot analyze each produce a stated reason rather than an empty result.
 */
export async function runFuncDiff(
  olderRootfs: string | null,
  newerRootfs: string | null,
  labels: { older: string; newer: string },
  handle: JobHandle,
  maxPairs = MAX_PAIRS,
  withText = true,
): Promise<FuncDiffResult> {
  const empty = (reason: string): FuncDiffResult => ({
    available: false,
    reason,
    older: labels.older,
    newer: labels.newer,
    paired: 0,
    identical: 0,
    analyzed: 0,
    notAnalyzed: 0,
    diffs: [],
    textDiffs: [],
    findings: [
      {
        kind: 'function-diff-blocked',
        title: `Function-level diff of ${labels.older} → ${labels.newer} could not run`,
        severity: 'info',
        proofState: 'blocked_by_platform',
        evidence: { reason },
        rationale:
          'The comparison was requested and this deployment could not perform it. Recorded so the absence of a ' +
          'localized change reads as a missing capability rather than as "nothing changed".',
      },
    ],
  });

  if (!olderRootfs || !newerRootfs) return empty('both images need an extracted rootfs — run extraction on each');
  if (!(await isToolAvailable('radare2'))) return empty('radare2 is not installed in this deployment');

  const a = listElves(olderRootfs);
  const b = listElves(newerRootfs);
  const shared = [...b.keys()].filter((p) => a.has(p)).sort();
  if (shared.length === 0) {
    return empty('the two rootfs share no binary at the same path — they are probably not two builds of one device');
  }

  // Hash first: an identical binary needs no analysis, and how many are identical is itself the shape of the
  // release (a security patch touches a handful; a platform bump touches everything).
  const changedPaths: string[] = [];
  let identical = 0;
  for (const p of shared) {
    const ha = sha1(a.get(p) as string);
    const hb = sha1(b.get(p) as string);
    if (ha && ha === hb) identical++;
    else changedPaths.push(p);
  }

  handle.log(`${shared.length} binaries in both builds; ${identical} byte-identical, ${changedPaths.length} differ.`);

  const toAnalyze = changedPaths.slice(0, maxPairs);
  const notAnalyzed = changedPaths.length - toAnalyze.length;
  const diffs: BinaryDiff[] = [];
  const textDiffs: FuncTextDiff[] = [];
  const findings: FindingDraft[] = [];

  for (const p of toAnalyze) {
    handle.log(`diffing ${p}…`);
    const [fa, fb] = await Promise.all([functionsOf(a.get(p) as string), functionsOf(b.get(p) as string)]);
    if (!fa || !fb) {
      diffs.push({
        path: p,
        verdict: 'incomparable',
        matched: 0,
        changed: 0,
        added: 0,
        removed: 0,
        unmatchable: 0,
        functions: [],
        reason: 'radare2 could not analyze one or both sides, so this pair was not compared at all.',
      });
      continue;
    }
    const diff = classifyDiff(p, matchFunctions(fa, fb));
    diffs.push(diff);
    findings.push(...buildFuncDiffFindings(diff, labels.older, labels.newer));
    handle.log(`  ${p}: ${diff.verdict} (${diff.changed}/${diff.matched} changed)`);

    // Only a `patched` verdict earns the expensive step. On a `recompiled` binary the candidate list is withheld
    // precisely because it means nothing, so decompiling from it would be rendering noise at greater cost.
    if (!withText || diff.verdict !== 'patched') continue;
    const cmd = await detectDecompiler(b.get(p) as string);
    const targets = diff.functions.filter((f) => f.status === 'changed').slice(0, MAX_TEXT_FUNCS);
    for (const t of targets) {
      // Match on the OLDER side by its own name: a stripped pair is matched structurally, so the two sides can
      // legitimately carry different `fcn.*` names, and seeking the new name in the old binary would miss.
      const oldName = t.a?.name ?? t.name;
      const [oldText, newText] = await Promise.all([
        decompileFunction(a.get(p) as string, oldName, cmd),
        decompileFunction(b.get(p) as string, t.name, cmd),
      ]);
      if (!oldText || !newText) {
        handle.log(`  ${p}:${t.name}: could not decompile both sides — no text diff for this function.`);
        continue;
      }
      const td = diffLines(oldText, newText);
      const { headline, looksTargeted } = summarizeTextDiff(td);
      textDiffs.push({
        binary: p,
        function: t.name,
        decompiler: cmd,
        headline,
        looksTargeted,
        unified: renderUnified(td, t.name),
        stats: { added: td.added, removed: td.removed, unchanged: td.unchanged, truncated: td.truncated },
      });
      handle.log(`  ${p}:${t.name}: ${headline}`);
    }
  }

  const patched = diffs.filter((d) => d.verdict === 'patched');
  // The readable end of the chain, attached to the finding that named the function.
  for (const td of textDiffs) {
    const target = findings.find(
      (f) => f.kind === 'function-diff-candidate' && (f.evidence as { binary?: string })?.binary === td.binary,
    );
    if (!target?.evidence) continue;
    const list = ((target.evidence as { decompiledDiffs?: unknown[] }).decompiledDiffs ??= []) as unknown[];
    list.push({
      function: td.function,
      decompiler: td.decompiler,
      headline: td.headline,
      looksTargeted: td.looksTargeted,
      unified: td.unified,
    });
  }
  const capNote = notAnalyzed
    ? ` ${notAnalyzed} further changed binar(ies) were NOT compared — the per-run cap of ${maxPairs} was reached, so this comparison is incomplete.`
    : '';
  const reason =
    `${shared.length} shared binaries: ${identical} identical, ${changedPaths.length} differ, ${toAnalyze.length} compared. ` +
    `${patched.length} pair(s) show a small localized delta.${capNote}`;
  handle.log(reason);

  // The cap is a bound on the ANSWER, so it belongs in the ledger, not only in a log line nobody re-reads.
  if (notAnalyzed > 0) {
    findings.push({
      kind: 'function-diff-truncated',
      title: `Function-level diff was truncated: ${notAnalyzed} changed binar(ies) not compared`,
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      evidence: { older: labels.older, newer: labels.newer, notAnalyzed, cap: maxPairs, analyzed: toAnalyze.length },
      rationale:
        'More binaries changed between these builds than one run compares. The binaries that were not examined ' +
        'may contain the change you are looking for, so this comparison is a partial answer, not a negative one.',
    });
  }

  return {
    available: true,
    reason,
    older: labels.older,
    newer: labels.newer,
    paired: shared.length,
    identical,
    analyzed: toAnalyze.length,
    notAnalyzed,
    diffs,
    textDiffs,
    findings,
  };
}
