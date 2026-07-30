/**
 * What the EXTRACTOR removed, told apart from what the firmware never shipped.
 *
 * `unsquashfs` will not write a symlink whose target would leave the extraction root — an absolute `/etc/resolv.conf`
 * or a `../../..` escape would otherwise land on the host filesystem — so it writes a symlink to `/dev/null` in its
 * place. That is the right call for a carver. It is a disaster for every reader downstream, because the neutered
 * entry is indistinguishable, by `readFileSync`, from a file the vendor shipped empty or never shipped at all.
 *
 * The corpus makes the cost concrete: **126 neutered entries across six images.** DVRF has `etc/passwd`,
 * `etc/shadow`, `etc/group`, `etc/hosts` and `etc/resolv.conf` all pointing at `/dev/null`, and the IMOU Ranger has
 * 93 — **45 of them under `/sbin`** (`netinit`, `syshelper`, `gethwid`, `armbenv`, `sb_util_r`, `sb_util_w`…),
 * binaries the camera genuinely ships that the ELF sweep never opens, because a directory walk that skips symlinks
 * skips these too and says nothing about it.
 *
 * So this is the project's central invariant one layer below where it is enforced: an empty result that cannot say
 * why. `extract-diagnose.ts` is the worked example for a MISSING ROOTFS and nothing did the equivalent for a
 * neutered file. The answer is deliberately NOT a fix in each of a dozen readers: the fact belongs where it is
 * discovered, stated once, so that any provider's silence about one of these paths is already explained. Nothing is
 * deleted — these entries are the extractor's own record, and removing them would make the tree less faithful.
 *
 * **What this cannot recover, and says so:** the original target. Once `unsquashfs` has substituted `/dev/null`, the
 * path the vendor pointed at is gone from the extracted tree. So a neutered entry proves the firmware had SOMETHING
 * at that path and proves nothing about what — never "the file is empty", never "the file is missing", and never a
 * guess at the destination.
 *
 * The decision is pure and takes the `lstat`/`readlink` facts as DATA; only `scanNeutered` touches the filesystem.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';

/** The sentinel `unsquashfs` substitutes for a symlink it refuses to write. */
export const NEUTER_TARGET = '/dev/null';

/**
 * How one extracted path presents, once the difference between the firmware's doing and the extractor's is kept.
 *
 * `neutered` and `empty` are the pair this module exists for: both read as zero bytes and only one of them is a fact
 * about the firmware. `escapes` is the same class of event with a target that is not the sentinel — kept separate
 * because it is the carver's own guard misfiring on a path that may be perfectly innocent, and because its target
 * survived, so a reader can still say where it pointed.
 */
export type ExtractedPathState =
  | 'present'
  | 'absent'
  | 'empty'
  | 'neutered'
  | 'escapes'
  | 'symlink-in-root'
  | 'unreadable';

/** The `lstat`/`readlink` facts about one entry, as data — so the decision below never touches a disk. */
export interface PathFacts {
  /** Rootfs-relative path, for the report. */
  rel: string;
  /** False when nothing exists at the path at all. */
  exists: boolean;
  isSymlink: boolean;
  /** The literal symlink target, when it is one. */
  target?: string | undefined;
  /** Where the target resolves to, absolute — the caller resolves it, since only it knows the root. */
  resolved?: string | undefined;
  /** True when `resolved` is inside the extraction root. Meaningless unless `isSymlink`. */
  insideRoot?: boolean | undefined;
  /** Size of what the path resolves to, when it could be stat-ed. */
  bytes?: number | undefined;
}

/**
 * Pure: classify one extracted path.
 *
 * The order of the tests is the argument. A symlink is judged on its TARGET before anything looks at a size, because
 * following it is exactly the mistake — `statSync` on `etc/passwd -> /dev/null` returns 0 bytes and every caller
 * that stops there has silently converted the extractor's refusal into a statement about the vendor's filesystem.
 */
export function classifyExtractedPath(f: PathFacts): ExtractedPathState {
  if (!f.exists) return 'absent';
  if (f.isSymlink) {
    if (f.target === undefined) return 'unreadable';
    if (f.target === NEUTER_TARGET) return 'neutered';
    if (f.insideRoot === false) return 'escapes';
    return 'symlink-in-root';
  }
  if (f.bytes === undefined) return 'unreadable';
  return f.bytes === 0 ? 'empty' : 'present';
}

/** One neutered or escaping entry, as reported. */
export interface NeuteredEntry {
  rel: string;
  state: 'neutered' | 'escapes';
  /** The target, which survives for `escapes` and is always the sentinel for `neutered`. */
  target: string;
}

/**
 * What a walk of one extraction found, and the bounds it hit.
 *
 * `scanned` is reported next to the entries because a cap that truncates has to say so: a survey that stopped early
 * is a floor on the count, not the count, and this module's whole purpose is refusing to let a bound read as an
 * answer.
 */
export interface NeuteredScan {
  entries: NeuteredEntry[];
  /** Directory entries examined. */
  scanned: number;
  /** True when a bound stopped the walk, so `entries` is a floor rather than a total. */
  truncated: boolean;
  /** Why it stopped, when it did. */
  truncatedReason?: string;
}

const WALK_CAP = 20000;
const ENTRY_CAP = 400;

/**
 * The directories whose neutering costs an ANALYSIS STAGE rather than a file, so a reader learns which question
 * went unasked and not merely that a path was cut. Prefix-matched on the rootfs-relative path.
 */
const STAGE_RELEVANT: ReadonlyArray<{ prefix: string; stage: string }> = [
  { prefix: 'etc/', stage: 'the credential and service-config audit reads this directory' },
  { prefix: 'bin/', stage: 'the ELF sweep and the emulation rungs run binaries from here' },
  { prefix: 'sbin/', stage: 'the ELF sweep and the emulation rungs run binaries from here' },
  { prefix: 'usr/bin/', stage: 'the ELF sweep and the emulation rungs run binaries from here' },
  { prefix: 'usr/sbin/', stage: 'the ELF sweep and the emulation rungs run binaries from here' },
  { prefix: 'lib/', stage: 'the dependency graph resolves DT_NEEDED against this directory' },
  { prefix: 'usr/lib/', stage: 'the dependency graph resolves DT_NEEDED against this directory' },
];

/** Pure: group the entries by which analysis stage their absence silently degrades. */
export function stageImpact(entries: readonly NeuteredEntry[]): { stage: string; paths: string[] }[] {
  const by = new Map<string, string[]>();
  for (const e of entries) {
    const hit = STAGE_RELEVANT.find((s) => e.rel.startsWith(s.prefix));
    if (!hit) continue;
    const list = by.get(hit.stage);
    if (list) list.push(e.rel);
    else by.set(hit.stage, [e.rel]);
  }
  return [...by.entries()]
    .map(([stage, paths]) => ({ stage, paths: paths.sort() }))
    .sort((a, b) => b.paths.length - a.paths.length || a.stage.localeCompare(b.stage));
}

/**
 * Pure: the findings a scan produces.
 *
 * An EMPTY scan emits nothing, and that is not an oversight: no neutered entry means every reader's silence is the
 * firmware's, which needs no explanation. The distinction this module cares about lives in the caller's own
 * reporting — `scanNeutered` returning `entries: []` after walking 6000 entries and never having walked at all are
 * different facts, and the difference is `scanned`, which the caller states.
 */
export function neuteredFindings(scan: NeuteredScan): FindingDraft[] {
  const neutered = scan.entries.filter((e) => e.state === 'neutered');
  const escaping = scan.entries.filter((e) => e.state === 'escapes');
  if (neutered.length === 0 && escaping.length === 0) return [];
  const drafts: FindingDraft[] = [];
  const bound = scan.truncated
    ? ` The survey stopped early (${scan.truncatedReason ?? 'a bound was reached'}), so this is a floor on the count and not the count.`
    : '';

  if (neutered.length > 0) {
    const impact = stageImpact(neutered);
    const impactNote = impact.length
      ? ` Stages affected: ${impact.map((i) => `${i.paths.length} under a path where ${i.stage}`).join('; ')}.`
      : '';
    drafts.push({
      kind: 'extract-neutered-paths',
      title: `${neutered.length} path(s) were cut by the extractor, not absent from the firmware`,
      severity: 'info',
      proofState: 'blocked_by_platform',
      evidence: {
        count: neutered.length,
        scanned: scan.scanned,
        truncated: scan.truncated,
        paths: neutered.slice(0, ENTRY_CAP).map((e) => e.rel),
        stages: stageImpact(neutered),
      },
      rationale: `\`unsquashfs\` refuses to write a symlink whose target would leave the extraction root and substitutes \`${NEUTER_TARGET}\` for it, so these paths read as ZERO BYTES to every provider that opens them. The firmware shipped something at each one; what it pointed at is not recoverable from the extracted tree, because the substitution discarded it. Any provider reporting nothing for one of these paths is reporting the extraction, not the firmware — and an empty result there must not be read as a clean one.${impactNote}${bound} Nothing was deleted: these entries are the extractor's own record of its refusal.`,
    });
  }

  if (escaping.length > 0) {
    drafts.push({
      kind: 'extract-escaping-symlinks',
      title: `${escaping.length} symlink(s) resolve outside the extraction root`,
      severity: 'info',
      proofState: 'blocked_by_platform',
      evidence: {
        count: escaping.length,
        entries: escaping.slice(0, ENTRY_CAP).map((e) => ({ path: e.rel, target: e.target })),
      },
      rationale: `These are symlinks the extraction wrote intact whose target lies outside the root, so following them would read the ANALYSIS HOST rather than the firmware and no provider does. Unlike the neutered paths above, the target survived and is reported, so what the firmware intended is still legible even though the content is not.${bound}`,
    });
  }
  return drafts;
}

/**
 * Walk an extraction root and gather the facts. Thin on purpose — every decision above is pure and unit-tested; this
 * only reads `lstat`/`readlink` and hands the results over.
 *
 * Bounded, and the bound is reported rather than swallowed: a rootfs with more entries than `WALK_CAP` yields a
 * floor on the count, which the findings then state.
 */
export function scanNeutered(root: string): NeuteredScan {
  const entries: NeuteredEntry[] = [];
  let scanned = 0;
  let truncated = false;
  let truncatedReason: string | undefined;
  let abs: string;
  try {
    abs = path.resolve(root);
    if (!fs.statSync(abs).isDirectory()) return { entries, scanned: 0, truncated: false };
  } catch {
    return { entries, scanned: 0, truncated: false };
  }

  const stack: string[] = [abs];
  while (stack.length > 0) {
    if (scanned >= WALK_CAP) {
      truncated = true;
      truncatedReason = `the ${WALK_CAP}-entry walk budget was exhausted`;
      break;
    }
    const dir = stack.pop() as string;
    let dirents: fs.Dirent[];
    try {
      dirents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    // Sorted so the survey is a fact about the rootfs and not about the disk that holds it — the same reason the
    // ELF sweep sorts its walk.
    dirents.sort((a, b) => a.name.localeCompare(b.name));
    for (const d of dirents) {
      if (scanned >= WALK_CAP) break;
      scanned++;
      const full = path.join(dir, d.name);
      if (d.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!d.isSymbolicLink()) continue;
      let target: string;
      try {
        target = fs.readlinkSync(full);
      } catch {
        continue;
      }
      const rel = path.relative(abs, full);
      const resolved = path.resolve(path.dirname(full), target);
      const insideRoot = resolved === abs || resolved.startsWith(abs + path.sep);
      const state = classifyExtractedPath({ rel, exists: true, isSymlink: true, target, resolved, insideRoot });
      if (state === 'neutered' || state === 'escapes') entries.push({ rel, state, target });
    }
  }
  entries.sort((a, b) => a.rel.localeCompare(b.rel));
  return {
    entries,
    scanned,
    truncated,
    ...(truncatedReason ? { truncatedReason } : {}),
  };
}
