/**
 * Decompiled-text diff — turning a candidate function into a readable change.
 *
 * `funcdiff.ts` narrows two builds to the handful of functions that moved. That is the localization step, and it
 * stops at "read `sym.set_name`". This closes the last gap: decompile that function on both sides and show what
 * actually differs, so the operator sees the added bounds check rather than a name and a delta.
 *
 * What the reader is looking at, stated plainly because it is easy to forget:
 *
 *  - **This is a RECONSTRUCTION, not the vendor's source.** radare2's `pdc` emits pseudo-C inferred from the
 *    disassembly; `pdg` (r2ghidra) is closer to C but still a decompiler's guess. Variable names, types and
 *    control-flow shape are the tool's, not the author's.
 *  - **A diff of two reconstructions carries decompiler noise.** Different register allocation across two builds
 *    changes the rendered text without changing behaviour, so a hunk is a place to look, not proof of a semantic
 *    change. `summarizeTextDiff` reports the hunk count so a wall of them reads as noise rather than as findings.
 *
 * The diff itself is pure and unit-tested; the runner supplies the two texts.
 */

/** One contiguous run of changed lines, with a little surrounding context. */
export interface DiffHunk {
  /** 1-based line number in the OLDER text where the hunk starts. */
  oldStart: number;
  /** 1-based line number in the NEWER text where the hunk starts. */
  newStart: number;
  lines: { sign: ' ' | '-' | '+'; text: string }[];
}

export interface TextDiff {
  hunks: DiffHunk[];
  added: number;
  removed: number;
  /** Lines identical on both sides — the denominator that says how much of the function actually moved. */
  unchanged: number;
  truncated: boolean;
}

/** Context lines kept around each change. Enough to orient, not enough to bury the change. */
const CONTEXT = 3;
/** A decompiled function is bounded; beyond this the diff is not something anyone reads line by line. */
export const MAX_HUNKS = 12;
export const MAX_LINE_LEN = 200;
/** An edit this small is targeted regardless of how short the function is — see `summarizeTextDiff`. */
export const SMALL_EDIT_LINES = 8;

/** Strip the ANSI colour radare2 emits, and the trailing whitespace that makes identical lines compare unequal. */
export function normalizeDecompiled(text: string): string[] {
  // An empty decompilation has no lines. `''.split('\n')` yields one blank one, which would add a phantom `-`
  // to every diff taken against it.
  if (!text.trim()) return [];
  return (
    text
      .split('\n')
      // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping the ESC of an ANSI SGR sequence is the point.
      .map((l) => l.replace(/\[[0-9;]*m/g, '').replace(/\s+$/, ''))
      .map((l) => (l.length > MAX_LINE_LEN ? `${l.slice(0, MAX_LINE_LEN)}…` : l))
  );
}

/**
 * Pure: longest-common-subsequence table over two line arrays. Decompiled functions are tens to low hundreds of
 * lines, so the quadratic table is comfortably affordable and gives a minimal, readable diff — a heuristic
 * matcher would produce hunks that look like changes where there are none.
 */
function lcsTable(a: string[], b: string[]): number[][] {
  const table: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      (table[i] as number[])[j] =
        a[i] === b[j]
          ? ((table[i + 1] as number[])[j + 1] as number) + 1
          : Math.max((table[i + 1] as number[])[j] as number, (table[i] as number[])[j + 1] as number);
    }
  }
  return table;
}

/** Pure: a unified-style diff of two decompiled functions. */
export function diffLines(oldText: string, newText: string): TextDiff {
  const a = normalizeDecompiled(oldText);
  const b = normalizeDecompiled(newText);
  const table = lcsTable(a, b);

  // Walk the table into a flat edit script first; hunks are grouped from it afterwards.
  const ops: { sign: ' ' | '-' | '+'; text: string; oi: number; ni: number }[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      ops.push({ sign: ' ', text: a[i] as string, oi: i, ni: j });
      i++;
      j++;
    } else if (((table[i + 1] as number[])[j] as number) >= ((table[i] as number[])[j + 1] as number)) {
      ops.push({ sign: '-', text: a[i] as string, oi: i, ni: j });
      i++;
    } else {
      ops.push({ sign: '+', text: b[j] as string, oi: i, ni: j });
      j++;
    }
  }
  while (i < a.length) ops.push({ sign: '-', text: a[i] as string, oi: i++, ni: j });
  while (j < b.length) ops.push({ sign: '+', text: b[j] as string, oi: i, ni: j++ });

  const added = ops.filter((o) => o.sign === '+').length;
  const removed = ops.filter((o) => o.sign === '-').length;
  const unchanged = ops.filter((o) => o.sign === ' ').length;

  // Group changed ops into hunks, keeping CONTEXT unchanged lines either side.
  const changedIdx = ops.map((o, k) => (o.sign === ' ' ? -1 : k)).filter((k) => k >= 0);
  const hunks: DiffHunk[] = [];
  let cursor = 0;
  while (cursor < changedIdx.length && hunks.length < MAX_HUNKS) {
    const start = changedIdx[cursor] as number;
    let end = start;
    // Extend while the next change is close enough that merging beats emitting two hunks.
    while (cursor + 1 < changedIdx.length && (changedIdx[cursor + 1] as number) - end <= CONTEXT * 2) {
      cursor++;
      end = changedIdx[cursor] as number;
    }
    cursor++;
    const from = Math.max(0, start - CONTEXT);
    const to = Math.min(ops.length - 1, end + CONTEXT);
    const slice = ops.slice(from, to + 1);
    hunks.push({
      oldStart: (slice[0]?.oi ?? 0) + 1,
      newStart: (slice[0]?.ni ?? 0) + 1,
      lines: slice.map((o) => ({ sign: o.sign, text: o.text })),
    });
  }

  return { hunks, added, removed, unchanged, truncated: cursor < changedIdx.length };
}

/**
 * Pure: the one-line reading of a text diff.
 *
 * The ratio matters more than the raw counts. A couple of changed lines in a 60-line function is a targeted edit
 * worth reading; two dozen hunks scattered through it is the decompiler rendering different register allocation,
 * and calling that "the patch" would be reading noise as signal.
 */
export function summarizeTextDiff(d: TextDiff): { headline: string; looksTargeted: boolean } {
  const total = d.unchanged + d.added + d.removed;
  if (d.added === 0 && d.removed === 0) {
    return {
      headline: 'The decompiled text is identical — the structural change did not survive decompilation.',
      looksTargeted: false,
    };
  }
  const moved = d.added + d.removed;
  const churn = total > 0 ? moved / total : 1;
  // Churn alone misjudges short functions. Wrapping one call in a guard is a handful of lines and a re-indent,
  // which in a 9-line function is ~44% churn — the textbook targeted fix, scored as "widespread". So a small
  // ABSOLUTE edit counts as targeted whatever the function's size, and the ratio only guards the large ones.
  const looksTargeted = d.hunks.length <= 3 && (moved <= SMALL_EDIT_LINES || churn < 0.25);
  const base = `+${d.added}/-${d.removed} lines across ${d.hunks.length} hunk(s)${d.truncated ? ' (truncated)' : ''}`;
  return {
    headline: looksTargeted
      ? `${base} — a small, localized edit. Read it: this is the shape of a targeted fix.`
      : `${base} — widespread. Much of this is likely decompiler noise (register allocation, naming) rather than semantic change; treat it as a place to look, not as the patch.`,
    looksTargeted,
  };
}

/** Pure: render a diff as unified-diff text, for a report or a terminal. */
export function renderUnified(d: TextDiff, name: string): string {
  const out = [`--- ${name} (older)`, `+++ ${name} (newer)`];
  for (const h of d.hunks) {
    out.push(`@@ -${h.oldStart} +${h.newStart} @@`);
    for (const l of h.lines) out.push(`${l.sign}${l.text}`);
  }
  if (d.truncated) out.push(`… further hunks omitted (cap ${MAX_HUNKS})`);
  return out.join('\n');
}
