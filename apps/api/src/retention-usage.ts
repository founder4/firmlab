/**
 * The bounded directory walk the retention sweep measures with — and the reason it lives in its own module.
 *
 * `retention.ts` imports `store.js`, and a vitest file that imports anything reaching `node:sqlite` does not even
 * load, so for as long as this walk sat there NO test could call it. That mattered more than usual here: the walk
 * is a guard's input, its budget branch fires only on a tree nobody has yet built, and this codebase has already
 * paid four times over for a guard whose success path was never exercised. Split out, both branches are reachable
 * from a temp directory and two lines of test.
 */
import fs from 'node:fs';
import path from 'node:path';

/**
 * Recursively sum file sizes under a directory, bounded so a pathological tree can't stall the sweep — and saying
 * so when the bound bit.
 *
 * `truncated` is not decoration. This number is what `sweepRetention` compares against `FIRMLAB_MAX_DATA_BYTES`,
 * so a silent partial sum is a FLOOR presented as the total, and a volume genuinely over quota then under-evicts
 * while the sweep reports success — the guard's success path again, and the branch nobody runs. The cache walk two
 * functions down has returned its own `truncated` since it was written; this one had not.
 *
 * Today `/data/extract` holds 19 811 entries for 25 images (~2.8k per extracted image), so the budget bites at
 * roughly 175 images, or on one deep recursive binwalk carve well before that.
 */
export function dirSize(dir: string, budget = 500_000): { bytes: number; truncated: boolean } {
  let total = 0;
  const stack = [dir];
  let visited = 0;
  while (stack.length > 0 && visited < budget) {
    const cur = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      visited++;
      const abs = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(abs);
      else if (e.isFile()) {
        try {
          total += fs.statSync(abs).size;
        } catch {
          // vanished mid-sweep — ignore
        }
      }
    }
  }
  // Entries left on the stack mean the walk stopped with tree still unvisited; `visited >= budget` alone would
  // also be true for a tree that happens to hold exactly `budget` entries and was in fact walked whole.
  return { bytes: total, truncated: stack.length > 0 };
}
