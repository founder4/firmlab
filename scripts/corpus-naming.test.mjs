/**
 * The naming contract for the three "corpora" — see "The three corpora" in docs/ARCHITECTURE.md.
 *
 * Three unrelated things in this repository are called "corpus": the CROSS-IMAGE corpus (the knowledge base in
 * `apps/api/src/corpus.ts`), the VALIDATION corpus (the locked sample set the coverage matrix is measured over)
 * and the YARA RULE corpus (the pinned rule set the scanner applies). Nothing here could be asserted by reading
 * the code — the ambiguity lives entirely in the strings an operator reads — so this pins the two properties that
 * a later edit can silently undo:
 *
 *  1. **Every qualified alias runs the identical command as the historical name it aliases.** The historical
 *     `corpus:*` names are in muscle memory, in `docs/` and in whatever automation already calls them, so the
 *     disambiguation was added ALONGSIDE them rather than in place of them. An alias that drifted from its
 *     original would be worse than no alias: two names for one job that quietly do different things.
 *  2. **Every one of those commands' `--help` names which corpus it is about.** The help text is where a hurried
 *     operator resolves the ambiguity, and this asserts the real spawned output rather than an exported string,
 *     because what is exported and what `--help` prints are two different claims.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const scripts = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts;

/** alias → the historical name it must stay identical to. */
const ALIASES = {
  'validation-corpus:matrix': 'corpus:matrix',
  'validation-corpus:campaign': 'corpus:campaign',
  'cross-image-corpus:reindex': 'corpus:reindex',
  'cross-image-corpus:refresh-credentials': 'corpus:refresh-credentials',
};

/**
 * Which corpus each command's help must name, as the phrase and the two it must disclaim. `yara-corpus:sync` is
 * the one with no historical name — it had no pnpm script at all — so it is help-checked without an alias pair.
 */
const HELP = {
  'corpus:matrix': { names: /validation corpus/i, disclaims: [/cross-image corpus/i, /yara rule corpus/i] },
  'corpus:campaign': { names: /validation corpus/i, disclaims: [/cross-image corpus/i, /yara rule corpus/i] },
  'corpus:reindex': { names: /cross-image corpus/i, disclaims: [/validation corpus/i, /yara rule corpus/i] },
  'corpus:refresh-credentials': {
    names: /cross-image corpus/i,
    disclaims: [/validation corpus/i, /yara rule corpus/i],
  },
  'yara-corpus:sync': {
    names: /corpus de reglas yara/i,
    disclaims: [/corpus de validación/i, /corpus entre imágenes/i],
  },
};

test('every qualified alias runs the identical command as the historical name it aliases', () => {
  for (const [alias, historical] of Object.entries(ALIASES)) {
    assert.ok(scripts[historical], `${historical} must stay: automation already calls it`);
    assert.ok(scripts[alias], `${alias} is missing`);
    assert.equal(scripts[alias], scripts[historical], `${alias} has drifted from ${historical}`);
  }
  assert.ok(scripts['yara-corpus:sync'], 'yara-corpus:sync is missing');
});

test('every corpus command names its own corpus in --help, and disclaims the other two', () => {
  for (const [name, { names, disclaims }] of Object.entries(HELP)) {
    // The npm script body, run directly: `pnpm run <name>` would need an install, and what is under test is the
    // command the script line points at.
    const [bin, ...args] = scripts[name].split(' ');
    const help = execFileSync(bin, [...args, '--help'], { cwd: root, encoding: 'utf8' });
    assert.match(help, names, `pnpm ${name} --help does not name its corpus`);
    for (const other of disclaims) {
      assert.match(help, other, `pnpm ${name} --help does not disclaim ${other}`);
    }
  }
});

test('the three qualified names are the ones ARCHITECTURE.md defines', () => {
  // The help strings above are only worth anything if they quote the same vocabulary the architecture doc fixes.
  // A rename there that forgot this file would leave the CLI speaking a vocabulary nothing else uses.
  const architecture = readFileSync(join(root, 'docs', 'ARCHITECTURE.md'), 'utf8');
  for (const name of ['cross-image corpus', 'validation corpus', 'YARA rule corpus']) {
    assert.ok(architecture.includes(`**${name}**`), `ARCHITECTURE.md no longer defines "${name}"`);
  }
  for (const [alias, historical] of Object.entries(ALIASES)) {
    assert.ok(architecture.includes(`pnpm ${alias}`), `ARCHITECTURE.md does not list the alias ${alias}`);
    assert.ok(architecture.includes(`pnpm ${historical}`), `ARCHITECTURE.md dropped the historical ${historical}`);
  }
});
