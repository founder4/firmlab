#!/usr/bin/env node
/**
 * Refuse a cap whose own output becomes the denominator.
 *
 * This is CLAUDE.md's fourth trap — "a bound is not an answer" — made mechanical. The shape it refuses is one line
 * long and reads as correct:
 *
 *     const shown = all.slice(0, cap);
 *     return { entries: shown, total: shown.length };   // `total` is now the CAP, not the total
 *
 * `all.length` is never read, so nothing in the result can say what was dropped, and every consumer downstream — a
 * coverage sentence, a percentage, an "N of M" line, an empty-set claim — is computed from a number that is an
 * artifact of the bound. `selectFindings` in `binvuln.ts`, `selectExportReachTargets`, `fsbrowse`'s directory
 * listing and `copilot`'s summary all get this right by measuring the ORIGINAL beside the cut; nothing stopped the
 * next one from measuring only the cut, because the wrong version compiles, lints, and passes a test written from
 * the same assumption as the code.
 *
 * The property, stated exactly: **if a collection is truncated by a cap and the truncated value is then counted,
 * some collection it was derived from must also be counted in the same scope.** Both halves matter — counting the
 * cut is fine when the whole is measured too (that is how you compute `dropped`), and truncating without counting
 * the result is fine, because then the count is simply not claimed.
 *
 * Three things keep it from crying wolf, each calibrated against a real site in this repository that an earlier
 * draft flagged:
 *
 *  - **Only a cap.** `slice(start, end)` keeps a prefix and `slice(-n)` a suffix; `xs.slice(n)` is the REST
 *    (`nvd.ts` takes the tail it dropped exactly that way) and `tokens.slice(sep + 1)` is a split, so a single
 *    non-negative argument is not a cap.
 *  - **Only a collection.** The receiver's type comes from the TypeScript checker, not from a guess: half of this
 *    repo's capped slices are `text.slice(at, at + 320)` over a string, where `.length` is an offset and not a
 *    population. A grep cannot tell those apart, which is the whole reason this guard carries a checker.
 *  - **Lineage, not the bare name.** `rest = measured.filter(…)` then `rest.slice(0, room)` is covered by
 *    `measured.length`, and `rankChangedPaths(changedPaths, sizeOf).slice(0, maxPairs)` by `changedPaths.length`.
 *    The identifiers feeding the sliced expression are followed back through their own declarations, so a
 *    measurement anywhere in that chain counts as knowing the whole.
 *
 * What it does NOT claim. It checks that the total is REACHED FOR, not that it is reported correctly or that the
 * dropped set is described — the `capRule` sentence is still a human's job, and measuring the original and then
 * printing the wrong one is as wrong as it ever was. It also sees one scope: a function that returns the cut and
 * leaves the counting to its caller is invisible here, and so is a cap applied across two files.
 *
 * Its own success path is the part that had to be got right, because a checker that resolves NOTHING reports zero
 * defects and reads exactly like a clean tree. So the counts are carried into the verdict line and checked: zero
 * files, zero capped slices, or capped slices of which NONE typed as an array all mean this guard could not look,
 * and each exits 2 rather than 0.
 *
 *   node scripts/check-slice-denominator.mjs      scan the workspace sources, tracked or newly added
 */
import { execFileSync } from 'node:child_process';
import ts from 'typescript';

// Written through `fromCharCode` and not as `\u001b`: the formatter rewrites the escape into the LITERAL
// control byte, which is the `check-nul.sh` trap wearing a different number — grep and `file` treat the
// source as binary, and the rewrite happens on the first `biome check --write` after anyone touches this.
const ESC = String.fromCharCode(27);

/** Identifiers a value was built from — `a.b.c` contributes `a`, not `b`, since only the root can be measured. */
function identifiersIn(node) {
  const out = new Set();
  const walk = (n) => {
    if (ts.isIdentifier(n)) {
      out.add(n.text);
      return;
    }
    if (ts.isPropertyAccessExpression(n)) {
      walk(n.expression);
      return;
    }
    ts.forEachChild(n, walk);
  };
  walk(node);
  return out;
}

/** The nearest enclosing function, or the file. Two functions in one file do not share a denominator. */
function scopeOf(node) {
  for (let n = node.parent; n; n = n.parent) {
    if (
      ts.isFunctionDeclaration(n) ||
      ts.isFunctionExpression(n) ||
      ts.isArrowFunction(n) ||
      ts.isMethodDeclaration(n) ||
      ts.isConstructorDeclaration(n) ||
      ts.isGetAccessorDeclaration(n) ||
      ts.isSourceFile(n)
    ) {
      return n;
    }
  }
  return node.getSourceFile();
}

/** Every name whose population is read in this scope, through `.length` or `.size`. */
function measuredIn(scope) {
  const out = new Set();
  const walk = (n) => {
    if (ts.isPropertyAccessExpression(n) && (n.name.text === 'length' || n.name.text === 'size')) {
      let recv = n.expression;
      while (ts.isParenthesizedExpression(recv) || ts.isNonNullExpression(recv) || ts.isAsExpression(recv)) {
        recv = recv.expression;
      }
      for (const id of identifiersIn(recv)) out.add(id);
    }
    ts.forEachChild(n, walk);
  };
  ts.forEachChild(scope, walk);
  return out;
}

/** Variable initializers in this scope, so a derived collection can be traced back to the one it came from. */
function declarationsIn(scope) {
  const out = new Map();
  const walk = (n) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
      out.set(n.name.text, n.initializer);
    }
    ts.forEachChild(n, walk);
  };
  ts.forEachChild(scope, walk);
  return out;
}

/** The seed names plus everything they were derived from, to a bounded depth. A cycle terminates on its own. */
function lineageOf(seeds, declarations, depth = 6) {
  const out = new Set(seeds);
  for (let i = 0; i < depth; i += 1) {
    const before = out.size;
    for (const name of [...out]) {
      const init = declarations.get(name);
      if (init) for (const id of identifiersIn(init)) out.add(id);
    }
    if (out.size === before) break;
  }
  return out;
}

/** A cap truncates: `slice(start, end)` keeps a prefix, `slice(-n)` a suffix. `slice(n)` is the rest, not a cap. */
function isCappedSlice(call) {
  if (call.arguments.length === 2) return true;
  const only = call.arguments[0];
  return (
    call.arguments.length === 1 &&
    only !== undefined &&
    ts.isPrefixUnaryExpression(only) &&
    only.operator === ts.SyntaxKind.MinusToken
  );
}

/** The `const NAME = <the slice>` this call is bound to, or null when the cut is never given a name to count. */
function boundName(call) {
  let n = call.parent;
  while (n && !ts.isVariableDeclaration(n) && !ts.isStatement(n)) n = n.parent;
  return n && ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) ? n.name.text : null;
}

/**
 * Analyse real files with a real checker. Returns the defects AND what was examined, because "found nothing" and
 * "looked at nothing" are only the same sentence when the counts are visible.
 */
export function analyzeFiles(fileNames) {
  const program = ts.createProgram(fileNames, {
    target: ts.ScriptTarget.ESNext,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    jsx: ts.JsxEmit.ReactJSX,
    skipLibCheck: true,
    strict: true,
  });
  const checker = program.getTypeChecker();
  const stats = { files: 0, unreadable: [], cappedSlices: 0, overCollections: 0, named: 0 };
  const defects = [];

  for (const fileName of fileNames) {
    const sf = program.getSourceFile(fileName);
    if (!sf) {
      stats.unreadable.push(fileName);
      continue;
    }
    stats.files += 1;
    const walk = (n) => {
      if (
        ts.isCallExpression(n) &&
        ts.isPropertyAccessExpression(n.expression) &&
        n.expression.name.text === 'slice' &&
        isCappedSlice(n)
      ) {
        stats.cappedSlices += 1;
        const receiver = n.expression.expression;
        const type = checker.getTypeAtLocation(receiver);
        const isCollection =
          (type.flags & ts.TypeFlags.StringLike) === 0 && (checker.isArrayType(type) || checker.isTupleType(type));
        if (isCollection) {
          stats.overCollections += 1;
          const bound = boundName(n);
          if (bound !== null) {
            stats.named += 1;
            const scope = scopeOf(n);
            const measured = measuredIn(scope);
            const lineage = lineageOf(identifiersIn(receiver), declarationsIn(scope));
            if (measured.has(bound) && ![...lineage].some((name) => measured.has(name))) {
              defects.push({
                file: fileName,
                line: sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1,
                bound,
                lineage: [...lineage].sort(),
                text: n.getText(sf).replace(/\s+/g, ' ').slice(0, 100),
              });
            }
          }
        }
      }
      ts.forEachChild(n, walk);
    };
    ts.forEachChild(sf, walk);
  }
  return { defects, stats };
}

/** The workspace sources this guard owns. `--others` because a file is most dangerous before its first commit. */
export function listSources(cwd) {
  const out = execFileSync(
    'git',
    [
      'ls-files',
      '--cached',
      '--others',
      '--exclude-standard',
      '--',
      'apps/*/src/*.ts',
      'apps/*/src/*.tsx',
      'packages/*/src/*.ts',
    ],
    { cwd, encoding: 'utf8' },
  );
  return [...new Set(out.split('\n').filter((f) => f !== '' && !/\.test\.tsx?$/.test(f)))].sort();
}

function main() {
  const root = new URL('..', import.meta.url).pathname;
  const cannotLook = (why) => {
    console.error(`${ESC}[1;31m[x]${ESC}[0m ${why}`);
    console.error(
      `${ESC}[1;33m[!]${ESC}[0m Refusing to exit 0: a guard that could not look must never read as "clean".`,
    );
    process.exit(2);
  };

  let sources = [];
  try {
    sources = listSources(root);
  } catch (err) {
    cannotLook(`listing the sources failed, so nothing was examined: ${err instanceof Error ? err.message : err}`);
  }
  if (sources.length === 0) cannotLook('matched 0 workspace sources — nothing was examined.');

  const { defects, stats } = analyzeFiles(sources.map((f) => root + f));
  if (stats.unreadable.length > 0) {
    cannotLook(`${stats.unreadable.length} file(s) the compiler could not open — they were not examined.`);
  }
  // A checker that resolved nothing calls every receiver "not an array" and then reports a clean tree. These two
  // lines are the difference between a passing guard and a guard that is switched off.
  if (stats.cappedSlices === 0) cannotLook('found 0 capped slices in the whole workspace — the walk is not looking.');
  if (stats.overCollections === 0) {
    cannotLook(`${stats.cappedSlices} capped slice(s) and NONE typed as an array — the type checker resolved nothing.`);
  }

  if (defects.length > 0) {
    for (const d of defects) {
      const where = `${d.file.slice(root.length)}:${d.line}`;
      console.error(`${ESC}[1;31m[x]${ESC}[0m ${where} counts \`${d.bound}.length\` and never measures what it cut`);
      console.error(`      ${d.text}`);
      console.error(`      nothing in ${d.lineage.map((n) => `\`${n}\``).join(', ')} is measured in this scope`);
    }
    console.error(`${ESC}[1;33m[!]${ESC}[0m Measure the original beside the cut, and state what the bound dropped:`);
    console.error('        const shown = all.slice(0, cap);');
    console.error('        return { entries: shown, total: all.length, dropped: all.length - shown.length };');
    console.error(
      `${ESC}[1;33m[!]${ESC}[0m \`shown.length\` is the CAP. A result reporting it as the total makes every`,
    );
    console.error('    coverage sentence, percentage and "N of M" line downstream an artifact of the bound —');
    console.error('    CLAUDE.md\'s fourth trap, "a bound is not an answer".');
    process.exit(1);
  }

  console.log(
    `${ESC}[1;36m==>${ESC}[0m no cap counted as a total: ${stats.files} source(s) scanned, ${stats.cappedSlices} ` +
      `capped slice(s), ${stats.overCollections} of them over collections, ${stats.named} of those named`,
  );
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) main();
