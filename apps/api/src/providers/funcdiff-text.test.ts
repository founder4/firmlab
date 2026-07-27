import { describe, expect, it } from 'vitest';
import {
  diffLines,
  maskCommentAddresses,
  normalizeDecompiled,
  renderUnified,
  summarizeTextDiff,
} from './funcdiff-text.js';

const V1 = `int set_name(char *in) {
    char *dst;
    dst = buf;
    strcpy(dst, in);
    return 0;
}`;

// The shape of a real fix: one guard added around the copy.
const V2 = `int set_name(char *in) {
    char *dst;
    dst = buf;
    if (strlen(in) < 64) {
        strcpy(dst, in);
    }
    return 0;
}`;

describe('normalizeDecompiled', () => {
  it('strips the ANSI colour radare2 emits, so identical lines compare equal', () => {
    expect(normalizeDecompiled('[32mint[0m main (void) {')).toEqual(['int main (void) {']);
  });
  it('strips trailing whitespace, which otherwise fakes a change', () => {
    expect(normalizeDecompiled('    return 0;   \n}')).toEqual(['    return 0;', '}']);
  });
  it('caps a runaway line rather than carrying it whole', () => {
    const long = `x${'y'.repeat(400)}`;
    expect((normalizeDecompiled(long)[0] as string).length).toBeLessThan(210);
  });
});

describe('diffLines', () => {
  it('finds the added guard, counting the re-indent of the wrapped call honestly', () => {
    const d = diffLines(V1, V2);
    // 3 added: the `if`, the re-indented strcpy, the closing brace. 1 removed: the old, less-indented strcpy.
    // Nesting a call really does rewrite its line, and pretending otherwise would need a whitespace-insensitive
    // compare that would then hide real indentation-only changes.
    expect(d.added).toBe(3);
    expect(d.removed).toBe(1);
    expect(d.hunks).toHaveLength(1);
    const added = (d.hunks[0]?.lines ?? []).filter((l) => l.sign === '+').map((l) => l.text.trim());
    expect(added.some((t) => t.includes('strlen(in) < 64'))).toBe(true);
  });

  it('reports no change for identical text', () => {
    const d = diffLines(V1, V1);
    expect(d.added).toBe(0);
    expect(d.removed).toBe(0);
    expect(d.hunks).toEqual([]);
  });

  // An empty decompilation has no lines; treating it as one blank line would add a phantom `-` to every diff.
  it('treats an empty side as zero lines, not one blank one', () => {
    expect(normalizeDecompiled('')).toEqual([]);
    expect(normalizeDecompiled('   \n  ')).toEqual([]);
    const d = diffLines('', V1);
    expect(d.removed).toBe(0);
    expect(d.added).toBeGreaterThan(0);
  });
});

describe('summarizeTextDiff — a hunk is a place to look, not proof of a change', () => {
  // Found by this test: churn alone called this "widespread" because the function is only 9 lines, so wrapping
  // one call in a guard is ~44% of it — the textbook targeted fix, scored as noise.
  it('calls a small localized edit targeted even in a short function', () => {
    const s = summarizeTextDiff(diffLines(V1, V2));
    expect(s.looksTargeted).toBe(true);
    expect(s.headline).toContain('the shape of a targeted fix');
  });

  // Two decompiled renderings of the same behaviour differ when register allocation does. Calling that "the
  // patch" would be reading noise as signal, so the summary says so instead.
  it('warns that widespread churn is probably decompiler noise', () => {
    const a = Array.from({ length: 40 }, (_, i) => `  v${i} = a${i} + ${i};`).join('\n');
    const b = Array.from({ length: 40 }, (_, i) => `  r${i} = b${i} - ${i};`).join('\n');
    const s = summarizeTextDiff(diffLines(a, b));
    expect(s.looksTargeted).toBe(false);
    expect(s.headline).toContain('decompiler noise');
    expect(s.headline).toContain('not as the patch');
  });

  it('says so when the structural change did not survive decompilation', () => {
    const s = summarizeTextDiff(diffLines(V1, V1));
    expect(s.headline).toContain('did not survive decompilation');
    expect(s.looksTargeted).toBe(false);
  });
});

describe('renderUnified', () => {
  it('renders a readable unified diff with both headers and a hunk marker', () => {
    const out = renderUnified(diffLines(V1, V2), 'sym.set_name');
    expect(out).toContain('--- sym.set_name (older)');
    expect(out).toContain('+++ sym.set_name (newer)');
    expect(out).toMatch(/@@ -\d+ \+\d+ @@/);
    expect(out).toContain('+    if (strlen(in) < 64) {');
  });
});

describe('maskCommentAddresses — an address that shifted is not a change', () => {
  // Seen on the real mipsel validation pair: inserting a guard early in set_name rewrote the XREF comment on
  // every later line, burying the actual edit under noise that is guaranteed to appear in every diff.
  it('masks hex addresses inside comments', () => {
    expect(maskCommentAddresses('   // CALL XREFS from main @ 0x40083c(r), 0x400840(x)')).toBe(
      '   // CALL XREFS from main @ 0x…(r), 0x…(x)',
    );
    expect(maskCommentAddresses('        call t9       // 0x4006fc(0x49edc0, 0x0, 0x0, 0x0)')).toBe(
      '        call t9       // 0x…(0x…, 0x0, 0x0, 0x0)',
    );
  });

  // An address in CODE carries meaning: 0x40 IS `sizeof(buf)`, and masking it would erase the bounds check.
  it('leaves addresses in code untouched', () => {
    const code = '        v0 = (unsigned) (v0 < 0x40)';
    expect(maskCommentAddresses(code)).toBe(code);
  });

  it('keeps the diff sensitive to a change in the NUMBER of xrefs', () => {
    const one = maskCommentAddresses('// CALL XREFS from main @ 0x400100(r)');
    const two = maskCommentAddresses('// CALL XREFS from main @ 0x400100(r), 0x400200(x)');
    expect(one).not.toBe(two);
  });
});
