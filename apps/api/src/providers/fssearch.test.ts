import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { SEARCH_FILE_CAP, buildMatcher, excerptAt, formatCoverage, searchExtraction } from './fssearch.js';

function tree(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fssearch-'));
  fs.mkdirSync(path.join(root, 'etc'), { recursive: true });
  fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(root, 'etc', 'config'), 'host=updates.vendor.example\nport=443\n');
  fs.writeFileSync(path.join(root, 'etc', 'other.conf'), 'nothing interesting here\n');
  // A "binary": NUL in the head, with the term inside it. Firmware's most interesting strings live in ELFs, so a
  // search that skipped binaries would answer a question nobody asked.
  fs.writeFileSync(
    path.join(root, 'bin', 'httpd'),
    Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00]), Buffer.from('GET updates.vendor.example/ok')]),
  );
  return root;
}

describe('buildMatcher', () => {
  it('escapes a literal query, so `a.out` does not also match `about`', () => {
    const m = buildMatcher('a.out', false);
    expect('m' in m || m instanceof RegExp).toBe(true);
    expect((m as RegExp).test('about')).toBe(false);
    (m as RegExp).lastIndex = 0;
    expect((m as RegExp).test('a.out')).toBe(true);
  });

  it('reports an invalid regex instead of quietly matching nothing', () => {
    expect(buildMatcher('([unclosed', true)).toHaveProperty('error');
    expect(buildMatcher('', false)).toHaveProperty('error');
  });
});

describe('excerptAt', () => {
  it('renders control bytes as dots and marks truncation', () => {
    const buf = Buffer.concat([Buffer.alloc(200, 0x41), Buffer.from([0x00, 0x01]), Buffer.from('TERM')]);
    const e = excerptAt(buf, 202, 4);
    expect(e).toContain('TERM');
    expect(e).toContain('..'); // the two control bytes
    expect(e.startsWith('…')).toBe(true);
  });
});

describe('searchExtraction', () => {
  it('finds the term in text and in binary, and dates each hit by the coordinate that means something', () => {
    const r = searchExtraction(tree(), 'updates.vendor.example');
    expect('error' in r).toBe(false);
    const res = r as Exclude<typeof r, { error: string }>;
    const byPath = Object.fromEntries(res.hits.map((h) => [h.path, h]));
    // A text file gets a line number; a binary gets a byte offset and NO line number, because "line 4211 of
    // busybox" is a fiction.
    expect(byPath[path.join('etc', 'config')]?.line).toBe(1);
    expect(byPath[path.join('bin', 'httpd')]?.binary).toBe(true);
    expect(byPath[path.join('bin', 'httpd')]?.line).toBeUndefined();
    expect(byPath[path.join('bin', 'httpd')]?.offset).toBe(10);
  });

  it('says the list is COMPLETE when nothing was skipped — the one case that earns a negative', () => {
    const r = searchExtraction(tree(), 'no-such-term-anywhere') as { verdict: string; hits: unknown[] };
    expect(r.hits).toEqual([]);
    expect(r.verdict).toMatch(/Every file in the extraction was opened/);
  });

  it('counts a file it refused to open and says a term inside it would not appear', () => {
    const root = tree();
    // Sparse file above the cap: never opened, and that has to be visible in the answer.
    const fd = fs.openSync(path.join(root, 'huge.bin'), 'w');
    fs.ftruncateSync(fd, SEARCH_FILE_CAP + 1);
    fs.closeSync(fd);

    const r = searchExtraction(root, 'updates.vendor.example') as {
      verdict: string;
      coverage: { skipped: { tooLarge: number } };
    };
    expect(r.coverage.skipped.tooLarge).toBe(1);
    expect(r.verdict).toMatch(/NOT searched/);
    expect(r.verdict).toMatch(/would not appear above/);
  });

  it('reports the hit cap instead of returning a short list that reads as complete', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fscap-'));
    fs.writeFileSync(path.join(root, 'many'), 'X\n'.repeat(50));
    const r = searchExtraction(root, 'X', { hitCap: 5 }) as {
      hits: unknown[];
      coverage: { hitCapReached: boolean };
      verdict: string;
    };
    expect(r.hits).toHaveLength(5);
    expect(r.coverage.hitCapReached).toBe(true);
    expect(r.verdict).toMatch(/further matches exist and are not listed/);
  });

  it('does not follow a symlink out of the extraction', () => {
    const root = tree();
    fs.symlinkSync('/etc', path.join(root, 'escape'));
    const r = searchExtraction(root, 'root:') as { hits: { path: string }[] };
    expect(r.hits.every((h) => !h.path.startsWith('escape'))).toBe(true);
  });

  it('terminates on a zero-width pattern rather than spinning', () => {
    const r = searchExtraction(tree(), 'x*', { regex: true, hitCap: 10 }) as { coverage: { hitCapReached: boolean } };
    expect(r.coverage).toBeDefined();
  });
});

describe('formatCoverage', () => {
  it('never emits a bare count — a clean search still states that it was complete', () => {
    const v = formatCoverage(
      {
        filesExamined: 12,
        bytesRead: 900,
        entriesWalked: 15,
        skipped: { tooLarge: 0, unreadable: 0, budgetExhausted: 0 },
        walkTruncated: false,
        hitCapReached: false,
        budgetSpent: false,
      },
      0,
    );
    expect(v).toMatch(/Every file in the extraction was opened/);
  });
});
