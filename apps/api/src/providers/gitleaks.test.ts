import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { mapFindings, redactMatch, rootfsContextReader, scrubContext } from './gitleaks.js';

/**
 * The strings below are the real gitleaks v8.30.1 output for the GL.iNet BE3600 rootfs, captured 2026-08-03.
 * `RWQf6LRC…` is dnscrypt-proxy's *published* minisign verification key — public by construction, which is the
 * whole reason it belongs in a test file: it is exactly the value the old normalizer called a confirmed secret.
 */
const BE3600_MINISIGN = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3';
const BE3600_TOML_COMMENTED_LINE = `  #   minisign_key = '${BE3600_MINISIGN}'`;
const BE3600_TOML_LIVE_LINE = `    minisign_key = '${BE3600_MINISIGN}'`;
const BE3600_TOML_MATCH = `minisign_key = '${BE3600_MINISIGN}'`;

describe('redactMatch', () => {
  it('passes short matches through (collapsing whitespace)', () => {
    expect(redactMatch('admin123')).toBe('admin123');
    expect(redactMatch('  foo\tbar\n')).toBe('foo bar');
  });

  it('fingerprints long key material instead of exposing it', () => {
    const key = `AKIA${'X'.repeat(60)}`;
    const out = redactMatch(key);
    expect(out).not.toContain('XXXXXXXXXX');
    expect(out).toContain('…');
    expect(out).toContain(`(${key.length} chars)`);
    expect(out.length).toBeLessThanOrEqual(120);
  });

  it('handles nullish input', () => {
    expect(redactMatch(undefined)).toBe('');
    expect(redactMatch(null)).toBe('');
  });
});

describe('mapFindings', () => {
  it('makes file paths rootfs-relative and maps fields', () => {
    const rows = [
      { RuleID: 'generic-api-key', Description: 'API key', File: '/x/rootfs/etc/passwd', StartLine: 3, Secret: 'abc' },
    ];
    const out = mapFindings(rows, '/x/rootfs');
    expect(out[0]).toEqual({
      rule: 'generic-api-key',
      description: 'API key',
      file: 'etc/passwd',
      line: 3,
      match: 'abc',
    });
  });

  it('falls back to the rule id for a missing description and caps at 500', () => {
    const rows = Array.from({ length: 600 }, (_, i) => ({ RuleID: 'r', File: `/r/f${i}`, StartLine: i }));
    const out = mapFindings(rows, '/r');
    expect(out).toHaveLength(500);
    expect(out[0]?.description).toBe('r');
  });
});

describe('scrubContext', () => {
  it('keeps the identifier that named the value and drops the value itself', () => {
    // This is the single most load-bearing transform in the module: `minisign_key` is what tells a reader the
    // 56 characters are a verification key rather than an API token, and it survives while the key does not.
    const out = scrubContext(BE3600_TOML_MATCH, BE3600_MINISIGN);
    expect(out).toBe("minisign_key = '…'");
    expect(out).not.toContain(BE3600_MINISIGN);
  });

  it('keeps the comment marker, which is the only reason the line is read at all', () => {
    // Trimming must not eat the `#`. gitleaks reports StartColumn but never the prefix, so this character is
    // the entire difference between live configuration and a commented-out example.
    expect(scrubContext(BE3600_TOML_COMMENTED_LINE, BE3600_MINISIGN)).toBe("# minisign_key = '…'");
    expect(scrubContext(BE3600_TOML_LIVE_LINE, BE3600_MINISIGN)).toBe("minisign_key = '…'");
  });

  it('scrubs a SECOND opaque token on the line, the one gitleaks did not name', () => {
    // gitleaks reports one secret per row. Without the generic net this field would be where the database
    // finally stored a whole credential — the exact thing redactMatch exists to prevent, reintroduced sideways.
    const line = `KEYS="${BE3600_MINISIGN} 4a5ea11b030ec1cfbc8b9947fdf2c872ffffffff"`;
    const out = scrubContext(line, BE3600_MINISIGN);
    expect(out).not.toContain(BE3600_MINISIGN);
    expect(out).not.toContain('4a5ea11b030ec1cfbc8b9947fdf2c872ffffffff');
    expect(out).toContain('KEYS');
  });

  it('flattens control characters instead of writing them into the database', () => {
    // A "line" sliced out of a mostly-binary file is not prose. It must not carry a NUL into a stored JSON blob.
    expect(scrubContext('key\u0000=\u0007 value', '')).toBe('key = value');
  });

  it('handles a match with no usable secret without exposing it', () => {
    expect(scrubContext(undefined, '')).toBe('');
    // A one-character "secret" is not scrubbed by name (split/join on it would shred the line), so the generic
    // net has to be what protects the field. Nothing long enough to be key material survives either way.
    expect(scrubContext('a = a', 'a')).toBe('a = a');
  });
});

describe('line context', () => {
  const withReader = (lines: string, rows: Parameters<typeof mapFindings>[0]) =>
    mapFindings(rows, '/x/rootfs', () => lines);

  it('carries entropy, context and the source line through to the finding', () => {
    const out = withReader(`x\n${BE3600_TOML_COMMENTED_LINE}\n`, [
      {
        RuleID: 'generic-api-key',
        Description: 'Detected a Generic API Key, potentially exposing access to various services.',
        File: '/x/rootfs/etc/dnscrypt-proxy2/dnscrypt-proxy.toml',
        StartLine: 2,
        Secret: BE3600_MINISIGN,
        Match: BE3600_TOML_MATCH,
        Entropy: 5.110577,
      },
    ]);
    expect(out[0]).toMatchObject({
      file: 'etc/dnscrypt-proxy2/dnscrypt-proxy.toml',
      line: 2,
      entropy: 5.110577,
      context: "minisign_key = '…'",
      lineText: "# minisign_key = '…'",
    });
  });

  it('omits the optional fields entirely when nothing measured them', () => {
    // Not `null`, not an empty string: ABSENT. A result stored by an older build looks exactly like this, and
    // the normalizer has to be able to tell "not measured" from "measured and found nothing".
    const out = mapFindings(
      [{ RuleID: 'generic-api-key', File: '/x/rootfs/etc/config', StartLine: 4, Secret: 'abcdefghijklmnop' }],
      '/x/rootfs',
    );
    expect('entropy' in (out[0] ?? {})).toBe(false);
    expect('lineText' in (out[0] ?? {})).toBe(false);
  });

  it('reports the hit anyway when the line cannot be read', () => {
    // The SUCCESS path of the guard is the one nobody runs: a reader that returns nothing must degrade to a
    // finding without context, never to a lost finding or a thrown job.
    const out = mapFindings(
      [{ RuleID: 'generic-api-key', File: '/x/rootfs/bin/blob', StartLine: 9, Secret: 'abcdefghijklmnop' }],
      '/x/rootfs',
      () => null,
    );
    expect(out).toHaveLength(1);
    expect(out[0]?.lineText).toBeUndefined();
  });

  it('reads each file once even when several hits land in it', () => {
    let reads = 0;
    const rows = [710, 719, 729].map((n) => ({
      RuleID: 'generic-api-key',
      File: '/x/rootfs/etc/dnscrypt-proxy2/dnscrypt-proxy.toml',
      StartLine: n,
      Secret: BE3600_MINISIGN,
      Match: BE3600_TOML_MATCH,
    }));
    const lines = Array.from({ length: 800 }, (_, i) => (i === 728 ? BE3600_TOML_COMMENTED_LINE : '')).join('\n');
    const out = mapFindings(rows, '/x/rootfs', () => {
      reads += 1;
      return lines;
    });
    expect(reads).toBe(1);
    expect(out[2]?.lineText).toBe("# minisign_key = '…'");
  });
});

describe('rootfsContextReader', () => {
  it('reads a real file and returns null for one that is not there', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-gitleaks-test-'));
    const file = path.join(dir, 'dnscrypt-proxy.toml');
    fs.writeFileSync(file, BE3600_TOML_COMMENTED_LINE);
    try {
      const read = rootfsContextReader();
      expect(read(file)).toBe(BE3600_TOML_COMMENTED_LINE);
      // The branch that matters: a path that is gone, and a directory. Neither may throw out of a job.
      expect(read(path.join(dir, 'gone'))).toBeNull();
      expect(read(dir)).toBeNull();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a binary file rather than slicing a "line" out of one', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-gitleaks-test-'));
    const file = path.join(dir, 'blob.bin');
    fs.writeFileSync(file, 'head\u0000\u0001\u0002tail');
    try {
      expect(rootfsContextReader()(file)).toBeNull();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
