import { describe, expect, it } from 'vitest';
import { classifySecret, extractSecrets, extractStrings, scanSecrets, scanStrings } from '../src/strings.js';

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe('extractStrings', () => {
  it('extracts printable runs at or above minLength', () => {
    const buf = bytes('ab\x00hello\x00world!!\x01x');
    const hits = extractStrings(buf, { minLength: 5 });
    const values = hits.map((h) => h.value);
    expect(values).toContain('hello');
    expect(values).toContain('world!!');
    expect(values).not.toContain('ab');
  });

  it('records correct offsets', () => {
    const buf = bytes('\x00\x00secret\x00');
    const hit = extractStrings(buf, { minLength: 5 })[0];
    expect(hit?.offset).toBe(2);
    expect(hit?.value).toBe('secret');
  });
});

describe('classifySecret', () => {
  it('flags vendor default-credential markers', () => {
    expect(classifySecret('SYS_ADMPASS=admin').secretKind).toBe('vendor-default-credential');
    expect(classifySecret('WLN_WPAPSK1=12345678').severity).toBe('high');
  });

  it('flags private keys as critical', () => {
    const c = classifySecret('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(c.secretKind).toBe('private-key');
    expect(c.severity).toBe('critical');
  });

  it('flags AWS keys and connection strings', () => {
    expect(classifySecret('AKIAIOSFODNN7EXAMPLE').secretKind).toBe('aws-access-key');
    expect(classifySecret('mysql://root:hunter2@10.0.0.1/db').secretKind).toBe('connection-string');
  });

  it('flags password assignments', () => {
    expect(classifySecret('admin_password=letmein').secretKind).toBe('password-assignment');
  });

  it('returns empty for benign strings', () => {
    expect(classifySecret('just a normal log line').secretKind).toBeUndefined();
  });
});

describe('extractSecrets', () => {
  it('returns only secrets, sorted by severity', () => {
    const buf = bytes('noise here\x00admin_pass=abc123\x00-----BEGIN RSA PRIVATE KEY-----\x00more benign text here');
    const secrets = extractSecrets(buf, { minLength: 6 });
    expect(secrets.length).toBeGreaterThanOrEqual(2);
    // critical (private key) must sort before medium (password assignment).
    expect(secrets[0]?.severity).toBe('critical');
  });
});

/**
 * The bounds, stated.
 *
 * Measured against the deployed corpus before this existed: the 106 MB GL.iNet image hit the 20 000-string cap at
 * 11.0% of the file and the 34.5 MB Framework BIOS capsule at 92.5%, and both then rendered as "no secret-like
 * strings detected in the raw image". The walk runs from offset 0 upward, so its cap truncates by arrival order —
 * what it drops was never examined, and that is the one thing a bound here may not leave unsaid.
 */
describe('scanStrings — a cap that truncates says how far it got', () => {
  /** A buffer of `n` NUL-separated printable runs, so every run is its own string and the count is exact. */
  const runs = (n: number, word = 'secretish'): Uint8Array => {
    const parts: number[] = [];
    for (let i = 0; i < n; i++) {
      for (const ch of word) parts.push(ch.charCodeAt(0));
      parts.push(0);
    }
    return new Uint8Array(parts);
  };

  it('reports a complete walk as having reached the end — the path nobody checks', () => {
    const buf = runs(5);
    const scan = scanStrings(buf, { minLength: 5 });
    expect(scan.hits).toHaveLength(5);
    expect(scan.scannedBytes).toBe(buf.length);
    expect(scan.totalBytes).toBe(buf.length);
    // A complete scan is the case a reader is entitled to treat as covering the image.
    expect(scan.scannedBytes).toBe(scan.totalBytes);
  });

  it('stops at the cap and reports the offset it stopped at, not the buffer length', () => {
    const buf = runs(100);
    const scan = scanStrings(buf, { minLength: 5, maxStrings: 10 });
    expect(scan.hits).toHaveLength(10);
    expect(scan.totalBytes).toBe(buf.length);
    // The claim that matters: the walk did NOT read the rest, and says so.
    expect(scan.scannedBytes).toBeLessThan(scan.totalBytes);
    // The walk stops on the separator that ended the tenth run: nine characters plus one NUL, ten times over,
    // less the one byte it has not stepped past yet.
    expect(scan.scannedBytes).toBe(10 * ('secretish'.length + 1) - 1);
  });

  it('keeps extractStrings returning exactly what it always did', () => {
    const buf = runs(7);
    expect(extractStrings(buf, { minLength: 5 })).toEqual(scanStrings(buf, { minLength: 5 }).hits);
  });
});

describe('scanSecrets — two caps, two axes, both stated', () => {
  const withKeys = (n: number): Uint8Array => {
    const parts: number[] = [];
    for (let i = 0; i < n; i++) {
      for (const ch of '-----BEGIN RSA PRIVATE KEY-----') parts.push(ch.charCodeAt(0));
      parts.push(0);
    }
    return new Uint8Array(parts);
  };

  it('counts every match even when the listing cap drops some of them', () => {
    const scan = scanSecrets(withKeys(20), { minLength: 6 }, 5);
    expect(scan.secrets).toHaveLength(5);
    // The number that separates "none found" from "more than fit" survives the cap.
    expect(scan.matched).toBe(20);
  });

  it('never reports matches it did not list as zero, and never lists more than it matched', () => {
    const scan = scanSecrets(withKeys(3), { minLength: 6 }, 500);
    expect(scan.matched).toBe(3);
    expect(scan.secrets).toHaveLength(3);
  });

  it('carries the walk coverage through, so an empty result can say what it covered', () => {
    const buf = withKeys(100);
    const scan = scanSecrets(buf, { minLength: 6, maxStrings: 4 }, 500);
    expect(scan.scannedBytes).toBeLessThan(scan.totalBytes);
    // Four strings were read and all four were keys; the other 96 were never looked at.
    expect(scan.matched).toBe(4);
  });

  it('leaves extractSecrets uncapped, as its callers have always relied on', () => {
    expect(extractSecrets(withKeys(600), { minLength: 6 })).toHaveLength(600);
  });
});
