import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  NEUTER_TARGET,
  type NeuteredScan,
  classifyExtractedPath,
  neuteredFindings,
  scanNeutered,
  stageImpact,
} from './extract-neutered.js';

/**
 * The distinction this module exists for, stated as a test rather than as a comment: four of these states read as
 * ZERO BYTES through `readFileSync` and only one of them is a fact about the firmware.
 */
describe('classifyExtractedPath — the extractor’s doing, told apart from the vendor’s', () => {
  const facts = (o: Partial<Parameters<typeof classifyExtractedPath>[0]>) =>
    classifyExtractedPath({ rel: 'etc/passwd', exists: true, isSymlink: false, ...o });

  it('calls a /dev/null symlink NEUTERED, not empty — the pair the whole module turns on', () => {
    expect(facts({ isSymlink: true, target: NEUTER_TARGET, insideRoot: false })).toBe('neutered');
    // A real zero-byte file is the vendor's choice and reads identically to the caller.
    expect(facts({ bytes: 0 })).toBe('empty');
  });

  it('distinguishes a path that was never there from one that was cut', () => {
    expect(facts({ exists: false })).toBe('absent');
    expect(facts({ isSymlink: true, target: NEUTER_TARGET, insideRoot: false })).toBe('neutered');
  });

  it('judges a symlink on its TARGET before any size, which is the mistake being fixed', () => {
    // `statSync` on this path returns 0 bytes, and a classifier that looked at the size first would call it empty.
    expect(facts({ isSymlink: true, target: NEUTER_TARGET, insideRoot: false, bytes: 0 })).toBe('neutered');
  });

  it('keeps an escaping symlink separate from a neutered one, because its target survived', () => {
    expect(facts({ isSymlink: true, target: '/etc/hosts', insideRoot: false })).toBe('escapes');
  });

  it('follows an in-root symlink normally — this module is not about ordinary aliases', () => {
    expect(facts({ isSymlink: true, target: '../bin/busybox', insideRoot: true })).toBe('symlink-in-root');
  });

  it('reports an unreadable link and an unstattable file as unreadable, never as absent', () => {
    expect(facts({ isSymlink: true, target: undefined })).toBe('unreadable');
    expect(facts({ bytes: undefined })).toBe('unreadable');
  });
});

describe('stageImpact — which question went unasked, not merely which path was cut', () => {
  it('groups by the stage a cut path silently degrades, biggest group first', () => {
    const impact = stageImpact([
      { rel: 'sbin/netinit', state: 'neutered', target: NEUTER_TARGET },
      { rel: 'sbin/syshelper', state: 'neutered', target: NEUTER_TARGET },
      { rel: 'etc/passwd', state: 'neutered', target: NEUTER_TARGET },
    ]);
    expect(impact[0]?.paths).toEqual(['sbin/netinit', 'sbin/syshelper']);
    expect(impact[0]?.stage).toMatch(/ELF sweep/);
    expect(impact[1]?.stage).toMatch(/credential/);
  });

  it('says nothing about a path no stage reads, rather than inventing an impact', () => {
    expect(stageImpact([{ rel: 'mnt/custom', state: 'neutered', target: NEUTER_TARGET }])).toEqual([]);
  });
});

describe('neuteredFindings', () => {
  const scan = (entries: NeuteredScan['entries'], o: Partial<NeuteredScan> = {}): NeuteredScan => ({
    entries,
    scanned: 100,
    truncated: false,
    ...o,
  });

  it('emits nothing when nothing was cut — an unexplained silence needs no explanation here', () => {
    expect(neuteredFindings(scan([]))).toEqual([]);
  });

  it('reports a cut path as blocked_by_platform and refuses to call it empty or absent', () => {
    const [f] = neuteredFindings(scan([{ rel: 'etc/shadow', state: 'neutered', target: NEUTER_TARGET }]));
    expect(f?.proofState).toBe('blocked_by_platform');
    expect(f?.rationale).toMatch(/ZERO BYTES/);
    expect(f?.rationale).toMatch(/must not be read as a clean one/);
    // And it refuses the one claim it cannot make: what the link pointed at.
    expect(f?.rationale).toMatch(/not recoverable from the extracted tree/);
  });

  it('states the bound when the survey was truncated, so a floor cannot read as a total', () => {
    const [f] = neuteredFindings(
      scan([{ rel: 'etc/shadow', state: 'neutered', target: NEUTER_TARGET }], {
        truncated: true,
        truncatedReason: 'the 20000-entry walk budget was exhausted',
      }),
    );
    expect(f?.rationale).toMatch(/floor on the count and not the count/);
  });

  it('separates escaping symlinks into their own finding, and reports their targets', () => {
    const drafts = neuteredFindings(
      scan([
        { rel: 'etc/shadow', state: 'neutered', target: NEUTER_TARGET },
        { rel: 'etc/resolv.conf', state: 'escapes', target: '/tmp/resolv.conf' },
      ]),
    );
    expect(drafts.map((d) => d.kind)).toEqual(['extract-neutered-paths', 'extract-escaping-symlinks']);
    const esc = drafts[1];
    expect(JSON.stringify(esc?.evidence)).toContain('/tmp/resolv.conf');
    expect(esc?.rationale).toMatch(/target survived/);
  });
});

describe('scanNeutered — the thin walk', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'neutered-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('finds a cut path, an escaping one, and leaves ordinary files and aliases alone', () => {
    const root = path.join(tmp, 'rootfs');
    fs.mkdirSync(path.join(root, 'etc'), { recursive: true });
    fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(root, 'bin/busybox'), 'x');
    fs.writeFileSync(path.join(root, 'etc/inittab'), 'console::respawn:/bin/sh');
    // A real zero-byte file: the vendor's own, and it must NOT be reported.
    fs.writeFileSync(path.join(root, 'etc/empty.conf'), '');
    fs.symlinkSync(NEUTER_TARGET, path.join(root, 'etc/passwd'));
    fs.symlinkSync('/somewhere/else', path.join(root, 'etc/hosts'));
    fs.symlinkSync('../bin/busybox', path.join(root, 'bin/sh'));

    const s = scanNeutered(root);
    expect(s.entries).toEqual([
      { rel: 'etc/hosts', state: 'escapes', target: '/somewhere/else' },
      { rel: 'etc/passwd', state: 'neutered', target: NEUTER_TARGET },
    ]);
    expect(s.truncated).toBe(false);
    expect(s.scanned).toBeGreaterThan(0);
  });

  it('returns an empty scan for a path that is not a directory, without throwing', () => {
    expect(scanNeutered(path.join(tmp, 'nope'))).toEqual({ entries: [], scanned: 0, truncated: false });
  });

  /**
   * `entries: []` after a real walk and `entries: []` because nothing was walked are different facts, and `scanned`
   * is the only thing that separates them — the same shape as every other "asked and found nothing" vs "never
   * asked" pair in this codebase.
   */
  it('separates “walked and found none” from “never walked”, via scanned', () => {
    const clean = path.join(tmp, 'clean');
    fs.mkdirSync(path.join(clean, 'etc'), { recursive: true });
    fs.writeFileSync(path.join(clean, 'etc/ok.conf'), 'x');
    const walked = scanNeutered(clean);
    const never = scanNeutered(path.join(tmp, 'does-not-exist'));
    expect(walked.entries).toEqual([]);
    expect(never.entries).toEqual([]);
    expect(walked.scanned).toBeGreaterThan(0);
    expect(never.scanned).toBe(0);
    // And neither produces a finding, because neither has anything to explain.
    expect(neuteredFindings(walked)).toEqual([]);
    expect(neuteredFindings(never)).toEqual([]);
  });
});
