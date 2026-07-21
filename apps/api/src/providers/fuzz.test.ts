import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { buildAflDict, buildFuzzCommand, chooseHarness, detectDesockPreload, isNetworkDaemon } from './fuzz.js';

describe('buildFuzzCommand', () => {
  it('builds an AFL++ qemu-mode, time-bounded invocation with file input (@@) by default', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/parser', '/w/seeds', '/w/out', 60);
    expect(cmd[0]).toBe('afl-fuzz');
    expect(cmd).toContain('-Q'); // binary-only qemu mode
    expect(cmd[cmd.indexOf('-V') + 1]).toBe('60');
    expect(cmd.slice(-2)).toEqual(['/rootfs/bin/parser', '@@']);
  });

  it('drops @@ for a stdin harness so AFL feeds the testcase on stdin', () => {
    const cmd = buildFuzzCommand('/rootfs/sbin/httpd', '/w/seeds', '/w/out', 60, { stdin: true });
    expect(cmd[cmd.length - 1]).toBe('/rootfs/sbin/httpd');
    expect(cmd).not.toContain('@@');
  });

  it('disables the memory limit (qemu mode forks die under an AS cap)', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/parser', '/w/seeds', '/w/out', 60);
    expect(cmd[cmd.indexOf('-m') + 1]).toBe('none');
  });

  it('includes a dictionary when supplied and omits it otherwise', () => {
    const withDict = buildFuzzCommand('/b', '/s', '/o', 30, { dictPath: '/w/dict.txt' });
    expect(withDict[withDict.indexOf('-x') + 1]).toBe('/w/dict.txt');
    expect(buildFuzzCommand('/b', '/s', '/o', 10)).not.toContain('-x');
  });
});

describe('chooseHarness / isNetworkDaemon', () => {
  it('routes network daemons and CGI to the desock (network) harness', () => {
    expect(chooseHarness('usr/sbin/httpd')).toBe('network');
    expect(chooseHarness('bin/dropbear')).toBe('network');
    expect(chooseHarness('www/cgi-bin/status.cgi')).toBe('network');
    expect(isNetworkDaemon('usr/sbin/telnetd')).toBe(true);
  });

  it('defaults everything else to the file (@@) harness', () => {
    expect(chooseHarness('bin/jsonparse')).toBe('file');
    expect(chooseHarness('usr/bin/libxml2test')).toBe('file');
    expect(isNetworkDaemon('bin/busybox')).toBe(false);
  });
});

describe('detectDesockPreload', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-desock-'));
  const lib = path.join(tmp, 'libdesock.so');
  fs.writeFileSync(lib, '');
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('returns the preload path when FIRMLAB_DESOCK points at an existing lib', () => {
    expect(detectDesockPreload({ FIRMLAB_DESOCK: lib })).toBe(lib);
  });

  it('returns null when unset or missing (→ honest degradation)', () => {
    expect(detectDesockPreload({})).toBeNull();
    expect(detectDesockPreload({ FIRMLAB_DESOCK: path.join(tmp, 'nope.so') })).toBeNull();
  });
});

describe('buildAflDict', () => {
  it('emits AFL dictionary entries for printable strings, deduped', () => {
    const d = buildAflDict(['admin', 'admin', 'password', 'ab']).split('\n');
    expect(d).toHaveLength(2); // 'ab' too short, 'admin' deduped
    expect(d[0]).toMatch(/^fw_0="admin"$/);
    expect(d[1]).toMatch(/^fw_1="password"$/);
  });

  it('strips non-printable bytes and escapes quotes/backslashes', () => {
    const d = buildAflDict(['a\x00b"c\\d']);
    expect(d).toBe('fw_0="ab\\"c\\\\d"');
  });
});
