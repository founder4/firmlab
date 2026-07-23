import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { runAuxSecrets } from './auxsecrets.js';

const RSA = '-----BEGIN RSA PRIVATE KEY-----\nMIICabc\n-----END RSA PRIVATE KEY-----\n';
const PUB = '-----BEGIN PUBLIC KEY-----\nMIIBIjANabc\n-----END PUBLIC KEY-----\n';

describe('runAuxSecrets (sibling-partition scan)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'auxsec-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('degrades honestly when there is no extraction output', () => {
    expect(runAuxSecrets(null, null).available).toBe(false);
    expect(runAuxSecrets(`${tmp}/does-not-exist`, null).available).toBe(false);
  });

  it('finds an RSA key in a sibling partition but SKIPS the recognized rootfs subtree', () => {
    const out = path.join(tmp, 'ext');
    // Recognized rootfs (fsaudit covers it) — a key here must NOT be double-reported by the aux scan.
    const rootfs = path.join(out, '_img.extracted', 'jffs2-root');
    fs.mkdirSync(path.join(rootfs, 'etc'), { recursive: true });
    fs.writeFileSync(path.join(rootfs, 'etc', 'ssl.key'), RSA);
    // Sibling config partition (the Tenda shape) — NOT a rootfs, holds the real private key.
    const sibling = path.join(out, '_img.extracted', 'jffs2-root-0', 'version');
    fs.mkdirSync(sibling, { recursive: true });
    fs.writeFileSync(path.join(sibling, 'privkey.pem'), RSA);
    fs.writeFileSync(path.join(sibling, 'cacert.pem'), PUB); // public key/cert → not a secret

    const r = runAuxSecrets(out, rootfs);
    expect(r.available).toBe(true);
    const keys = r.findings.filter((f) => f.kind === 'embedded-private-key');
    expect(keys).toHaveLength(1); // the sibling privkey.pem only — the rootfs key is skipped, the public key ignored
    expect(keys[0]?.title).toContain('jffs2-root-0/version/privkey.pem');
    expect(keys[0]?.severity).toBe('high');
  });

  it('scans the whole output when no rootfs was recognized (BeanView shape)', () => {
    const out = path.join(tmp, 'ext2', '_img.extracted', 'jffs2-root');
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, 'private_key.pem'), PUB); // BeanView: actually a PUBLIC key → not flagged
    fs.writeFileSync(path.join(out, 'real.key'), RSA);
    const r = runAuxSecrets(path.join(tmp, 'ext2'), null);
    expect(r.findings.filter((f) => f.kind === 'embedded-private-key')).toHaveLength(1); // real.key only
  });
});
