import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { runAuxSecrets } from './auxsecrets.js';

/**
 * Real key material, and that is the point of this edit.
 *
 * These fixtures used to be `-----BEGIN RSA PRIVATE KEY-----\nMIICabc\n-----END…` — armor around seven characters
 * that decode to nothing. They passed because the detector matched the MARKER, which is the same reason a
 * `libwolfssl` format string reads as a key: the old scanner could not tell a PEM block from the words that
 * spell one. Now that the detector decodes the body, a fake fixture fails — correctly — so the fixture has to be
 * a key. `PUB` is the public half of `RSA`, which makes the BeanView case below exact rather than approximate:
 * the same key pair, one half of it a secret and the other half not.
 *
 * Generated for these tests only (`openssl genrsa 1024`, then its SPKI public half). Not a credential.
 */
const RSA = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCbXuNIEpNWcjq88lQ1lWlXd1kU2S67TX0xits4GGWjZawrq6Ms
eizb7Gi8pu8Z2oB1KuY8fz0kDtx0gLYVlmZXDz6k22AYrJnfjHyb611PKFbR6Uo1
cARDO3cItB6w8cfb71EFL2fcg1al0Z31hbBODvTKeHIcYAvKHO9Ijs7pPwIDAQAB
AoGABEUKR+vCwshm1tRt/f76Ix4zg4AoaZtKinb/aT46ZNAheB3CYTGGVBDeG/kW
bwZzK0UfiKAShRAnfMgguN0mOMlKqF1qYsfS/MLVnPJAsiSP3Tu2FQCi5LA7GYaO
YMXK/jzTYt1fN+1uxoiPHbf57yJhlCiYeGNdmacHQIzL80ECQQDL2W0uXU9jhRV7
bvdbCmd+v/uJ7G+7xnwi2QjZdPh/Kki1gQEvkdAcl34aSfh/nvsQ2fUypW75uBks
Tz7wPmafAkEAwx56nWkZ/jRnccy261itNHZQ0XZnXGlemmyRdS+3AIH+tj3LUY6C
AN9Iybbhb02Tw93rR7M8a0239S/yTQuZYQJATmSAE0t5A0mjuEM1RsKaiGjmH+VY
Frs+89vJBm9wPN8S9RH2VcfaY5Ryv0NhGBsYbCOVovNx2QDOVXboOlWU+wJAHzUW
w2p1/9R93xOxBf9O5J8v2fCoI32u5eALe8S/7lLcXGWRyV+Tp3QO/kRD1juAMMmj
wfoG5dquW4bpqCz8wQJASX38vRM+1fnCU/Qs8mN7/vVvxiLL8vjkH+UVfwsUaGDk
s+q0B/YV4bkgTmF7RZUkbqpYxGEcSVYIOKLtFn8F1A==
-----END RSA PRIVATE KEY-----
`;

const PUB = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCbXuNIEpNWcjq88lQ1lWlXd1kU
2S67TX0xits4GGWjZawrq6Mseizb7Gi8pu8Z2oB1KuY8fz0kDtx0gLYVlmZXDz6k
22AYrJnfjHyb611PKFbR6Uo1cARDO3cItB6w8cfb71EFL2fcg1al0Z31hbBODvTK
eHIcYAvKHO9Ijs7pPwIDAQAB
-----END PUBLIC KEY-----
`;

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
