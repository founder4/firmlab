import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  auditAccountSources,
  auditCredentials,
  auditInittab,
  auditServiceConfigs,
  inspectAccountFile,
  keyMaterialFindings,
  notableFiles,
  runFsAudit,
  scanContentSecrets,
  unclaimedKeyBlockFindings,
} from './fsaudit.js';
import type { AccountFileState, AccountSource } from './fsaudit.js';
import type { PemBlock } from './pem-scan.js';
import { findPemBlocks, readPrivateKeyBlock } from './pem-scan.js';

// A UID-0 root that defers its password to /etc/shadow, plus a normal daemon account.
const PASSWD = 'root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n';

// STATIC key material generated for these tests only (`openssl genrsa 1024`, `openssl ecparam -genkey`, and the
// same RSA key re-emitted encrypted). Real bytes on purpose: this provider must decide what a block IS by
// decoding it, so a fixture that only LOOKS like a key would test the opposite of what matters.
const RSA_KEY = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`;

const EC_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMnKvCNhfc2dphEJ4Lu1Hc23eKCVLCFxWERzpx53Em0HoAoGCCqGSM49
AwEHoUQDQgAEsDgQ1td4rd00bUluvh9sSP25M/r3G7NEr5QqiEMSzPp1ARYrAk0g
Uo/GdmR1u1+TpcvdqoqZnpfjLHtoIbdHJQ==
-----END EC PRIVATE KEY-----`;

const ENCRYPTED_KEY = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC5TBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQLfJFt9Y155cqAurq
LWxrXAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEECdBZ7NCjdsJqDEE
Fg8BcCcEggKAC058Xse5xI+SCFoGuEuas2qdGDzss4+GUn3yxTCSnUn+dsR75kRr
DhLmhjfxs9AYjgVSk+GS6Y954FB+FG8j6KPJZNWNd39CJWuv3E7Dz6IJbb+olKd+
Qk7EMgQ/Kn4eYJNKX0hM8h2qIaT1Q092WsELq6L8COxOqeRSqDDhhXSOUQ8zXBTZ
f7deq9B8ZvHUHXk9Tr8pZx1wIIBsCbt4qgMo1HfNZs1uV5BCEaR7p10cVGrmlLYS
HxqTTy7Kps8hrJMC/6JGlUMtuxIpRfsMStKyKKpcpIlG/1gFUWk4yicROFLDNyp/
tEbAyfCcmsToimlnNJMq6Heg4Wu8YSxIoXwAQ3g5VY8+Bg9EMaqA/b2ifMo5Lhdd
8D30zQKyfoP66EVcYpgLWQBlM4qnKPr9LaVQ99/Y48hm8i3jARmM6sQ/m3BOON5M
jgeYWE0R2tOqeMbOwTCDnkAJgloSamyRyoIoDssbXnDSzD8fwFCRAXUsbY0UpjRr
U1Cwc9Ibgua0bmNsqTEzh6KH4Zy5PV96bzU2S7OYL0ry0HEF+XTr1JSS8eHxkSaj
pdhlC4DR66Ob70dEnigeQIBa/WRslj7GpE3EZuSY1tq5KYlmGIpsqGhpLg5swY5v
9qhiZmkkulFBAtJmzt2l89/86085Dy033oMVw+V9R445E2iBtSzcK5EMJR+5vJHA
HR0G4N4DAzWJF2FPTMETY8iP+31vY/RWymUC9XUhprbw73avY6EyeMmm4QmatRA+
yfMabv4uhnR3A+SvAhM164zmfoUdBOrO+Tk0HdbYfdXxEjQ3ttZVyyMQzeJCr9s6
CzVUEhev4MEUwIVXCy0wECQ0NktwAiPuXg==
-----END ENCRYPTED PRIVATE KEY-----`;

// A documentation placeholder: the label of a key, none of the substance. This shape is why the provider must
// open the block — the project already had to withdraw one claim made on a filename alone.
const PLACEHOLDER_KEY =
  '-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCbXuNIEpNWcjq88lQ1lWlX\n-----END RSA PRIVATE KEY-----';

describe('auditCredentials', () => {
  it('flags an empty root password (root:: in shadow) as CRITICAL static_confirmed', () => {
    const drafts = auditCredentials(PASSWD, 'root::19000:0:99999:7:::\n');
    const empty = drafts.find((d) => d.kind === 'empty-uid0-password');
    expect(empty?.severity).toBe('critical');
    expect(empty?.proofState).toBe('static_confirmed');
    expect((empty?.evidence as { account: string }).account).toBe('root');
  });

  it('flags an MD5 ($1$) shadow hash as HIGH and REDACTS the hash value', () => {
    const shadow = 'root:$1$abcdefgh$0123456789abcdefABCDEF01:19000:0:99999:7:::\n';
    const drafts = auditCredentials(PASSWD, shadow);
    const weak = drafts.find((d) => d.kind === 'weak-password-hash');
    expect(weak?.severity).toBe('high');
    expect(weak?.proofState).toBe('static_confirmed');
    // The real hash body must never appear in the evidence — it is redacted.
    expect(JSON.stringify(weak?.evidence)).not.toContain('0123456789abcdefABCDEF01');
    expect(JSON.stringify(weak?.evidence)).toContain('<redacted>');
  });

  it('flags a 13-char DES crypt hash as HIGH', () => {
    const drafts = auditCredentials(PASSWD, 'admin:ab1234567890X:19000:0:99999:7:::\n');
    const weak = drafts.find((d) => d.kind === 'weak-password-hash');
    expect(weak?.severity).toBe('high');
    expect((weak?.evidence as { scheme: string }).scheme).toMatch(/DES/);
  });

  it('flags a second UID-0 account besides root as HIGH', () => {
    const passwd = 'root:x:0:0:root:/root:/bin/sh\nbackdoor:x:0:0::/root:/bin/sh\n';
    const drafts = auditCredentials(passwd, '');
    const extra = drafts.find((d) => d.kind === 'extra-uid0-account');
    expect(extra?.severity).toBe('high');
    expect(extra?.title).toContain('backdoor');
  });

  it('does not flag a strong $6$ hash or an empty/absent shadow', () => {
    const strong = auditCredentials(PASSWD, 'root:$6$salt$longsha512hashvalue:19000:0:99999:7:::\n');
    expect(strong.some((d) => d.kind === 'weak-password-hash')).toBe(false);
    // pw='x' with no shadow entry → cannot confirm empty, so nothing is claimed.
    expect(auditCredentials(PASSWD, '')).toHaveLength(0);
  });
});

describe('auditInittab', () => {
  it('flags a bare root shell (::respawn:/bin/sh) as HIGH needs_runtime_reproduction', () => {
    const drafts = auditInittab('::sysinit:/etc/init.d/rcS\n::respawn:/bin/sh\n');
    const shell = drafts.find((d) => d.kind === 'inittab-root-shell');
    expect(shell?.severity).toBe('high');
    expect(shell?.proofState).toBe('needs_runtime_reproduction');
    // The normal sysinit line must not be flagged.
    expect(drafts).toHaveLength(1);
  });

  it('flags a getty that skips login (-n / -l /bin/sh)', () => {
    const drafts = auditInittab('::respawn:/sbin/getty -n -l /bin/sh 115200 ttyS0\n');
    expect(drafts.some((d) => d.kind === 'inittab-root-shell')).toBe(true);
  });

  it('flags an init-spawned telnetd', () => {
    const drafts = auditInittab('::respawn:/usr/sbin/telnetd -l /bin/sh\n');
    expect(drafts.some((d) => d.kind === 'inittab-telnetd' && d.severity === 'high')).toBe(true);
  });

  it('does not flag a normal getty', () => {
    expect(auditInittab('::respawn:/sbin/getty 38400 tty1\n')).toHaveLength(0);
  });
});

describe('auditServiceConfigs', () => {
  it('flags dropbear/sshd with PermitRootLogin yes + PermitEmptyPasswords yes as HIGH', () => {
    const files = [{ path: 'etc/dropbear/dropbear.conf', content: 'PermitRootLogin yes\nPermitEmptyPasswords yes\n' }];
    const drafts = auditServiceConfigs(files);
    const hit = drafts.find((d) => d.kind === 'ssh-permit-root-empty');
    expect(hit?.severity).toBe('high');
    expect(hit?.proofState).toBe('static_confirmed');
  });

  it('does not flag when only one of the two directives is present', () => {
    const files = [{ path: 'etc/ssh/sshd_config', content: 'PermitRootLogin yes\nPermitEmptyPasswords no\n' }];
    expect(auditServiceConfigs(files).some((d) => d.kind === 'ssh-permit-root-empty')).toBe(false);
  });

  it('flags telnetd in an rc script as MEDIUM needs_runtime_reproduction', () => {
    const files = [{ path: 'etc/init.d/S50telnet', content: '#!/bin/sh\ntelnetd -l /bin/sh &\n' }];
    const hit = auditServiceConfigs(files).find((d) => d.kind === 'rc-telnetd');
    expect(hit?.severity).toBe('medium');
    expect(hit?.proofState).toBe('needs_runtime_reproduction');
  });

  it('flags anonymous ftp as MEDIUM', () => {
    const files = [{ path: 'etc/vsftpd.conf', content: 'listen=YES\nanonymous_enable=YES\n' }];
    expect(auditServiceConfigs(files).some((d) => d.kind === 'anon-ftp' && d.severity === 'medium')).toBe(true);
  });
});

describe('notableFiles', () => {
  const drafts = notableFiles([
    'etc/dropbear/id_rsa',
    'root/.ssh/authorized_keys',
    'var/lib/capture.pcap',
    'usr/bin/busybox',
  ]);

  it('flags a private key, authorized_keys and a pcap — all static_confirmed leads', () => {
    expect(drafts.find((d) => d.kind === 'notable-private-key')?.title).toContain('id_rsa');
    expect(drafts.some((d) => d.kind === 'notable-authorized-keys')).toBe(true);
    expect(drafts.some((d) => d.kind === 'notable-pcap')).toBe(true);
    expect(drafts.every((d) => d.proofState === 'static_confirmed')).toBe(true);
  });

  it('does not flag an ordinary binary', () => {
    expect(drafts.some((d) => d.title.includes('busybox'))).toBe(false);
  });
});

describe('runFsAudit', () => {
  it('degrades honestly to available:false on a nonexistent rootfs path', () => {
    const res = runFsAudit('/nonexistent/rootfs/path/does-not-exist');
    expect(res.available).toBe(false);
    expect(res.findings).toHaveLength(0);
    expect(res.filesScanned).toBe(0);
    expect(res.reason).toMatch(/run extraction first/i);
  });

  it('audits a real extracted rootfs directory end-to-end', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-fsaudit-'));
    try {
      fs.mkdirSync(path.join(dir, 'etc/dropbear'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'root/.ssh'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'etc/passwd'), 'root:x:0:0:root:/root:/bin/sh\n');
      fs.writeFileSync(path.join(dir, 'etc/shadow'), 'root::19000:0:99999:7:::\n');
      fs.writeFileSync(path.join(dir, 'etc/inittab'), '::respawn:/bin/sh\n');
      fs.writeFileSync(path.join(dir, 'etc/dropbear/id_rsa'), '-----BEGIN RSA PRIVATE KEY-----\n');
      fs.writeFileSync(path.join(dir, 'root/.ssh/authorized_keys'), 'ssh-rsa AAAA...\n');

      const res = runFsAudit(dir);
      expect(res.available).toBe(true);
      expect(res.filesScanned).toBeGreaterThan(0);
      const kinds = res.findings.map((f) => f.kind);
      expect(kinds).toContain('empty-uid0-password');
      expect(kinds).toContain('inittab-root-shell');
      expect(kinds).toContain('notable-private-key');
      expect(kinds).toContain('notable-authorized-keys');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('readPrivateKeyBlock — open the block before naming it', () => {
  /** The single block a fixture is supposed to contain — throwing here means the fixture itself is wrong. */
  const block = (pem: string): PemBlock => {
    const b = findPemBlocks(pem)[0];
    if (!b) throw new Error('fixture contains no complete PEM block');
    return b;
  };

  it('decodes a real RSA key and reports the algorithm and strength from the key itself', () => {
    expect(readPrivateKeyBlock(block(RSA_KEY))).toMatchObject({
      isKey: true,
      keyType: 'rsa',
      keyBits: 1024,
      encrypted: false,
    });
  });

  it('decodes an EC key with its curve', () => {
    expect(readPrivateKeyBlock(block(EC_KEY))).toMatchObject({
      isKey: true,
      keyType: 'ec',
      namedCurve: 'prime256v1',
      keyBits: 256,
    });
  });

  it('accepts an encrypted key block as key material without attempting the passphrase', () => {
    expect(readPrivateKeyBlock(block(ENCRYPTED_KEY))).toMatchObject({ isKey: true, encrypted: true, keyType: null });
  });

  it('refuses a placeholder body that carries a key label and nothing else', () => {
    const read = readPrivateKeyBlock(block(PLACEHOLDER_KEY));
    expect(read.isKey).toBe(false);
    expect(read.note).toMatch(/did not decode/);
  });
});

describe('keyMaterialFindings (private key by content, not filename)', () => {
  const hits = (path: string, content: string) => [{ path, blocks: findPemBlocks(content) }];

  it('flags a decoded RSA private key regardless of filename, with its shape and never its body', () => {
    const drafts = scanContentSecrets([{ path: 'etc/config/device.conf', content: `foo=bar\n${RSA_KEY}\n` }]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('embedded-private-key');
    expect(drafts[0]?.severity).toBe('high');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(drafts[0]?.title).toBe('Embedded RSA 1024-bit private key in firmware: etc/config/device.conf');
    expect(drafts[0]?.evidence).toMatchObject({ keyCount: 1, keys: [{ keyType: 'rsa', keyBits: 1024 }] });
    // The key body must NOT leak into evidence.
    expect(JSON.stringify(drafts[0]?.evidence)).not.toContain('MIICWwIBAAKBgQ');
  });

  it('does not claim a placeholder block as a key — it returns it as unclaimed instead', () => {
    const { findings, unclaimed } = keyMaterialFindings(hits('etc/example.conf', PLACEHOLDER_KEY));
    expect(findings).toEqual([]);
    expect(unclaimed).toHaveLength(1);
    expect(unclaimed[0]?.label).toBe('RSA PRIVATE KEY');
  });

  it('drops to MEDIUM for a passphrase-protected key and says why', () => {
    const drafts = scanContentSecrets([{ path: 'etc/ssl/server.key', content: ENCRYPTED_KEY }]);
    expect(drafts[0]?.severity).toBe('medium');
    expect(drafts[0]?.title).toContain('encrypted');
    expect(drafts[0]?.rationale).toMatch(/passphrase/);
  });

  it('dedupes per file: a two-key bundle is one finding that counts both', () => {
    const drafts = scanContentSecrets([{ path: 'etc/keys.pem', content: `${RSA_KEY}\n${EC_KEY}\n` }]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.evidence).toMatchObject({ keyCount: 2 });
    expect(drafts[0]?.title).toContain('2 blocks');
  });

  it('does not flag a public key, a certificate or DH parameters', () => {
    const publicKey = [
      '-----BEGIN PUBLIC KEY-----',
      'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJte40gSk1ZyOrzyVDWVaVd3WRTZLrtN',
      'fTGK2zgYZaNlrCuroyx6LNvsaLym7xnagHUq5jx/PSQO3HSAthWWZlcCAwEAAQ==',
      '-----END PUBLIC KEY-----',
    ].join('\n');
    const dhParams = [
      '-----BEGIN DH PARAMETERS-----',
      'MIGHAoGBAIbWb6fGbivhtqbMuJTofsFHrHcD0m8cFh2eDU4VEnjSJvoKr/gYOxfP',
      'mROD3fJ2mWOyKxr91IbgGrhsbrrEKaAv/jV/0XRMYoIb+7fBprfgAu3ux+rAFbKj',
      '-----END DH PARAMETERS-----',
    ].join('\n');
    expect(scanContentSecrets([{ path: 'x', content: publicKey }])).toHaveLength(0);
    expect(scanContentSecrets([{ path: 'y', content: '-----BEGIN CERTIFICATE-----' }])).toHaveLength(0);
    // Measured beside the real key in the WR940N's httpd: parameters are not a secret.
    expect(scanContentSecrets([{ path: 'z', content: dhParams }])).toHaveLength(0);
  });
});

describe('unclaimedKeyBlockFindings', () => {
  it('reports the blocks it refused to claim, so zero keys is not read as zero key-shaped bytes', () => {
    const drafts = unclaimedKeyBlockFindings([
      { path: 'usr/lib/libgnutls.so', label: 'EC PRIVATE KEY', offset: 1_447_091, note: 'body did not decode' },
      { path: 'usr/lib/libgnutls.so', label: 'PRIVATE KEY', offset: 1_451_249, note: 'body did not decode' },
    ]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('pem-block-unclaimed');
    expect(drafts[0]?.severity).toBe('info');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(drafts[0]?.evidence).toMatchObject({ count: 2, files: 1 });
    expect(drafts[0]?.rationale).toMatch(/without claiming them/);
  });

  it('says nothing when there is nothing to say', () => {
    expect(unclaimedKeyBlockFindings([])).toEqual([]);
  });
});

describe('runFsAudit — the key lane over real files', () => {
  it('surfaces a key inside a 700 KB binary with no telling extension, and reports its bound', () => {
    // The measured defect: the content scan only ever saw files whose extension was whitelisted (plus
    // extensionless files under etc/), read to 512 KB — so the WR940N's 1.9 MB usr/bin/httpd, which carries a
    // complete RSA key in plain PEM, was unreachable and the audit reported nothing.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsaudit-binkey-'));
    try {
      fs.mkdirSync(path.join(dir, 'usr/bin'), { recursive: true });
      fs.writeFileSync(
        path.join(dir, 'usr/bin/httpd'),
        Buffer.concat([Buffer.alloc(700 * 1024), Buffer.from(`${RSA_KEY}\n`, 'latin1'), Buffer.alloc(4096)]),
      );
      const r = runFsAudit(dir);
      const hit = r.findings.find((f) => f.kind === 'embedded-private-key');
      expect(hit?.title).toContain('usr/bin/httpd');
      expect(hit?.evidence).toMatchObject({ keys: [{ keyType: 'rsa', keyBits: 1024, offset: 700 * 1024 }] });
      expect(r.scan?.filesScanned).toBe(1);
      expect(r.scan?.bytesUnread).toBe(0);
      expect(r.reason).toMatch(/Read every byte of all 1 file\(s\)/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('surfaces an embedded key in an innocuously-named file under etc/', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsaudit-key-'));
    try {
      fs.mkdirSync(path.join(dir, 'etc'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'etc', 'server.pem'), `${RSA_KEY}\n`);
      const r = runFsAudit(dir);
      expect(r.findings.some((f) => f.kind === 'embedded-private-key')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('auditAccountSources — the four ways an account file is silent', () => {
  const src = (p: string, state: AccountFileState): AccountSource => ({ path: p, state });

  it('flags the DVRF case: the whole account database symlinked out of the filesystem', () => {
    // The real DVRF rootfs points passwd/shadow/group/gshadow at /dev/null; every read returns '' and every
    // credential check then passes, which is how a bit-bucket reads as a clean bill of health.
    const out = auditAccountSources([
      src('etc/passwd', { state: 'symlink-escapes', target: '/dev/null' }),
      src('etc/shadow', { state: 'symlink-escapes', target: '/dev/null' }),
      src('etc/group', { state: 'symlink-escapes', target: '/dev/null' }),
      src('etc/gshadow', { state: 'symlink-escapes', target: '/dev/null' }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]?.kind).toBe('account-db-redirected');
    expect(out[0]?.proofState).toBe('static_confirmed');
    expect(out[0]?.title).toContain('/dev/null');
    // The claim that matters: an empty credential list here is a gap, not a negative.
    expect(out[0]?.rationale).toMatch(/not a clean result/i);
  });

  it('stays quiet on an ordinary rootfs that simply has no gshadow', () => {
    const out = auditAccountSources([
      src('etc/passwd', { state: 'present', bytes: 420 }),
      src('etc/shadow', { state: 'present', bytes: 310 }),
      src('etc/group', { state: 'present', bytes: 200 }),
      src('etc/gshadow', { state: 'absent' }),
    ]);
    expect(out).toEqual([]);
  });

  it('reports blocked_by_platform when nothing could be read at all', () => {
    const out = auditAccountSources([
      src('etc/passwd', { state: 'absent' }),
      src('etc/shadow', { state: 'absent' }),
      src('etc/group', { state: 'empty' }),
      src('etc/gshadow', { state: 'unreadable', reason: 'target could not be stat-ed' }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]?.proofState).toBe('blocked_by_platform');
    expect(out[0]?.rationale).toMatch(/never that the accounts are sound/i);
  });

  it('does not double-report: a redirected database is not also "nothing readable"', () => {
    const out = auditAccountSources([
      src('etc/passwd', { state: 'symlink-escapes', target: '/dev/null' }),
      src('etc/shadow', { state: 'absent' }),
    ]);
    expect(out.map((d) => d.kind)).toEqual(['account-db-redirected']);
  });
});

describe('inspectAccountFile', () => {
  it('separates an escaping symlink from an in-root one, and from a real file', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'acct-'));
    fs.mkdirSync(path.join(root, 'etc'), { recursive: true });
    fs.writeFileSync(path.join(root, 'etc', 'group'), 'root:x:0:\n');
    fs.symlinkSync('/dev/null', path.join(root, 'etc', 'passwd'));
    fs.symlinkSync('group', path.join(root, 'etc', 'shadow')); // in-root symlink: followed normally
    fs.writeFileSync(path.join(root, 'etc', 'gshadow'), '');

    expect(inspectAccountFile(root, 'etc/passwd')).toEqual({ state: 'symlink-escapes', target: '/dev/null' });
    expect(inspectAccountFile(root, 'etc/shadow').state).toBe('present');
    expect(inspectAccountFile(root, 'etc/group').state).toBe('present');
    expect(inspectAccountFile(root, 'etc/gshadow')).toEqual({ state: 'empty' });
    expect(inspectAccountFile(root, 'etc/nope')).toEqual({ state: 'absent' });
  });
});

/**
 * A real certificate FOR `RSA_KEY` above — the pair matters, not the shape. `keyMaterialFindings` compares the two
 * public halves byte for byte, so a fixture whose certificate merely looked plausible would assert nothing.
 */
const CERT_FOR_RSA_KEY = `-----BEGIN CERTIFICATE-----
MIICGjCCAYOgAwIBAgIUaz9DP2bDaJGN3nr2TuQhB6Qn2rEwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUZmlybWxhYi1wYWlyaW5nLXRlc3QwHhcNMjYwODAzMTky
NzE3WhcNMzYwNzMxMTkyNzE3WjAfMR0wGwYDVQQDDBRmaXJtbGFiLXBhaXJpbmct
dGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAm17jSBKTVnI6vPJUNZVp
V3dZFNkuu019MYrbOBhlo2WsK6ujLHos2+xovKbvGdqAdSrmPH89JA7cdIC2FZZm
Vw8+pNtgGKyZ34x8m+tdTyhW0elKNXAEQzt3CLQesPHH2+9RBS9n3INWpdGd9YWw
Tg70ynhyHGALyhzvSI7O6T8CAwEAAaNTMFEwHQYDVR0OBBYEFBuHaVjSsH8hgh9i
EPAEbIn4awbcMB8GA1UdIwQYMBaAFBuHaVjSsH8hgh9iEPAEbIn4awbcMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEARWx3npUGiks/X3njr8GvdUMJ
0dLbqVry8I6ql/nJJNajEZcU7uPh0hzNKcJ5ZkM0uOnLdDlXHpfW2Xm6zoU4XWO5
x7O3ZO+Nw4NIiPZ0fItXCVvdtafhGJMfwnqbIjsCB6YXh/Oniy3MG7f0IOC1fpj2
Mz5bKwXg2tj+b6hbExY=
-----END CERTIFICATE-----`;

/** A certificate for a DIFFERENT key — the negative control, without which the pairing test proves nothing. */
const UNRELATED_CERT = `-----BEGIN CERTIFICATE-----
MIICFjCCAX+gAwIBAgIUKibSPh5JaC++fNM8lqca1WMRKlkwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSdW5yZWxhdGVkLWlkZW50aXR5MB4XDTI2MDgwMzE5Mjky
NVoXDTM2MDczMTE5MjkyNVowHTEbMBkGA1UEAwwSdW5yZWxhdGVkLWlkZW50aXR5
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYCoAePiZeVQR30lYVCDou+m1w
jUprduEf4vn2DOAEc5ugaySJ0sTs24HM8/zLnY5zNmekrW/kN2otSsF5CyLzLY0X
B7ohlCKem1bkIb5KmDhnWO+7XmtPzd4DbNpf/t0HQ8ua34aYZsAPhmHwRIK5nLT4
puV0Jtb4xfNGVZbEywIDAQABo1MwUTAdBgNVHQ4EFgQUlmrVnq9spsAE5p+ytcm9
8pV7rs4wHwYDVR0jBBgwFoAUlmrVnq9spsAE5p+ytcm98pV7rs4wDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQAoc8cdJRZfm8kcp87C2gPYOHgpbf0t
OEs4WBY2r9RQH+N3I/WUOQMUYYza//d8MvOxQWyiN9uf2F/0TVBk5vh8+w9VUFJR
DncCSro4rTPqk9b8W2rCPpIU2Bo2tWSXunfGlvBFFvcFduy8ZEBrBYXXOYAH1SJB
hxNaR/rKZ+ZwNA==
-----END CERTIFICATE-----`;

describe('keyMaterialFindings — the key beside its own certificate', () => {
  it('calls the shipped identity forgeable when the key opens the certificate in the same file', () => {
    const blocks = findPemBlocks(`${RSA_KEY}\n${CERT_FOR_RSA_KEY}\n`);
    const { findings } = keyMaterialFindings([{ path: 'usr/bin/httpd', blocks }]);
    const pair = findings.find((f) => f.kind === 'private-key-matches-shipped-certificate');
    expect(pair?.severity).toBe('critical');
    expect(pair?.proofState).toBe('static_confirmed');
    expect(pair?.title).toContain('forgeable');
    expect(pair?.title).toContain('firmlab-pairing-test');
    // The pair is established by comparing exported public halves, so the rationale must not overclaim runtime.
    expect(pair?.rationale).toContain('does NOT say');
    // And the plain "there is a key here" row still stands beside it — two claims, two rows.
    expect(findings.some((f) => f.kind === 'embedded-private-key')).toBe(true);
  });

  it('makes no pairing claim when the certificate in the file belongs to a different key', () => {
    const blocks = findPemBlocks(`${RSA_KEY}\n${UNRELATED_CERT}\n`);
    const { findings } = keyMaterialFindings([{ path: 'etc/ssl/mixed.pem', blocks }]);
    expect(findings.some((f) => f.kind === 'private-key-matches-shipped-certificate')).toBe(false);
    expect(findings.some((f) => f.kind === 'embedded-private-key')).toBe(true);
  });
});
