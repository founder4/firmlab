import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  auditCredentials,
  auditInittab,
  auditServiceConfigs,
  notableFiles,
  runFsAudit,
  scanContentSecrets,
} from './fsaudit.js';

// A UID-0 root that defers its password to /etc/shadow, plus a normal daemon account.
const PASSWD = 'root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n';

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

describe('scanContentSecrets (private key by content, not filename)', () => {
  it('flags an embedded RSA private key regardless of filename', () => {
    const files = [
      {
        path: 'etc/config/device.conf',
        content: 'foo=bar\n-----BEGIN RSA PRIVATE KEY-----\nMIIC...\n-----END RSA PRIVATE KEY-----\n',
      },
    ];
    const drafts = scanContentSecrets(files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('embedded-private-key');
    expect(drafts[0]?.severity).toBe('high');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(drafts[0]?.title).toContain('etc/config/device.conf');
    // The key body must NOT leak into evidence.
    expect(JSON.stringify(drafts[0]?.evidence)).not.toContain('MIIC');
  });

  it('detects OpenSSH/EC/PKCS#8 key headers and dedupes per file', () => {
    expect(scanContentSecrets([{ path: 'a', content: '-----BEGIN OPENSSH PRIVATE KEY-----' }])[0]?.title).toContain(
      'OpenSSH private key',
    );
    expect(scanContentSecrets([{ path: 'b', content: '-----BEGIN EC PRIVATE KEY-----' }])[0]?.title).toContain(
      'EC private key',
    );
    // Two key blocks in one file → one finding.
    const multi = scanContentSecrets([
      { path: 'c', content: '-----BEGIN RSA PRIVATE KEY-----\n...\n-----BEGIN RSA PRIVATE KEY-----' },
    ]);
    expect(multi).toHaveLength(1);
  });

  it('does not flag a public key or certificate', () => {
    expect(scanContentSecrets([{ path: 'x', content: '-----BEGIN PUBLIC KEY-----' }])).toHaveLength(0);
    expect(scanContentSecrets([{ path: 'y', content: '-----BEGIN CERTIFICATE-----' }])).toHaveLength(0);
  });

  it('runFsAudit surfaces an embedded key in an innocuously-named file under etc/', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsaudit-key-'));
    try {
      fs.mkdirSync(path.join(dir, 'etc'), { recursive: true });
      fs.writeFileSync(
        path.join(dir, 'etc', 'server.pem'),
        '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n',
      );
      const r = runFsAudit(dir);
      expect(r.findings.some((f) => f.kind === 'embedded-private-key')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
