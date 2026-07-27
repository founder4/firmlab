import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  crc32,
  detectNvramStore,
  findNvramStores,
  nvramFindings,
  parseNvramRecords,
  parseNvramStore,
  runNvramScan,
  verifyNvramCrc,
} from './nvram.js';

// ============================================================================
// Fixtures — built to the shape measured on the deployed corpus.
// ============================================================================

/** Encode `name=value\0` records followed by the empty record that ends the list. */
function body(records: string[], { terminate = true } = {}): Buffer {
  const parts = records.map((r) => Buffer.concat([Buffer.from(r, 'latin1'), Buffer.from([0])]));
  if (terminate) parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/**
 * A flash partition exactly as the corpus stores are laid out: a 4-byte LE CRC32 header, the record body, the
 * terminating empty record, then padding — and the CRC covers `[4, size)`, padding included. That last detail is
 * the one that decides whether verification is possible at all.
 */
function partition(records: string[], size: number, pad = 0x00): Buffer {
  const buf = Buffer.alloc(size, pad);
  const b = body(records);
  b.copy(buf, 4);
  buf.writeUInt32LE(crc32(buf, 4, size), 0);
  return buf;
}

/** The AliExpress-Repeater config store (@0x32000, CRC over 0x4000), reduced to its security-relevant records. */
const ALIEXPRESS_CONFIG = [
  'Platform=RT7620',
  'WebInit=1',
  'langType=0',
  'Login=admin',
  'Password=admin',
  'myapname=AP-88AD38',
  'lanIpAddr=192.168.10.1',
  'wanPppoeUserName=',
  'wanPppoePassword=',
  'WPAPSK1=12345678',
  'RADIUS_Key=verysecretkey',
  'sta_pass=',
  'Key1Str=12345678',
  // These three are why `isSelectorValue` exists — their NAMES match the credential/key patterns but their values
  // are mode selectors. The first in-container run reported all three as secrets.
  'LoginFlag=0',
  'sta_wep_key_index=0',
  'sta_wep_key_fmt=1',
];

/** The Xiaomi 2023 U-Boot environment (@0x30000, CRC over 0x1000). */
const XIAOMI_ENV = [
  'bootcmd=tftp',
  'bootdelay=0',
  'baudrate=115200',
  'ethaddr="00:AA:BB:CC:DD:10"',
  'ipaddr=10.10.10.123',
  'serverip=10.10.10.3',
  'miio_token_seed=xZg3ALbF3sePd5YZIhgSbA==',
  'ecos_version=3.0.14',
  'flag_boot_rootfs=0',
];

/** The TP-Link WR940N bootloader's compiled-in default environment (`4254` @0x1ad50) — no CRC header at all. */
const WR940N_DEFAULTS = [
  'bootargs=console=ttyS0,115200 root=31:02 rootfstype=squashfs init=/sbin/init mtdparts=ath-nor0:256k(u-boot)',
  'bootcmd=bootm 0x9f020000',
  'bootdelay=1',
  'baudrate=115200',
  'ethaddr=0x00:0xaa:0xbb:0xcc:0xdd:0xee',
  'ipaddr=192.168.1.111',
  'serverip=192.168.1.100',
  'dir=',
  'lu=tftp 0x80060000 ${dir}u-boot.bin',
  'lf=tftp 0x80060000 ${dir}firmware.bin',
  'lk=tftp 0x80060000 ${dir}vmlinux.lzma.uImage',
];

// ============================================================================

describe('crc32', () => {
  it('matches the standard check vector', () => {
    expect(crc32(Buffer.from('123456789'))).toBe(0xcbf43926);
  });

  it('computes over a sub-range only', () => {
    const buf = Buffer.from('XX123456789YY');
    expect(crc32(buf, 2, 11)).toBe(0xcbf43926);
  });
});

describe('parseNvramRecords', () => {
  it('splits NUL-terminated name=value records and stops at the empty record', () => {
    const buf = Buffer.concat([body(['a=1', 'b=two', 'c=']), Buffer.alloc(64, 0xff)]);
    const run = parseNvramRecords(buf, 0);
    expect(run.records.map((r) => [r.key, r.value])).toEqual([
      ['a', '1'],
      ['b', 'two'],
      ['c', ''],
    ]);
    expect(run.terminated).toBe(true);
    expect(run.malformed).toBe(0);
  });

  it('keeps parsing past a corrupt record — the Xiaomi 2018 env has one wedged between good ones', () => {
    // `bootcmd\xc2\xc2="…"` sits between two valid records in the real store; stopping there would lose the
    // four records after it AND the terminator, which would have rejected a genuine store outright.
    const buf = body(['bootcmd=bootm', 'bootcmd\xc2\xc2="bootm=0xbd050000"', 'stdin=serial', 'flag_boot_rootfs=0']);
    const run = parseNvramRecords(buf, 0);
    expect(run.malformed).toBe(1);
    expect(run.records.map((r) => r.key)).toEqual(['bootcmd', 'stdin', 'flag_boot_rootfs']);
    expect(run.terminated).toBe(true);
    expect(run.firstRecordMalformed).toBe(false);
  });

  it('flags a mis-aligned start (the first record is garbage) so a candidate offset can be rejected', () => {
    const buf = body(['\x02\x02ootdelay=1', 'baudrate=115200']);
    expect(parseNvramRecords(buf, 0).firstRecordMalformed).toBe(true);
  });

  it('reports truncation honestly: no terminator when the blob is cut short', () => {
    const buf = Buffer.from('bootcmd=bootm\x00bootdelay=1', 'latin1');
    const run = parseNvramRecords(buf, 0);
    expect(run.records.map((r) => r.key)).toEqual(['bootcmd']);
    expect(run.terminated).toBe(false);
  });

  it('is bounded: a record longer than the cap stops the walk and says so', () => {
    const buf = Buffer.concat([Buffer.from(`k=${'A'.repeat(9000)}`, 'latin1'), Buffer.from([0, 0])]);
    const run = parseNvramRecords(buf, 0);
    expect(run.records).toHaveLength(0);
    expect(run.capped).toMatch(/exceeds 4096 bytes/);
  });

  it('is bounded: a huge NUL-free blob returns immediately instead of scanning it all', () => {
    const buf = Buffer.alloc(4 * 1024 * 1024, 0x41); // 4 MiB of 'A', no NUL anywhere
    const run = parseNvramRecords(buf, 0);
    expect(run.records).toHaveLength(0);
    expect(run.terminated).toBe(false);
  });
});

describe('verifyNvramCrc', () => {
  it('recovers the partition size the CRC covers (padding included)', () => {
    const buf = partition(XIAOMI_ENV, 0x1000);
    expect(verifyNvramCrc(buf, 0)).toEqual({ stored: buf.readUInt32LE(0), regionSize: 0x1000 });
  });

  it('finds the size for each partition geometry seen in the corpus', () => {
    for (const size of [0x1000, 0x2000, 0x4000, 0x10000]) {
      expect(verifyNvramCrc(partition(ALIEXPRESS_CONFIG, size), 0)?.regionSize).toBe(size);
    }
  });

  it('returns null when the stored word is not a CRC over any standard size', () => {
    const buf = partition(XIAOMI_ENV, 0x1000);
    buf.writeUInt32LE(0xdeadbeef, 0);
    expect(verifyNvramCrc(buf, 0)).toBeNull();
  });
});

describe('parseNvramStore', () => {
  it('parses a CRC-verified store and marks it crc-verified', () => {
    const store = parseNvramStore(partition(XIAOMI_ENV, 0x1000), 0);
    expect(store).not.toBeNull();
    expect(store?.headerBytes).toBe(4);
    expect(store?.confidence).toBe('crc-verified');
    expect(store?.recordCount).toBe(XIAOMI_ENV.length);
    expect(store?.crc?.regionSize).toBe(0x1000);
    expect(store?.records.find((r) => r.key === 'miio_token_seed')?.value).toBe('xZg3ALbF3sePd5YZIhgSbA==');
  });

  it('parses a headerless store (a bootloader default environment) as structural', () => {
    const buf = Buffer.concat([body(WR940N_DEFAULTS), Buffer.alloc(256, 0)]);
    const store = parseNvramStore(buf, 0);
    expect(store?.headerBytes).toBe(0);
    expect(store?.confidence).toBe('structural');
    expect(store?.crc).toBeNull();
    expect(store?.recordCount).toBe(WR940N_DEFAULTS.length);
  });

  it('never claims a 4-byte header it cannot verify', () => {
    const buf = Buffer.concat([Buffer.from([0xde, 0xad, 0xbe, 0xef]), body(WR940N_DEFAULTS), Buffer.alloc(64, 0)]);
    expect(parseNvramStore(buf, 0)).toBeNull(); // offset 0 is not a header, and not a record either
    expect(parseNvramStore(buf, 4)?.headerBytes).toBe(0); // the store itself starts at 4, headerless
  });

  it('records superseded duplicate keys instead of silently keeping one', () => {
    const buf = Buffer.concat([
      body(['bootcmd=old', 'bootdelay=1', 'bootcmd=new', 'x=1', 'y=2', 'z=3', 'w=4', 'v=5']),
      Buffer.alloc(32, 0),
    ]);
    expect(parseNvramStore(buf, 0)?.duplicateKeys).toEqual(['bootcmd']);
  });

  // --- rejections: every one of these shapes really occurs in the corpus and is NOT a store ---

  it('rejects a kernel .modinfo section (the corpus false positive, up to 40 records)', () => {
    const modinfo = [
      'license=GPL v2',
      'import_ns=DMA_BUF',
      'depends=cfg80211',
      'intree=Y',
      'name=ipq_cnss2',
      'vermagic=5.4.213 SMP preempt mod_unload',
      'parmtype=bus_type:uint',
      'parmtype=qmi_timeout:ulong',
      'srcversion=A1B2C3',
      'alias=of:N*T*Cqcom,cnss2',
    ];
    expect(parseNvramStore(Buffer.concat([body(modinfo), Buffer.alloc(32, 0)]), 0)).toBeNull();
  });

  it('rejects an all-empty-value `opt=` template table (sudo/ppecfg .rodata)', () => {
    const template = [
      'runas_egid=',
      'runas_euid=',
      'runas_gid=',
      'runas_uid=',
      'set_utmp=',
      'sudoedit=',
      'timeout=',
      'umask=',
      'use_pty=',
    ];
    expect(parseNvramStore(Buffer.concat([body(template), Buffer.alloc(32, 0)]), 0)).toBeNull();
  });

  it('rejects a duplicate-dominated alias table (sd_mod.ko: 9 records, 1 distinct key)', () => {
    const aliases = new Array(10).fill('alias=scsi:t-0x00');
    expect(parseNvramStore(Buffer.concat([body(aliases), Buffer.alloc(32, 0)]), 0)).toBeNull();
  });

  it('rejects an unterminated run of adjacent .rodata strings', () => {
    // The discriminator that took the corpus from 93 candidate files to 9 real stores: a real store declares its
    // own end with an empty record; a coincidental run of `key=value` C strings just continues into more text.
    const rodata = Buffer.concat([
      body(['MAX_ATTACHED=', 'MAX_COLUMN=', 'MAX_LENGTH=', 'MAX_PAGE_SIZE=', 'MAX_VDBE_OP=', 'a=1', 'b=2', 'c=3'], {
        terminate: false,
      }),
      Buffer.from('MUTEX_PTHREADS\x00', 'latin1'),
    ]);
    expect(parseNvramStore(rodata, 0)).toBeNull();
  });

  it('rejects a run too short to be distinguishable when there is no CRC to prove it', () => {
    expect(parseNvramStore(Buffer.concat([body(['a=1', 'b=2', 'c=3']), Buffer.alloc(16, 0)]), 0)).toBeNull();
  });

  it('accepts a short store when the CRC proves it', () => {
    expect(parseNvramStore(partition(['a=1', 'b=2', 'c=3'], 0x400), 0)?.recordCount).toBe(3);
  });
});

describe('detectNvramStore', () => {
  it('says yes with the CRC region it verified', () => {
    const d = detectNvramStore(partition(XIAOMI_ENV, 0x1000));
    expect(d.isStore).toBe(true);
    expect(d.reason).toMatch(/CRC32 0x[0-9a-f]{8} verifies over the 4096-byte partition/);
  });

  it('says no — with a reason — rather than returning noise', () => {
    const noise = Buffer.alloc(4096);
    for (let i = 0; i < noise.length; i++) noise[i] = (i * 37 + 11) & 0xff;
    const d = detectNvramStore(noise);
    expect(d.isStore).toBe(false);
    expect(d.store).toBeNull();
    expect(d.reason).toMatch(/Not an nvram store/);
  });
});

describe('findNvramStores', () => {
  it('finds every store in a flash image and reports each one at its true offset', () => {
    // AliExpress-Repeater's layout: two adjacent config partitions inside erased flash.
    const img = Buffer.alloc(0x40000, 0xff);
    partition(ALIEXPRESS_CONFIG, 0x4000).copy(img, 0x32000);
    partition(XIAOMI_ENV, 0x2000).copy(img, 0x36000);
    const stores = findNvramStores(img);
    expect(stores.map((s) => s.offset)).toEqual([0x32000, 0x36000]);
    expect(stores.every((s) => s.confidence === 'crc-verified')).toBe(true);
    expect(stores[0]?.crc?.regionSize).toBe(0x4000);
  });

  it('does not report a mid-record start as a store (what an aligned grid scan gets wrong)', () => {
    const img = Buffer.alloc(0x2000, 0xff);
    partition(XIAOMI_ENV, 0x1000).copy(img, 0x1000);
    const stores = findNvramStores(img);
    expect(stores).toHaveLength(1);
    expect(stores[0]?.offset).toBe(0x1000);
    expect(stores[0]?.records[0]?.key).toBe('bootcmd'); // not a truncated `ootcmd`
  });

  it('finds a headerless store embedded in a binary (a bootloader default environment)', () => {
    const blob = Buffer.alloc(0x8000, 0x41);
    blob.fill(0, 0x2000, 0x2100);
    body(WR940N_DEFAULTS).copy(blob, 0x2010);
    const stores = findNvramStores(blob);
    expect(stores).toHaveLength(1);
    expect(stores[0]).toMatchObject({ offset: 0x2010, headerBytes: 0, confidence: 'structural' });
  });

  it('returns nothing for a blob with no store, rather than something', () => {
    expect(findNvramStores(Buffer.alloc(0x10000, 0xff))).toEqual([]);
    expect(findNvramStores(Buffer.from('a plain text file with = signs and no NUL records at all'))).toEqual([]);
  });

  it('is bounded on a large blob', () => {
    const big = Buffer.alloc(8 * 1024 * 1024, 0x00); // every offset is a candidate start
    expect(findNvramStores(big)).toEqual([]);
  });
});

describe('nvramFindings', () => {
  const stores = [
    parseNvramStore(partition(ALIEXPRESS_CONFIG, 0x4000), 0),
    parseNvramStore(partition(XIAOMI_ENV, 0x1000), 0),
  ].filter((s) => s !== null);

  it('reports the store inventory as a static fact', () => {
    const inv = nvramFindings(stores).find((f) => f.kind === 'nvram-store');
    expect(inv?.proofState).toBe('static_confirmed');
    expect(inv?.severity).toBe('info');
    expect(inv?.title).toMatch(/2 \(/);
  });

  it('flags a factory-default admin credential as critical / static_confirmed', () => {
    const f = nvramFindings(stores).filter((d) => d.kind === 'nvram-credential');
    const password = f.find((d) => (d.evidence as { key: string }).key === 'Password');
    expect(password?.severity).toBe('critical');
    expect(password?.proofState).toBe('static_confirmed');
    expect(password?.evidence).toMatchObject({ valueClass: 'well-known-default', valueLength: 5, value: '<redacted>' });
  });

  it('rates a configured (non-default) credential high rather than critical', () => {
    const token = nvramFindings(stores).find((d) => (d.evidence as { key?: string }).key === 'miio_token_seed');
    expect(token?.severity).toBe('high');
    expect(token?.evidence).toMatchObject({ valueClass: 'opaque', valueLength: 24 });
  });

  it('flags a default WPA PSK as wireless key material', () => {
    const wifi = nvramFindings(stores).filter((d) => d.kind === 'nvram-wifi-key');
    expect(wifi.map((d) => (d.evidence as { key: string }).key).sort()).toEqual(['Key1Str', 'RADIUS_Key', 'WPAPSK1']);
    expect(wifi.find((d) => (d.evidence as { key: string }).key === 'WPAPSK1')?.severity).toBe('critical');
    expect(wifi.find((d) => (d.evidence as { key: string }).key === 'RADIUS_Key')?.severity).toBe('high');
  });

  it('never emits a value — not in a title, a rationale, or evidence', () => {
    const serialized = JSON.stringify(nvramFindings(stores));
    for (const secret of ['admin', '12345678', 'verysecretkey', 'xZg3ALbF3sePd5YZIhgSbA==']) {
      expect(serialized).not.toContain(secret);
    }
  });

  it('does not call a mode selector a secret because its name contains login/key', () => {
    // Found by running the provider over the real AliExpress-Repeater image, not by a unit test: `LoginFlag=0`,
    // `sta_wep_key_index=0` and `sta_wep_key_fmt=1` were all reported as credentials on the first pass.
    const keys = nvramFindings(stores).map((d) => (d.evidence as { key?: string }).key);
    expect(keys).not.toContain('LoginFlag');
    expect(keys).not.toContain('sta_wep_key_index');
    expect(keys).not.toContain('sta_wep_key_fmt');
    expect(keys).toContain('Password'); // …while the real secrets in the same store still fire
    expect(keys).toContain('WPAPSK1');
  });

  it('skips empty slots — an unset key is a template, not a configured secret', () => {
    const keys = nvramFindings(stores).map((d) => (d.evidence as { key?: string }).key);
    expect(keys).not.toContain('wanPppoePassword');
    expect(keys).not.toContain('sta_pass');
  });

  it('treats a remote-service enable flag as a lead, not a verdict', () => {
    const store = parseNvramStore(partition([...XIAOMI_ENV, 'telnet_enable=1', 'remote_management=0'], 0x1000), 0);
    const svc = nvramFindings(store ? [store] : []).filter((d) => d.kind === 'nvram-service-enabled');
    expect(svc.map((d) => (d.evidence as { key: string }).key)).toEqual(['telnet_enable']); // the `0` one is not on
    expect(svc[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(svc[0]?.severity).toBe('medium');
  });

  it('flags an interruptible boot delay as a runtime lead, and stays quiet at bootdelay=0', () => {
    const quiet = parseNvramStore(partition(XIAOMI_ENV, 0x1000), 0); // bootdelay=0
    expect(nvramFindings(quiet ? [quiet] : []).some((d) => d.kind === 'nvram-boot-interruptible')).toBe(false);

    const loud = parseNvramStore(Buffer.concat([body(WR940N_DEFAULTS), Buffer.alloc(64, 0)]), 0); // bootdelay=1
    const boot = nvramFindings(loud ? [loud] : []).find((d) => d.kind === 'nvram-boot-interruptible');
    expect(boot?.proofState).toBe('needs_runtime_reproduction');
    expect(boot?.severity).toBe('low');
  });

  it('takes the LAST value of a duplicated key, as the device would', () => {
    const store = parseNvramStore(partition([...XIAOMI_ENV, 'bootdelay=10'], 0x1000), 0);
    const boot = nvramFindings(store ? [store] : []).find((d) => d.kind === 'nvram-boot-interruptible');
    expect(boot?.evidence).toMatchObject({ bootdelaySeconds: 10 });
  });

  it('catches a PEM private key stored inside a value, via fsaudit’s tested detector', () => {
    const withKey = parseNvramStore(
      partition([...XIAOMI_ENV, 'device_cert=-----BEGIN RSA PRIVATE KEY-----MIIB'], 0x1000),
      0,
    );
    const f = nvramFindings(withKey ? [withKey] : []).find((d) => d.kind === 'embedded-private-key');
    expect(f?.proofState).toBe('static_confirmed');
    expect(f?.evidence).toMatchObject({ keyType: 'RSA private key' });
  });

  it('produces nothing at all when there are no stores', () => {
    expect(nvramFindings([])).toEqual([]);
  });
});

// ============================================================================
// Runner
// ============================================================================

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-nvram-'));
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe('runNvramScan', () => {
  it('scans a flash image on disk and states what it verified', () => {
    const img = Buffer.alloc(0x40000, 0xff);
    partition(ALIEXPRESS_CONFIG, 0x4000).copy(img, 0x32000);
    const p = path.join(tmp, 'flash.bin');
    fs.writeFileSync(p, img);

    const res = runNvramScan(p);
    expect(res.available).toBe(true);
    expect(res.stores).toHaveLength(1);
    expect(res.reason).toMatch(
      new RegExp(
        `1 nvram store\\(s\\): 0x32000 — ${ALIEXPRESS_CONFIG.length} record\\(s\\), CRC32 verified over 16384 bytes`,
      ),
    );
    expect(res.reason).toMatch(/all values redacted/);
    expect(res.findings.some((f) => f.kind === 'nvram-credential')).toBe(true);
  });

  it('says why an empty result is empty, so absence never reads as clean', () => {
    const p = path.join(tmp, 'empty.bin');
    fs.writeFileSync(p, Buffer.alloc(0x1000, 0xff));
    const res = runNvramScan(p);
    expect(res.available).toBe(true);
    expect(res.findings).toEqual([]);
    expect(res.reason).toMatch(/not that the device has no nvram/);
  });

  it('degrades honestly when the file cannot be read', () => {
    const res = runNvramScan(path.join(tmp, 'does-not-exist.bin'));
    expect(res.available).toBe(true);
    expect(res.stores).toEqual([]);
    expect(res.reason).toMatch(/Could not read image bytes/);
  });
});
