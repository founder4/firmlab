import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  DIGEST_SYMBOLS,
  SIGNATURE_VERIFY_SYMBOLS,
  TPLINK_MD5_SALTS,
  type UpdaterCandidate,
  assessRollback,
  assessScript,
  assessSymbols,
  buildUpdatePathFindings,
  classifyFitStrings,
  classifyKeyMaterial,
  classifySiblings,
  classifyUpdaterPath,
  findArmoredSignatures,
  findPkcs7SignedData,
  isUpdaterSymbol,
  parseFdtHeader,
  parseTpLinkHeader,
  parseUImageHeader,
  selectUpdaters,
  stripInertText,
  verifyTpLinkChecksum,
} from './updatepath.js';

/** The FDT string block is NUL-separated; the separator is an escape here for the same reason it is in the source. */
const NUL = '\u0000';

function fdt(opts: { totalSize?: number; offDtStrings?: number; sizeDtStrings?: number }): Uint8Array {
  const b = Buffer.alloc(64);
  b.writeUInt32BE(0xd00dfeed, 0);
  b.writeUInt32BE(opts.totalSize ?? 4096, 4);
  b.writeUInt32BE(0x38, 8); // off_dt_struct
  b.writeUInt32BE(opts.offDtStrings ?? 2048, 12);
  b.writeUInt32BE(0x28, 16); // off_mem_rsvmap
  b.writeUInt32BE(17, 20); // version
  b.writeUInt32BE(opts.sizeDtStrings ?? 64, 32);
  return b;
}

describe('parseFdtHeader', () => {
  it('reads a well-formed FIT header', () => {
    const h = parseFdtHeader(fdt({}));
    expect(h).not.toBeNull();
    expect(h?.version).toBe(17);
    expect(h?.offDtStrings).toBe(2048);
  });

  it('refuses a coincidental magic whose offsets do not fit inside the declared size', () => {
    expect(parseFdtHeader(fdt({ totalSize: 100, offDtStrings: 4096 }))).toBeNull();
  });

  it('returns null on a non-FDT buffer', () => {
    expect(parseFdtHeader(Buffer.alloc(64))).toBeNull();
  });
});

describe('classifyFitStrings', () => {
  // The real GL.iNet BE3600 property-name block, read out of the deployed image at off_dt_strings.
  const glinet = [
    'description',
    '#address-cells',
    'data',
    'type',
    'arch',
    'compression',
    'algo',
    'timestamp',
    'value',
  ].join(NUL);

  it('reports a hash-only FIT as hashed and NOT signed', () => {
    const r = classifyFitStrings(glinet);
    expect(r.hashed).toBe(true);
    expect(r.signed).toBe(false);
  });

  it('recognises a signature node when the container declares one', () => {
    const r = classifyFitStrings(`${glinet}${NUL}signature${NUL}key-name-hint`);
    expect(r.signed).toBe(true);
  });

  it('does not mistake an empty block for either answer', () => {
    const r = classifyFitStrings('');
    expect(r.signed).toBe(false);
    expect(r.hashed).toBe(false);
    expect(r.props).toEqual([]);
  });
});

describe('parseUImageHeader', () => {
  it('reads the CRC fields and the image name', () => {
    const b = Buffer.alloc(64);
    b.writeUInt32BE(0x27051956, 0);
    b.writeUInt32BE(0xdeadbeef, 4);
    b.writeUInt32BE(1234, 12);
    b.writeUInt32BE(0xcafebabe, 24);
    b.write('MIPS OpenWrt Linux-3.10', 32, 'latin1');
    const h = parseUImageHeader(b);
    expect(h?.headerCrc).toBe(0xdeadbeef);
    expect(h?.dataCrc).toBe(0xcafebabe);
    expect(h?.dataSize).toBe(1234);
    expect(h?.name).toBe('MIPS OpenWrt Linux-3.10');
  });

  it('returns null without the magic', () => {
    expect(parseUImageHeader(Buffer.alloc(64))).toBeNull();
  });
});

describe('parseTpLinkHeader / verifyTpLinkChecksum', () => {
  /** Build a TP-Link image whose stored checksum is the real keyed MD5 for `salt`. */
  function tplinkImage(salt: Uint8Array, size = 0x400): Buffer {
    const img = Buffer.alloc(size);
    img.writeUInt32BE(1, 0);
    img.write('TP-LINK Technologies', 4, 'latin1');
    img.writeUInt32BE(0x09400006, 0x40);
    img.writeUInt32BE(size, 0x7c);
    img.writeUInt32BE(0x200, 0x80);
    img.fill(0xab, 0x200); // some payload so the hash is not over zeros alone
    const probe = Buffer.from(img);
    probe.set(salt, 0x4c);
    img.set(crypto.createHash('md5').update(probe).digest(), 0x4c);
    return img;
  }

  it('accepts a structurally consistent header', () => {
    const img = tplinkImage(TPLINK_MD5_SALTS[1]?.bytes as Uint8Array);
    const h = parseTpLinkHeader(img, img.length);
    expect(h?.vendor).toBe('TP-LINK Technologies');
    expect(h?.hardwareId).toBe(0x09400006);
  });

  it('refuses a header whose declared length disagrees with the file size', () => {
    const img = tplinkImage(TPLINK_MD5_SALTS[1]?.bytes as Uint8Array);
    expect(parseTpLinkHeader(img, img.length + 1)).toBeNull();
  });

  it('names the published constant that reproduces the stored checksum', () => {
    for (const salt of TPLINK_MD5_SALTS) {
      const img = tplinkImage(salt.bytes);
      const h = parseTpLinkHeader(img, img.length);
      expect(h).not.toBeNull();
      expect(verifyTpLinkChecksum(img, h as NonNullable<typeof h>)).toBe(salt.name);
    }
  });

  it('reports null rather than guessing when no published constant reproduces the value', () => {
    const img = tplinkImage(TPLINK_MD5_SALTS[0]?.bytes as Uint8Array);
    const h = parseTpLinkHeader(img, img.length);
    // Rewrite the payload AFTER the header was read, so the stored value no longer describes these bytes — which
    // is exactly a repacked image, and exactly the case where claiming "public constant" would be a fabrication.
    img.fill(0x5c, 0x200);
    expect(verifyTpLinkChecksum(img, h as NonNullable<typeof h>)).toBeNull();
  });
});

describe('findPkcs7SignedData', () => {
  it('finds the signedData OID and biases by the window base', () => {
    const oid = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
    const buf = Buffer.concat([Buffer.alloc(17), oid, Buffer.alloc(5)]);
    expect(findPkcs7SignedData(buf)).toEqual([17]);
    expect(findPkcs7SignedData(buf, 1000)).toEqual([1017]);
  });

  it('does not match the plain `data` OID (…1.7.1)', () => {
    const data = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
    expect(findPkcs7SignedData(data)).toEqual([]);
  });
});

describe('findArmoredSignatures', () => {
  // Both blocks below are the real bytes of the GL.iNet BE3600 image: the signature is appended 167 bytes from the
  // end of the file, the public key is a file inside the shipped squashfs. They open with the same 18 characters.
  const signature =
    'untrusted comment: signed by key 06a6bf2ad909388f\nRWQGpr8q2Qk4j9M2hBSlEgFRW20lqnVr2DP9kO2X76u0W1Za3tObZh8P\n';
  const publicKey =
    'untrusted comment: public key 06a6bf2ad909388f\nRWQGpr8q2Qk4j5MR3UqUiemnPkEH/2nFoyD3cOkXMwTAvy7zEA0KDyLP\n';

  it('recognises a usign signature block, which is how OpenWrt signs an image', () => {
    const items = findArmoredSignatures(signature);
    expect(items).toHaveLength(1);
    expect(items[0]?.strength).toBe('signature');
    expect(items[0]?.offset).toBe(0);
    expect(items[0]?.detail).toContain('06a6bf2ad909388f');
  });

  it('refuses to read a shipped usign PUBLIC KEY as a signature over the image', () => {
    // The failure this prevents is the central overclaim of the whole provider: a key file inside the payload
    // would otherwise satisfy the "image carries a signature" half of the three-part conjunction on its own.
    expect(findArmoredSignatures(publicKey)).toEqual([]);
  });

  it('finds the signature when both blocks are present in the same window', () => {
    const items = findArmoredSignatures(`${publicKey}\npadding\n${signature}`);
    expect(items).toHaveLength(1);
    expect(items[0]?.kind).toContain('signature');
  });

  it('finds nothing in ordinary bytes', () => {
    expect(findArmoredSignatures('just some firmware strings')).toEqual([]);
  });
});

describe('classifySiblings', () => {
  it('keeps detached signatures/digests for the image and ignores unrelated files', () => {
    expect(classifySiblings('fw.bin', ['fw.bin', 'fw.bin.sig', 'fw.sha256', 'other.bin.asc', 'notes.md'])).toEqual([
      'fw.bin.sig',
      'fw.sha256',
    ]);
  });
});

describe('classifyUpdaterPath', () => {
  it('treats the OpenWrt entry points as strong candidates', () => {
    expect(classifyUpdaterPath('sbin/sysupgrade').tier).toBe('strong');
    expect(classifyUpdaterPath('sbin/upgraded').tier).toBe('strong');
    expect(classifyUpdaterPath('lib/upgrade/fwtool.sh').tier).toBe('strong');
    expect(classifyUpdaterPath('usr/bin/force_upgrade').tier).toBe('strong');
    expect(classifyUpdaterPath('usr/data/sd_otaUpgrade/otaUpgrade_ISTNT').tier).toBe('strong');
  });

  it('excludes the DDNS clients a bare *update* glob returns on the real DVRF rootfs', () => {
    // Reporting "the updater imports no verify routine" about ez-ipupdate would be a fabricated finding about a
    // program that has nothing to do with firmware. These three are what the glob actually returns there.
    for (const p of ['usr/sbin/ez-ipupdate', 'sbin/ipupdated', 'usr/sbin/tzoupdate-1.11']) {
      expect(classifyUpdaterPath(p).tier).toBe('excluded');
    }
  });

  it('excludes UCI configuration, which is data even when the file is called "upgrade"', () => {
    expect(classifyUpdaterPath('etc/config/upgrade').tier).toBe('excluded');
  });

  it('excludes documentation, translations and package bookkeeping', () => {
    for (const p of [
      'www/i18n/gl-sdk4-ui-upgrade.en.json',
      'web/userRpm/SoftwareUpgradeRpm.htm',
      'usr/lib/opkg/info/gl-sdk4-upgrade.control',
      'www/views/gl-sdk4-ui-upgrade.common.js.gz',
    ]) {
      expect(classifyUpdaterPath(p).tier).toBe('excluded');
    }
  });

  it('keeps a generic mention as a weak candidate, and says why', () => {
    const c = classifyUpdaterPath('usr/bin/one_click_upgrade');
    expect(c.tier).toBe('weak');
    expect(c.why).toContain('one_click_upgrade');
  });

  it('excludes a file with no update evidence in the name', () => {
    expect(classifyUpdaterPath('usr/bin/httpd').tier).toBe('excluded');
  });

  it('does not find "ota" inside "quota"', () => {
    // The corpus caught this: nft_quota.ko / xt_quota.ko on the GL.iNet and usr/lib/iptables/libxt_quota.so on
    // DVRF were all opened as firmware updaters, and on DVRF the iptables plugin became "the 1 updater located".
    for (const p of ['lib/modules/5.4.213/nft_quota.ko', 'usr/lib/iptables/libxt_quota.so']) {
      expect(classifyUpdaterPath(p).tier).toBe('excluded');
    }
    expect(classifyUpdaterPath('usr/local/lib/lua/5.4/cloud/ota.lua').tier).not.toBe('excluded');
  });

  it('separates a name match from a directory match, because they license different confidence', () => {
    expect(classifyUpdaterPath('sbin/sysupgrade').basis).toBe('name');
    expect(classifyUpdaterPath('lib/upgrade/keep.d/dropbear').basis).toBe('directory');
  });
});

describe('selectUpdaters', () => {
  const c = (path: string, over: Partial<UpdaterCandidate> = {}): UpdaterCandidate =>
    candidate({ path, why: 'path match — helper directory', ...over });

  it('keeps the entry point when a helper directory would otherwise fill the cap', () => {
    // The real failure: `lib/upgrade/keep.d/` holds 30 package manifests, the walk reached them before `sbin/`,
    // and `sbin/sysupgrade` — the file that answers this question — was silently outside the list.
    const noise = Array.from({ length: 30 }, (_, i) => c(`lib/upgrade/keep.d/pkg-${String(i).padStart(2, '0')}`));
    const entry = c('sbin/sysupgrade', {
      why: 'entry point — file name "sysupgrade" is a firmware-update entry point',
    });
    const { kept, dropped } = selectUpdaters([...noise, entry], 5);
    expect(kept.map((k) => k.path)).toContain('sbin/sysupgrade');
    expect(dropped).toBe(26);
  });

  it('prefers a candidate that verifies over one that only flashes', () => {
    const { kept } = selectUpdaters(
      [c('a/flash.sh', { flashWrites: ['mtd write'] }), c('b/verify.sh', { verifyCommands: ['gpg --verify'] })],
      1,
    );
    expect(kept[0]?.path).toBe('b/verify.sh');
  });

  it('is stable regardless of the order the walk produced', () => {
    const list = [c('z.sh', { flashWrites: ['mtd write'] }), c('a.sh'), c('m.sh', { verifyCommands: ['gpgv'] })];
    expect(selectUpdaters(list, 2).kept.map((k) => k.path)).toEqual(
      selectUpdaters([...list].reverse(), 2).kept.map((k) => k.path),
    );
  });
});

describe('isUpdaterSymbol', () => {
  it('recognises the TP-Link update routines that live inside httpd', () => {
    for (const s of ['upgradeFirmware', 'checkAndUpgradeFirmware', 'isSysUpgradeNeedChecksum']) {
      expect(isUpdaterSymbol(s)).toBe(true);
    }
  });

  it('requires both an update verb and a firmware noun, so config updaters do not qualify', () => {
    for (const s of ['update_dns_list', 'apn_db_update', 'checkFirmware', 'uloop_timeout_set']) {
      expect(isUpdaterSymbol(s)).toBe(false);
    }
  });
});

describe('assessSymbols', () => {
  it('reports edsign_verify as a signature routine (the real usign import set)', () => {
    const usign = new Set(['edsign_verify', 'edsign_verify_init', 'sha512_init', 'b64_decode', 'memcpy']);
    const a = assessSymbols(usign);
    expect(a.signatureFns).toContain('edsign_verify');
    expect(a.digestFns).toContain('sha512_init');
  });

  it('does NOT read TP-Link httpd’s SSH/TLS RSA bignum helpers as a signature check', () => {
    // The real dynamic symbol set of usr/bin/httpd on TP-Link-WR940Nv6: plenty of RSA_*, no verify entry point.
    // A substring match on "RSA_" would have reported this binary as verifying update signatures. It does not.
    const httpd = new Set([
      'RSA_modpow',
      'RSA_bignum_from_bytes',
      'RSA_freebn',
      'RSA_SHA_Simple',
      'wc_FreeRsaKey',
      'wc_RsaPrivateDecrypt',
      'MD5_Init',
      'md5_verify_digest',
      'upgradeFirmware',
    ]);
    const a = assessSymbols(httpd);
    expect(a.signatureFns).toEqual([]);
    expect(a.digestFns).toEqual(expect.arrayContaining(['MD5_Init', 'md5_verify_digest']));
  });

  it('keeps the two vocabularies disjoint', () => {
    const overlap = SIGNATURE_VERIFY_SYMBOLS.filter((s) => DIGEST_SYMBOLS.includes(s));
    expect(overlap).toEqual([]);
  });
});

describe('stripInertText / assessScript', () => {
  it('does not count a check that is commented out inside a heredoc', () => {
    // The Tenda camera ships exactly this: its md5sum verification sits inside `: <<'COMMENT' … COMMENT`.
    const script = [
      '#!/bin/sh',
      'dd if=fw.bin of=/dev/mtdblock8 bs=64k',
      ": <<'COMMENT'",
      'md5sum -c fw.md5 || exit 1',
      'COMMENT',
      'sync',
    ].join('\n');
    const a = assessScript(script);
    expect(a.verifyCommands).toEqual([]);
    expect(a.flashWrites).toContain('dd of=/dev/…');
    expect(stripInertText(script)).not.toContain('md5sum');
  });

  it('sees a flash write whose target is a shell variable', () => {
    // The Tenda camera writes `of=/dev/$upgradeblock`; a device-name whitelist missed it entirely.
    const a = assessScript('dd if=fw.bin of=/dev/$upgradeblock skip=1 bs=64k count=243 conv=fsync');
    expect(a.flashWrites).toContain('dd of=/dev/…');
  });

  it('does not treat the word "sysupgrade" as a flash write', () => {
    // It appears in comments, variable names and log lines all over an OpenWrt rootfs, and it labelled
    // lib/upgrade/common.sh — which flashes nothing — as committing an image to flash.
    expect(assessScript('# called from sysupgrade\nSYSUPGRADE_OPT=1\n').flashWrites).toEqual([]);
  });

  it('reads the real OpenWrt fwtool.sh verification path', () => {
    const fwtool = [
      'fwtool_check_signature() {',
      '\t[ ! -x /usr/bin/ucert ] && return 0',
      '\tfwtool -q -T -s /dev/null "$1" | \\',
      '\t\tucert -V -m - -c "/tmp/sysupgrade.ucert" -P /etc/opkg/keys',
      '}',
    ].join('\n');
    const a = assessScript(fwtool);
    expect(a.signatureCommands).toEqual(['ucert -V (OpenWrt Ed25519 cert)']);
    expect(a.verifierBinaries).toContain('ucert');
  });

  it('separates a checksum invocation from a signature one', () => {
    const a = assessScript('sha256sum -c manifest.sha256 || exit 1');
    expect(a.verifyCommands).toEqual(['sha256sum -c']);
    expect(a.signatureCommands).toEqual([]);
  });

  it('drops trailing # comments without eating a URL fragment mid-token', () => {
    expect(stripInertText('gpg --verify a.sig # legacy path')).toBe('gpg --verify a.sig ');
  });
});

describe('classifyKeyMaterial', () => {
  const usignPub =
    'untrusted comment: public key 06a6bf2ad909388f\nRWQGpr8q2Qk4j5MR3UqUiemnPkEH/2nFoyD3cOkXMwTAvy7zEA0KDyLP\n';
  const pemPub = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----\n';

  it('recognises the real GL.iNet usign key', () => {
    expect(classifyKeyMaterial('etc/opkg/keys/06a6bf2ad909388f', usignPub)?.kind).toContain('usign');
    expect(classifyKeyMaterial('etc/key-build.pub', usignPub)?.kind).toContain('usign');
  });

  it('does NOT treat the system CA bundle as update trust material', () => {
    // On the real GL.iNet this returned all 40 Mozilla roots, and they then fed the three-part conjunction — so
    // the strongest claim this provider can make would have been attributed to AC_RAIZ_FNMT-RCM.crt.
    const cert = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';
    expect(classifyKeyMaterial('etc/ssl/certs/Amazon_Root_CA_1.crt', cert)).toBeNull();
    expect(classifyKeyMaterial('usr/share/ca-certificates/mozilla/GTS_Root_R1.crt', cert)).toBeNull();
  });

  it('keeps a public key that sits on an update / secure-boot path', () => {
    // The IMOU camera ships exactly this one.
    expect(classifyKeyMaterial('usr/bin/secboot/public.pem', pemPub)?.kind).toContain('PEM public key');
    expect(classifyKeyMaterial('usr/bin/ssl/logPubkey.pem', pemPub)).toBeNull();
  });

  it('never files private key material as a trust anchor', () => {
    const priv = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n';
    expect(classifyKeyMaterial('etc/opkg/keys/signing.pub', priv)).toBeNull();
  });

  it('ignores a file that carries no key material', () => {
    expect(classifyKeyMaterial('etc/config/network', 'config interface lan\n')).toBeNull();
  });
});

/** A minimal candidate, so each test only states the fields it is about. */
function candidate(over: Partial<UpdaterCandidate> = {}): UpdaterCandidate {
  return {
    path: 'sbin/sysupgrade',
    kind: 'script',
    discoveredBy: 'path',
    why: 'strong path match',
    signatureFns: [],
    digestFns: [],
    verifyCommands: [],
    missingVerifiers: [],
    flashWrites: [],
    rollbackMarkers: [],
    ...over,
  };
}

describe('assessRollback', () => {
  it('is unknown, not off, when no updater was examined at all', () => {
    expect(assessRollback([]).state).toBe('unknown');
  });

  it('scores a version floor as on', () => {
    expect(assessRollback([candidate({ rollbackMarkers: ['anti-rollback'] })]).state).toBe('on');
  });

  it('refuses to score compat_version as rollback protection', () => {
    // OpenWrt's compat_version gates whether config survives; `sysupgrade -F` walks straight past it.
    const r = assessRollback([candidate({ rollbackMarkers: ['compat_version'] })]);
    expect(r.state).toBe('unknown');
    expect(r.evidence).toContain('compatibility');
  });

  it('reports off only when an updater was read and named no version bound', () => {
    expect(assessRollback([candidate({})]).state).toBe('off');
  });
});

describe('buildUpdatePathFindings', () => {
  const noIntegrity = { container: 'unknown' as const, containerNote: 'n/a', items: [], siblings: [] };
  const rollbackUnknown = { state: 'unknown' as const, evidence: 'not measured', markers: [] };

  it('records a missing updater as blocked_by_platform and lists what was searched for', () => {
    const f = buildUpdatePathFindings(noIntegrity, [], [], rollbackUnknown, true);
    const blocked = f.find((d) => d.kind === 'update-path-not-located');
    expect(blocked?.proofState).toBe('blocked_by_platform');
    expect((blocked?.evidence as { searchedFor: string[] }).searchedFor.length).toBeGreaterThan(3);
    // The one thing it must never do is read as a pass.
    expect(blocked?.title).not.toMatch(/clean|no issue|verified/i);
  });

  it('never states an absent verify routine above needs_runtime_reproduction, and names where it could not look', () => {
    const f = buildUpdatePathFindings(
      noIntegrity,
      [candidate({ kind: 'elf', symbolSource: 'dynsym' })],
      [],
      rollbackUnknown,
      true,
    );
    const d = f.find((x) => x.kind === 'update-no-signature-verification-found');
    expect(d?.proofState).toBe('needs_runtime_reproduction');
    expect(d?.title).toContain('located');
    expect(d?.title).not.toMatch(/unsigned/i);
    expect((d?.evidence as { unexamined: string[] }).unexamined).toEqual(
      expect.arrayContaining([expect.stringContaining('bootloader')]),
    );
    expect(d?.rationale).toContain('NOT "the firmware is unsigned"');
  });

  it('carries a bound that truncated the search into the negative finding', () => {
    // A bound is not an answer: an absence measured over 500 of a rootfs's ELFs is weaker than one measured over
    // all of them, and the reader cannot tell which without being told. The GL.iNet exhausts this budget for real.
    const f = buildUpdatePathFindings(noIntegrity, [candidate({})], [], rollbackUnknown, true, {
      elfBudgetExhausted: true,
      walkTruncated: false,
    });
    const d = f.find((x) => x.kind === 'update-no-signature-verification-found');
    expect(d?.rationale).toContain('The search was itself bounded');
    expect((d?.evidence as { boundsThatTruncatedTheSearch?: string[] }).boundsThatTruncatedTheSearch).toHaveLength(1);
  });

  it('reports a present signature block as static_confirmed without implying anything checks it', () => {
    const integrity = {
      container: 'fit' as const,
      containerNote: 'n/a',
      items: [
        { strength: 'signature' as const, kind: 'PKCS#7/CMS signedData structure', detail: 'DER OID', offset: 96 },
      ],
      siblings: [],
    };
    const d = buildUpdatePathFindings(integrity, [], [], rollbackUnknown, true).find(
      (x) => x.kind === 'update-image-signature-block',
    );
    expect(d?.proofState).toBe('static_confirmed');
    expect(d?.rationale).toContain('does NOT');
  });

  it('reports an invoked-but-absent verifier as a static presence fact', () => {
    const d = buildUpdatePathFindings(
      noIntegrity,
      [candidate({ verifyCommands: ['ucert -V (OpenWrt Ed25519 cert)'], missingVerifiers: ['ucert'] })],
      [],
      rollbackUnknown,
      true,
    ).find((x) => x.kind === 'update-verifier-binary-absent');
    expect(d?.proofState).toBe('static_confirmed');
    expect(d?.severity).toBe('high');
    expect(d?.title).toContain('ucert');
  });

  it('states the strongest positive as a conjunction with each part attributed', () => {
    const integrity = {
      container: 'fit' as const,
      containerNote: 'n/a',
      items: [{ strength: 'signature' as const, kind: 'FIT signature node', detail: 'declared' }],
      siblings: [],
    };
    const f = buildUpdatePathFindings(
      integrity,
      [candidate({ verifyCommands: ['ucert -V (OpenWrt Ed25519 cert)'] })],
      [{ path: 'etc/opkg/keys/06a6bf2ad909388f', kind: 'usign Ed25519 public key (OpenWrt)' }],
      rollbackUnknown,
      true,
    );
    const chain = f.find((x) => x.kind === 'update-verify-chain');
    expect(chain?.proofState).toBe('static_confirmed');
    expect(chain?.rationale).toContain('(1)');
    expect(chain?.rationale).toContain('(2)');
    expect(chain?.rationale).toContain('(3)');
    // The rung it must not climb.
    expect(chain?.rationale).toContain('do not show it is reached');
  });

  it('does not emit the conjunction when only two of the three parts are present', () => {
    const integrity = {
      container: 'fit' as const,
      containerNote: 'n/a',
      items: [{ strength: 'signature' as const, kind: 'FIT signature node', detail: 'declared' }],
      siblings: [],
    };
    const f = buildUpdatePathFindings(
      integrity,
      [candidate({ verifyCommands: ['gpg --verify'] })],
      [],
      rollbackUnknown,
      true,
    );
    expect(f.find((x) => x.kind === 'update-verify-chain')).toBeUndefined();
  });

  it('grades a verified public-constant checksum high and says it authenticates nothing', () => {
    const integrity = {
      container: 'tplink' as const,
      containerNote: 'n/a',
      items: [
        {
          strength: 'checksum' as const,
          kind: 'TP-Link keyed-MD5 header checksum',
          detail: 'verified by recomputation: the published constant reproduces the stored value.',
          offset: 0x4c,
        },
      ],
      siblings: [],
    };
    const d = buildUpdatePathFindings(integrity, [], [], rollbackUnknown, true).find(
      (x) => x.kind === 'update-image-unauthenticated-integrity',
    );
    expect(d?.severity).toBe('high');
    expect(d?.proofState).toBe('static_confirmed');
    expect(d?.title).toContain('authenticates nothing');
  });
});
