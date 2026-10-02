import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fingerprintMcu } from '@firmlab/core';
import { afterAll, describe, expect, it } from 'vitest';
import {
  OFFLINE_RENODE_ENV,
  RENODE_REFUSING_PROXY,
  type RenodeResult,
  buildRenodeFindings,
  buildRenodeInvocation,
  buildRenodeScript,
  describeRefusedRemote,
  discoverUarts,
  listPlatformCatalog,
  offlineRenodeEnv,
  scanRemoteResources,
  selectPlatform,
} from './renode.js';

/** A stand-in Renode catalog covering common + less-common families, mirroring real `.repl` filenames. */
const CATALOG = [
  'boards/stm32f4_discovery-kit.repl',
  'boards/stm32f072b_discovery.repl',
  'boards/stm32l072.repl',
  'cpus/stm32f4.repl',
  'cpus/nrf52840.repl',
  'cpus/efr32mg.repl',
  'cpus/cc2538.repl',
  'boards/sifive_fe310.repl',
  'boards/nucleo_h753zi.repl',
  'cpus/stm32h743.repl',
  'cpus/samd51.repl',
];

/** Build a fingerprint straight from a marker string, the way the real firmware bytes would produce one. */
function fpFrom(marker: string) {
  return fingerprintMcu(new TextEncoder().encode(`padding ${marker} padding`));
}

describe('buildRenodeScript', () => {
  it('loads the platform + ELF and surfaces every discovered UART, ending on start', () => {
    const s = buildRenodeScript('/plat/stm32f4.repl', '/fw/app.elf', ['usart1', 'uart4']).split('\n');
    expect(s[0]).toBe('mach create');
    expect(s).toContain('machine LoadPlatformDescription @/plat/stm32f4.repl');
    expect(s).toContain('sysbus LoadELF @/fw/app.elf');
    expect(s).toContain('showAnalyzer sysbus.usart1');
    expect(s).toContain('showAnalyzer sysbus.uart4');
    expect(s[s.length - 1]).toBe('start');
  });

  it('falls back to uart0 when no UARTs are known', () => {
    expect(buildRenodeScript('/p.repl', '/f.elf', [])).toContain('showAnalyzer sysbus.uart0');
  });

  it('adds a file backend per UART when a capture dir is given', () => {
    const s = buildRenodeScript('/p.repl', '/f.elf', ['uart4'], '/tmp/cap');
    expect(s).toContain('sysbus.uart4 CreateFileBackend @/tmp/cap/uart_uart4.txt true');
  });
});

describe('discoverUarts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'renode-repl-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

  it('follows `using` includes (both ./relative and root-relative) to find the real UARTs', () => {
    // Mirror the STM32F4 board→SoC layout: a board repl that declares no UART, pulling them from an included SoC repl.
    fs.mkdirSync(path.join(root, 'platforms/boards'), { recursive: true });
    fs.mkdirSync(path.join(root, 'platforms/cpus'), { recursive: true });
    fs.writeFileSync(
      path.join(root, 'platforms/cpus/soc.repl'),
      'usart1: UART.STM32_UART @ sysbus <0x40011000, +0x100>\nuart4: UART.STM32_UART @ sysbus <0x40004C00, +0x100>\n',
    );
    fs.writeFileSync(
      path.join(root, 'platforms/boards/mid.repl'),
      'using "platforms/cpus/soc.repl"\nUserLED: Miscellaneous.LED @ gpioPortD\n',
    );
    fs.writeFileSync(path.join(root, 'platforms/boards/board.repl'), 'using "./mid.repl"\n');
    const uarts = discoverUarts(path.join(root, 'platforms/boards/board.repl'), root);
    expect(uarts.sort()).toEqual(['uart4', 'usart1']);
  });

  it('returns nothing for a missing platform (→ script falls back to uart0)', () => {
    expect(discoverUarts(path.join(root, 'nope.repl'), root)).toEqual([]);
  });
});

describe('selectPlatform', () => {
  it('steers a fingerprinted STM32F4 to the known-good Discovery board, not a bare cpu', () => {
    const sel = selectPlatform(fpFrom('STM32F407VG'), [], CATALOG);
    expect(sel?.repl).toBe('boards/stm32f4_discovery-kit.repl');
    expect(sel?.via).toBe('family');
  });

  it('matches families beyond the common three from the real catalog (RISC-V FE310, SAMD51)', () => {
    expect(selectPlatform(fpFrom('SiFive FE310-G002'), [], CATALOG)?.repl).toBe('boards/sifive_fe310.repl');
    expect(selectPlatform(fpFrom('Microchip ATSAMD51J20'), [], CATALOG)?.repl).toBe('cpus/samd51.repl');
  });

  it('prefers a part-specific board over a bare cpu (STM32H753 → nucleo_h753zi, not cpus/stm32h743)', () => {
    // The board names the exact part (via its stripped core `h753`) and carries the SoC peripherals.
    expect(selectPlatform(fpFrom('STM32H753ZI'), [], CATALOG)?.repl).toBe('boards/nucleo_h753zi.repl');
  });

  it('picks the exact part when the catalog names it (nRF52840 → cpus/nrf52840)', () => {
    const sel = selectPlatform(fpFrom('Nordic nRF52840 SoftDevice'), [], CATALOG);
    expect(sel?.repl).toBe('cpus/nrf52840.repl');
    expect(sel?.via).toBe('part');
  });

  it('blocks honestly on a bare Cortex-M with no vendor identity (real Renode ships no generic core .repl)', () => {
    // A raw vector table (valid Cortex-M memory map) but no vendor family string → cannot pick a real board.
    const buf = new Uint8Array(0x40);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x2000_5000, true);
    dv.setUint32(4, 0x0800_0abd, true);
    buf.set(new TextEncoder().encode('Cortex-M0 bare metal'), 0x20);
    const fp = fingerprintMcu(buf);
    expect(fp.arch).toBe('arm'); // it IS recognized as Cortex-M…
    expect(selectPlatform(fp, [], CATALOG)).toBeNull(); // …but without a vendor family we honestly block
  });

  it('mines the free-text hints too (a "discovery" hint reinforces the board)', () => {
    expect(selectPlatform(fpFrom('STM32F072'), ['STM32F072B Discovery kit'], CATALOG)?.repl).toBe(
      'boards/stm32f072b_discovery.repl',
    );
  });

  it('returns null when nothing matches (→ honest blocked_by_platform)', () => {
    expect(selectPlatform(fpFrom('some x86 linux server'), [], CATALOG)).toBeNull();
    expect(selectPlatform(fingerprintMcu(new Uint8Array()), [], CATALOG)).toBeNull();
  });
});

describe('listPlatformCatalog', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'renode-cat-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

  it('recursively lists .repl files as paths relative to the platforms dir', () => {
    fs.mkdirSync(path.join(root, 'boards'), { recursive: true });
    fs.mkdirSync(path.join(root, 'cpus'), { recursive: true });
    fs.writeFileSync(path.join(root, 'boards/stm32f4_discovery-kit.repl'), '');
    fs.writeFileSync(path.join(root, 'cpus/nrf52840.repl'), '');
    fs.writeFileSync(path.join(root, 'cpus/notes.txt'), 'ignored');
    const cat = listPlatformCatalog(root).sort();
    expect(cat).toEqual(['boards/stm32f4_discovery-kit.repl', 'cpus/nrf52840.repl']);
  });

  it('returns [] for a missing platforms dir (→ selection blocks honestly)', () => {
    expect(listPlatformCatalog(path.join(root, 'nope'))).toEqual([]);
  });
});

describe('buildRenodeFindings', () => {
  const base: RenodeResult = {
    available: true,
    ran: true,
    booted: true,
    reason: 'Renode booted the firmware on stm32f4_discovery-kit and the UART printed a recognisable banner.',
    proofState: 'confirmed_in_emulation',
    platform: 'boards/stm32f4_discovery-kit.repl',
    uartExcerpt: 'Contiki 3.x started\n',
    command: 'renode --disable-xwt -e ...',
  };

  it('a boot names the platform and refuses the device in its own title', () => {
    const [d] = buildRenodeFindings(base);
    expect(d?.kind).toBe('renode-booted');
    expect(d?.proofState).toBe('confirmed_in_emulation');
    expect(d?.evidenceChannel).toBe('emulated_run');
    expect(d?.title).toContain('stm32f4_discovery-kit');
    expect(d?.title).toContain('not on the part');
    expect(d?.evidence?.uartExcerpt).toContain('Contiki 3.x started');
  });

  // Renode is an opt-in layer, so "not installed" is the common case — and it must not read as "nothing to find"
  // on images whose ONLY dynamic question this is.
  it('a blocked run earns a row that says it is not a negative, and carries no evidence channel', () => {
    const [d] = buildRenodeFindings({
      ...base,
      available: false,
      ran: false,
      booted: false,
      proofState: 'blocked_by_platform',
      platform: null,
      uartExcerpt: '',
      command: '',
      reason: 'Renode not installed (opt-in layer).',
    });
    expect(d?.kind).toBe('renode-blocked');
    expect(d?.proofState).toBe('blocked_by_platform');
    expect(d && 'evidenceChannel' in d).toBe(false);
    expect(d?.title).toContain('not a negative result');
    expect(d?.rationale).toContain('not evidence that there is nothing to find');
  });

  it('ran-but-never-booted is its own row, not a boot and not a block', () => {
    const [d] = buildRenodeFindings({ ...base, booted: false, proofState: 'needs_runtime_reproduction' });
    expect(d?.kind).toBe('renode-boot-unconfirmed');
    expect(d?.proofState).toBe('needs_runtime_reproduction');
    expect(d?.evidenceChannel).toBe('emulated_run');
    expect(d?.title).toContain('not a verdict about the firmware');
  });

  it('carries the proof state the runner decided, never one of its own', () => {
    // `booted` is read from real UART output; a composer that re-derived the state would be a second opinion on
    // evidence it never saw.
    const [d] = buildRenodeFindings({ ...base, proofState: 'blocked_by_security' });
    expect(d?.proofState).toBe('blocked_by_security');
  });

  it('bounds the UART excerpt so a chatty firmware cannot grow the row without limit', () => {
    const [d] = buildRenodeFindings({ ...base, uartExcerpt: 'A'.repeat(9000) });
    expect(String(d?.evidence?.uartExcerpt).length).toBe(4000);
  });
});

// Renode fetches `ApplySVD @https://…` files on platform load, and the deployed container cannot drop its network
// namespace — the env is the only thing between a boot and an unrequested download.
describe('offlineRenodeEnv', () => {
  const PROXY_VARS = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'];

  it('aims every proxy variable, in both spellings, at the refusing loopback port', () => {
    const env = offlineRenodeEnv({ PATH: '/usr/bin' });
    for (const k of PROXY_VARS) expect(env[k]).toBe(RENODE_REFUSING_PROXY);
    expect(Object.keys(OFFLINE_RENODE_ENV).sort()).toEqual([...PROXY_VARS].sort());
    expect(RENODE_REFUSING_PROXY).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  it('overrides an inherited proxy and removes the bypass list rather than trusting it', () => {
    const env = offlineRenodeEnv({
      HTTPS_PROXY: 'http://corp-proxy:3128',
      https_proxy: 'http://corp-proxy:3128',
      NO_PROXY: '*',
      no_proxy: '.antmicro.com',
    });
    expect(env.HTTPS_PROXY).toBe(RENODE_REFUSING_PROXY);
    expect(env.https_proxy).toBe(RENODE_REFUSING_PROXY);
    expect('NO_PROXY' in env).toBe(false);
    expect('no_proxy' in env).toBe(false);
  });

  it('keeps HOME unless a per-run home is given, and leaves the base env untouched', () => {
    const base = { HOME: '/home/firmlab', PATH: '/usr/bin', NO_PROXY: '*' };
    expect(offlineRenodeEnv(base).HOME).toBe('/home/firmlab');
    expect(offlineRenodeEnv(base, '/tmp/run').HOME).toBe('/tmp/run');
    expect(offlineRenodeEnv(base).PATH).toBe('/usr/bin');
    expect(base.NO_PROXY).toBe('*');
  });
});

describe('buildRenodeInvocation', () => {
  it('runs the boot script under the offline env with HOME at the work dir', () => {
    const inv = buildRenodeInvocation('/w/boot.resc', 15, '/w', { HOME: '/home/x', NO_PROXY: '*' });
    expect(inv.argv[0]).toBe('renode');
    expect(inv.argv.at(-1)).toBe('include @/w/boot.resc; sleep 15; quit');
    for (const [k, v] of Object.entries(OFFLINE_RENODE_ENV)) expect(inv.options.env[k]).toBe(v);
    expect('NO_PROXY' in inv.options.env).toBe(false);
    expect(inv.options.env.HOME).toBe('/w');
  });

  it('keeps the bounds the .NET runtime needs (no --as, no --fsize) and scales cpu/wall with the run', () => {
    const { limits } = buildRenodeInvocation('/w/boot.resc', 10, '/w', {}).options;
    expect(limits.addressSpaceBytes).toBe(0);
    expect(limits.fileSizeBytes).toBe(0);
    expect(limits.cpuSeconds).toBe(100);
    expect(limits.wallMs).toBe(55_000);
  });
});

describe('scanRemoteResources', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'renode-remote-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (rel: string, text: string): string => {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, text);
    return p;
  };
  const SVD = 'https://dl.antmicro.com/projects/renode/svd/STM32L0x1.svd';

  it('follows a nested include chain (root-relative and ./relative) to the remote SVD', () => {
    // Mirrors stm32l072.repl → stm32l071.repl, whose init block applies a remote SVD.
    write(
      'platforms/cpus/stm32l071.repl',
      `nvic: IRQControllers.NVIC @ sysbus 0xE000E000\n\nsysbus:\n    init:\n        ApplySVD @${SVD}\n`,
    );
    write('platforms/cpus/stm32l072.repl', 'using "platforms/cpus/stm32l071.repl"\n');
    const board = write('platforms/boards/l072-board.repl', 'using "../cpus/stm32l072"\n');
    const scan = scanRemoteResources(board, root);
    expect(scan.remote).toEqual([SVD]);
    expect(scan.filesScanned).toBe(3);
    expect(scan.unscanned).toEqual([]);
  });

  it('reports no remote references for a self-contained chain (an empty list, nothing unscanned)', () => {
    write('platforms/cpus/local.repl', 'uart0: UART.PL011 @ sysbus 0x4000C000\n');
    const board = write('platforms/boards/local-board.repl', 'using "platforms/cpus/local.repl"\n');
    expect(scanRemoteResources(board, root)).toEqual({ remote: [], filesScanned: 2, unscanned: [] });
  });

  it('ignores a commented-out ApplySVD, which Renode never fetches', () => {
    const p = write(
      'platforms/cpus/commented.repl',
      '// ApplySVD @https://example.invalid/a.svd\n/* ApplySVD @https://example.invalid/b.svd */\n',
    );
    expect(scanRemoteResources(p, root).remote).toEqual([]);
  });

  it('stops at a cycle and still reports what each file references, once', () => {
    write('platforms/cyc/a.repl', `using "./b.repl"\nsysbus:\n    init:\n        ApplySVD @${SVD}\n`);
    write('platforms/cyc/b.repl', `using "./a.repl"\nsysbus:\n    init:\n        ApplySVD @${SVD}\n`);
    const scan = scanRemoteResources(path.join(root, 'platforms/cyc/a.repl'), root);
    expect(scan.remote).toEqual([SVD]);
    expect(scan.filesScanned).toBe(2);
  });

  it('refuses an include that escapes the Renode root, and names it as unscanned', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'renode-outside-'));
    try {
      fs.writeFileSync(
        path.join(outside, 'evil.repl'),
        'sysbus:\n    init:\n        ApplySVD @https://x.invalid/e.svd\n',
      );
      const rel = path.relative(path.join(root, 'platforms/esc'), path.join(outside, 'evil.repl'));
      const p = write('platforms/esc/board.repl', `using "./${rel}"\nusing "${path.join(outside, 'evil.repl')}"\n`);
      const scan = scanRemoteResources(p, root);
      expect(scan.remote).toEqual([]); // never read
      expect(scan.filesScanned).toBe(1);
      expect(scan.unscanned).toHaveLength(1); // both spellings resolve to the same file, refused once
      expect(scan.unscanned[0]).toContain('outside the Renode root');
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('does not read a starting platform outside the root either', () => {
    const scan = scanRemoteResources('/etc/hosts', root);
    expect(scan.filesScanned).toBe(0);
    expect(scan.unscanned[0]).toContain('outside the Renode root');
  });

  it('names what a depth or file bound left unread instead of dropping it silently', () => {
    write('platforms/deep/d0.repl', 'using "./d1.repl"\n');
    write('platforms/deep/d1.repl', 'using "./d2.repl"\n');
    write('platforms/deep/d2.repl', `ApplySVD @${SVD}\n`);
    const deep = scanRemoteResources(path.join(root, 'platforms/deep/d0.repl'), root, { maxDepth: 1 });
    expect(deep.remote).toEqual([]);
    expect(deep.unscanned).toEqual([
      `${path.join(root, 'platforms/deep/d2.repl')} (past the include depth bound of 1)`,
    ]);
    const few = scanRemoteResources(path.join(root, 'platforms/deep/d0.repl'), root, { maxFiles: 2 });
    expect(few.filesScanned).toBe(2);
    expect(few.unscanned[0]).toContain('past the file bound of 2');
  });

  it('reports an unreadable include, and a platform that is itself a URL as remote', () => {
    const p = write('platforms/miss/board.repl', 'using "./gone.repl"\n');
    expect(scanRemoteResources(p, root).unscanned[0]).toContain('(unreadable)');
    expect(scanRemoteResources('https://x.invalid/p.repl', root).remote).toEqual(['https://x.invalid/p.repl']);
  });
});

describe('describeRefusedRemote', () => {
  it('says nothing when nothing was refused and the chain was read whole', () => {
    expect(describeRefusedRemote({ remote: [], filesScanned: 2, unscanned: [] })).toBe('');
  });

  it('names the refused resource and that the run used the platform without it', () => {
    const s = describeRefusedRemote({ remote: ['https://a.invalid/x.svd'], filesScanned: 2, unscanned: [] });
    expect(s).toContain('refused rather than downloaded');
    expect(s).toContain('https://a.invalid/x.svd');
    expect(s).toContain('without it');
  });

  it('says the list may be incomplete when part of the chain went unread', () => {
    const s = describeRefusedRemote({ remote: [], filesScanned: 1, unscanned: ['/x.repl (unreadable)'] });
    expect(s).toContain('may be incomplete');
  });
});

describe('buildRenodeFindings — refused remote resources', () => {
  it('carries the refused list into the evidence when there is one, and omits it otherwise', () => {
    const r: RenodeResult = {
      available: true,
      ran: true,
      booted: true,
      reason: 'ok',
      proofState: 'confirmed_in_emulation',
      platform: 'boards/x.repl',
      uartExcerpt: 'Booting Zephyr OS',
      command: 'renode',
    };
    expect(buildRenodeFindings(r)[0]?.evidence?.remoteResourcesRefused).toBeUndefined();
    expect(
      buildRenodeFindings({ ...r, remoteResourcesRefused: [] })[0]?.evidence?.remoteResourcesRefused,
    ).toBeUndefined();
    const [d] = buildRenodeFindings({ ...r, remoteResourcesRefused: ['https://a.invalid/x.svd'] });
    expect(d?.evidence?.remoteResourcesRefused).toEqual(['https://a.invalid/x.svd']);
    expect(d?.proofState).toBe('confirmed_in_emulation');
  });
});
