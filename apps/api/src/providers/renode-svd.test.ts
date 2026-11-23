import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  RENODE_SVD_MANIFEST,
  type SvdManifestEntry,
  decideSvd,
  describeSvdResolution,
  isRenodeSafePath,
  isSafeSvdFileName,
  maskReplComments,
  parseApplySvdRefs,
  parseSvdManifest,
  parseUsingRefs,
  prepareSvdOverlay,
  renodeSvdDir,
  rewritePlatformText,
  withoutServedLocally,
} from './renode-svd.js';
import { buildRenodeFindings } from './renode.js';

const URL_L0 = 'https://dl.antmicro.com/projects/renode/svd/STM32L0x1.svd';
const URL_F4 = 'https://dl.antmicro.com/projects/renode/svd/STM32F40x.svd.gz';
const URL_F429 = 'https://dl.antmicro.com/projects/renode/svd/STM32F429x.svd.gz';
const sha = (b: string | Buffer): string => crypto.createHash('sha256').update(b).digest('hex');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-renode-svd-test-'));
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe('parseApplySvdRefs', () => {
  it('finds each ApplySVD URL with offsets into the original text and its line', () => {
    const text = `sysbus:\n    init:\n        ApplySVD @${URL_L0}\n        Tag <0x1, 0x2> "X"\n`;
    const refs = parseApplySvdRefs(text);
    expect(refs).toHaveLength(1);
    const r = refs[0];
    expect(r?.url).toBe(URL_L0);
    expect(text.slice(r?.start, r?.end)).toBe(URL_L0);
    expect(r?.line).toBe(3);
  });

  it('ignores commented-out references, both // lines and /* */ blocks, without shifting offsets', () => {
    const text = `// ApplySVD @${URL_F4}\n/* ApplySVD @${URL_F429} */\n    ApplySVD @${URL_L0}\n`;
    expect(maskReplComments(text)).toHaveLength(text.length);
    const refs = parseApplySvdRefs(text);
    expect(refs.map((r) => r.url)).toEqual([URL_L0]);
    expect(text.slice(refs[0]?.start, refs[0]?.end)).toBe(URL_L0);
  });

  it('does not take a local ApplySVD, or a remote reference that is not an ApplySVD', () => {
    expect(parseApplySvdRefs('    ApplySVD @/opt/svd/x.svd\n    LoadBinary @https://example.com/x.bin\n')).toEqual([]);
  });
});

describe('parseUsingRefs', () => {
  it('resolves ./relative against the file and anything else against the Renode root, adding .repl', () => {
    const text = 'using "./stm32f4.repl"\nusing "platforms/cpus/nrf52840"\n';
    const refs = parseUsingRefs(text, '/r/platforms/cpus/stm32f429.repl', '/r');
    expect(refs.map((r) => r.resolved)).toEqual(['/r/platforms/cpus/stm32f4.repl', '/r/platforms/cpus/nrf52840.repl']);
    expect(refs.map((r) => text.slice(r.start, r.end))).toEqual(['./stm32f4.repl', 'platforms/cpus/nrf52840']);
  });
});

describe('rewritePlatformText', () => {
  it('rewrites only the named URLs and the includes it is asked to, leaving everything else byte-identical', () => {
    const text = `using "./stm32f4.repl"\n\nsysbus:\n    init:\n        ApplySVD @${URL_F429}\n        ApplySVD @${URL_L0}\n`;
    const usings = parseUsingRefs(text, '/r/platforms/cpus/stm32f429.repl', '/r');
    const out = rewritePlatformText(
      text,
      new Map([[URL_F429, '/w/svd-0-F429.svd.gz']]),
      usings,
      () => '/w/0-stm32f4.repl',
    );
    expect(out.rewritten).toEqual([URL_F429]);
    expect(out.text).toBe(
      `using "/w/0-stm32f4.repl"\n\nsysbus:\n    init:\n        ApplySVD @/w/svd-0-F429.svd.gz\n        ApplySVD @${URL_L0}\n`,
    );
  });

  it('is the identity when nothing is local and no include is retargeted', () => {
    const text = `x\n    ApplySVD @${URL_L0}\n`;
    expect(rewritePlatformText(text, new Map()).text).toBe(text);
  });
});

describe('parseSvdManifest', () => {
  const good: SvdManifestEntry = { url: URL_L0, file: 'abc-STM32L0x1.svd', sha256: 'a'.repeat(64), size: 3 };

  it('keeps well-formed entries and drops malformed ones', () => {
    const m = parseSvdManifest(
      JSON.stringify({ version: 1, entries: [good, { url: URL_F4 }, { ...good, sha256: 'xyz' }] }),
    );
    expect(m?.entries).toEqual([good]);
  });

  it('treats unparsable JSON and an unknown version as no manifest at all', () => {
    expect(parseSvdManifest('{not json')).toBeNull();
    expect(parseSvdManifest(JSON.stringify({ version: 2, entries: [good] }))).toBeNull();
  });
});

describe('decideSvd', () => {
  const entry: SvdManifestEntry = { url: URL_L0, file: 'abc-STM32L0x1.svd', sha256: sha('svd') };

  it('is local only when an entry exists and the observed sha256 equals the recorded one', () => {
    const r = decideSvd(URL_L0, entry, { sha256: sha('svd'), size: 3 });
    expect(r.status).toBe('local');
    expect(r.observedSha256).toBe(entry.sha256);
  });

  it('is missing with no entry, and missing — not trusted — when the entry names an absent file', () => {
    expect(decideSvd(URL_L0, undefined, null).status).toBe('missing');
    const absent = decideSvd(URL_L0, entry, null);
    expect(absent.status).toBe('missing');
    expect(absent.reason).toContain('absent');
  });

  it('is a mismatch, naming both hashes, when the file changed after provisioning', () => {
    const r = decideSvd(URL_L0, entry, { sha256: sha('tampered'), size: 8 });
    expect(r.status).toBe('mismatch');
    expect(r.expectedSha256).toBe(sha('svd'));
    expect(r.observedSha256).toBe(sha('tampered'));
  });

  it('refuses a manifest file name that is a path, and a file past the size cap', () => {
    expect(decideSvd(URL_L0, { ...entry, file: '../../etc/passwd' }, { sha256: entry.sha256, size: 3 }).status).toBe(
      'unusable',
    );
    expect(decideSvd(URL_L0, entry, { sha256: entry.sha256, size: 10 }, 5).status).toBe('unusable');
  });

  it('file-name and path guards', () => {
    expect(isSafeSvdFileName('7f60-S32K118.svd-s_4356973-8b6f')).toBe(true);
    expect(isSafeSvdFileName('.hidden')).toBe(false);
    expect(isSafeSvdFileName('a/b.svd')).toBe(false);
    expect(isRenodeSafePath('/tmp/firmlab-renode-x/svd-overlay')).toBe(true);
    expect(isRenodeSafePath('/tmp/with space/x')).toBe(false);
  });
});

describe('renodeSvdDir', () => {
  it('lives under the data root', () => {
    expect(renodeSvdDir({ FIRMLAB_DATA_DIR: '/data' })).toBe('/data/renode-svd');
  });
});

/** A miniature Renode root: a board that includes a cpu (root-relative), which includes another (./relative). */
function fixture(name: string): { root: string; board: string; svdDir: string; work: string } {
  const root = path.join(tmp, name, 'renode');
  const cpus = path.join(root, 'platforms', 'cpus');
  const boards = path.join(root, 'platforms', 'boards');
  fs.mkdirSync(cpus, { recursive: true });
  fs.mkdirSync(boards, { recursive: true });
  fs.writeFileSync(
    path.join(cpus, 'stm32f4.repl'),
    `nvic: IRQControllers.NVIC @ sysbus 0xE000E000\n\nsysbus:\n    init:\n        ApplySVD @${URL_F4}\n`,
  );
  fs.writeFileSync(
    path.join(cpus, 'stm32f429.repl'),
    `using "./stm32f4.repl"\n\nsysbus:\n    init:\n        ApplySVD @${URL_F429}\n`,
  );
  fs.writeFileSync(path.join(cpus, 'plain.repl'), 'uart0: UART.PL011 @ sysbus 0x1000\n');
  const board = path.join(boards, 'disco.repl');
  fs.writeFileSync(
    board,
    'using "platforms/cpus/stm32f429.repl"\nusing "platforms/cpus/plain"\n\nled: Miscellaneous.LED @ gpio 1\n',
  );
  const svdDir = path.join(tmp, name, 'data', 'renode-svd');
  fs.mkdirSync(svdDir, { recursive: true });
  const work = path.join(tmp, name, 'work');
  fs.mkdirSync(work, { recursive: true });
  return { root, board, svdDir, work };
}

function provision(svdDir: string, entries: { url: string; file: string; body: string; recorded?: string }[]): void {
  for (const e of entries) fs.writeFileSync(path.join(svdDir, e.file), e.body);
  const manifest = {
    version: 1,
    entries: entries.map((e) => ({ url: e.url, file: e.file, sha256: e.recorded ?? sha(e.body), size: e.body.length })),
  };
  fs.writeFileSync(path.join(svdDir, RENODE_SVD_MANIFEST), JSON.stringify(manifest));
}

describe('prepareSvdOverlay', () => {
  it('with no manifest, writes nothing and loads the original platform — every SVD is missing', () => {
    const f = fixture('none');
    const o = prepareSvdOverlay(f.board, f.root, f.work, { svdDir: f.svdDir });
    expect(o.platformPath).toBe(f.board);
    expect(o.servedLocally).toEqual([]);
    expect(o.resolutions.map((r) => [r.url, r.status])).toEqual([
      [URL_F429, 'missing'],
      [URL_F4, 'missing'],
    ]);
    expect(fs.existsSync(path.join(f.work, 'svd-overlay'))).toBe(false);
  });

  it('serves verified SVDs through a rewritten copy of the chain, absolute includes, bundled files untouched', () => {
    const f = fixture('all');
    provision(f.svdDir, [
      { url: URL_F4, file: '1111-STM32F40x.svd.gz', body: 'f4-bytes' },
      { url: URL_F429, file: '2222-STM32F429x.svd.gz', body: 'f429-bytes' },
    ]);
    const before = fs.readFileSync(path.join(f.root, 'platforms/cpus/stm32f4.repl'), 'utf8');
    const o = prepareSvdOverlay(f.board, f.root, f.work, { svdDir: f.svdDir });

    expect(o.resolutions.every((r) => r.status === 'local')).toBe(true);
    expect(new Set(o.servedLocally)).toEqual(new Set([URL_F4, URL_F429]));
    expect(o.platformPath.startsWith(path.join(f.work, 'svd-overlay'))).toBe(true);
    expect(fs.readFileSync(path.join(f.root, 'platforms/cpus/stm32f4.repl'), 'utf8')).toBe(before);

    // Follow the copy the way Renode would: every include is absolute, and no remote reference is left anywhere.
    const top = fs.readFileSync(o.platformPath, 'utf8');
    const incs = parseUsingRefs(top, o.platformPath, f.root);
    expect(incs.every((u) => path.isAbsolute(u.raw))).toBe(true);
    expect(incs.map((u) => u.raw)).toContain(path.join(f.root, 'platforms/cpus/plain.repl')); // unchanged file: original
    const f429Copy = incs.find((u) => u.raw.startsWith(f.work))?.raw ?? '';
    const f429 = fs.readFileSync(f429Copy, 'utf8');
    expect(parseApplySvdRefs(f429)).toEqual([]);
    const f4Copy = parseUsingRefs(f429, f429Copy, f.root)[0]?.raw ?? '';
    expect(f4Copy.startsWith(f.work)).toBe(true);
    const f4 = fs.readFileSync(f4Copy, 'utf8');
    const svdPath = /ApplySVD @(\S+)/.exec(f4)?.[1] ?? '';
    // The bytes Renode loads are a copy of the verified bytes, inside the run's work dir.
    expect(svdPath.startsWith(f.work)).toBe(true);
    expect(fs.readFileSync(svdPath, 'utf8')).toBe('f4-bytes');
  });

  it('keeps a mismatched SVD remote, still serving the one that verifies', () => {
    const f = fixture('mismatch');
    provision(f.svdDir, [
      { url: URL_F4, file: '1111-STM32F40x.svd.gz', body: 'f4-bytes' },
      { url: URL_F429, file: '2222-STM32F429x.svd.gz', body: 'tampered', recorded: sha('f429-bytes') },
    ]);
    const o = prepareSvdOverlay(f.board, f.root, f.work, { svdDir: f.svdDir });
    const by = Object.fromEntries(o.resolutions.map((r) => [r.url, r.status]));
    expect(by).toEqual({ [URL_F4]: 'local', [URL_F429]: 'mismatch' });
    expect(o.servedLocally).toEqual([URL_F4]);
    const all = fs
      .readdirSync(path.join(f.work, 'svd-overlay'))
      .filter((n) => n.endsWith('.repl'))
      .map((n) => fs.readFileSync(path.join(f.work, 'svd-overlay', n), 'utf8'))
      .join('\n');
    expect(all).toContain(`ApplySVD @${URL_F429}`);
    expect(all).not.toContain(`ApplySVD @${URL_F4}`);
  });

  it('a chain with no SVD reference is left alone and reports nothing', () => {
    const f = fixture('plain');
    const plain = path.join(f.root, 'platforms/cpus/plain.repl');
    expect(prepareSvdOverlay(plain, f.root, f.work, { svdDir: f.svdDir })).toEqual({
      platformPath: plain,
      resolutions: [],
      servedLocally: [],
    });
  });

  it('refuses to build an overlay Renode could not parse (a work path with whitespace)', () => {
    const f = fixture('space');
    provision(f.svdDir, [{ url: URL_F4, file: '1111-STM32F40x.svd.gz', body: 'f4-bytes' }]);
    const work = path.join(tmp, 'space', 'work dir');
    fs.mkdirSync(work, { recursive: true });
    const o = prepareSvdOverlay(f.board, f.root, work, { svdDir: f.svdDir });
    expect(o.platformPath).toBe(f.board);
    expect(o.servedLocally).toEqual([]);
    expect(o.resolutions.find((r) => r.url === URL_F4)?.status).toBe('unusable');
  });
});

describe('describeSvdResolution / withoutServedLocally', () => {
  it('says nothing when the chain referenced no SVD', () => {
    expect(describeSvdResolution([])).toBe('');
  });

  it('names what was served locally and why each other one was not, never that it was applied', () => {
    const s = describeSvdResolution([
      { url: URL_F4, status: 'local' },
      { url: URL_F429, status: 'mismatch', reason: 'hashes differ' },
    ]);
    expect(s).toContain(`served from the provisioned local copy after its sha256 matched the manifest (${URL_F4})`);
    expect(s).toContain(`${URL_F429}: mismatch — hashes differ`);
    expect(s).not.toMatch(/applied/);
  });

  it('removes only the locally served URLs from the refused list', () => {
    const scan = { remote: [URL_F4, URL_F429], filesScanned: 3, unscanned: [] };
    expect(withoutServedLocally(scan, [URL_F4])).toEqual({ ...scan, remote: [URL_F429] });
    expect(withoutServedLocally(scan, [])).toBe(scan);
  });

  it('carries the per-URL resolution into the finding evidence, and omits it when empty', () => {
    const base = {
      available: true,
      ran: true,
      booted: true,
      reason: 'r',
      proofState: 'confirmed_in_emulation' as const,
      platform: 'p',
      uartExcerpt: '',
      command: '',
    };
    const res = [{ url: URL_F4, status: 'local' as const }];
    expect(buildRenodeFindings({ ...base, svdResolution: res })[0]?.evidence?.svdResolution).toEqual(res);
    expect(buildRenodeFindings({ ...base, svdResolution: [] })[0]?.evidence).not.toHaveProperty('svdResolution');
    expect(buildRenodeFindings(base)[0]?.evidence).not.toHaveProperty('svdResolution');
  });
});
