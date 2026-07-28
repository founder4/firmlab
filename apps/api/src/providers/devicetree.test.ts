import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  analyzeDeviceTree,
  classifyPeripheral,
  deviceTreeFindings,
  isNodeEnabled,
  isPartitionContainer,
  readPartitions,
  resolveStdoutPath,
  runDeviceTreeAnalysis,
} from './devicetree.js';
import { FDT_MAGIC, nodeAt, parseFdt } from './fdt.js';

// === A minimal FDT writer (see fdt.test.ts — deliberately self-contained per test file) ===

const NUL = Buffer.alloc(1);
function str(s: string): Buffer {
  return Buffer.concat([Buffer.from(s, 'ascii'), NUL]);
}
function strlist(...v: string[]): Buffer {
  return Buffer.concat(v.map(str));
}
function cells(...v: number[]): Buffer {
  const b = Buffer.alloc(v.length * 4);
  v.forEach((n, i) => b.writeUInt32BE(n >>> 0, i * 4));
  return b;
}
const EMPTY = Buffer.alloc(0);

interface NodeSpec {
  name: string;
  props?: [string, Buffer][];
  children?: NodeSpec[];
}

function pad4(b: Buffer): Buffer {
  const r = b.length % 4;
  return r === 0 ? b : Buffer.concat([b, Buffer.alloc(4 - r)]);
}
function token(t: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(t, 0);
  return b;
}

function buildFdt(root: NodeSpec): Buffer {
  const names: string[] = [];
  const offsets = new Map<string, number>();
  let stringsLen = 0;
  const nameOff = (n: string): number => {
    const existing = offsets.get(n);
    if (existing !== undefined) return existing;
    const o = stringsLen;
    offsets.set(n, o);
    names.push(n);
    stringsLen += n.length + 1;
    return o;
  };
  const chunks: Buffer[] = [];
  const emit = (node: NodeSpec): void => {
    chunks.push(token(1), pad4(str(node.name)));
    for (const [n, v] of node.props ?? []) {
      const h = Buffer.alloc(8);
      h.writeUInt32BE(v.length, 0);
      h.writeUInt32BE(nameOff(n), 4);
      chunks.push(token(3), h, pad4(v));
    }
    for (const c of node.children ?? []) emit(c);
    chunks.push(token(2));
  };
  emit(root);
  chunks.push(token(9));

  const structBlock = Buffer.concat(chunks);
  const stringsBlock = Buffer.concat(names.map(str));
  const HEADER = 40;
  const memRsv = Buffer.alloc(16);
  const offStruct = HEADER + memRsv.length;
  const offStrings = offStruct + structBlock.length;
  const header = Buffer.alloc(HEADER);
  header.writeUInt32BE(FDT_MAGIC, 0);
  header.writeUInt32BE(offStrings + stringsBlock.length, 4);
  header.writeUInt32BE(offStruct, 8);
  header.writeUInt32BE(offStrings, 12);
  header.writeUInt32BE(HEADER, 16);
  header.writeUInt32BE(17, 20);
  header.writeUInt32BE(16, 24);
  header.writeUInt32BE(0, 28);
  header.writeUInt32BE(stringsBlock.length, 32);
  header.writeUInt32BE(structBlock.length, 36);
  return Buffer.concat([header, memRsv, structBlock, stringsBlock]);
}

// A board tree carrying every fact the provider claims to read: identity, a `fixed-partitions` map with a
// read-only entry, a /chosen command line that drops to a root shell, and an `ok`-spelled console UART next to a
// `disable`-spelled second one and a pin-mux child that must not be mistaken for a device.
const BOARD = buildFdt({
  name: '',
  props: [
    ['#address-cells', cells(2)],
    ['#size-cells', cells(2)],
    ['model', str('EVB_CBDM_AK3918EV300L_V1.0.0 board')],
    ['compatible', strlist('anyka,ak3918ev300l')],
  ],
  children: [
    {
      name: 'soc',
      props: [
        ['#address-cells', cells(1)],
        ['#size-cells', cells(1)],
      ],
      children: [
        {
          name: 'pinctrl@08000000',
          props: [
            ['compatible', str('anyka,ak3918ev300l-pinctrl')],
            ['reg', cells(0x8000000, 0x1000)],
            ['status', str('okay')],
          ],
          children: [
            // No `compatible`, no `reg`, no unit address — a pin list, not a device.
            {
              name: 'uart0_pins',
              props: [
                ['anyka,pins', cells(0x34, 0x33)],
                ['anyka,function', cells(1, 1)],
              ],
            },
          ],
        },
        {
          name: 'uart0@20130000',
          props: [
            ['compatible', str('anyka,ak3918ev300l-uart0')],
            ['reg', cells(0x20130000, 0x1000)],
            ['status', str('ok')], // the deprecated spelling the corpus actually uses
          ],
        },
        {
          name: 'uart1@20140000',
          props: [
            ['compatible', str('anyka,ak3918ev300l-uart1')],
            ['reg', cells(0x20140000, 0x1000)],
            ['status', str('disable')], // a third spelling, in neither spec list
          ],
        },
        {
          name: 'watchdog@20000000',
          props: [
            ['compatible', str('anyka,ak3918-wdt')],
            ['reg', cells(0x20000000, 0x100)],
          ],
        },
        {
          name: 'spi@20120000',
          props: [
            ['compatible', str('anyka,ak3918-spi')],
            ['reg', cells(0x20120000, 0x1000)],
            ['status', str('okay')],
          ],
          children: [
            {
              name: 'flash@0',
              props: [
                ['compatible', str('jedec,spi-nor')],
                ['reg', cells(0)],
              ],
              children: [
                {
                  name: 'partitions',
                  props: [
                    ['compatible', str('fixed-partitions')],
                    ['#address-cells', cells(1)],
                    ['#size-cells', cells(1)],
                  ],
                  children: [
                    {
                      name: 'partition@0',
                      props: [
                        ['label', str('u-boot')],
                        ['reg', cells(0x0, 0x40000)],
                        ['read-only', EMPTY],
                      ],
                    },
                    {
                      name: 'partition@40000',
                      props: [
                        ['label', str('kernel')],
                        ['reg', cells(0x40000, 0x200000)],
                      ],
                    },
                    {
                      name: 'partition@240000',
                      props: [
                        ['label', str('rootfs')],
                        ['reg', cells(0x240000, 0xd00000)],
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
    { name: 'aliases', props: [['serial0', str('/soc/uart0@20130000')]] },
    {
      name: 'chosen',
      props: [
        ['stdout-path', str('serial0:115200n8')],
        ['bootargs', str('console=ttySAK0,115200n8 root=/dev/mtdblock5 rootfstype=squashfs init=/bin/sh')],
        ['bootargs-append', str(' clk_ignore_unused')],
      ],
    },
  ],
});

const PARSED = parseFdt(BOARD, 0);
const BLOB = analyzeDeviceTree(PARSED as never, 'test fixture', BOARD.length);

describe('isNodeEnabled — the kernel rule, not the spec wording', () => {
  it('treats an absent status as enabled', () => {
    expect(isNodeEnabled(undefined)).toBe(true);
  });

  it('accepts the deprecated "ok" spelling the GL.iNet tree uses 32 times', () => {
    expect(isNodeEnabled('ok')).toBe(true);
    expect(isNodeEnabled('okay')).toBe(true);
  });

  it('treats every other value as unavailable, including the "disable" the Tenda tree uses', () => {
    expect(isNodeEnabled('disabled')).toBe(false);
    expect(isNodeEnabled('disable')).toBe(false);
    expect(isNodeEnabled('fail')).toBe(false);
    expect(isNodeEnabled('reserved')).toBe(false);
  });
});

describe('classifyPeripheral', () => {
  const at = (p: string) => nodeAt(PARSED?.root as never, p) as never;

  it('classifies an addressable node with a compatible', () => {
    expect(classifyPeripheral(at('/soc/uart0@20130000'))).toBe('uart');
    expect(classifyPeripheral(at('/soc/watchdog@20000000'))).toBe('watchdog');
    expect(classifyPeripheral(at('/soc/spi@20120000'))).toBe('spi');
  });

  it('refuses a pin-mux child — it matches the name rule but is not a device', () => {
    expect(classifyPeripheral(at('/soc/pinctrl@08000000/uart0_pins'))).toBeNull();
  });

  it('refuses a node with no compatible at all', () => {
    expect(classifyPeripheral(at('/aliases'))).toBeNull();
    expect(classifyPeripheral(at('/chosen'))).toBeNull();
  });
});

describe('partitions', () => {
  const partitionsNode = nodeAt(PARSED?.root as never, '/soc/spi@20120000/flash@0/partitions') as never;

  it('recognises a fixed-partitions container', () => {
    expect(isPartitionContainer(partitionsNode)).toBe(true);
    expect(isPartitionContainer(nodeAt(PARSED?.root as never, '/soc') as never)).toBe(false);
  });

  it('reads offsets and sizes using the container-declared cell counts', () => {
    const parts = readPartitions(partitionsNode, { address: 2, size: 2 });
    expect(parts).toHaveLength(3);
    expect(parts[0]).toEqual({
      nodeName: 'partition@0',
      label: 'u-boot',
      offset: 0,
      size: 0x40000,
      declaredReadOnly: true,
    });
    expect(parts[2]?.offset).toBe(0x240000);
    expect(parts[2]?.size).toBe(0xd00000);
    expect(parts[2]?.declaredReadOnly).toBe(false);
  });

  it('folds 2-cell addresses when the container declares them', () => {
    const wide = buildFdt({
      name: '',
      children: [
        {
          name: 'partitions',
          props: [
            ['compatible', str('fixed-partitions')],
            ['#address-cells', cells(2)],
            ['#size-cells', cells(2)],
          ],
          children: [
            {
              name: 'partition@0',
              props: [
                ['label', str('big')],
                ['reg', cells(0x1, 0x00000000, 0x0, 0x1000)],
              ],
            },
          ],
        },
      ],
    });
    const tree = parseFdt(wide, 0);
    const parts = readPartitions(nodeAt(tree?.root as never, '/partitions') as never, { address: 2, size: 1 });
    expect(parts[0]?.offset).toBe(0x1_00000000);
    expect(parts[0]?.size).toBe(0x1000);
  });
});

describe('resolveStdoutPath', () => {
  it('resolves an alias and strips the options suffix', () => {
    expect(resolveStdoutPath(PARSED?.root as never)).toEqual({
      stdoutPath: 'serial0:115200n8',
      consolePath: '/soc/uart0@20130000',
    });
  });

  it('returns nothing when /chosen declares no console', () => {
    const bare = parseFdt(buildFdt({ name: '', props: [['model', str('x')]] }), 0);
    expect(resolveStdoutPath(bare?.root as never)).toEqual({});
  });
});

describe('analyzeDeviceTree', () => {
  it('reads board identity from the root', () => {
    expect(BLOB.model).toBe('EVB_CBDM_AK3918EV300L_V1.0.0 board');
    expect(BLOB.compatible).toEqual(['anyka,ak3918ev300l']);
  });

  it('assembles the command line from every /chosen property that contributes to it', () => {
    expect(BLOB.bootargsFrom).toEqual(['bootargs', 'bootargs-append']);
    expect(BLOB.bootargs).toContain('init=/bin/sh');
    expect(BLOB.bootargs).toContain('clk_ignore_unused');
  });

  it('marks the console UART and honours all three status spellings', () => {
    const uarts = BLOB.peripherals.filter((p) => p.kind === 'uart');
    const console = uarts.find((p) => p.console);
    expect(console?.path).toBe('/soc/uart0@20130000');
    expect(console?.status).toBe('ok');
    expect(console?.enabled).toBe(true);
    expect(uarts.find((p) => p.path === '/soc/uart1@20140000')?.enabled).toBe(false);
  });

  it('treats a node with no status as enabled', () => {
    const wdt = BLOB.peripherals.find((p) => p.kind === 'watchdog');
    expect(wdt?.status).toBe('(absent)');
    expect(wdt?.enabled).toBe(true);
  });

  it('reads the declared flash map and records the node it came from', () => {
    expect(BLOB.partitionNode).toBe('/soc/spi@20120000/flash@0/partitions');
    expect(BLOB.partitions.map((p) => p.label)).toEqual(['u-boot', 'kernel', 'rootfs']);
    expect(BLOB.partitions[0]?.declaredReadOnly).toBe(true);
  });

  it('does not report a pin-mux child as a peripheral', () => {
    expect(BLOB.peripherals.some((p) => p.path.includes('_pins'))).toBe(false);
  });

  it('excludes a driver chip-support table nested under a bus device, and says how many it dropped', () => {
    // The Tenda camera tree hangs 47 `spi-norflash@NN` nodes off `spi0/spi-flash@0`, each with a compatible, a
    // reg and a JEDEC id. They are the parts the driver recognises, not parts on this board — and unfiltered they
    // alone overflowed the peripheral cap and pushed 45 genuine nodes out of the result.
    const withTable = buildFdt({
      name: '',
      props: [['model', str('chip table board')]],
      children: [
        {
          name: 'spi0@21100000',
          props: [
            ['compatible', str('anyka,ak3918ev300l-spi0')],
            ['reg', cells(0x21100000, 0x1000)],
          ],
          children: [
            {
              name: 'spi-flash@0',
              props: [
                ['compatible', str('anyka,ak-spiflash')],
                ['reg', cells(0)],
              ],
              children: ['winbond,w25q64', 'gd,gd25q64', 'xmc,xm25qh64a'].map((c, i) => ({
                name: `spi-norflash@${44 + i}`,
                props: [
                  ['compatible', str(c)],
                  ['reg', cells(0x2c + i)],
                  ['norflash-jedec-id', cells(0xef4017)],
                ],
              })),
            },
          ],
        },
      ],
    });
    const blob = analyzeDeviceTree(parseFdt(withTable, 0) as never, 'test fixture', withTable.length);
    // The controller and the flash device it carries survive; the chip table does not.
    expect(blob.peripherals.map((p) => p.path)).toEqual(['/spi0@21100000', '/spi0@21100000/spi-flash@0']);
    expect(blob.nestedNodesSkipped).toBe(3);
    expect(blob.peripheralNote).toMatch(/chip-support table/);
  });

  it('says why the flash map is empty rather than reporting a bare zero', () => {
    const noParts = parseFdt(buildFdt({ name: '', props: [['model', str('no map')]] }), 0);
    const blob = analyzeDeviceTree(noParts as never, 'test fixture', 0);
    expect(blob.partitions).toEqual([]);
    expect(blob.partitionNote).toMatch(/silence about the layout, not a device with no partitions/);
    expect(BLOB.partitionNote).toBeUndefined(); // a tree that DOES declare one carries no note
  });
});

describe('deviceTreeFindings', () => {
  const findings = deviceTreeFindings(BLOB);
  const byKind = (k: string) => findings.find((f) => f.kind === k);

  it('reports board identity as info / static_confirmed and says it is the BUILD target', () => {
    const f = byKind('devicetree-board-identity');
    expect(f?.severity).toBe('info');
    expect(f?.proofState).toBe('static_confirmed');
    expect(f?.rationale).toMatch(/built for/i);
    expect(f?.rationale).toMatch(/not a claim about the board in hand/i);
  });

  it('reports the console UART as medium / static_confirmed and refuses to claim the hardware', () => {
    const f = byKind('devicetree-debug-uart');
    expect(f?.severity).toBe('medium');
    expect(f?.proofState).toBe('static_confirmed');
    expect(f?.title).toContain('kernel console');
    expect(f?.rationale).toMatch(/claim about the TREE/);
    expect(f?.rationale).toMatch(/pads are populated/);
    expect(f?.rationale).toMatch(/lead for hardware inspection/);
  });

  it('never emits a UART finding for a disabled node', () => {
    const uartFindings = findings.filter((f) => f.kind === 'devicetree-debug-uart');
    expect(uartFindings).toHaveLength(1);
    expect(JSON.stringify(uartFindings)).not.toContain('uart1@20140000');
  });

  it('states that read-only is a declaration and not protection', () => {
    const f = byKind('devicetree-flash-layout');
    expect(f?.severity).toBe('info');
    expect(f?.proofState).toBe('static_confirmed');
    expect(f?.title).toContain('1 marked read-only');
    expect(f?.rationale).toMatch(/NOT write protection/);
    expect(f?.rationale).toMatch(/never as "this region cannot be modified"/);
  });

  it('audits /chosen bootargs under the SAME finding codes uboot.ts mints — one dialect per fact', () => {
    const shell = byKind('uboot-root-shell');
    expect(shell?.severity).toBe('high');
    expect(shell?.proofState).toBe('needs_runtime_reproduction');
    expect((shell?.evidence as { node: string }).node).toBe('/chosen');
    const console = byKind('uboot-serial-console');
    expect(console?.severity).toBe('info');
    expect(console?.proofState).toBe('static_confirmed');
  });
});

describe('runDeviceTreeAnalysis', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-dt-test-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  const write = (name: string, buf: Buffer): string => {
    const p = path.join(tmp, name);
    fs.writeFileSync(p, buf);
    return p;
  };

  it('finds a tree embedded at a non-zero offset in a raw image', () => {
    const p = write('raw.bin', Buffer.concat([Buffer.alloc(4096, 0xff), BOARD, Buffer.alloc(1024, 0xff)]));
    const res = runDeviceTreeAnalysis(p, null);
    expect(res.found).toBe(true);
    expect(res.blobs).toHaveLength(1);
    expect(res.blobs[0]?.model).toBe('EVB_CBDM_AK3918EV300L_V1.0.0 board');
    expect(res.blobs[0]?.origin).toMatch(/raw image offset 4096/);
  });

  it('reports blocked_by_platform naming where it looked when the image has no device tree', () => {
    const p = write('none.bin', Buffer.alloc(65536, 0xff));
    const res = runDeviceTreeAnalysis(p, null);
    expect(res.available).toBe(true);
    expect(res.found).toBe(false);
    expect(res.searched.length).toBeGreaterThan(0);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]?.proofState).toBe('blocked_by_platform');
    expect(res.findings[0]?.kind).toBe('devicetree-absent');
    expect(res.reason).toMatch(/No readable device tree/i);
  });

  it('rejects a tree it cannot walk to completion instead of reporting a partial one', () => {
    // Reproduces the GL.iNet raw-scan failure: a valid header over bytes that carry UBI eraseblock metadata.
    const corrupt = Buffer.from(BOARD);
    const offStruct = corrupt.readUInt32BE(8);
    for (let i = 0; i < 16; i++) corrupt.writeUInt32BE(0x55424923, offStruct + 40 + i * 4);
    const p = write('spliced.bin', corrupt);
    const res = runDeviceTreeAnalysis(p, null);
    expect(res.found).toBe(false);
    expect(res.blobs).toHaveLength(0);
    expect(res.rejected).toHaveLength(1);
    expect(res.rejected[0]?.reason).toMatch(/could not be read to completion/i);
    expect(res.rejected[0]?.reason).toMatch(/UBI eraseblock header/);
    expect(res.reason).toMatch(/validated but no tree could be read/i);
  });

  it('descends a FIT to its flat_dt sub-image and reports which configuration selects it', () => {
    const fit = buildFdt({
      name: '',
      props: [['description', str('ARM64 OpenWrt FIT (Flattened Image Tree)')]],
      children: [
        {
          name: 'images',
          children: [
            {
              name: 'kernel-1',
              props: [
                ['data', Buffer.alloc(64, 0x11)],
                ['type', str('kernel')],
                ['arch', str('arm64')],
              ],
            },
            {
              name: 'fdt-1',
              props: [
                ['data', BOARD],
                ['type', str('flat_dt')],
                ['arch', str('arm64')],
              ],
            },
          ],
        },
        {
          name: 'configurations',
          props: [['default', str('config-1')]],
          children: [
            {
              name: 'config-1',
              props: [
                ['kernel', str('kernel-1')],
                ['fdt', str('fdt-1')],
              ],
            },
          ],
        },
      ],
    });
    const res = runDeviceTreeAnalysis(write('fit.bin', fit), null);
    expect(res.found).toBe(true);
    // The FIT itself is an FDT but describes an image layout, not a board — it must not be reported as a tree.
    expect(res.blobs).toHaveLength(1);
    expect(res.blobs[0]?.origin).toContain('/images/fdt-1');
    expect(res.blobs[0]?.selected).toBe(true);
    expect(res.blobs[0]?.selectedBy).toMatch(/default = config-1/);
  });

  it('reports every device tree an image carries, not just the first', () => {
    const other = buildFdt({
      name: '',
      props: [
        ['model', str('EVB_CBD_AK3918EV300L_V1.0.0 board')],
        ['compatible', strlist('anyka,ak3918ev300l')],
      ],
    });
    const res = runDeviceTreeAnalysis(write('two.bin', Buffer.concat([BOARD, Buffer.alloc(64, 0), other])), null);
    expect(res.found).toBe(true);
    expect(res.blobs.map((b) => b.model)).toEqual([
      'EVB_CBDM_AK3918EV300L_V1.0.0 board',
      'EVB_CBD_AK3918EV300L_V1.0.0 board',
    ]);
    expect(res.reason).toMatch(/Nothing in the image declares which one the board uses/);
  });

  it('picks up a .dtb written into the extraction output', () => {
    const dir = path.join(tmp, 'extract');
    fs.mkdirSync(path.join(dir, 'boot'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'boot', 'board.dtb'), BOARD);
    const res = runDeviceTreeAnalysis(write('empty.bin', Buffer.alloc(4096, 0xff)), dir);
    expect(res.found).toBe(true);
    expect(res.blobs[0]?.origin).toMatch(/extracted file/);
    expect(res.searched.some((s) => s.includes('.dtb'))).toBe(true);
  });
});
