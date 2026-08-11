/**
 * Every disassembly fixture here was captured from the REAL `NetUSB.ko` on the corpus's TP-Link WDR3600
 * (`lib/modules/2.6.31/nas/NetUSB.ko`, 250401 bytes, MIPS32 big-endian), not written by hand. That matters more
 * than usual for this provider: the two defects these tests pin were both invisible to a fixture written from
 * the same assumption as the code, which is the failure mode this codebase has already paid for repeatedly.
 */
import { describe, expect, it } from 'vitest';
import {
  type KmodModuleResult,
  argRegister,
  assessProvenanceUsability,
  buildKmodFindings,
  chaseSizeArgument,
  classifyKernelApi,
  containingFunction,
  dedupeRelocations,
  definesFirstOperand,
  findAdjacentCall,
  isGplCompatible,
  parseDisasm,
  rankModules,
  rankSites,
  readIdentity,
  readVersionCandidate,
  scoreModule,
  splitMarkedWindows,
} from './kmod.js';

/**
 * The allocation site: `SoftwareBus_dispatchNormalEPMsgOut` + 0x514. A length is loaded off the stack, byte
 * swapped with the MIPS32R2 `wsbh`/`rotr` idiom, has 0x11 added, and lands in `__kmalloc`'s size argument.
 *
 * The `beqz v0` four instructions above is the trap: it tests the PREVIOUS call's return value, in the same
 * register that later carries the length. A window scan for comparison mnemonics reports a bound here.
 */
const NETUSB_ALLOC_WINDOW = `
            0x08011940      27a50010       addiu a1, sp, 0x10
            0x08011944      0200f809       jalr s0
            0x08011948      24060004       addiu a2, zero, 4
        ,=< 0x0801194c      10400205       beqz v0, 0x8012164
        |   0x08011950      8fbf0054       lw ra, 0x54(sp)
        |   0x08011954      8fa20010       lw v0, 0x10(sp)
        |   0x08011958      7c0210a0       wsbh v0, v0
        |   0x0801195c      00221402       rotr v0, v0, 0x10
        |   0x08011960      24440011       addiu a0, v0, 0x11
        |   0x08011964      afa20010       sw v0, 0x10(sp)
`;

/**
 * The vendor's own bounds check, in `run_init_sbus` at 0xd3a8 — the reason a reviewer DECLINED CVE-2015-3036 for
 * this module. The length lives in `a2` and nothing ever compares `a2`: the check computes `v0 = a2 - 1` and
 * compares that. Only a forward pass sees it.
 */
const NETUSB_CHECKED_WINDOW = `
        :   0x0800d398      8fa60040       lw a2, 0x40(sp)
        :   0x0800d39c      7c0630a0       wsbh a2, a2
        :   0x0800d3a0      00263402       rotr a2, a2, 0x10
        :   0x0800d3a4      24c2ffff       addiu v0, a2, -1
        :   0x0800d3a8      2c42003f       sltiu v0, v0, 0x3f
       ,==< 0x0800d3ac      14400005       bnez v0, 0x800d3c4
       |:   0x0800d3b0      afa60040       sw a2, 0x40(sp)
`;

describe('the call-site chase', () => {
  it('reads the real NetUSB allocation: byte-swapped, +0x11, no check in view', () => {
    const window = parseDisasm(NETUSB_ALLOC_WINDOW);
    const e = chaseSizeArgument(window, 'a0');
    expect(e.byteSwapped).toBe(true);
    expect(e.rotated).toBe(true);
    expect(e.addend).toBe(0x11);
    expect(e.chain).toEqual(['a0', 'v0']);
    expect(e.truncated).toBe(false);
  });

  it('does NOT read the beqz above it as a bound — the false-exoneration trap', () => {
    // `beqz v0` at 0x0801194c tests the return of the call at 0x08011944. The length is reloaded into the same
    // register at 0x08011954, so the comparison is against a different value entirely. Counting it would drop a
    // real lead to `info` and report a check that is not on the path.
    const e = chaseSizeArgument(parseDisasm(NETUSB_ALLOC_WINDOW), 'a0');
    expect(e.compared).toBe(false);
  });

  it('finds the vendor check that only a forward pass can see', () => {
    // Nothing in this window compares `a2`. The check is `v0 = a2 - 1; v0 < 0x3f`, on a DERIVED value.
    const e = chaseSizeArgument(parseDisasm(NETUSB_CHECKED_WINDOW), 'a2');
    expect(e.compared).toBe(true);
    expect(e.byteSwapped).toBe(true);
  });

  it('treats a store as a use, not a definition', () => {
    // MIPS spells a store `sw rt, off(base)` — the register sits where `lw` puts its destination.
    expect(definesFirstOperand('sw')).toBe(false);
    expect(definesFirstOperand('lw')).toBe(true);
    expect(definesFirstOperand('beqz')).toBe(false);
    expect(definesFirstOperand('jalr')).toBe(false);
    expect(definesFirstOperand('addiu')).toBe(true);
  });

  it('reports a chase that ran out of window instead of concluding from it', () => {
    const e = chaseSizeArgument(parseDisasm('  0x1000  00000000  move a0, s3\n'), 'a0');
    expect(e.truncated).toBe(true);
    expect(e.compared).toBe(false);
  });
});

describe('telling a call site from a parked address', () => {
  // Real listing at 0x08011968: lui/addiu/jalr — the relocation IS the call.
  const REAL_CALL = `
            0x08011968      3c020000       lui v0, 0                   ; RELOC 32 __kmalloc
            0x0801196c      24420000       addiu v0, v0, 0             ; RELOC 32 __kmalloc
            0x08011970      0040f809       jalr v0
            0x08011974      240500d0       addiu a1, zero, 0xd0
`;
  // Real listing at 0x0800cfc0, the second instruction of run_init_sbus: memcpy's address is parked in `s0`
  // and called from elsewhere in the function. The instructions above are the prologue.
  const PARKED = `
            0x0800cfc0      3c020000       lui v0, 0                   ; RELOC 32 memcpy
            0x0800cfc4      afb00318       sw s0, 0x318(sp)
            0x0800cfc8      24500000       addiu s0, v0, 0             ; RELOC 32 memcpy
            0x0800cfcc      24020002       addiu v0, zero, 2
            0x0800cfd0      a3a20029       sb v0, 0x29(sp)
            0x0800cfd4      24020003       addiu v0, zero, 3
`;

  it('accepts a relocation followed by a call through the register it loaded', () => {
    expect(findAdjacentCall(parseDisasm(REAL_CALL))).toBe(true);
  });

  it('rejects an address the compiler parked in a saved register', () => {
    // 29% of MIPS sink relocations in this corpus are this shape. Reading the prologue above one as argument
    // setup would attribute a check — or its absence — to code that never runs on this path.
    expect(findAdjacentCall(parseDisasm(PARKED))).toBe(false);
  });

  it('accepts a direct call that names no register', () => {
    expect(findAdjacentCall(parseDisasm('  0x1000  00000000  bl 0x2000\n'))).toBe(true);
  });
});

describe('batched disassembly', () => {
  it('splits a marked listing back into one window per address', () => {
    const out = splitMarkedWindows(
      'preamble\n==FIRMLAB-SITE==0x1000==FIRMLAB-SITE==\n  0x0ffc  00  nop \n==FIRMLAB-SITE==0x2000==FIRMLAB-SITE==\n  0x1ffc  00  nop \n',
    );
    expect(out.map(([a]) => a)).toEqual([0x1000, 0x2000]);
    expect(parseDisasm(out[0]?.[1] ?? '')).toHaveLength(1);
  });
});

describe('parseDisasm', () => {
  it('survives radare2 gutters, flags and trailing comments', () => {
    const lines = parseDisasm(NETUSB_ALLOC_WINDOW);
    expect(lines).toHaveLength(10);
    expect(lines[0]?.mnemonic).toBe('addiu');
    expect(lines[6]?.mnemonic).toBe('wsbh');
    expect(lines[8]?.operands).toEqual(['a0', 'v0', '0x11']);
  });

  it('drops the reloc comment rather than parsing it as an operand', () => {
    const l = parseDisasm('  0x08011968  3c020000  lui v0, 0  ; RELOC 32 __kmalloc\n');
    expect(l[0]?.operands).toEqual(['v0', '0']);
  });

  it('does not turn an address inside a comment into an instruction', () => {
    // r2 prints standalone comment lines carrying addresses. Reading one as an instruction would insert a
    // phantom into the middle of a window and shift every reaching-definition conclusion drawn from it.
    expect(parseDisasm('        ; RELOC 32 $LC127 @ 0x0801e104\n')).toHaveLength(0);
    expect(parseDisasm('        ;-- reloc.sock_create:\n')).toHaveLength(0);
    expect(parseDisasm('/ 156: fcn.08011000 ();\n')).toHaveLength(0);
  });
});

describe('identity', () => {
  /**
   * The real records, in the real order, from `NetUSB.ko`'s `.modinfo`.
   *
   * The separator is written `\u0000` and never as the byte itself. `.modinfo` genuinely is NUL-separated, so a
   * faithful fixture wants the real terminator — and a literal NUL in a source file passes tsc, biome and vitest
   * while making `grep` skip the whole file without saying so. `scripts/check-nul.sh` refused this file when the
   * fixture first carried them, which is the guard doing exactly what it exists for.
   */
  const NUL = '\u0000';
  const NETUSB_MODINFO =
    `${NUL}license=Proprietary${NUL}author=KCodes${NUL}description=NetUSB module for Linux 2.6 from KCodes.` +
    `${NUL}description=Apr 22 2015 : 18:23:53${NUL}description=1.02.66 TL-WDR3600 v1 7437` +
    `${NUL}description= filterAudio${NUL}description= AUTH ISOC${NUL}depends=GPL_NetUSB` +
    `${NUL}vermagic=2.6.31--LSDK-9.2.0_U6.616 mod_unload MIPS32_R2 32BIT${NUL}`;

  it('keeps every description record, not just the first', () => {
    const id = readIdentity(NETUSB_MODINFO);
    expect(id.descriptions).toHaveLength(5);
    expect(id.license).toBe('Proprietary');
    expect(id.author).toBe('KCodes');
    expect(id.depends).toEqual(['GPL_NetUSB']);
  });

  it('recovers the product version from the third description record', () => {
    const id = readIdentity(NETUSB_MODINFO);
    expect(id.versionCandidate?.value).toBe('1.02.66');
    expect(id.versionCandidate?.from).toContain('TL-WDR3600');
    // It is a candidate, not a declared field: this module has no `version=` record at all.
    expect(id.version).toBeUndefined();
  });

  it('does not mistake a two-component number for a version', () => {
    expect(readVersionCandidate(['NetUSB module for Linux 2.6 from KCodes.'])).toBeUndefined();
    expect(readVersionCandidate(['Apr 22 2015 : 18:23:53'])).toBeUndefined();
  });

  it('reports no intree tag as absent rather than false', () => {
    expect(readIdentity(NETUSB_MODINFO).intree).toBeUndefined();
    expect(readIdentity(`${NUL}intree=Y${NUL}`).intree).toBe(true);
  });
});

describe('provenance calibration', () => {
  it('refuses to decide out-of-tree on a build that does not emit the tag', () => {
    // The real WDR3600: 84 modules, not one `intree=` record. The tag decides nothing there.
    const u = assessProvenanceUsability([{ descriptions: [], depends: [], license: 'GPL' }]);
    expect(u.intreeTagInUse).toBe(false);
    expect(u.note).toContain('NOT ONE module');
    const rec = {
      file: 'lib/modules/2.6.31/nas/NetUSB.ko',
      size: 250401,
      identity: { descriptions: [], depends: [], license: 'Proprietary' },
      api: {},
      importCount: 85,
    };
    // `outOfTree` must stay false: absence of the tag is not evidence when the build never writes it.
    expect(scoreModule(rec, u).outOfTree).toBe(false);
  });

  it('uses the tag on an image where it IS in use', () => {
    const u = assessProvenanceUsability([
      { descriptions: [], depends: [], intree: true, license: 'GPL' },
      { descriptions: [], depends: [], license: 'GPL' },
    ]);
    expect(u.intreeTagInUse).toBe(true);
    const rec = {
      file: 'qca-mcs.ko',
      size: 100,
      identity: { descriptions: [], depends: [], license: 'Dual BSD/GPL' },
      api: {},
      importCount: 1,
    };
    expect(scoreModule(rec, u).outOfTree).toBe(true);
  });

  it('reads GPL variants as GPL-compatible and Proprietary as not', () => {
    expect(isGplCompatible('GPL')).toBe(true);
    expect(isGplCompatible('GPL v2')).toBe(true);
    expect(isGplCompatible('Dual BSD/GPL')).toBe(true);
    expect(isGplCompatible('Proprietary')).toBe(false);
    expect(isGplCompatible(undefined)).toBe(false);
  });
});

describe('ranking', () => {
  const mk = (file: string, license: string | undefined, api: Record<string, string[]>) => ({
    file,
    size: 1000,
    identity: { descriptions: [], depends: [], ...(license ? { license } : {}) },
    api,
    importCount: 10,
  });

  it('puts the proprietary network module first, which is the whole point', () => {
    // The real WDR3600 shape: 84 modules, one of which is NetUSB.
    const recs = [
      mk('lib/modules/2.6.31/kernel/nf_conntrack.ko', 'GPL', { netfilter: ['nf_register_hook'], alloc: ['kmalloc'] }),
      mk('lib/modules/2.6.31/nas/NetUSB.ko', 'Proprietary', {
        socket: ['sock_create', 'kernel_accept'],
        alloc: ['__kmalloc'],
        'length-copy': ['memcpy'],
      }),
      mk('lib/modules/2.6.31/kernel/usbcore.ko', 'GPL', { alloc: ['kmalloc'] }),
    ];
    const usable = assessProvenanceUsability(recs.map((r) => r.identity));
    const ranked = rankModules(recs, usable);
    expect(ranked[0]?.file).toContain('NetUSB.ko');
    expect(ranked[0]?.keys.nonGpl).toBe(true);
    expect(ranked[0]?.keys.socket).toBe(true);
  });

  it('breaks ties by path, never by the order the walk returned them', () => {
    const recs = [mk('z/b.ko', 'GPL', {}), mk('a/a.ko', 'GPL', {}), mk('m/c.ko', 'GPL', {})];
    const usable = assessProvenanceUsability(recs.map((r) => r.identity));
    expect(rankModules(recs, usable).map((r) => r.file)).toEqual(['a/a.ko', 'm/c.ko', 'z/b.ko']);
  });
});

describe('relocations and symbols', () => {
  it('collapses the MIPS lui/addiu pair into one reference', () => {
    // A single `__kmalloc` call emits R_MIPS_HI16 then R_MIPS_LO16 four bytes apart. Counting both doubles
    // every sink in the module.
    const out = dedupeRelocations([
      { name: '__kmalloc', vaddr: 0x08011968 },
      { name: '__kmalloc', vaddr: 0x0801196c },
      { name: '__kmalloc', vaddr: 0x08000e6c },
      { name: '__kmalloc', vaddr: 0x08000e70 },
    ]);
    expect(out).toHaveLength(2);
    expect(out.map((r) => r.vaddr)).toEqual([0x08000e6c, 0x08011968]);
  });

  it('keeps distinct sinks that happen to sit close together', () => {
    const out = dedupeRelocations([
      { name: 'memcpy', vaddr: 0x1000 },
      { name: '__kmalloc', vaddr: 0x1004 },
    ]);
    expect(out).toHaveLength(2);
  });

  it('maps an address to the function containing it', () => {
    const fns = [
      { name: 'tcpConnector', vaddr: 0x0800c934, size: 1172 },
      { name: 'SoftwareBus_dispatchNormalEPMsgOut', vaddr: 0x0801144c, size: 3396 },
    ];
    expect(containingFunction(fns, 0x08011968)).toBe('SoftwareBus_dispatchNormalEPMsgOut');
    expect(containingFunction(fns, 0x0800c940)).toBe('tcpConnector');
    expect(containingFunction(fns, 0x08099999)).toBeNull();
  });

  it('spends the per-module site budget on allocators before copies', () => {
    const ordered = rankSites([
      { name: 'memcpy', vaddr: 0x100 },
      { name: '__kmalloc', vaddr: 0x900 },
      { name: 'copy_from_user', vaddr: 0x500 },
    ]);
    expect(ordered.map((s) => s.name)).toEqual(['__kmalloc', 'copy_from_user', 'memcpy']);
  });

  it('knows the size argument register per architecture', () => {
    expect(argRegister('mips', 32, 0)).toBe('a0');
    expect(argRegister('mips', 32, 2)).toBe('a2');
    expect(argRegister('arm', 64, 2)).toBe('x2');
    expect(argRegister('arm', 32, 2)).toBe('r2');
    expect(argRegister('sparc', 32, 0)).toBeNull();
  });
});

describe('classifyKernelApi', () => {
  it('separates a kernel socket from a netfilter hook', () => {
    const api = classifyKernelApi(['sock_create', 'kernel_bind', 'kernel_accept', '__kmalloc', 'memcpy', 'printk']);
    expect(api.socket).toEqual(['sock_create', 'kernel_bind', 'kernel_accept']);
    expect(api.alloc).toEqual(['__kmalloc']);
    expect(api['length-copy']).toEqual(['memcpy']);
    expect(api.netfilter).toBeUndefined();
  });

  it('does not match on substrings', () => {
    // `gpl_usb_submit_urb` must not register as anything; `__kmalloc_node` is a real distinct name.
    const api = classifyKernelApi(['gpl_usb_submit_urb', 'my_sock_create_wrapper']);
    expect(Object.keys(api)).toHaveLength(0);
  });
});

describe('findings', () => {
  const base = {
    file: 'lib/modules/2.6.31/nas/NetUSB.ko',
    size: 250401,
    identity: {
      descriptions: ['1.02.66 TL-WDR3600 v1 7437'],
      depends: ['GPL_NetUSB'],
      license: 'Proprietary',
      author: 'KCodes',
      versionCandidate: { value: '1.02.66', from: '1.02.66 TL-WDR3600 v1 7437' },
    },
    api: { socket: ['sock_create', 'kernel_accept'], alloc: ['__kmalloc'] },
    importCount: 85,
    keys: { nonGpl: true, outOfTree: false, socket: true, allocAndCopy: true, userBoundary: false, score: 14 },
    symbolsRead: true,
  };

  it('states the network surface as a fact about the symbol table', () => {
    const f = buildKmodFindings([{ ...base, sites: [] } as KmodModuleResult]);
    const surface = f.find((x) => x.kind === 'kernel-module-network-surface');
    expect(surface?.proofState).toBe('static_confirmed');
    expect(surface?.severity).toBe('high');
    expect(surface?.title).toContain('1.02.66');
    expect(surface?.rationale).toContain('does NOT follow');
  });

  it('files an unchecked wire length as a LEAD, never as a proven bug', () => {
    const f = buildKmodFindings([
      {
        ...base,
        sites: [
          {
            sink: '__kmalloc',
            addr: 0x08011968,
            fn: 'SoftwareBus_dispatchNormalEPMsgOut',
            evidence: {
              byteSwapped: true,
              rotated: true,
              compared: false,
              addend: 0x11,
              chain: ['a0', 'v0'],
              crossedCall: false,
              truncated: false,
            },
          },
        ],
      } as KmodModuleResult,
    ]);
    const lead = f.find((x) => x.kind === 'kernel-module-wire-length-alloc');
    expect(lead?.proofState).toBe('needs_runtime_reproduction');
    expect(lead?.severity).toBe('high');
    expect(lead?.rationale).toContain('This is a LEAD');
    // The claim is bounded to the window, in the row itself.
    expect(lead?.rationale).toContain('invisible here');
  });

  it('records the checked site instead of staying silent about it', () => {
    const f = buildKmodFindings([
      {
        ...base,
        sites: [
          {
            sink: '__kmalloc',
            addr: 0xd3a8,
            fn: 'run_init_sbus',
            evidence: {
              byteSwapped: true,
              rotated: true,
              compared: true,
              addend: -1,
              chain: ['a2'],
              crossedCall: false,
              truncated: false,
            },
          },
        ],
      } as KmodModuleResult,
    ]);
    expect(f.find((x) => x.kind === 'kernel-module-wire-length-alloc')).toBeUndefined();
    const checked = f.find((x) => x.kind === 'kernel-module-checked-alloc');
    expect(checked?.severity).toBe('info');
    expect(checked?.rationale).toContain('SUFFICIENT');
  });

  it('does not file a row for a locally-computed size that happens to be compared', () => {
    // Measured on the corpus: 265 sites are compared without ever being byte-swapped. A row each would put 265
    // `info` entries in the ledger reporting that nothing had gone wrong.
    const f = buildKmodFindings([
      {
        ...base,
        sites: [
          {
            sink: 'memcpy',
            addr: 0x1000,
            fn: 'some_local',
            evidence: {
              byteSwapped: false,
              rotated: false,
              compared: true,
              addend: null,
              chain: ['a2'],
              crossedCall: false,
              truncated: false,
            },
          },
        ],
      } as KmodModuleResult,
    ]);
    expect(f.find((x) => x.kind === 'kernel-module-checked-alloc')).toBeUndefined();
  });

  it('says a window ran short rather than concluding from it', () => {
    const f = buildKmodFindings([
      {
        ...base,
        sites: [
          {
            sink: '__kmalloc',
            addr: 0x1000,
            fn: null,
            evidence: {
              byteSwapped: true,
              rotated: false,
              compared: false,
              addend: null,
              chain: ['a0', 's3'],
              crossedCall: true,
              truncated: true,
            },
          },
        ],
      } as KmodModuleResult,
    ]);
    const lead = f.find((x) => x.kind === 'kernel-module-wire-length-alloc');
    expect(lead?.rationale).toContain('ran out of window');
    expect(lead?.rationale).toContain('crossed a call');
  });
});
