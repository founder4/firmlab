import { describe, expect, it } from 'vitest';
import {
  type AssembledCmdlineSource,
  type CmdlineSource,
  type UbootScriptCmdlines,
  auditKernelCommandLine,
  crossCheckBootCmdlines,
  diffCommandLines,
  expandCmdlineVariables,
  normalizeCommandLine,
} from './boot-cmdline.js';

/** The device-tree half, with exactly the provenance `devicetree.ts` hands the shared auditor. */
function tree(value: string, origin = 'FIT /images/fdt-1'): CmdlineSource {
  return {
    value,
    origin: {
      where: `the device tree's /chosen node (${origin})`,
      evidence: { origin, node: '/chosen', properties: ['bootargs'] },
    },
  };
}

/** The U-Boot half, with exactly the provenance `uboot.ts` hands the shared auditor. */
function env(value: string, variables?: Record<string, string>): CmdlineSource {
  return {
    value,
    origin: { where: 'the stored U-Boot environment', evidence: { var: 'bootargs' } },
    ...(variables ? { variables } : {}),
  };
}

/** One command line a boot script assembles, shaped exactly as `opacidad.ts` hands it to the cross-check. */
function assembled(
  value: string,
  via: string[],
  variables?: Record<string, string>,
  opts?: { conditional?: boolean; complete?: boolean },
): AssembledCmdlineSource {
  return {
    value,
    origin: {
      where: `the kernel command line \`${via.join(' → ')}\` assembles`,
      evidence: { var: 'bootargs', via, statement: `env set bootargs ${value}` },
    },
    ...(variables ? { variables } : {}),
    ...(opts?.complete ? { variablesComplete: true } : {}),
    ...(opts?.conditional ? { conditional: true } : {}),
  };
}

/** The script half of the U-Boot side, with the reader's own sentence attached as the provider supplies it. */
function script(assembledLines: AssembledCmdlineSource[], opts?: { ambiguous?: boolean }): UbootScriptCmdlines {
  return {
    assembled: assembledLines,
    ...(opts?.ambiguous ? { ambiguous: true } : {}),
    note: 'A static read of bootcmd found the assignment(s) listed.',
  };
}

const LINE = 'console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs ro';

function evidenceOf(draft: { evidence?: Record<string, unknown> }): Record<string, unknown> {
  return draft.evidence ?? {};
}

describe('auditKernelCommandLine — one dialect for one fact', () => {
  it('flags a root shell as a LEAD, not an asserted compromise', () => {
    const drafts = auditKernelCommandLine('console=ttyS0 init=/bin/sh', {
      where: 'the stored U-Boot environment',
      evidence: { var: 'bootargs' },
    });
    const shell = drafts.find((d) => d.kind === 'uboot-root-shell');
    expect(shell?.proofState).toBe('needs_runtime_reproduction');
    expect(evidenceOf(shell as { evidence?: Record<string, unknown> }).markers).toEqual(['init=/bin/sh']);
  });

  it('flags a console directive as static_confirmed and carries the provenance it was given', () => {
    const drafts = auditKernelCommandLine(LINE, {
      where: "the device tree's /chosen node (FIT /images/fdt-1)",
      evidence: { origin: 'FIT /images/fdt-1', node: '/chosen' },
    });
    const con = drafts.find((d) => d.kind === 'uboot-serial-console');
    expect(con?.proofState).toBe('static_confirmed');
    expect(evidenceOf(con as { evidence?: Record<string, unknown> }).node).toBe('/chosen');
    expect(con?.rationale).toContain('/chosen');
  });

  it('says nothing about an empty command line', () => {
    expect(auditKernelCommandLine('', { where: 'nowhere', evidence: {} })).toEqual([]);
  });
});

describe('normalizeCommandLine — what a difference has to survive', () => {
  it('collapses whitespace and trims', () => {
    expect(normalizeCommandLine('  ro   rw\tquiet \n').canonical).toBe(normalizeCommandLine('ro rw quiet').canonical);
  });

  it('is insensitive to the order of independent parameters', () => {
    expect(normalizeCommandLine('root=/dev/sda1 ro quiet').canonical).toBe(
      normalizeCommandLine('quiet ro root=/dev/sda1').canonical,
    );
  });

  it('resolves a repeated last-wins parameter to its last occurrence, as the kernel does', () => {
    expect(normalizeCommandLine('root=/dev/sda1 ro root=/dev/sda2').canonical).toBe(
      normalizeCommandLine('root=/dev/sda2 ro').canonical,
    );
  });

  it('keeps every console= and its order — each registers, and the last becomes /dev/console', () => {
    expect(normalizeCommandLine('console=ttyS0 console=tty1').canonical).not.toBe(
      normalizeCommandLine('console=tty1 console=ttyS0').canonical,
    );
    expect(normalizeCommandLine('console=ttyS0 console=tty1').byKey.get('console')).toEqual([
      'console=ttyS0',
      'console=tty1',
    ]);
  });

  it('keeps init argv after a standalone -- verbatim and in order', () => {
    const a = normalizeCommandLine('ro -- first second');
    expect(a.initArgs).toEqual(['first', 'second']);
    expect(a.canonical).not.toBe(normalizeCommandLine('ro -- second first').canonical);
  });

  it('honours the kernel double-quote rule so a quoted value stays one parameter', () => {
    expect(normalizeCommandLine('ubi.mtd=rootfs opt="a b" ro').byKey.get('opt')).toEqual(['opt="a b"']);
  });

  it('diffCommandLines returns nothing for two lines that are the same boot', () => {
    expect(diffCommandLines(normalizeCommandLine('ro quiet'), normalizeCommandLine('quiet  ro'))).toEqual([]);
  });
});

describe('crossCheckBootCmdlines — a disagreement is the finding, absence is not', () => {
  it('reports agreement and no finding for two identical command lines', () => {
    const r = crossCheckBootCmdlines({ deviceTree: [tree(LINE)], ubootEnv: env(LINE) });
    expect(r.verdict).toBe('agree');
    expect(r.comparable).toBe(true);
    expect(r.findings).toEqual([]);
    expect(r.comparisons).toHaveLength(1);
    expect(r.comparisons[0]?.agrees).toBe(true);
  });

  it('makes no finding out of a whitespace-only difference', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('  console=ttyS0,115200   root=/dev/mtdblock2\tro  ')],
      ubootEnv: env('console=ttyS0,115200 root=/dev/mtdblock2 ro'),
    });
    expect(r.verdict).toBe('agree');
    expect(r.findings).toEqual([]);
  });

  it('makes no finding out of a parameter-order-only difference', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('ro root=/dev/mtdblock2 console=ttyS0,115200')],
      ubootEnv: env('console=ttyS0,115200 root=/dev/mtdblock2 ro'),
    });
    expect(r.verdict).toBe('agree');
    expect(r.findings).toEqual([]);
  });

  it('makes no finding out of a repeated last-wins parameter that resolves to the same value', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock1 ro root=/dev/mtdblock2 rw rw')],
      ubootEnv: env('root=/dev/mtdblock2 ro rw'),
    });
    expect(r.verdict).toBe('agree');
    expect(r.findings).toEqual([]);
  });

  it('reports a genuine disagreement once, carrying BOTH values and the parameter-level diff', () => {
    const dt = 'console=ttyS0,115200 root=/dev/mtdblock2 ro';
    const ub = 'console=ttyS0,115200 root=/dev/mtdblock5 ro';
    const r = crossCheckBootCmdlines({ deviceTree: [tree(dt)], ubootEnv: env(ub) });
    expect(r.verdict).toBe('disagree');
    expect(r.comparable).toBe(true);
    expect(r.findings).toHaveLength(1);

    const f = r.findings[0];
    expect(f?.kind).toBe('boot-cmdline-disagreement');
    expect(f?.proofState).toBe('static_confirmed');
    const ev = evidenceOf(f as { evidence?: Record<string, unknown> });
    expect(ev.deviceTreeCmdline).toBe(dt);
    expect(ev.ubootEnvCmdline).toBe(ub);
    expect(ev.deviceTreeSource).toMatchObject({ node: '/chosen' });
    expect(ev.ubootEnvSource).toMatchObject({ var: 'bootargs' });
    expect(ev.differences).toEqual([
      { key: 'root', deviceTree: ['root=/dev/mtdblock2'], ubootEnv: ['root=/dev/mtdblock5'] },
    ]);
    // It claims the two sources differ — nothing about the board, and nothing about which line wins.
    expect(f?.rationale).toContain('does NOT claim the board is misconfigured');
    expect(f?.rationale).toContain('which line the kernel actually receives');
  });

  it('escalates severity only when the difference changes a security answer, and names the delta', () => {
    const material = crossCheckBootCmdlines({
      deviceTree: [tree('console=ttyS0 root=/dev/mtdblock2 init=/bin/sh')],
      ubootEnv: env('console=ttyS0 root=/dev/mtdblock2'),
    });
    expect(material.findings[0]?.severity).toBe('medium');
    expect(evidenceOf(material.findings[0] as { evidence?: Record<string, unknown> }).securityRelevantDelta).toEqual({
      deviceTree: ['uboot-root-shell', 'uboot-serial-console'],
      ubootEnv: ['uboot-serial-console'],
    });

    const inert = crossCheckBootCmdlines({
      deviceTree: [tree('console=ttyS0 root=/dev/mtdblock2 mtdparts=spi0.0:1m(boot)')],
      ubootEnv: env('console=ttyS0 root=/dev/mtdblock2'),
    });
    expect(inert.findings[0]?.severity).toBe('info');
    expect(
      evidenceOf(inert.findings[0] as { evidence?: Record<string, unknown> }).securityRelevantDelta,
    ).toBeUndefined();
  });

  it('does not equate values that merely MIGHT name the same device', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2')],
      ubootEnv: env('root=31:02'),
    });
    expect(r.verdict).toBe('disagree');
  });

  it('keeps a console= reordering as a real disagreement', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('console=ttyS0 console=tty1 ro')],
      ubootEnv: env('console=tty1 console=ttyS0 ro'),
    });
    expect(r.verdict).toBe('disagree');
    expect(evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).differences).toEqual([
      { key: 'console', deviceTree: ['console=ttyS0', 'console=tty1'], ubootEnv: ['console=tty1', 'console=ttyS0'] },
    ]);
  });

  it('keeps init argv order after a standalone -- as a real disagreement', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('ro -- alpha beta')],
      ubootEnv: env('ro -- beta alpha'),
    });
    expect(r.verdict).toBe('disagree');
    expect(evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).differences).toEqual([
      { key: '-- (arguments passed to init)', deviceTree: ['alpha', 'beta'], ubootEnv: ['beta', 'alpha'] },
    ]);
  });

  describe('bootargs-append (the OpenWrt/U-Boot extension) is part of the line being compared', () => {
    // `devicetree.ts` hands the ASSEMBLED line — `bootargs` concatenated with `bootargs-append` — so the
    // concatenation is what gets cross-checked, not just the first property.
    const assembled = 'root=/dev/mtdblock2 ro console=ttyS0,115200';

    it('agrees when the env carries what the two properties concatenate to', () => {
      const r = crossCheckBootCmdlines({
        deviceTree: [
          {
            value: assembled,
            origin: {
              where: "the device tree's /chosen node (FIT /images/fdt-1)",
              evidence: { origin: 'FIT /images/fdt-1', node: '/chosen', properties: ['bootargs', 'bootargs-append'] },
            },
          },
        ],
        ubootEnv: env('console=ttyS0,115200 root=/dev/mtdblock2 ro'),
      });
      expect(r.verdict).toBe('agree');
      expect(r.findings).toEqual([]);
    });

    it('disagrees on the appended parameter alone, and names it', () => {
      const r = crossCheckBootCmdlines({
        deviceTree: [tree(assembled)],
        ubootEnv: env('root=/dev/mtdblock2 ro'),
      });
      expect(r.verdict).toBe('disagree');
      expect(evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).differences).toEqual([
        { key: 'console', deviceTree: ['console=ttyS0,115200'], ubootEnv: null },
      ]);
    });
  });

  describe('a FIT ships one tree per board variant', () => {
    it('collapses byte-identical lines to one comparison and one finding', () => {
      const r = crossCheckBootCmdlines({
        deviceTree: [tree(LINE, 'FIT /images/fdt-1'), tree(LINE, 'FIT /images/fdt-2')],
        ubootEnv: env('root=/dev/mtdblock9'),
      });
      expect(r.comparisons).toHaveLength(1);
      expect(r.findings).toHaveLength(1);
      expect(r.reason).toContain('byte-for-byte repeats');
    });

    it('reports each genuinely different variant against the same environment', () => {
      const r = crossCheckBootCmdlines({
        deviceTree: [
          tree('root=/dev/mtdblock2', 'FIT /images/fdt-1'),
          tree('root=/dev/mtdblock3', 'FIT /images/fdt-2'),
        ],
        ubootEnv: env('root=/dev/mtdblock9'),
      });
      expect(r.verdict).toBe('disagree');
      expect(r.comparisons).toHaveLength(2);
      expect(r.findings).toHaveLength(2);
    });
  });

  describe('both present is a precondition, not an assumption', () => {
    it('only the device tree → no finding, and explicitly not agreement', () => {
      const r = crossCheckBootCmdlines({ deviceTree: [tree(LINE)], ubootEnv: null });
      expect(r.verdict).toBe('device-tree-only');
      expect(r.comparable).toBe(false);
      expect(r.comparisons).toEqual([]);
      expect(r.findings).toEqual([]);
      expect(r.reason).toContain('not agreement');
    });

    it('only the U-Boot environment → no finding, and explicitly not agreement', () => {
      const r = crossCheckBootCmdlines({ deviceTree: [], ubootEnv: env(LINE) });
      expect(r.verdict).toBe('uboot-env-only');
      expect(r.comparable).toBe(false);
      expect(r.findings).toEqual([]);
      expect(r.reason).toContain('not agreement');
    });

    it('neither → no finding, and explicitly not agreement', () => {
      const r = crossCheckBootCmdlines({ deviceTree: [], ubootEnv: null });
      expect(r.verdict).toBe('neither');
      expect(r.comparable).toBe(false);
      expect(r.findings).toEqual([]);
      expect(r.reason).toContain('not agreement');
    });

    it('treats an empty or blank command line as absent, never as an empty line to compare', () => {
      const r = crossCheckBootCmdlines({ deviceTree: [tree('   ')], ubootEnv: env('') });
      expect(r.verdict).toBe('neither');
      expect(r.findings).toEqual([]);
    });
  });

  describe('a U-Boot bootargs is routinely a template, not a command line', () => {
    // Straight off the real corpus: /data/images/75976cfa Tenda-Camera.bin is the ONE image in sixteen that
    // carries both sources, and its stored bootargs is nothing but ${…} references. Compared literally it would
    // report console= as differing when the env's own `console` variable holds exactly the tree's value.
    const TENDA_ENV = 'console=${console} root=${mtd_root} rootfstype=${rootfstype} init=${init} ';
    const TENDA_VARS = {
      console: 'ttySAK0,115200n8',
      mtd_root: '/dev/mtdblock3',
      rootfstype: 'jffs2',
      init: '/sbin/init',
      bootargs: TENDA_ENV,
    };
    const TENDA_TREE =
      'console=ttySAK0,115200n8 root=/dev/mtdblock5 rootfstype=squashfs init=/sbin/init mem=64M memsize=64M';

    it('expands ${x}, $(x) and bare $x from the source own store', () => {
      const vars = { a: '1', b: '2', c: '3' };
      expect(expandCmdlineVariables('x=${a} y=$(b) z=$c', vars).value).toBe('x=1 y=2 z=3');
      expect(expandCmdlineVariables('x=${a}', vars).substitutions).toEqual({ a: '1' });
      expect(expandCmdlineVariables('x=${a}', vars).unresolved).toEqual([]);
    });

    it('leaves a literal $ alone when the source has no variable store at all', () => {
      const r = expandCmdlineVariables('root=/dev/$disk');
      expect(r.value).toBe('root=/dev/$disk');
      expect(r.unresolved).toEqual([]);
    });

    it('does not report console= as differing once the env template is expanded', () => {
      const r = crossCheckBootCmdlines({ deviceTree: [tree(TENDA_TREE)], ubootEnv: env(TENDA_ENV, TENDA_VARS) });
      expect(r.verdict).toBe('disagree');
      const ev = evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> });
      const keys = (ev.differences as { key: string }[]).map((d) => d.key);
      expect(keys).not.toContain('console');
      // What genuinely differs on this image: the rootfs partition, its filesystem, and two memory parameters.
      expect(keys).toEqual(['mem', 'memsize', 'root', 'rootfstype']);
    });

    it('quotes the stored template, the expanded line and every substitution, so a reader can redo it', () => {
      const r = crossCheckBootCmdlines({ deviceTree: [tree(TENDA_TREE)], ubootEnv: env(TENDA_ENV, TENDA_VARS) });
      const ev = evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> });
      expect(ev.ubootEnvCmdline).toBe(TENDA_ENV);
      expect(ev.ubootEnvExpanded).toBe(
        'console=ttySAK0,115200n8 root=/dev/mtdblock3 rootfstype=jffs2 init=/sbin/init ',
      );
      expect(ev.ubootEnvSubstitutions).toEqual({
        console: 'ttySAK0,115200n8',
        mtd_root: '/dev/mtdblock3',
        rootfstype: 'jffs2',
        init: '/sbin/init',
      });
      // The tree is a literal, so it gains no expansion keys at all.
      expect(ev.deviceTreeExpanded).toBeUndefined();
    });

    it('refuses the comparison when a reference does not resolve, rather than comparing a ${…} to a value', () => {
      const r = crossCheckBootCmdlines({
        deviceTree: [tree(TENDA_TREE)],
        ubootEnv: env(TENDA_ENV, { console: 'ttySAK0,115200n8' }),
      });
      expect(r.verdict).toBe('unresolved-variables');
      expect(r.comparable).toBe(false);
      expect(r.findings).toEqual([]);
      expect(r.reason).toContain('init, mtd_root, rootfstype');
      expect(r.reason).toContain('not agreement and not a disagreement');
    });

    it('audits the EXPANDED line, so init=${init} pointing at a shell is still a root-shell delta', () => {
      const r = crossCheckBootCmdlines({
        deviceTree: [tree('console=ttyS0 root=/dev/mtdblock2')],
        ubootEnv: env('console=${console} root=/dev/mtdblock2 init=${init}', {
          console: 'ttyS0',
          init: '/bin/sh',
        }),
      });
      expect(r.findings[0]?.severity).toBe('medium');
      expect(evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).securityRelevantDelta).toEqual({
        deviceTree: ['uboot-serial-console'],
        ubootEnv: ['uboot-root-shell', 'uboot-serial-console'],
      });
    });

    it('treats a template that expands to nothing as an absent line, not as an empty one to compare', () => {
      const r = crossCheckBootCmdlines({ deviceTree: [tree(LINE)], ubootEnv: env('${extra}', { extra: '' }) });
      expect(r.verdict).toBe('device-tree-only');
      expect(r.findings).toEqual([]);
    });
  });

  it('bounds the listed differences and says how many it dropped, and by what rule', () => {
    const many = Array.from({ length: 20 }, (_, i) => `p${i}=1`).join(' ');
    const r = crossCheckBootCmdlines({ deviceTree: [tree(many)], ubootEnv: env('root=/dev/sda') });
    const f = r.findings[0];
    const ev = evidenceOf(f as { evidence?: Record<string, unknown> });
    expect((ev.differences as unknown[]).length).toBe(16);
    expect(ev.differencesDropped).toBe(5);
    expect(String(ev.differencesRule)).toContain('alphabetical order by parameter name');
    // The title states the TOTAL, so the cap can never be mistaken for the answer.
    expect(f?.title).toContain('(21 parameter(s))');
  });

  it('truncates the quoted values so one absurd parameter cannot bloat the finding', () => {
    const huge = `opt=${'A'.repeat(500)}`;
    const r = crossCheckBootCmdlines({ deviceTree: [tree(huge)], ubootEnv: env('ro') });
    const ev = evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> });
    expect(String(ev.deviceTreeCmdline).length).toBeLessThanOrEqual(201);
    expect(String(ev.deviceTreeCmdline).endsWith('…')).toBe(true);
    const first = (ev.differences as { deviceTree: string[] | null }[])[0];
    expect((first?.deviceTree ?? [])[0]?.length).toBeLessThanOrEqual(121);
  });
});

/**
 * `bootargs` is a stored variable and a `bootcmd` is free to overwrite it. Until this existed the check compared
 * the stored one unconditionally, which on the one corpus image carrying both sources was comparing the wrong
 * string — the Tenda's `boot_normal` appends the very `mem`/`memsize` the check was reporting as missing.
 */
describe('crossCheckBootCmdlines — the assembled line, and saying which one was compared', () => {
  it('prefers the line the script assembles over the stored variable, and names it in the finding', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2 ro')],
      ubootEnv: env('root=/dev/mtdblock9 ro'),
      ubootScript: script([assembled('root=/dev/mtdblock5 ro', ['bootcmd', 'boot_normal'])]),
    });
    expect(r.comparedUbootLine).toBe('assembled');
    expect(r.comparisons[0]?.ubootLine).toBe('assembled');
    expect(r.comparisons[0]?.ubootWhere).toContain('boot_normal');
    // The diff is against the ASSEMBLED value; the stored mtdblock9 never enters it.
    expect(evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).differences).toEqual([
      { key: 'root', deviceTree: ['root=/dev/mtdblock2'], ubootEnv: ['root=/dev/mtdblock5'] },
    ]);
  });

  it('states which line it compared in the evidence and leads the rationale with it', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2 ro')],
      ubootEnv: env('root=/dev/mtdblock9 ro'),
      ubootScript: script([assembled('root=/dev/mtdblock5 ro', ['bootcmd', 'boot_normal'])]),
    });
    const f = r.findings[0];
    const ev = evidenceOf(f as { evidence?: Record<string, unknown> });
    expect(ev.ubootEnvLine).toBe('assembled');
    expect(ev.ubootEnvWhere).toContain('bootcmd → boot_normal');
    expect(ev.ubootEnvSource).toMatchObject({ via: ['bootcmd', 'boot_normal'] });
    expect(f?.rationale?.startsWith('Compared against')).toBe(true);
    expect(f?.rationale).toContain('ASSEMBLES');
    expect(f?.rationale).toContain('not that this board ran it');
    expect(r.reason).toContain('static read of the script text, not an execution');
  });

  it('says that the stored bootargs and the assembled line are themselves different boot configurations', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2 ro')],
      ubootEnv: env('root=/dev/mtdblock9 ro'),
      ubootScript: script([assembled('root=/dev/mtdblock5 ro', ['bootcmd', 'boot_normal'])]),
    });
    expect(r.storedAndAssembledDiffer).toBe(true);
    const ev = evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> });
    expect(ev.ubootStoredCmdline).toBe('root=/dev/mtdblock9 ro');
    expect(ev.ubootStoredDiffersFromAssembled).toBe(true);
    expect(r.reason).toContain('not the string this result is about');
  });

  it('says so just as explicitly when the two U-Boot lines agree with each other', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2 ro')],
      ubootEnv: env('ro root=/dev/mtdblock5'),
      ubootScript: script([assembled('root=/dev/mtdblock5 ro', ['bootcmd', 'boot_normal'])]),
    });
    expect(r.storedAndAssembledDiffer).toBe(false);
    expect(evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).ubootStoredDiffersFromAssembled).toBe(
      false,
    );
  });

  it('compares EVERY reachable variant rather than picking one, and labels each comparison', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2 ro')],
      ubootEnv: null,
      ubootScript: script(
        [
          assembled('root=/dev/mtdblock2 ro', ['bootcmd', 'boot_normal'], undefined, { conditional: true }),
          assembled('root=/dev/mtdblock2 ro single', ['bootcmd', 'boot_rescue'], undefined, { conditional: true }),
        ],
        { ambiguous: true },
      ),
    });
    expect(r.comparisons).toHaveLength(2);
    expect(r.comparisons.map((c) => c.agrees)).toEqual([true, false]);
    // One variant agrees and one does not; only the disagreement mints a finding, and it names its own variant.
    expect(r.findings).toHaveLength(1);
    const ev = evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> });
    expect(ev.ubootEnvWhere).toContain('boot_rescue');
    expect(ev.ubootEnvConditional).toBe(true);
    expect(r.verdict).toBe('disagree');
    expect(r.reason).toContain('2 distinct assembled line(s) are statically reachable');
    expect(r.reason).toContain('which one a powered board takes is not decidable');
  });

  it('collapses two reachable assignments that normalise to one boot configuration into one comparison', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2 ro')],
      ubootEnv: null,
      ubootScript: script([
        assembled('root=/dev/mtdblock5 ro', ['bootcmd', 'a']),
        assembled('ro   root=/dev/mtdblock5', ['bootcmd', 'b']),
      ]),
    });
    expect(r.comparisons).toHaveLength(1);
    expect(r.findings).toHaveLength(1);
  });

  it('refuses rather than falling back to a stored variable the script is known to overwrite', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2 ro')],
      ubootEnv: env('root=/dev/mtdblock9 ro'),
      ubootScript: script([assembled('root=${unknown_root} ro', ['bootcmd', 'boot_normal'], { ro: '' })]),
    });
    expect(r.verdict).toBe('unresolved-variables');
    expect(r.comparable).toBe(false);
    expect(r.findings).toEqual([]);
    expect(r.comparedUbootLine).toBe('none');
    expect(r.reason).toContain('was NOT compared in its place');
    expect(r.reason).toContain('unknown_root');
  });

  it('uses the assembled line even when the environment stores no bootargs at all', () => {
    const r = crossCheckBootCmdlines({
      deviceTree: [tree('root=/dev/mtdblock2 ro')],
      ubootEnv: null,
      ubootScript: script([assembled('root=/dev/mtdblock5 ro', ['bootcmd', 'boot_normal'])]),
    });
    expect(r.verdict).toBe('disagree');
    expect(r.comparedUbootLine).toBe('assembled');
  });

  describe('no boot script behaves exactly as it did before the reader existed', () => {
    const dt = 'console=ttyS0,115200 root=/dev/mtdblock2 ro';
    const ub = 'console=ttyS0,115200 root=/dev/mtdblock5 ro';

    it('compares the stored line and says so, with no ubootScript supplied at all', () => {
      const r = crossCheckBootCmdlines({ deviceTree: [tree(dt)], ubootEnv: env(ub) });
      expect(r.verdict).toBe('disagree');
      expect(r.comparedUbootLine).toBe('stored');
      expect(r.storedAndAssembledDiffer).toBe(false);
      expect(evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).ubootEnvLine).toBe('stored');
      expect(r.findings[0]?.rationale).toContain('the line stored in the `bootargs` variable');
    });

    it('produces the identical verdict and diff when the script was read and sets nothing', () => {
      const without = crossCheckBootCmdlines({ deviceTree: [tree(dt)], ubootEnv: env(ub) });
      const withEmpty = crossCheckBootCmdlines({
        deviceTree: [tree(dt)],
        ubootEnv: env(ub),
        ubootScript: { assembled: [], note: 'nothing in the script re-sets the stored command line' },
      });
      expect(withEmpty.verdict).toBe(without.verdict);
      expect(withEmpty.comparedUbootLine).toBe('stored');
      expect(evidenceOf(withEmpty.findings[0] as { evidence?: Record<string, unknown> }).differences).toEqual(
        evidenceOf(without.findings[0] as { evidence?: Record<string, unknown> }).differences,
      );
      // The reader's own sentence travels, so "no script" and "a script that sets nothing" stay distinguishable.
      expect(withEmpty.reason).toContain('nothing in the script re-sets');
    });
  });

  describe('a complete variable store makes an ABSENT variable the board answer, not our blind spot', () => {
    it('expands an unset reference to nothing and records it, instead of refusing', () => {
      const r = expandCmdlineVariables('ro ${gone} rw', { ro: '' }, { complete: true });
      expect(r.value).toBe('ro  rw');
      expect(r.unresolved).toEqual([]);
      expect(r.unset).toEqual(['gone']);
    });

    it('still refuses when the store was not declared complete — it may be our cap that dropped it', () => {
      const r = expandCmdlineVariables('ro ${gone} rw', { ro: '' });
      expect(r.unresolved).toEqual(['gone']);
      expect(r.unset).toEqual([]);
    });
  });

  /**
   * The board this whole feature came from. `bootcmd=run boot_normal`, and `boot_normal` performs
   * `env set bootargs … ${mtdparts}${mtdparts1} ${mem} ${memsize}` — where `mtdparts1` is not in the environment at
   * all. Against the STORED variable the check reported mem/memsize/root/rootfstype as differing; against the line
   * the board actually assembles, mem and memsize agree and what is left is the real disagreement.
   */
  describe('the Tenda camera, straight off the corpus', () => {
    const TENDA_VARS: Record<string, string> = {
      console: 'ttySAK0,115200n8',
      mtd_root: '/dev/mtdblock3',
      rootfstype: 'jffs2',
      init: '/sbin/init',
      mem: 'mem=64M',
      memsize: 'memsize=64M',
      mtdparts: 'mtdparts=spi0.0:320k(boot),2112k(kernel),64k(dtb),5120k(rootfs)',
      bootargs: 'console=${console} root=${mtd_root} rootfstype=${rootfstype} init=${init} ',
    };
    const TENDA_STORED = TENDA_VARS.bootargs as string;
    const TENDA_ASSEMBLED =
      'console=${console} root=${mtd_root} rootfstype=${rootfstype} init=${init} ${mtdparts}${mtdparts1} ${mem} ${memsize}';
    const TENDA_TREE =
      'console=ttySAK0,115200n8 root=/dev/mtdblock5 rootfstype=squashfs init=/sbin/init mem=64M memsize=64M';

    const run = () =>
      crossCheckBootCmdlines({
        deviceTree: [tree(TENDA_TREE, 'raw image offset 2490368')],
        ubootEnv: { ...env(TENDA_STORED, TENDA_VARS), variablesComplete: true },
        ubootScript: script([assembled(TENDA_ASSEMBLED, ['bootcmd', 'boot_normal'], TENDA_VARS, { complete: true })]),
      });

    it('survives as a disagreement, and it is the sharper one', () => {
      const r = run();
      expect(r.verdict).toBe('disagree');
      expect(r.comparedUbootLine).toBe('assembled');
      const keys = (
        evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).differences as { key: string }[]
      ).map((d) => d.key);
      // mem and memsize now AGREE — they were an artefact of comparing the stored variable, not a real difference.
      expect(keys).not.toContain('mem');
      expect(keys).not.toContain('memsize');
      expect(keys).toEqual(['mtdparts', 'root', 'rootfstype']);
    });

    it('records ${mtdparts1} as a variable the board does not carry, rather than refusing over it', () => {
      const r = run();
      const ev = evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> });
      expect(ev.ubootEnvUnsetVariables).toEqual(['mtdparts1']);
      expect(ev.ubootEnvExpanded).toContain('mem=64M memsize=64M');
    });

    it('keeps the stored template beside it, marked as a different boot configuration', () => {
      const r = run();
      expect(r.storedAndAssembledDiffer).toBe(true);
      expect(evidenceOf(r.findings[0] as { evidence?: Record<string, unknown> }).ubootStoredCmdline).toBe(TENDA_STORED);
    });

    it('is still only a provenance fact — neither line answers the security questions differently', () => {
      expect(run().findings[0]?.severity).toBe('info');
    });
  });
});
