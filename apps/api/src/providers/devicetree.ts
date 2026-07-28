/**
 * Device-tree provider — the board description the workbench was already parsing and throwing away.
 *
 * `carve.ts` has walked flattened device trees since W1 landed, because a FIT container *is* an FDT; it used the
 * walk only to locate a sub-image's inlined `data` and discarded the tree. But the tree is the single most
 * authoritative artefact in an embedded image: it is the firmware telling the kernel, in its own words, what
 * hardware it expects. That is strictly better evidence than the heuristic MCU fingerprint, and it costs nothing —
 * the bytes are already open. This module reads the tree itself, sharing the one walk in `fdt.ts`.
 *
 * Four things come out, and each is bounded by what a device tree can actually witness:
 *
 *  - **Board and SoC identity** (`model`, root `compatible`). Authoritative for the board the image was BUILT FOR.
 *    It is not a statement about the board in hand; a device tree describes the hardware the image expects.
 *  - **The declared flash layout** (`fixed-partitions` / `partition@…` with `reg`, `label`, `read-only`). This is a
 *    DECLARATION, never a verified layout — nothing here was read back from a device. And `read-only` is not
 *    protection: it tells Linux not to offer a writable mtd node, and a bootloader, a direct SPI/NAND write, or a
 *    kernel built without it ignore it completely. Any wording that lets a reader conclude "this region is
 *    protected" would be false, so the finding says the opposite explicitly.
 *  - **The kernel command line** in `/chosen`. Exactly the same fact `uboot.ts` reads out of the U-Boot
 *    environment, so it is audited by the SAME shared code under the SAME finding codes (`boot-cmdline.ts`) — one
 *    dialect for one fact, with the provenance carried in the evidence.
 *  - **The peripheral inventory** — UART, SPI, I2C, watchdog, USB, GPIO, flash, MMC nodes the kernel is told to
 *    bring up. An enabled UART is `static_confirmed` about the TREE and only a LEAD about the hardware: whether the
 *    pads are populated, whether a console is attached, and whether it authenticates are three further questions
 *    these bytes cannot answer, and the finding refuses to conflate them.
 *
 * Three refusals worth stating outright, all of them forced by real corpus bytes rather than by the spec:
 *
 *  1. **A FIT commonly carries one device tree per board variant, so it reports them ALL** and marks which one the
 *     FIT `/configurations` node selects. Silently picking the first would make the answer an artefact of tree
 *     order. The Tenda-Camera image carries two — `EVB_CBD_AK3918EV300L_V1.0.0 board` and
 *     `EVB_CBDM_AK3918EV300L_V1.0.0 board` — with nothing in the image declaring which the device uses; that is
 *     reported as the open question it is.
 *  2. **A tree that could not be read to completion is REJECTED, not reported.** See `fdt.ts` for the GL.iNet
 *     BE3600 case that forced this: an FDT header in the raw image validates perfectly, yet the blob is a device
 *     tree living inside a UBI volume, so the raw file splices eraseblock metadata through it. The true tree comes
 *     from the carve chain (FIT → UBI → `kernel` volume → inner FIT → `flat_dt` sub-image); the raw hit is kept in
 *     `rejected` with the reason, because a disagreement between two readings of the same bytes is information.
 *  3. **No device tree is `blocked_by_platform`, naming where it looked.** Every stock TP-Link image in the corpus
 *     has no FDT at all — an ath79 vendor build describes its board in compiled-in C. That is a fact about the
 *     build style, not a clean result, and certainly not "this image has no board description".
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';
import { auditKernelCommandLine, truncate } from './boot-cmdline.js';
import { detectFormat, parseFitConfigurations, parseFitImages, parseUbiVolumes } from './carve.js';
import {
  type FdtNode,
  type ParsedFdt,
  eachNode,
  hasProp,
  nodeAt,
  parseFdt,
  propCells,
  propString,
  propStrings,
  propU32,
  scanFdtCandidates,
} from './fdt.js';

// === Result shape ========================================================================================

/** One entry of a declared flash map. Every field is what the tree SAYS, not what a device was observed to do. */
export interface DtPartition {
  nodeName: string;
  label?: string;
  /** Byte offset from the `reg` address cells, when the tree declares one. */
  offset?: number;
  /** Byte length from the `reg` size cells, when the tree declares one. */
  size?: number;
  /**
   * The `read-only` property is present. This is a request to the kernel to withhold a writable mtd node. It is
   * NOT hardware write protection and implies nothing about a bootloader or a direct flash write.
   */
  declaredReadOnly: boolean;
}

/** The interface classes worth inventorying for a hardware assessment. */
export type DtPeripheralKind = 'uart' | 'watchdog' | 'spi' | 'i2c' | 'usb' | 'gpio' | 'flash' | 'mmc';

/** One hardware node the tree describes, with the literal status string it declared. */
export interface DtPeripheral {
  path: string;
  kind: DtPeripheralKind;
  compatible: string[];
  /** The literal `status` value, or `(absent)` — which per the kernel's own rule means enabled. */
  status: string;
  enabled: boolean;
  /** True when `/chosen` `stdout-path` resolves (possibly through `/aliases`) to this node. */
  console?: boolean;
}

/** One device tree read out of the image, with everything it declares about itself. */
export interface DeviceTreeBlob {
  /** How this blob was reached — the provenance chain, not just an offset. */
  origin: string;
  sizeBytes: number;
  model?: string;
  compatible: string[];
  /** The assembled kernel command line, and which `/chosen` properties it was assembled from. */
  bootargs?: string;
  bootargsFrom: string[];
  stdoutPath?: string;
  /** The node `stdout-path` resolves to, when it resolves. */
  consolePath?: string;
  partitions: DtPartition[];
  /** The node the partitions were read from, so the claim can be traced back into the tree. */
  partitionNode?: string;
  /** Why `partitions` is empty, when it is — an empty flash map is a result and has to say what it means. */
  partitionNote?: string;
  peripherals: DtPeripheral[];
  /** How many peripheral nodes the cap dropped, and by what rule (never by tree order). */
  peripheralsDropped?: number;
  /**
   * Nodes that matched a peripheral rule but sit more than one level under another peripheral — a driver's
   * chip-support table rather than board hardware. Counted so the exclusion is visible instead of silent.
   */
  nestedNodesSkipped?: number;
  peripheralNote?: string;
  nodeCount: number;
  /** True when a FIT `/configurations` node selects this device tree. Absent means nothing declared a choice. */
  selected?: boolean;
  selectedBy?: string;
}

/** An FDT header that validated but whose tree could not be trusted — kept, because the disagreement is evidence. */
export interface RejectedFdt {
  origin: string;
  sizeBytes: number;
  reason: string;
}

/** Outcome of a device-tree analysis over one image. `found:false` always carries the reason and the search list. */
export interface DeviceTreeResult {
  available: boolean;
  found: boolean;
  blobs: DeviceTreeBlob[];
  rejected: RejectedFdt[];
  /** Every place that was actually searched — what a `found:false` does and does not cover. */
  searched: string[];
  findings: FindingDraft[];
  reason: string;
}

// === Pure analysis =======================================================================================

/**
 * The kernel's own availability rule (`of_device_is_available`): a node is available when it declares no `status`,
 * or declares exactly `okay` or `ok`. Everything else — including `disabled`, `fail`, `reserved` — is unavailable.
 *
 * The deprecated `ok` spelling is not a curiosity: the GL.iNet BE3600 tree uses `status = "ok"` 32 times against a
 * single `okay`, so a parser matching only the spec-blessed spelling would call 32 live nodes disabled. The Tenda
 * camera tree adds a third spelling, `disable`, which is in neither list and which this rule correctly treats as
 * unavailable precisely because it is not an allow-listed value.
 */
export function isNodeEnabled(status: string | undefined): boolean {
  if (status === undefined) return true;
  return status === 'okay' || status === 'ok';
}

interface CellSpec {
  address: number;
  size: number;
}

/** The `#address-cells` / `#size-cells` a node imposes on its children, falling back to what it inherited. */
function childCells(node: FdtNode, inherited: CellSpec): CellSpec {
  return {
    address: propU32(node, '#address-cells') ?? inherited.address,
    size: propU32(node, '#size-cells') ?? inherited.size,
  };
}

/** Fold `n` big-endian u32 cells into one number (flash offsets and sizes stay far inside 2^53). */
function foldCells(cells: number[], start: number, count: number): number | undefined {
  if (count <= 0 || start + count > cells.length) return undefined;
  let v = 0;
  for (let i = 0; i < count; i++) v = v * 0x1_0000_0000 + (cells[start + i] ?? 0);
  return v;
}

/** A node is a partition entry when it carries a `reg` or a `label` — the two things a flash map entry needs. */
function isPartitionEntry(node: FdtNode): boolean {
  return hasProp(node, 'reg') || hasProp(node, 'label');
}

/**
 * Is this node a flash partition table? Either it says so (`compatible = "fixed-partitions"`, or the node is named
 * `partitions`), or it has `partition@…` children — the pre-`fixed-partitions` layout, which is still what a lot of
 * shipping trees use and which a rule keyed only on the modern binding would miss entirely.
 */
export function isPartitionContainer(node: FdtNode): boolean {
  const compatible = propStrings(node, 'compatible');
  if (compatible.some((c) => c === 'fixed-partitions' || c.endsWith('-partitions'))) return true;
  if (node.name === 'partitions' || node.name.startsWith('partitions@')) return true;
  return node.children.some((c) => c.name === 'partition' || c.name.startsWith('partition@'));
}

/** Pure: read one partition table into declared entries. Order follows the tree, which for a flash map is the map. */
export function readPartitions(container: FdtNode, inherited: CellSpec): DtPartition[] {
  const cells = childCells(container, inherited);
  const out: DtPartition[] = [];
  for (const child of container.children) {
    if (!isPartitionEntry(child)) continue;
    const reg = propCells(child, 'reg');
    const label = propString(child, 'label');
    const offset = foldCells(reg, 0, cells.address);
    const size = foldCells(reg, cells.address, cells.size);
    out.push({
      nodeName: child.name,
      ...(label ? { label } : {}),
      ...(offset === undefined ? {} : { offset }),
      ...(size === undefined ? {} : { size }),
      declaredReadOnly: hasProp(child, 'read-only'),
    });
  }
  return out;
}

/**
 * Peripheral classification. A rule matches on the node name or on any `compatible` string; the ORDER of this list
 * is also the reporting priority used when the cap truncates, so the interfaces that matter most to a hardware
 * assessment (a debug UART, then a watchdog) can never be the ones dropped.
 */
const PERIPHERAL_RULES: { kind: DtPeripheralKind; name: RegExp; compatible: RegExp }[] = [
  { kind: 'uart', name: /^(serial|uart|usart)([@_-]|$)/i, compatible: /(uart|serial|usart|8250|16550)/i },
  { kind: 'watchdog', name: /^(watchdog|wdt)([@_-]|$)/i, compatible: /(watchdog|[-,]wdt)/i },
  { kind: 'spi', name: /^(spi|qspi)([@_-]|$)/i, compatible: /spi(-|$|[0-9])/i },
  { kind: 'i2c', name: /^i2c([@_-]|$)/i, compatible: /i2c/i },
  { kind: 'usb', name: /^(usb|xhci|ehci|ohci|dwc3)([@_-]|$)/i, compatible: /(usb|xhci|ehci|ohci|dwc3)/i },
  { kind: 'gpio', name: /^gpio([@_-]|$)/i, compatible: /gpio(-controller)?/i },
  { kind: 'flash', name: /^(nand|nor|flash|spi-nor)([@_-]|$)/i, compatible: /(nand|spi-nor|jedec)/i },
  { kind: 'mmc', name: /^(mmc|sdhci|sdhc|mshc)([@_-]|$)/i, compatible: /(mmc|sdhci|mshc)/i },
];

/**
 * Pure: does this node describe a real peripheral? It must carry a `compatible` AND be addressable — a `reg`
 * property or a unit address in its name. Without that test the pin-multiplexing children sweep straight in: the
 * corpus has `serial0-pinmux`, `uart0_pins`, `spi_clock` and `usb_pins`, all of which match a name rule and none
 * of which is a device. They carry pin lists, not a `compatible` and not an address.
 */
export function classifyPeripheral(node: FdtNode): DtPeripheralKind | null {
  const compatible = propStrings(node, 'compatible');
  if (compatible.length === 0) return null;
  if (!hasProp(node, 'reg') && !node.name.includes('@')) return null;
  for (const rule of PERIPHERAL_RULES) {
    if (rule.name.test(node.name) || compatible.some((c) => rule.compatible.test(c))) return rule.kind;
  }
  return null;
}

/**
 * How deep under another peripheral a node may sit and still be one itself. One level is a real device on a bus
 * (the SPI-NOR chip hanging off a SPI controller); two is not.
 *
 * The Tenda camera tree forced this. Under `/soc/spi0@21100000/spi-flash@0` it carries FORTY-SEVEN nodes named
 * `spi-norflash@44`, `spi-norflash@45`, … each with a `compatible` ("winbond,w25q64", "gd,gd25q64", …), a `reg`
 * and a `norflash-jedec-id`. They are not devices on the board: they are the driver's table of SPI-NOR parts it
 * knows how to talk to, one entry per JEDEC ID. Reporting them as an inventory of the hardware would be wrong —
 * and they alone overflowed the peripheral cap, pushing 45 genuine nodes out of the result.
 */
const MAX_PERIPHERAL_NESTING = 1;

const PERIPHERAL_CAP = 64;
const KIND_ORDER = new Map(PERIPHERAL_RULES.map((r, i) => [r.kind, i]));

/**
 * Resolve `/chosen` `stdout-path` to a node path. The value may be an alias (`serial0`), an absolute path, and may
 * carry a `:115200n8` options suffix. Returns undefined when nothing declares a console.
 */
export function resolveStdoutPath(root: FdtNode): { stdoutPath?: string; consolePath?: string } {
  const chosen = nodeAt(root, '/chosen');
  if (!chosen) return {};
  const raw = propString(chosen, 'stdout-path') ?? propString(chosen, 'linux,stdout-path');
  if (!raw) return {};
  const withoutOptions = raw.split(':')[0] ?? raw;
  if (withoutOptions.startsWith('/')) return { stdoutPath: raw, consolePath: withoutOptions };
  const aliases = nodeAt(root, '/aliases');
  const target = aliases ? propString(aliases, withoutOptions) : undefined;
  return target ? { stdoutPath: raw, consolePath: target } : { stdoutPath: raw };
}

/**
 * Pure: read one parsed device tree into the reportable shape. Assumes the caller already accepted the tree's
 * integrity — this function does not re-decide that, it only reads.
 */
export function analyzeDeviceTree(parsed: ParsedFdt, origin: string, sizeBytes: number): DeviceTreeBlob {
  const { root } = parsed;
  const model = propString(root, 'model');
  const compatible = propStrings(root, 'compatible');

  // /chosen: the kernel command line. `bootargs-append` is a U-Boot/OpenWrt extension that is concatenated onto the
  // final line, so it is part of the command line and is audited as such — recorded so the reader can see which
  // properties the audited string was assembled from.
  const chosen = nodeAt(root, '/chosen');
  const bootargsFrom: string[] = [];
  const parts: string[] = [];
  if (chosen) {
    for (const name of ['bootargs', 'bootargs-append'] as const) {
      const v = propString(chosen, name);
      if (v === undefined || v === '') continue;
      bootargsFrom.push(name);
      parts.push(v.trim());
    }
  }
  const bootargs = parts.join(' ').trim();
  const { stdoutPath, consolePath } = resolveStdoutPath(root);

  // Flash map: the first partition container wins, and the node it came from is reported so the claim is traceable.
  let partitions: DtPartition[] = [];
  let partitionNode: string | undefined;
  const peripherals: DtPeripheral[] = [];
  let nodeCount = 0;

  let chipTableSkipped = 0;

  const visit = (node: FdtNode, inherited: CellSpec, peripheralAncestors: number): void => {
    nodeCount++;
    if (partitionNode === undefined && node !== root && isPartitionContainer(node)) {
      const read = readPartitions(node, inherited);
      if (read.length > 0) {
        partitions = read;
        partitionNode = node.path;
      }
    }
    const kind = classifyPeripheral(node);
    if (kind && peripheralAncestors > MAX_PERIPHERAL_NESTING) {
      chipTableSkipped++;
    } else if (kind) {
      const status = propString(node, 'status');
      peripherals.push({
        path: node.path,
        kind,
        compatible: propStrings(node, 'compatible'),
        status: status ?? '(absent)',
        enabled: isNodeEnabled(status),
        ...(consolePath !== undefined && consolePath === node.path ? { console: true } : {}),
      });
    }
    const cells = childCells(node, inherited);
    for (const child of node.children) visit(child, cells, peripheralAncestors + (kind ? 1 : 0));
  };
  // Device Tree spec defaults when the root declares nothing: 2 address cells, 1 size cell.
  visit(root, { address: 2, size: 1 }, 0);

  // The cap must not truncate by tree order — that would make the reported set an artefact of where a node sits.
  // Enabled first (an enabled interface is the one an assessment acts on), then interface class, then path.
  peripherals.sort((a, b) => {
    if (a.enabled !== b.enabled) return a.enabled ? -1 : 1;
    const ka = KIND_ORDER.get(a.kind) ?? 99;
    const kb = KIND_ORDER.get(b.kind) ?? 99;
    if (ka !== kb) return ka - kb;
    return a.path.localeCompare(b.path);
  });
  const dropped = Math.max(0, peripherals.length - PERIPHERAL_CAP);
  const noteParts: string[] = [];
  if (dropped > 0) {
    noteParts.push(
      [
        `Reporting ${PERIPHERAL_CAP} of ${peripherals.length} peripheral nodes; ${dropped} dropped. The kept set`,
        'is ordered enabled-first, then by interface class (uart, watchdog, spi, i2c, usb, gpio, flash, mmc),',
        'then by path — never by tree order, so it does not depend on where a node sits in the tree.',
      ].join(' '),
    );
  }
  if (chipTableSkipped > 0) {
    noteParts.push(
      [
        `${chipTableSkipped} node(s) matched a peripheral rule but sit more than ${MAX_PERIPHERAL_NESTING} level`,
        'below another peripheral and were excluded as a driver chip-support table (a list of parts the driver',
        'recognises by JEDEC id), not hardware on this board.',
      ].join(' '),
    );
  }

  return {
    origin,
    sizeBytes,
    ...(model ? { model } : {}),
    compatible,
    ...(bootargs ? { bootargs } : {}),
    bootargsFrom,
    ...(stdoutPath ? { stdoutPath } : {}),
    ...(consolePath ? { consolePath } : {}),
    partitions,
    ...(partitionNode
      ? { partitionNode }
      : {
          // Not a clean "no partitions": plenty of real trees describe the board and leave the flash map to the
          // bootloader. The GL.iNet BE3600 is one — its 378-node tree declares no `fixed-partitions` at all,
          // because on IPQ5332 the layout comes from the MIBIB partition table in flash, not from the DT.
          partitionNote:
            'This tree declares no partition table. The flash map is not described here — it may live in the ' +
            'bootloader, a vendor-specific node, or an on-flash partition table — so this is silence about the ' +
            'layout, not a device with no partitions.',
        }),
    peripherals: peripherals.slice(0, PERIPHERAL_CAP),
    ...(dropped > 0 ? { peripheralsDropped: dropped } : {}),
    ...(chipTableSkipped > 0 ? { nestedNodesSkipped: chipTableSkipped } : {}),
    ...(noteParts.length > 0 ? { peripheralNote: noteParts.join(' ') } : {}),
    nodeCount,
  };
}

// === Findings ============================================================================================

/** Format a byte count as the hex offset/size a flash map is normally read in. */
function hex(n: number | undefined): string {
  return n === undefined ? '?' : `0x${n.toString(16)}`;
}

/**
 * Pure: the findings one device tree supports. Severity and proof state are decided here, by code, from what the
 * tree literally declares — never inferred and never upgraded by anything downstream.
 */
export function deviceTreeFindings(blob: DeviceTreeBlob): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const where = `the device tree (${blob.origin})`;

  if (blob.model || blob.compatible.length > 0) {
    drafts.push({
      kind: 'devicetree-board-identity',
      title: `Device tree declares board ${blob.model ? `"${truncate(blob.model, 80)}"` : blob.compatible[0]}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: {
        origin: blob.origin,
        ...(blob.model ? { model: blob.model } : {}),
        compatible: blob.compatible,
        ...(blob.selected === undefined ? {} : { selected: blob.selected }),
        ...(blob.selectedBy ? { selectedBy: blob.selectedBy } : {}),
      },
      rationale:
        'The flattened device tree names the SoC and board the image was BUILT FOR, and the strings are literally ' +
        'in the bytes — authoritative hardware identity, and far stronger than a heuristic MCU fingerprint. It is ' +
        'not a claim about the board in hand: a device tree describes the hardware the image expects to find.',
    });
  }

  if (blob.bootargs) {
    drafts.push(
      ...auditKernelCommandLine(blob.bootargs, {
        where: `the device tree's /chosen node (${blob.origin})`,
        evidence: { origin: blob.origin, node: '/chosen', properties: blob.bootargsFrom },
      }),
    );
  }

  for (const p of blob.peripherals) {
    if (p.kind !== 'uart' || !p.enabled) continue;
    drafts.push({
      kind: 'devicetree-debug-uart',
      title: `Debug UART enabled in the device tree (${p.path}${p.console ? ', kernel console' : ''})`,
      severity: p.console ? 'medium' : 'low',
      proofState: 'static_confirmed',
      evidence: {
        origin: blob.origin,
        path: p.path,
        compatible: p.compatible,
        status: p.status,
        ...(p.console ? { console: true, stdoutPath: blob.stdoutPath } : {}),
      },
      rationale: [
        `The node is present in ${where} with a status the kernel reads as available ("okay", "ok", or absent),`,
        'so the kernel is told to bring this UART up. static_confirmed is a claim about the TREE and nothing',
        'more: whether the pads are populated on the board in hand, whether anything is attached to them, and',
        'whether that console authenticates are three further questions these bytes cannot answer. Treat it as a',
        'lead for hardware inspection, not as a proven open interface.',
      ].join(' '),
    });
  }

  if (blob.partitions.length > 0) {
    const readOnly = blob.partitions.filter((p) => p.declaredReadOnly);
    const readOnlySuffix = readOnly.length > 0 ? ` (${readOnly.length} marked read-only)` : '';
    drafts.push({
      kind: 'devicetree-flash-layout',
      title: `Device tree declares a ${blob.partitions.length}-partition flash layout${readOnlySuffix}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: {
        origin: blob.origin,
        ...(blob.partitionNode ? { node: blob.partitionNode } : {}),
        partitions: blob.partitions.map((p) => ({
          label: p.label ?? p.nodeName,
          offset: hex(p.offset),
          size: hex(p.size),
          declaredReadOnly: p.declaredReadOnly,
        })),
      },
      rationale:
        'The firmware declares its own storage map, which is where to look for a region rather than proof of one: ' +
        'nothing here was read back from a device, so it is a declaration and not a verified layout. A `read-only` ' +
        'property is NOT write protection — it asks Linux to withhold a writable mtd node, and a bootloader, a ' +
        'direct SPI/NAND write, or a kernel built without that property ignores it entirely. Read it as "the ' +
        'vendor did not intend this to change at runtime", never as "this region cannot be modified".',
    });
  }

  return drafts;
}

/** Pure: the honest finding for an image no device tree could be read from. Not a negative — a question unanswered. */
export function absentFinding(searched: string[], rejected: RejectedFdt[]): FindingDraft {
  return {
    kind: 'devicetree-absent',
    title: 'No readable device tree in this image',
    severity: 'info',
    proofState: 'blocked_by_platform',
    evidence: { searched, ...(rejected.length > 0 ? { rejected } : {}) },
    rationale: [
      `The question "what board does this image declare?" was asked in ${searched.length} place(s) and could not`,
      'be answered from these bytes. That is not a finding that the image lacks a board description: a great many',
      'vendor builds (every pre-device-tree ath79 or Broadcom image in this corpus among them) describe their',
      'board in compiled-in C instead, so there is nothing here to read. Board identity for this image has to',
      'come from another source, and the MCU fingerprint remains a heuristic.',
    ].join(' '),
  };
}

// === Runner (I/O; composes the pure parts) ===============================================================

/** Beyond this the image is not read — a device tree lives near the front of a container, not past a quarter GB. */
const READ_CAP = 512 * 1024 * 1024;
/** How many device trees to report. A FIT with more board variants than this states what it dropped. */
const BLOB_CAP = 8;
/** How deep the FIT → UBI → FIT descent may go before it stops looking. */
const CHAIN_DEPTH = 3;
const UBI_EC_MAGIC = 0x55424923; // "UBI#"

interface Candidate {
  origin: string;
  bytes: Uint8Array;
  base: number;
  selectedBy?: string;
}

/** Does this tree look like a FIT container (an `/images` node whose children inline `data`) rather than a board? */
function isFitContainer(root: FdtNode): boolean {
  const images = root.children.find((c) => c.name === 'images');
  return !!images && images.children.some((c) => hasProp(c, 'data'));
}

/** Locate `UBI#` inside a blob — the evidence that a raw-image FDT hit is really a tree inside a UBI volume. */
function ubiMagicOffset(bytes: Uint8Array, base: number, length: number): number {
  const end = Math.min(base + length, bytes.length);
  for (let i = base + 4; i + 4 <= end; i++) {
    if (
      (((bytes[i] ?? 0) << 24) | ((bytes[i + 1] ?? 0) << 16) | ((bytes[i + 2] ?? 0) << 8) | (bytes[i + 3] ?? 0)) >>>
        0 ===
      UBI_EC_MAGIC
    ) {
      return i - base;
    }
  }
  return -1;
}

/** Walk a FIT (and any UBI volume it wraps that is itself a FIT) collecting `flat_dt` sub-images. */
function collectFromFit(bytes: Uint8Array, origin: string, depth: number, searched: Set<string>): Candidate[] {
  if (depth > CHAIN_DEPTH) return [];
  const out: Candidate[] = [];
  const images = parseFitImages(bytes);
  if (images.length === 0) return out;
  searched.add(`${origin} sub-images`);

  const configs = parseFitConfigurations(bytes);
  const chosen = configs.find((c) => c.isDefault) ?? (configs.length === 1 ? configs[0] : undefined);

  for (const img of images) {
    const sub = bytes.subarray(img.dataOffset, img.dataOffset + img.dataSize);
    const subOrigin = `${origin} /images/${img.name}`;
    if ((img.type ?? '').includes('flat_dt')) {
      const selectedBy =
        chosen?.fdt === img.name
          ? `${origin} /configurations${chosen.isDefault ? ` default = ${chosen.name}` : `/${chosen.name}`}` +
            ` selects fdt = ${img.name}`
          : undefined;
      out.push({ origin: subOrigin, bytes: sub, base: 0, ...(selectedBy ? { selectedBy } : {}) });
      continue;
    }
    const fmt = detectFormat(sub);
    if (fmt === 'fit') {
      out.push(...collectFromFit(sub, subOrigin, depth + 1, searched));
    } else if (fmt === 'ubi') {
      searched.add(`${subOrigin} UBI volumes`);
      for (const vol of parseUbiVolumes(sub)) {
        const volOrigin = `${subOrigin} → UBI volume ${vol.name ?? `#${vol.volId}`}`;
        const volFmt = detectFormat(vol.data);
        if (volFmt === 'fit') out.push(...collectFromFit(vol.data, volOrigin, depth + 1, searched));
      }
    }
  }
  return out;
}

/** Collect `*.dtb` / `*.dtbo` files from the extraction output, bounded so a huge rootfs cannot stall the job. */
function collectFromDir(dir: string, searched: Set<string>): Candidate[] {
  const out: Candidate[] = [];
  const queue: string[] = [dir];
  let visited = 0;
  searched.add(`the extraction output (*.dtb / *.dtbo under ${dir})`);
  while (queue.length > 0 && visited < 20000 && out.length < BLOB_CAP) {
    const current = queue.shift() as string;
    visited++;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        queue.push(full);
      } else if (entry.isFile() && /\.dtbo?$/i.test(entry.name)) {
        try {
          const stat = fs.statSync(full);
          if (stat.size > 16 * 1024 * 1024) continue;
          out.push({
            origin: `extracted file ${path.relative(dir, full)}`,
            bytes: new Uint8Array(fs.readFileSync(full)),
            base: 0,
          });
        } catch {
          // unreadable file — skipped, and the raw-image scan still covers the same bytes
        }
      }
    }
  }
  return out;
}

function blocked(reason: string, searched: string[]): DeviceTreeResult {
  return {
    available: true,
    found: false,
    blobs: [],
    rejected: [],
    searched,
    findings: [absentFinding(searched, [])],
    reason,
  };
}

/**
 * Analyze the device tree(s) a firmware image carries — offline, and honest at every step. Candidates come from
 * three places, in descending order of trust: the FIT/UBI carve chain (where a tree is contiguous and correct),
 * `*.dtb` files in the extraction output, and last a raw magic scan of the image. Content-identical blobs collapse
 * to the highest-trust origin; a header that validates but whose tree cannot be walked to completion is rejected
 * with its reason rather than reported as a tree.
 */
export function runDeviceTreeAnalysis(imagePath: string, extractDir: string | null): DeviceTreeResult {
  const searched = new Set<string>();
  let bytes: Uint8Array;
  try {
    const size = fs.statSync(imagePath).size;
    if (size > READ_CAP) {
      return blocked(
        `The image is ${size} bytes, over the ${READ_CAP}-byte device-tree read cap; it was not scanned.`,
        ['nothing — the image exceeded the read cap'],
      );
    }
    bytes = new Uint8Array(fs.readFileSync(imagePath));
  } catch {
    return blocked('The image could not be read.', ['nothing — the image could not be opened']);
  }

  const candidates: Candidate[] = [];
  if (detectFormat(bytes) === 'fit') candidates.push(...collectFromFit(bytes, 'FIT', 0, searched));
  if (extractDir && fs.existsSync(extractDir)) candidates.push(...collectFromDir(extractDir, searched));

  searched.add('the raw image (FDT magic scan with full header validation)');
  for (const header of scanFdtCandidates(bytes)) {
    candidates.push({ origin: `raw image offset ${header.base}`, bytes, base: header.base });
  }

  const blobs: DeviceTreeBlob[] = [];
  const rejected: RejectedFdt[] = [];
  const seen = new Set<string>();
  let containerCount = 0;
  let droppedBlobs = 0;

  for (const cand of candidates) {
    const parsed = parseFdt(cand.bytes, cand.base);
    if (!parsed) continue;
    const length = parsed.header.totalSize;
    const digest = createHash('sha256')
      .update(cand.bytes.subarray(cand.base, cand.base + length))
      .digest('hex');
    if (seen.has(digest)) continue;
    seen.add(digest);

    if (!parsed.outcome.complete || parsed.outcome.unnamedProps > 0) {
      const spliceAt = ubiMagicOffset(cand.bytes, cand.base, length);
      const detail = [
        parsed.outcome.stopReason ?? 'the walk completed but property names did not resolve',
        parsed.outcome.unnamedProps > 0
          ? `${parsed.outcome.unnamedProps} property name(s) did not resolve inside the strings block`
          : null,
        spliceAt >= 0
          ? [
              `a UBI eraseblock header ("UBI#") appears ${spliceAt} bytes in, so this is a device tree stored`,
              'inside a UBI volume — the raw image interleaves per-eraseblock metadata through it, and the blob',
              'is only contiguous once the volume is reassembled by the carve chain',
            ].join(' ')
          : null,
      ]
        .filter((s): s is string => s !== null)
        .join('; ');
      rejected.push({
        origin: cand.origin,
        sizeBytes: length,
        reason: `FDT header valid but the tree could not be read to completion: ${detail}.`,
      });
      continue;
    }

    if (isFitContainer(parsed.root)) {
      containerCount++;
      continue; // a FIT is an FDT but not a board description; its sub-images were already descended into
    }
    if (blobs.length >= BLOB_CAP) {
      droppedBlobs++;
      continue;
    }
    const blob = analyzeDeviceTree(parsed, cand.origin, length);
    blobs.push({
      ...blob,
      ...(cand.selectedBy ? { selected: true, selectedBy: cand.selectedBy } : {}),
    });
  }

  const searchedList = [...searched];
  if (blobs.length === 0) {
    const why =
      rejected.length > 0
        ? `${rejected.length} FDT header(s) validated but no tree could be read to completion — see rejected.`
        : containerCount > 0
          ? 'The only flattened device trees present are FIT containers, which describe an image layout, not a board.'
          : 'No FDT magic with a valid header was present.';
    return {
      available: true,
      found: false,
      blobs: [],
      rejected,
      searched: searchedList,
      findings: [absentFinding(searchedList, rejected)],
      reason: `No readable device tree found. ${why}`,
    };
  }

  const findings = blobs.flatMap(deviceTreeFindings);
  const selected = blobs.filter((b) => b.selected);
  const multiNote =
    blobs.length === 1
      ? ''
      : selected.length > 0
        ? ` The FIT configuration selects ${selected.map((b) => b.model ?? b.origin).join(', ')}.`
        : ' Nothing in the image declares which one the board uses, so all are reported.';
  const droppedNote =
    droppedBlobs > 0 ? ` ${droppedBlobs} further device tree(s) beyond the ${BLOB_CAP} cap were not analyzed.` : '';
  const rejectedNote =
    rejected.length > 0
      ? ` ${rejected.length} further FDT header(s) validated but could not be read to completion (see rejected).`
      : '';

  return {
    available: true,
    found: true,
    blobs,
    rejected,
    searched: searchedList,
    findings,
    reason: [
      `Read ${blobs.length} device tree${blobs.length === 1 ? '' : 's'} from the image.`,
      `${multiNote}${droppedNote}${rejectedNote}`.trim(),
      'Static analysis of the tree bytes — it proves what the image declares about its hardware, never what the',
      'hardware does.',
    ]
      .filter((s) => s !== '')
      .join(' '),
  };
}
