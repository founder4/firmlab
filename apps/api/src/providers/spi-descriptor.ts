/**
 * Read the static Intel SPI flash descriptor map carried in an image. Descriptor FLREG entries describe the
 * image's region layout; they do not contain the live PRx or BIOS_CNTL register values needed to prove that the
 * running device protects flash writes. Missing, malformed, or truncated descriptor data therefore stays unknown.
 *
 * The master section is read for ONE question: does the descriptor grant the host CPU/BIOS master (`FLMSTR1`, always
 * the first master record, so the master count never matters) write access to the descriptor region itself? The
 * FLMSTR1 bit layout depends on the PCH generation, and the image does not name its PCH: chipsec's own register
 * definitions carry two layouts (`cfg/8086/common.xml`: read 16..23, write 24..31; `pch_1xx.xml`, `pch_2xx.xml`,
 * `pch_c620.xml`, `skl.xml`, `kbl.xml`: read 8..19, write 20..31). Both are evaluated; a verdict is given only when
 * they agree, and a disagreement is reported as `layout-dependent`, never resolved by picking one. A grant is a fact
 * of the shipped bytes (`static_confirmed`), not of the running device: the live FRAP register chipsec's
 * `spi_desc` module reads can differ (a descriptor-override strap, a reflashed descriptor), and stays unknown here.
 *
 * The same FLMSTR1 value answers a second question under the same two-layout rule: does the host master hold write
 * access to the Intel ME region (chipsec `hal/spi.py` region index 2, so bit `1 << 2` in either layout)? A grant is
 * only flagged when the region map actually enables the ME region; a write bit for a region the descriptor leaves
 * disabled or never declares names no flash range, so it is recorded with its reason but is not a finding.
 */

export const SPI_DESCRIPTOR_SCAN_CAP_BYTES = 1024 * 1024;
export const SPI_DESCRIPTOR_PARSE_CAP_BYTES = 0x1100;

const DESCRIPTOR_SIGNATURE = 0x0ff0a55a;
const DESCRIPTOR_SIGNATURE_OFFSET = 0x10;
const FLASH_MAP0_OFFSET = 0x14;
const REGION_BASE_SHIFT = 16;
const REGION_COUNT_SHIFT = 24;
const REGION_COUNT_MASK = 0x7;
const REGION_REGISTER_BYTES = 4;
const REGION_ADDRESS_UNIT_BYTES = 0x1000;
const REGION_NAMES = ['Flash Descriptor', 'BIOS', 'Intel ME', 'GbE', 'Platform Data'];
const FLASH_MAP1_OFFSET = 0x18;
/** The descriptor region is region 0, so its bit is bit 0 of each access mask. */
const DESCRIPTOR_REGION_BIT = 1;
/** chipsec `hal/spi.py`: ME = 2. Its bit is `1 << 2` under both FLMSTR layouts. */
const ME_REGION_INDEX = 2;
const ME_REGION_BIT = 1 << ME_REGION_INDEX;

/** FLMSTR1 access-field layouts, verbatim from chipsec's register definitions (see the module comment). */
export const SPI_MASTER_LAYOUTS = [
  { layout: 'ich-8bit', source: 'chipsec cfg/8086/common.xml', readShift: 16, writeShift: 24, width: 8 },
  { layout: 'pch-12bit', source: 'chipsec cfg/8086/pch_1xx.xml', readShift: 8, writeShift: 20, width: 12 },
] as const;

export interface SpiFlashRegion {
  index: number;
  name: string;
  rawValue: number;
  enabled: boolean;
  baseBytes: number;
  limitBytesInclusive: number;
  startBytes: number | null;
  endBytesExclusive: number | null;
}

export interface SpiRangeRelationship {
  firstRegion: string;
  secondRegion: string;
  startBytes: number;
  endBytesExclusive: number;
}

/** What FLMSTR1 grants the host CPU/BIOS master under one chipsec layout. Masks are region-index bitmaps. */
export interface SpiMasterLayoutReading {
  layout: (typeof SPI_MASTER_LAYOUTS)[number]['layout'];
  source: string;
  readMask: number;
  writeMask: number;
  descriptorReadable: boolean;
  descriptorWritable: boolean;
  /** Optional forever: results stored before the ME-write check lack it. */
  meWritable?: boolean;
}

export interface SpiHostMasterAccess {
  status: 'read' | 'unknown';
  reason: string;
  /** Image offset of FLMSTR1, or null when the master section could not be located. */
  flmstr1Offset: number | null;
  rawValue: number | null;
  layouts: SpiMasterLayoutReading[];
  /** `granted`/`denied` only when every layout agrees; never resolved by choosing a layout. */
  descriptorWrite: 'granted' | 'denied' | 'layout-dependent' | 'unknown';
  /** The same agreement rule for the Intel ME region's write bit. Optional forever: older results predate it. */
  meWrite?: 'granted' | 'denied' | 'layout-dependent' | 'unknown';
  /** Why `meWrite` is what it is, and why a grant did or did not become a finding. Optional forever. */
  meWriteReason?: string;
}

export interface SpiDescriptorFinding {
  kind: string;
  title: string;
  severity: 'info' | 'medium';
  proofState: 'static_confirmed';
  evidence: Record<string, unknown>;
  rationale: string;
}

export interface SpiDescriptorAnalysis {
  status: 'parsed' | 'unknown';
  reason: string;
  descriptorOffset: number | null;
  regions: SpiFlashRegion[];
  overlaps: SpiRangeRelationship[];
  gaps: SpiRangeRelationship[];
  coverage: {
    imageBytes: number;
    scannedBytes: number;
    scanLimitBytes: number;
    parsedBytes: number;
    parseLimitBytes: number;
    parsedStartBytes: number | null;
    parsedEndBytesExclusive: number | null;
  };
  runtimeRegisterPosture: {
    state: 'unknown';
    reason: string;
  };
  findings: SpiDescriptorFinding[];
  /** FLMSTR1 read for the host master's descriptor-write grant. Optional forever: older results predate it. */
  hostMasterAccess?: SpiHostMasterAccess;
}

export interface SpiDescriptorOptions {
  /** Total source-image length when `bytes` is only a bounded prefix. */
  imageSizeBytes?: number;
  scanLimitBytes?: number;
  parseLimitBytes?: number;
}

interface CandidateResult {
  status: 'parsed' | 'unknown';
  reason: string;
  descriptorOffset: number;
  parsedBytes: number;
  regions: SpiFlashRegion[];
}

const RUNTIME_REGISTER_REASON =
  'The image descriptor contains static region defaults only. Current SPI protected-range (PRx) and BIOS_CNTL/SMM_BWP values require a live register dump and are unknown here.';

/** Parse an Intel flash descriptor using bounded signature scanning and bounded region-map reads. */
export function analyzeSpiDescriptor(
  bytes: Uint8Array | null,
  options: SpiDescriptorOptions = {},
): SpiDescriptorAnalysis {
  const scanLimitBytes = normalizeLimit(options.scanLimitBytes, SPI_DESCRIPTOR_SCAN_CAP_BYTES);
  const parseLimitBytes = normalizeLimit(options.parseLimitBytes, SPI_DESCRIPTOR_PARSE_CAP_BYTES);
  const imageBytes = options.imageSizeBytes ?? bytes?.byteLength ?? 0;
  const scannedBytes = bytes ? Math.min(bytes.byteLength, scanLimitBytes) : 0;

  const unknown = (reason: string, descriptorOffset: number | null = null, parsedBytes = 0): SpiDescriptorAnalysis => ({
    status: 'unknown',
    reason,
    descriptorOffset,
    regions: [],
    overlaps: [],
    gaps: [],
    coverage: {
      imageBytes,
      scannedBytes,
      scanLimitBytes,
      parsedBytes,
      parseLimitBytes,
      parsedStartBytes: descriptorOffset,
      parsedEndBytesExclusive: descriptorOffset === null ? null : descriptorOffset + parsedBytes,
    },
    runtimeRegisterPosture: { state: 'unknown', reason: RUNTIME_REGISTER_REASON },
    findings: [],
  });

  if (!bytes) return unknown('Image bytes could not be read; SPI descriptor presence is unknown.');
  if (!Number.isSafeInteger(imageBytes) || imageBytes < bytes.byteLength) {
    return unknown('Image byte bounds are inconsistent; SPI descriptor parsing is unknown.');
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const candidates: number[] = [];
  for (let base = 0; base + DESCRIPTOR_SIGNATURE_OFFSET + 4 <= scannedBytes; base += 16) {
    if (view.getUint32(base + DESCRIPTOR_SIGNATURE_OFFSET, true) === DESCRIPTOR_SIGNATURE) candidates.push(base);
  }
  if (candidates.length === 0) {
    return unknown(
      `No aligned Intel flash descriptor signature was found in the ${scannedBytes}-byte scanned prefix; descriptor state is unknown.`,
    );
  }

  const parsed: CandidateResult[] = [];
  const failures: CandidateResult[] = [];
  for (const descriptorOffset of candidates) {
    const result = parseCandidate(view, bytes.byteLength, imageBytes, descriptorOffset, parseLimitBytes);
    (result.status === 'parsed' ? parsed : failures).push(result);
  }
  if (parsed.length > 1)
    return unknown('Multiple bounded Intel flash descriptor maps were found; selected map is unknown.');
  if (parsed.length === 0) {
    const failed = failures[0];
    return unknown(
      failed?.reason ?? 'Intel flash descriptor signature was present, but its map could not be parsed.',
      failed?.descriptorOffset ?? candidates[0] ?? null,
      failed?.parsedBytes ?? 0,
    );
  }

  const result = parsed[0];
  if (!result) return unknown('Intel flash descriptor map could not be selected.');
  const active = result.regions.filter((region) => region.enabled);
  const overlaps = findOverlaps(active);
  const gaps = findGaps(active);
  const coverage = {
    imageBytes,
    scannedBytes,
    scanLimitBytes,
    parsedBytes: result.parsedBytes,
    parseLimitBytes,
    parsedStartBytes: result.descriptorOffset,
    parsedEndBytesExclusive: result.descriptorOffset + result.parsedBytes,
  };
  const findings: SpiDescriptorFinding[] = [
    {
      kind: 'spi-descriptor-map',
      title: `SPI descriptor maps ${active.length} active flash region${active.length === 1 ? '' : 's'}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { descriptorOffset: result.descriptorOffset, regions: result.regions, coverage },
      rationale:
        'The Intel flash descriptor and FLREG defaults are present in the image bytes. This is static layout evidence; it does not prove the running device locks flash writes.',
    },
  ];
  if (overlaps.length > 0) {
    findings.push({
      kind: 'spi-descriptor-overlap',
      title: `SPI descriptor declares ${overlaps.length} overlapping flash-region pair${overlaps.length === 1 ? '' : 's'}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { overlaps },
      rationale:
        'The listed extents overlap in the static descriptor map. This records the declared layout and is not by itself proof of a write-protection failure.',
    });
  }
  const masterAccess = readHostMasterAccess(view, bytes.byteLength, result.descriptorOffset, parseLimitBytes);
  const meAssessment = assessHostMeWrite(masterAccess, result.regions);
  const hostMasterAccess: SpiHostMasterAccess = { ...masterAccess, meWriteReason: meAssessment.reason };
  if (hostMasterAccess.descriptorWrite === 'granted') {
    findings.push({
      kind: 'spi-descriptor-host-write',
      title: 'SPI descriptor grants the CPU/BIOS master write access to the flash descriptor region',
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { hostMasterAccess },
      rationale:
        'FLMSTR1 in the shipped descriptor sets the descriptor-region write bit under every chipsec FLMSTR layout, so ' +
        'software running as the host master could rewrite the descriptor and with it every region permission. This ' +
        'is the static default; the running device FRAP register (which a descriptor-override strap can change) was ' +
        'not read.',
    });
  }
  if (meAssessment.flag && meAssessment.meRegion) {
    findings.push({
      kind: 'spi-descriptor-host-me-write',
      title: 'SPI descriptor grants the CPU/BIOS master write access to the Intel ME region',
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { hostMasterAccess, meRegion: meAssessment.meRegion },
      rationale:
        'FLMSTR1 in the shipped descriptor sets the Intel ME region write bit under every chipsec FLMSTR layout, and ' +
        'the region map enables the ME region, so software running as the host master could write the ME firmware ' +
        'region. This is the static default; the running device FRAP register was not read, and a descriptor-override ' +
        'strap can change the runtime behavior.',
    });
  }
  if (gaps.length > 0) {
    findings.push({
      kind: 'spi-descriptor-gap',
      title: `SPI descriptor leaves ${gaps.length} gap${gaps.length === 1 ? '' : 's'} between active flash regions`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { gaps },
      rationale:
        'The listed extents leave unmapped address intervals between active descriptor regions. A gap does not imply a vulnerability or a protected range.',
    });
  }

  return {
    status: 'parsed',
    reason: `Parsed ${active.length} active flash region${active.length === 1 ? '' : 's'} from the static Intel descriptor map.`,
    descriptorOffset: result.descriptorOffset,
    regions: result.regions,
    overlaps,
    gaps,
    coverage,
    runtimeRegisterPosture: { state: 'unknown', reason: RUNTIME_REGISTER_REASON },
    findings,
    hostMasterAccess,
  };
}

/**
 * Pure: FLMSTR1 under every chipsec layout, and the descriptor-write verdict they agree on. Bounded by the same
 * parse limit as the region map; a master section inside the descriptor header, absent, or out of bounds is unknown.
 */
export function readHostMasterAccess(
  view: DataView,
  availableBytes: number,
  descriptorOffset: number,
  parseLimitBytes: number,
): SpiHostMasterAccess {
  const unknown = (reason: string, flmstr1Offset: number | null = null): SpiHostMasterAccess => ({
    status: 'unknown',
    reason,
    flmstr1Offset,
    rawValue: null,
    layouts: [],
    descriptorWrite: 'unknown',
    meWrite: 'unknown',
    meWriteReason: reason,
  });
  const map1Offset = descriptorOffset + FLASH_MAP1_OFFSET;
  if (map1Offset + 4 > availableBytes || map1Offset + 4 - descriptorOffset > parseLimitBytes) {
    return unknown('Descriptor FLMAP1 is truncated or exceeds the parse bound; master access is unknown.');
  }
  const masterBaseUnits = view.getUint32(map1Offset, true) & 0xff;
  if (masterBaseUnits === 0) return unknown('Descriptor FLMAP1 declares no master section; master access is unknown.');
  const flmstr1Offset = descriptorOffset + masterBaseUnits * 16;
  if (flmstr1Offset < descriptorOffset + 0x20) {
    return unknown('Descriptor FLMAP1 points the master section inside the descriptor header.', flmstr1Offset);
  }
  if (flmstr1Offset + 4 > availableBytes || flmstr1Offset + 4 - descriptorOffset > parseLimitBytes) {
    return unknown(
      'Descriptor FLMSTR1 is truncated or exceeds the parse bound; master access is unknown.',
      flmstr1Offset,
    );
  }
  const rawValue = view.getUint32(flmstr1Offset, true);
  const layouts = SPI_MASTER_LAYOUTS.map(({ layout, source, readShift, writeShift, width }): SpiMasterLayoutReading => {
    const mask = (1 << width) - 1;
    const readMask = (rawValue >>> readShift) & mask;
    const writeMask = (rawValue >>> writeShift) & mask;
    return {
      layout,
      source,
      readMask,
      writeMask,
      descriptorReadable: (readMask & DESCRIPTOR_REGION_BIT) !== 0,
      descriptorWritable: (writeMask & DESCRIPTOR_REGION_BIT) !== 0,
      meWritable: (writeMask & ME_REGION_BIT) !== 0,
    };
  });
  const writable = layouts.map((l) => l.descriptorWritable);
  const descriptorWrite = writable.every(Boolean) ? 'granted' : writable.some(Boolean) ? 'layout-dependent' : 'denied';
  const hex = `0x${rawValue.toString(16).padStart(8, '0')}`;
  const reason =
    descriptorWrite === 'layout-dependent'
      ? `FLMSTR1 ${hex} grants descriptor write under ${layouts
          .filter((l) => l.descriptorWritable)
          .map((l) => l.layout)
          .join(', ')} only; the image does not name its PCH generation, so the grant is undetermined.`
      : `FLMSTR1 ${hex} ${descriptorWrite === 'granted' ? 'grants' : 'denies'} the host master descriptor write under every chipsec layout.`;
  const meWritable = layouts.map((l) => l.meWritable === true);
  const meWrite = meWritable.every(Boolean) ? 'granted' : meWritable.some(Boolean) ? 'layout-dependent' : 'denied';
  const meWriteReason =
    meWrite === 'layout-dependent'
      ? `FLMSTR1 ${hex} grants Intel ME region write under ${layouts
          .filter((l) => l.meWritable)
          .map((l) => l.layout)
          .join(', ')} only; the image does not name its PCH generation, so the grant is undetermined.`
      : `FLMSTR1 ${hex} ${meWrite === 'granted' ? 'grants' : 'denies'} the host master Intel ME region write under every chipsec layout.`;
  return { status: 'read', reason, flmstr1Offset, rawValue, layouts, descriptorWrite, meWrite, meWriteReason };
}

/**
 * Pure: whether an agreed host-master ME write grant becomes a finding. It does only when the parsed region map
 * enables the Intel ME region; a grant over a disabled or undeclared region is kept in `hostMasterAccess` and the
 * returned reason says why it was not flagged. Anything short of an agreed grant is passed through unflagged.
 */
export function assessHostMeWrite(
  access: SpiHostMasterAccess,
  regions: SpiFlashRegion[],
): { flag: boolean; reason: string; meRegion: SpiFlashRegion | null } {
  const meRegion = regions.find((r) => r.index === ME_REGION_INDEX) ?? null;
  const reason = access.meWriteReason ?? access.reason;
  if (access.meWrite !== 'granted') return { flag: false, reason, meRegion };
  if (!meRegion) {
    return {
      flag: false,
      reason: `${reason} The region map declares no Intel ME region, so the grant covers no flash range and is not flagged.`,
      meRegion,
    };
  }
  if (!meRegion.enabled) {
    return {
      flag: false,
      reason: `${reason} The region map leaves the Intel ME region disabled (base above limit), so the grant covers no flash range and is not flagged.`,
      meRegion,
    };
  }
  return { flag: true, reason, meRegion };
}

function parseCandidate(
  view: DataView,
  availableBytes: number,
  imageBytes: number,
  descriptorOffset: number,
  parseLimitBytes: number,
): CandidateResult {
  const read = (offset: number): number | null => {
    if (offset < descriptorOffset || offset + 4 > availableBytes || offset + 4 - descriptorOffset > parseLimitBytes) {
      return null;
    }
    return view.getUint32(offset, true);
  };
  const map0Offset = descriptorOffset + FLASH_MAP0_OFFSET;
  const map0 = read(map0Offset);
  if (map0 === null) {
    return candidateUnknown(
      descriptorOffset,
      'Descriptor FLMAP0 is truncated or exceeds the parse bound.',
      map0Offset + 4,
    );
  }

  const regionBaseUnits = (map0 >>> REGION_BASE_SHIFT) & 0xff;
  const regionCount = ((map0 >>> REGION_COUNT_SHIFT) & REGION_COUNT_MASK) + 1;
  const regionMapOffset = descriptorOffset + regionBaseUnits * 16;
  const mapEnd = regionMapOffset + regionCount * REGION_REGISTER_BYTES;
  if (regionBaseUnits === 0 || regionMapOffset < descriptorOffset + 0x20) {
    return candidateUnknown(
      descriptorOffset,
      'Descriptor FLMAP0 points the region map inside the descriptor header.',
      map0Offset + 4,
    );
  }
  if (mapEnd - descriptorOffset > parseLimitBytes) {
    return candidateUnknown(
      descriptorOffset,
      'Descriptor region map exceeds the configured parse bound.',
      map0Offset + 4,
    );
  }
  if (mapEnd > availableBytes) {
    return candidateUnknown(
      descriptorOffset,
      'Descriptor region map is truncated in the available image bytes.',
      map0Offset + 4,
    );
  }

  const regions: SpiFlashRegion[] = [];
  for (let index = 0; index < regionCount; index++) {
    const offset = regionMapOffset + index * REGION_REGISTER_BYTES;
    const rawValue = read(offset);
    if (rawValue === null) {
      return candidateUnknown(
        descriptorOffset,
        'Descriptor region map is truncated or exceeds the parse bound.',
        offset + 4,
      );
    }
    const baseUnits = rawValue & 0x7fff;
    const limitUnits = (rawValue >>> 16) & 0x7fff;
    const enabled = baseUnits <= limitUnits;
    const startBytes = enabled ? baseUnits * REGION_ADDRESS_UNIT_BYTES : null;
    const endBytesExclusive = enabled ? (limitUnits + 1) * REGION_ADDRESS_UNIT_BYTES : null;
    const name = REGION_NAMES[index] ?? `Region ${index}`;
    if (enabled && endBytesExclusive !== null && endBytesExclusive > imageBytes) {
      return candidateUnknown(
        descriptorOffset,
        `${name} ends beyond the ${imageBytes}-byte source image; complete region bounds are unknown.`,
        offset + 4,
      );
    }
    regions.push({
      index,
      name,
      rawValue,
      enabled,
      baseBytes: baseUnits * REGION_ADDRESS_UNIT_BYTES,
      limitBytesInclusive: (limitUnits + 1) * REGION_ADDRESS_UNIT_BYTES - 1,
      startBytes,
      endBytesExclusive,
    });
  }
  return {
    status: 'parsed',
    reason: 'Descriptor map parsed.',
    descriptorOffset,
    parsedBytes: mapEnd - descriptorOffset,
    regions,
  };
}

function candidateUnknown(descriptorOffset: number, reason: string, parsedEndBytes: number): CandidateResult {
  return {
    status: 'unknown',
    reason,
    descriptorOffset,
    parsedBytes: Math.max(0, parsedEndBytes - descriptorOffset),
    regions: [],
  };
}

function findOverlaps(regions: SpiFlashRegion[]): SpiRangeRelationship[] {
  const overlaps: SpiRangeRelationship[] = [];
  const sorted = [...regions].sort((a, b) => (a.startBytes ?? 0) - (b.startBytes ?? 0));
  for (let i = 0; i < sorted.length; i++) {
    const first = sorted[i];
    if (!first || first.startBytes === null || first.endBytesExclusive === null) continue;
    for (let j = i + 1; j < sorted.length; j++) {
      const second = sorted[j];
      if (!second || second.startBytes === null || second.endBytesExclusive === null) continue;
      const startBytes = Math.max(first.startBytes, second.startBytes);
      const endBytesExclusive = Math.min(first.endBytesExclusive, second.endBytesExclusive);
      if (startBytes < endBytesExclusive) {
        overlaps.push({
          firstRegion: first.name,
          secondRegion: second.name,
          startBytes,
          endBytesExclusive,
        });
      }
    }
  }
  return overlaps;
}

function findGaps(regions: SpiFlashRegion[]): SpiRangeRelationship[] {
  const sorted = [...regions]
    .filter((region) => region.startBytes !== null && region.endBytesExclusive !== null)
    .sort((a, b) => (a.startBytes ?? 0) - (b.startBytes ?? 0));
  const gaps: SpiRangeRelationship[] = [];
  let furthest: SpiFlashRegion | null = null;
  for (const current of sorted) {
    if (current.startBytes === null || current.endBytesExclusive === null) continue;
    if (!furthest) {
      furthest = current;
      continue;
    }
    if (furthest.endBytesExclusive !== null && current.startBytes > furthest.endBytesExclusive) {
      gaps.push({
        firstRegion: furthest.name,
        secondRegion: current.name,
        startBytes: furthest.endBytesExclusive,
        endBytesExclusive: current.startBytes,
      });
    }
    if ((furthest.endBytesExclusive ?? 0) < current.endBytesExclusive) furthest = current;
  }
  return gaps;
}

function normalizeLimit(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : fallback;
}
