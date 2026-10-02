/**
 * Read the static Intel SPI flash descriptor map carried in an image. Descriptor FLREG entries describe the
 * image's region layout; they do not contain the live PRx or BIOS_CNTL register values needed to prove that the
 * running device protects flash writes. Missing, malformed, or truncated descriptor data therefore stays unknown.
 *
 * The master section is read for ONE question: does the descriptor grant the host CPU/BIOS master (`FLMSTR1`, always
 * the first master record) write access to the descriptor region itself? The master count matters once: chipsec
 * iterates `range(NM)`, so NM = 0 reads as no master record at all, and whether NM is zero-based cannot be settled
 * from the offline material — such a descriptor leaves master access unknown rather than reading FLMSTR1 anyway. The
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
 * disabled names no flash range, so it is recorded with its reason but is not a finding.
 *
 * The region map itself has the same two-definition problem. `common.xml` gives FLMAP0 an NR field (bits 24..26,
 * region count NR + 1) and 13-bit FLREG base/limit; the 12-bit-generation files above have NO NR field (chipsec then
 * reads 12 regions) and 15-bit FLREG fields. The region list keeps the NR-based count, but a region beyond NR + 1 is
 * not thereby undeclared: when the ME region falls outside it, FLREG2 is read anyway (inside the same bounds) and
 * the ME declaration is reported as layout-dependent. Likewise the ME region must be enabled under both FLREG widths
 * before a grant over it is flagged.
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
/** FLREG RB/RL widths: 13 bits in chipsec `common.xml`, 15 bits in `pch_1xx.xml` and the other 12-bit-gen files. */
const FLREG_WIDTHS = [
  { width: 13, source: 'chipsec cfg/8086/common.xml' },
  { width: 15, source: 'chipsec cfg/8086/pch_1xx.xml' },
] as const;
/** FLMAP1 NM (number of masters) starts at bit 8: 2 bits wide in `common.xml`, 3 bits in `pch_1xx.xml`. */
const MASTER_COUNT_SHIFT = 8;
const MASTER_COUNT_FIELDS = [
  { width: 2, source: 'chipsec cfg/8086/common.xml' },
  { width: 3, source: 'chipsec cfg/8086/pch_1xx.xml' },
] as const;

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
  /**
   * FLMAP1 NM under each chipsec definition, recorded whenever FLMAP1 points at a master section. Any 0 leaves
   * master access unknown (chipsec reads no master record). Optional forever: older results predate it.
   */
  masterCount?: { source: string; width: number; value: number }[];
}

/**
 * FLREG2 read when the ME region lies beyond the FLMAP0 NR count. Under `common.xml` NR makes the region undeclared;
 * the 12-bit-generation definitions have no NR field and read FLREG2 with 15-bit fields, as recorded here.
 */
export interface SpiMeRegionBeyondNr {
  /** NR + 1 under `common.xml`. */
  regionCountUnderNr: number;
  flreg2Offset: number;
  status: 'read' | 'unread';
  reason: string;
  /** Null when FLREG2 lies outside the available bytes or the parse bound. */
  rawValue: number | null;
  /** The 15-bit reading the definitions without NR apply; chipsec also treats 0xFFFFFFFF as not used. */
  source: string;
  enabled: boolean | null;
  startBytes: number | null;
  endBytesExclusive: number | null;
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
  /** Present when the ME region lies beyond the NR count. Optional forever: older results predate it. */
  meRegionBeyondNr?: SpiMeRegionBeyondNr;
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
  /** Image offset of FLREG0; set when the map parsed. */
  regionMapOffset?: number;
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
  const masterAccess = readHostMasterAccess(view, bytes.byteLength, result.descriptorOffset, parseLimitBytes);
  const meRegionBeyondNr =
    result.regionMapOffset !== undefined && result.regions.length <= ME_REGION_INDEX
      ? readMeRegionBeyondNr(
          view,
          bytes.byteLength,
          result.descriptorOffset,
          result.regionMapOffset,
          result.regions.length,
          parseLimitBytes,
        )
      : undefined;
  const meAssessment = assessHostMeWrite(masterAccess, result.regions, meRegionBeyondNr);
  const hostMasterAccess: SpiHostMasterAccess = { ...masterAccess, meWriteReason: meAssessment.reason };
  // Every word read counts as parsed: the region map, FLMSTR1 when read, and FLREG2 when read beyond NR.
  const parsedEndBytesExclusive = Math.max(
    result.descriptorOffset + result.parsedBytes,
    masterAccess.rawValue !== null && masterAccess.flmstr1Offset !== null ? masterAccess.flmstr1Offset + 4 : 0,
    meRegionBeyondNr?.rawValue != null ? meRegionBeyondNr.flreg2Offset + REGION_REGISTER_BYTES : 0,
  );
  const coverage = {
    imageBytes,
    scannedBytes,
    scanLimitBytes,
    parsedBytes: parsedEndBytesExclusive - result.descriptorOffset,
    parseLimitBytes,
    parsedStartBytes: result.descriptorOffset,
    parsedEndBytesExclusive,
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
    ...(meRegionBeyondNr ? { meRegionBeyondNr } : {}),
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
  const unknown = (
    reason: string,
    flmstr1Offset: number | null = null,
    masterCount?: SpiHostMasterAccess['masterCount'],
  ): SpiHostMasterAccess => ({
    status: 'unknown',
    reason,
    flmstr1Offset,
    rawValue: null,
    layouts: [],
    descriptorWrite: 'unknown',
    meWrite: 'unknown',
    meWriteReason: reason,
    ...(masterCount ? { masterCount } : {}),
  });
  const map1Offset = descriptorOffset + FLASH_MAP1_OFFSET;
  if (map1Offset + 4 > availableBytes || map1Offset + 4 - descriptorOffset > parseLimitBytes) {
    return unknown('Descriptor FLMAP1 is truncated or exceeds the parse bound; master access is unknown.');
  }
  const map1 = view.getUint32(map1Offset, true);
  const masterBaseUnits = map1 & 0xff;
  if (masterBaseUnits === 0) return unknown('Descriptor FLMAP1 declares no master section; master access is unknown.');
  const flmstr1Offset = descriptorOffset + masterBaseUnits * 16;
  if (flmstr1Offset < descriptorOffset + 0x20) {
    return unknown('Descriptor FLMAP1 points the master section inside the descriptor header.', flmstr1Offset);
  }
  const masterCount = MASTER_COUNT_FIELDS.map(({ width, source }) => ({
    source,
    width,
    value: (map1 >>> MASTER_COUNT_SHIFT) & ((1 << width) - 1),
  }));
  if (masterCount.some((field) => field.value === 0)) {
    const readings = masterCount
      .map((f) => `${f.value} under ${f.source} (bits ${MASTER_COUNT_SHIFT}..${MASTER_COUNT_SHIFT + f.width - 1})`)
      .join(' and ');
    return unknown(
      `Descriptor FLMAP1 NM reads ${readings}. chipsec iterates range(NM) and reads NM = 0 as no master records, and the offline material cannot establish whether NM is zero-based, so FLMSTR1 was not read and master access is unknown.`,
      flmstr1Offset,
      masterCount,
    );
  }
  if (flmstr1Offset + 4 > availableBytes || flmstr1Offset + 4 - descriptorOffset > parseLimitBytes) {
    return unknown(
      'Descriptor FLMSTR1 is truncated or exceeds the parse bound; master access is unknown.',
      flmstr1Offset,
      masterCount,
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
  return {
    status: 'read',
    reason,
    flmstr1Offset,
    rawValue,
    layouts,
    descriptorWrite,
    meWrite,
    meWriteReason,
    masterCount,
  };
}

/**
 * Pure: whether an agreed host-master ME write grant becomes a finding. It does only when the parsed region map
 * enables the Intel ME region under both chipsec FLREG widths. A grant over a region that is disabled, enabled under
 * only one width, or outside the NR count (declared under one FLMAP0 definition and not the other) is kept in
 * `hostMasterAccess`, and the returned reason says why it was not flagged. Anything short of an agreed grant is
 * passed through unflagged.
 */
export function assessHostMeWrite(
  access: SpiHostMasterAccess,
  regions: SpiFlashRegion[],
  beyondNr?: SpiMeRegionBeyondNr,
): { flag: boolean; reason: string; meRegion: SpiFlashRegion | null } {
  const meRegion = regions.find((r) => r.index === ME_REGION_INDEX) ?? null;
  const reason = access.meWriteReason ?? access.reason;
  if (access.meWrite !== 'granted') return { flag: false, reason, meRegion };
  if (!meRegion) {
    if (!beyondNr) {
      return {
        flag: false,
        reason: `${reason} The Intel ME region lies beyond the FLMAP0 NR region count and FLREG2 was not read, so whether the descriptor declares it is unknown and the grant is not flagged.`,
        meRegion,
      };
    }
    const count = `${beyondNr.regionCountUnderNr} region${beyondNr.regionCountUnderNr === 1 ? '' : 's'}`;
    const lead = `${reason} FLMAP0 NR covers ${count} under chipsec common.xml, which leaves the Intel ME region (index 2) outside it; the 12-bit-generation definitions (pch_1xx, pch_2xx, pch_c620, skl, kbl) have no NR field`;
    if (beyondNr.status !== 'read') {
      return {
        flag: false,
        reason: `${lead}, and ${beyondNr.reason} Whether the descriptor declares an ME region is unknown, so the grant is not flagged.`,
        meRegion,
      };
    }
    const reading =
      beyondNr.enabled && beyondNr.startBytes !== null && beyondNr.endBytesExclusive !== null
        ? `enabled at [${hexBytes(beyondNr.startBytes)}, ${hexBytes(beyondNr.endBytesExclusive)})`
        : 'disabled';
    return {
      flag: false,
      reason: `${lead}, and FLREG2 at ${hexBytes(beyondNr.flreg2Offset)} reads ${reading} there. The Intel ME declaration is therefore layout-dependent, so the grant is not flagged.`,
      meRegion,
    };
  }
  const widths = flregWidthReadings(meRegion.rawValue);
  if (widths.every((w) => !w.enabled)) {
    return {
      flag: false,
      reason: `${reason} The region map leaves the Intel ME region disabled (base above limit), so the grant covers no flash range and is not flagged.`,
      meRegion,
    };
  }
  if (!widths.every((w) => w.enabled)) {
    const describe = (enabled: boolean) =>
      widths
        .filter((w) => w.enabled === enabled)
        .map((w) => `${w.width}-bit (${w.source})`)
        .join(', ');
    return {
      flag: false,
      reason: `${reason} FLREG2 ${hexBytes(meRegion.rawValue, 8)} enables the Intel ME region under the ${describe(true)} FLREG width but not the ${describe(false)} one; the image does not name its PCH generation, so whether the grant covers a flash range is undetermined and it is not flagged.`,
      meRegion,
    };
  }
  return { flag: true, reason, meRegion };
}

/**
 * Pure: FLREG2 read for the ME region when it lies beyond the FLMAP0 NR count, inside the same parse bound and
 * available bytes as the region map. An out-of-bounds FLREG2 is `unread`, never "undeclared".
 */
export function readMeRegionBeyondNr(
  view: DataView,
  availableBytes: number,
  descriptorOffset: number,
  regionMapOffset: number,
  regionCountUnderNr: number,
  parseLimitBytes: number,
): SpiMeRegionBeyondNr {
  const flreg2Offset = regionMapOffset + ME_REGION_INDEX * REGION_REGISTER_BYTES;
  const source = FLREG_WIDTHS[1].source;
  const base = { regionCountUnderNr, flreg2Offset, source };
  if (
    flreg2Offset + REGION_REGISTER_BYTES > availableBytes ||
    flreg2Offset + REGION_REGISTER_BYTES - descriptorOffset > parseLimitBytes
  ) {
    return {
      ...base,
      status: 'unread',
      reason: `FLREG2 at ${hexBytes(flreg2Offset)} lies beyond the available bytes or the parse bound and was not read.`,
      rawValue: null,
      enabled: null,
      startBytes: null,
      endBytesExclusive: null,
    };
  }
  const rawValue = view.getUint32(flreg2Offset, true);
  const reading = flregWidthReadings(rawValue).find((w) => w.width === FLREG_WIDTHS[1].width);
  // chipsec marks 0xFFFFFFFF "(not used)" as well as base above limit.
  const enabled = rawValue !== 0xffffffff && reading?.enabled === true;
  return {
    ...base,
    status: 'read',
    reason: `FLREG2 ${hexBytes(rawValue, 8)} read with the 15-bit fields of the definitions that have no NR field.`,
    rawValue,
    enabled,
    startBytes: enabled && reading ? reading.baseUnits * REGION_ADDRESS_UNIT_BYTES : null,
    endBytesExclusive: enabled && reading ? (reading.limitUnits + 1) * REGION_ADDRESS_UNIT_BYTES : null,
  };
}

function flregWidthReadings(rawValue: number) {
  return FLREG_WIDTHS.map(({ width, source }) => {
    const mask = (1 << width) - 1;
    const baseUnits = rawValue & mask;
    const limitUnits = (rawValue >>> 16) & mask;
    return { width, source, baseUnits, limitUnits, enabled: baseUnits <= limitUnits };
  });
}

function hexBytes(value: number, pad = 0): string {
  return `0x${value.toString(16).padStart(pad, '0')}`;
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
    regionMapOffset,
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
