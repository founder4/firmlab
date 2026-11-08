/**
 * Conservative MediaTek container subsets, derived from U-Boot's public host image generator (`tools/mtk_image.c`)
 * at 5508406582f6f7120dce0c4b3059819a41788db2: the 512-byte LK legacy header, and the generic NOR/SD/eMMC BootROM
 * device + BRLYT + GFH envelope with the default hdroffset=0. Each is a container boundary, never device attribution
 * or bootability. The LK header has no checksum; the BootROM envelope's SHA-256 field is located but not verified.
 * Either way complete declared bytes establish consistency only, not integrity or authenticity. Other LK layouts,
 * NAND/SNAND, nonzero hdroffset, MT7621 and every other producer are deliberately unsupported.
 */
export type MediaTekLkHeaderResult =
  | { valid: false; reason: string }
  | {
      valid: true;
      name: string;
      payloadSize: number;
      totalSize: number;
      loadAddress: number;
      mode: number;
    };

/**
 * Parse one header at a buffer-relative offset without modifying or reading outside the Uint8Array view.
 * Accept the generator's NUL-padded names (including empty/non-ASCII), erased reserved area, and nonzero
 * mode required by its source comment. Payload size excludes the header; zero is emitted by mkimage -s.
 * Extra bytes after the declared payload may belong to another embedded image and are not constrained.
 */
export function parseMediaTekLkHeader(buf: Uint8Array, offset = 0): MediaTekLkHeaderResult {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > buf.length) {
    return { valid: false, reason: 'LK header offset is outside this buffer' };
  }
  const remaining = buf.length - offset;
  if (remaining < 512) return { valid: false, reason: 'the complete 512-byte LK header is unavailable' };
  const view = new DataView(buf.buffer, buf.byteOffset + offset, 512);
  if (view.getUint32(0, true) !== 0x58881688) {
    return { valid: false, reason: 'little-endian LK_PART_MAGIC is absent' };
  }
  const payloadSize = view.getUint32(4, true);
  // Subtraction preserves the full unsigned size: do not wrap 512 + size through a 32-bit bitwise operation.
  if (payloadSize > remaining - 512) {
    return { valid: false, reason: `declared ${payloadSize}-byte LK payload exceeds the remaining bytes` };
  }
  const loadAddress = view.getUint32(40, true);
  if (loadAddress === 0) return { valid: false, reason: 'supported LK generator requires a nonzero load address' };
  const mode = view.getUint32(44, true);
  if (mode === 0) return { valid: false, reason: 'LK mode must be nonzero in the supported legacy subset' };
  let nameEnd = 8;
  while (nameEnd < 40 && view.getUint8(nameEnd) !== 0) nameEnd++;
  // snprintf into the generator's 32-byte lk_name actually permits 31 bytes, despite README's "32".
  if (nameEnd === 40) return { valid: false, reason: 'supported LK name requires a NUL within its 32 bytes' };
  for (let at = nameEnd; at < 40; at++) {
    if (view.getUint8(at) !== 0) return { valid: false, reason: 'LK name has nonzero bytes after its NUL' };
  }
  for (let at = 48; at < 512; at++) {
    if (view.getUint8(at) !== 0xff) {
      return { valid: false, reason: `LK reserved byte ${at} is not erased (unsupported header variant)` };
    }
  }
  return {
    valid: true,
    name: new TextDecoder('utf-8', { ignoreBOM: true }).decode(buf.subarray(offset + 8, offset + nameEnd)),
    payloadSize,
    totalSize: 512 + payloadSize,
    loadAddress,
    mode,
  };
}

/**
 * Boot-media names `mtk_image_set_gen_header` writes for the generic (non-NAND) BootROM path, paired with the BRLYT
 * type the same `hdr_media` value writes. The two are derived from one CLI choice, so a mismatch is not this producer.
 */
const BROM_GENERIC_MEDIA = [
  { media: 'nor', deviceName: 'SF_BOOT', brlytType: 0x10007 },
  { media: 'emmc', deviceName: 'EMMC_BOOT', brlytType: 0x10005 },
  { media: 'sdmmc', deviceName: 'SDMMC_BOOT', brlytType: 0x10008 },
] as const;
type BromGenericMedia = (typeof BROM_GENERIC_MEDIA)[number];

/** sizeof(union gen_boot_header), sizeof(struct gen_device_header), sizeof(struct gfh_header) at the pinned commit. */
const BROM_BOOT_SIZE = 0x200;
const BROM_DEVICE_SIZE = 0x600;
const BROM_GFH_SIZE = 0x300;
const BROM_HEADER_SIZE = BROM_DEVICE_SIZE + BROM_GFH_SIZE;
const SHA256_LEN = 32;
const GFH_MAGIC = 0x4d4d4d;
const BROM_CFG_DEFAULT = 0x190; // USBDL_AUTO_DETECT_DIS | USBDL_BY_KCOL0_TIMEOUT_EN | USBDL_BY_FLAG_TIMEOUT_EN
const BROM_CFG_ARM64 = 0x1190; // ... | JUMP_BL_ARM64_EN, written with jump_bl_arm64 = 0x64 when -n arm64=1

export type MediaTekBromHeaderResult =
  | { valid: false; reason: string }
  | {
      valid: true;
      /** The boot-media name the header declares. A producer setting, never the device's actual boot medium. */
      declaredMedia: BromGenericMedia['media'];
      deviceName: BromGenericMedia['deviceName'];
      brlytType: number;
      /** Device header + BRLYT + GFH: 0x900 in the only supported variant (hdroffset=0). */
      headerSize: number;
      payloadSize: number;
      /** Declared image size, header through digest field. Bytes beyond it are not constrained. */
      totalSize: number;
      /** GFH load_addr + jump_offset, the value the generator received as `-a` (as its own lister prints it). */
      loadAddress: number;
      gfhLoadAddress: number;
      /** BROM_CFG jump_bl_arm64 request as stored (`-n arm64=1`). Not an architecture attribution. */
      arm64JumpFlag: boolean;
      /** The SHA-256 field the generator wrote. Its presence and value are reported; it is NOT verified here. */
      digest: {
        algorithm: 'sha256';
        offset: number;
        length: number;
        coveredStart: number;
        coveredEnd: number;
        hex: string;
        verified: false;
      };
    };

function hex(value: number): string {
  return `0x${value.toString(16)}`;
}

/**
 * Write the GFH bytes `put_ghf_header` produces for the given variable fields, so everything else is compared
 * as an exact template: reserved/unused areas, record sizes, types and versions are all producer constants.
 */
function gfhTemplate(gfhLoadAddress: number, totalSize: number, arm64: boolean): Uint8Array {
  const out = new Uint8Array(BROM_GFH_SIZE);
  const dv = new DataView(out.buffer);
  const common = (at: number, size: number, type: number, version: number) => {
    dv.setUint32(at, (GFH_MAGIC | (version << 24)) >>> 0, true);
    dv.setUint16(at + 4, size, true);
    dv.setUint16(at + 6, type, true);
  };
  common(0, 56, 0, 1); // GFH_FILE_INFO
  out.set([0x46, 0x49, 0x4c, 0x45, 0x5f, 0x49, 0x4e, 0x46, 0x4f], 8); // "FILE_INFO", NUL-padded to 12
  dv.setUint32(20, 1, true);
  dv.setUint16(24, 1, true);
  out[26] = 5; // GFH_FLASH_TYPE_GEN
  out[27] = 1; // GFH_SIG_TYPE_SHA256
  dv.setUint32(28, gfhLoadAddress, true);
  dv.setUint32(32, totalSize - BROM_DEVICE_SIZE, true);
  dv.setUint32(36, totalSize, true);
  dv.setUint32(40, BROM_GFH_SIZE, true);
  dv.setUint32(44, SHA256_LEN, true);
  dv.setUint32(48, BROM_GFH_SIZE, true);
  dv.setUint32(52, 1, true);
  common(56, 12, 1, 1); // GFH_BL_INFO
  dv.setUint32(64, 1, true);
  common(68, 100, 7, 3); // GFH_BROM_CFG, version 3
  dv.setUint32(76, arm64 ? BROM_CFG_ARM64 : BROM_CFG_DEFAULT, true);
  if (arm64) out[153] = 0x64;
  dv.setUint32(156, 5000, true);
  common(168, 0x214, 3, 1); // GFH_BL_SEC_KEY (zero key area)
  common(700, 20, 2, 1); // GFH_ANTI_CLONE
  dv.setUint32(712, 0x10, true);
  dv.setUint32(716, 0x80, true);
  common(720, 48, 8, 1); // GFH_BROM_SEC_CFG
  dv.setUint32(728, 3, true);
  return out;
}

const GFH_RECORDS: readonly [number, string][] = [
  [0, 'FILE_INFO'],
  [56, 'BL_INFO'],
  [68, 'BROM_CFG'],
  [168, 'BL_SEC_KEY'],
  [700, 'ANTI_CLONE'],
  [720, 'BROM_SEC_CFG'],
];

/**
 * Parse one MediaTek BootROM generic (NOR/SD/eMMC) device + BRLYT + GFH envelope at a buffer-relative offset,
 * as U-Boot's `mtk_image` host generator writes it at 5508406582f6f7120dce0c4b3059819a41788db2 with the default
 * `hdroffset=0`. Reads stay inside the view; nothing is modified. NAND/SNAND headers, nonzero `hdroffset`, the
 * header-only `-s` output and any other producer are refused with a reason rather than guessed at.
 *
 * The 32-byte SHA-256 field over [0x600, total - 32) is located and reported but NOT verified: core has no
 * vetted synchronous digest, so a changed payload or digest still parses. A consistent result is structural
 * only — never integrity, authenticity, bootability, chip/device or runtime attribution.
 */
export function parseMediaTekBromHeader(buf: Uint8Array, offset = 0): MediaTekBromHeaderResult {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > buf.length) {
    return { valid: false, reason: 'BootROM header offset is outside this buffer' };
  }
  const remaining = buf.length - offset;
  if (remaining < BROM_BOOT_SIZE) {
    return { valid: false, reason: 'the complete 512-byte BootROM device header is unavailable' };
  }
  const dv = new DataView(buf.buffer, buf.byteOffset + offset, Math.min(remaining, BROM_HEADER_SIZE));
  const u8 = (at: number) => dv.getUint8(at);
  const u32 = (at: number) => dv.getUint32(at, true);

  // union gen_boot_header: snprintf("%s") into a 0xff-filled 12-byte name, then version 1 and size 0x200.
  const known = BROM_GENERIC_MEDIA.find((m) => {
    for (let i = 0; i < m.deviceName.length; i++) if (u8(i) !== m.deviceName.charCodeAt(i)) return false;
    return u8(m.deviceName.length) === 0;
  });
  if (!known) return { valid: false, reason: 'no SF_BOOT/EMMC_BOOT/SDMMC_BOOT generic device name' };
  for (let at = known.deviceName.length + 1; at < 12; at++) {
    if (u8(at) !== 0xff) return { valid: false, reason: `device name byte ${at} after NUL is not 0xff` };
  }
  if (u32(12) !== 1) return { valid: false, reason: `device header version ${hex(u32(12))} is not 1` };
  if (u32(16) !== BROM_BOOT_SIZE) return { valid: false, reason: `device header size ${hex(u32(16))} is not 0x200` };
  for (let at = 20; at < BROM_BOOT_SIZE; at++) {
    if (u8(at) !== 0xff) return { valid: false, reason: `device header byte ${hex(at)} is not erased (unsupported)` };
  }

  // struct brom_layout_header inside a 0x400-byte 0xff-filled pad.
  if (remaining < BROM_DEVICE_SIZE)
    return { valid: false, reason: 'the complete 0x400-byte BRLYT area is unavailable' };
  const b = BROM_BOOT_SIZE;
  const brlytName = [0x42, 0x52, 0x4c, 0x59, 0x54, 0, 0, 0]; // strncpy("BRLYT", 8) NUL-pads
  for (let i = 0; i < 8; i++) if (u8(b + i) !== brlytName[i]) return { valid: false, reason: 'BRLYT name is absent' };
  if (u32(b + 8) !== 1) return { valid: false, reason: `BRLYT version ${hex(u32(b + 8))} is not 1` };
  if (u32(b + 20) !== 0x42424242) return { valid: false, reason: 'BRLYT magic 0x42424242 is absent' };
  const brlytType = u32(b + 24);
  if (brlytType === 0x10002 || brlytType === 0x10009) {
    return { valid: false, reason: 'BRLYT type is NAND/SNAND, outside the supported generic subset' };
  }
  if (!BROM_GENERIC_MEDIA.some((m) => m.brlytType === brlytType)) {
    return { valid: false, reason: `BRLYT type ${hex(brlytType)} is not NOR/eMMC/SD` };
  }
  if (brlytType !== known.brlytType) {
    return { valid: false, reason: `BRLYT type ${hex(brlytType)} does not match device name ${known.deviceName}` };
  }
  const headerSize = u32(b + 12);
  if (headerSize !== BROM_DEVICE_SIZE) {
    return {
      valid: false,
      reason: `BRLYT header_size ${hex(headerSize)} is not 0x600: a nonzero hdroffset or another producer (unsupported)`,
    };
  }
  if (u32(b + 28) !== headerSize) return { valid: false, reason: 'BRLYT header_size copy disagrees' };
  const totalSize = u32(b + 16);
  if (u32(b + 32) !== totalSize) return { valid: false, reason: 'BRLYT total_size copy disagrees' };
  if (u32(b + 36) !== 0xffffffff) return { valid: false, reason: 'BRLYT unused word is not 0xffffffff' };
  for (let at = b + 40; at < BROM_DEVICE_SIZE; at++) {
    if (u8(at) !== 0xff) return { valid: false, reason: `BRLYT pad byte ${hex(at)} is not erased (unsupported)` };
  }
  // Sizes are compared as unsigned JS numbers: nothing below wraps through 32-bit arithmetic.
  if (totalSize === BROM_HEADER_SIZE) {
    return {
      valid: false,
      reason: 'declared size 0x900 is the header-only mkimage -s output, whose digest overwrites GFH (unsupported)',
    };
  }
  if (totalSize < BROM_HEADER_SIZE + 1 + SHA256_LEN) {
    return { valid: false, reason: `declared size ${hex(totalSize)} leaves no payload and SHA-256 field` };
  }

  if (remaining < BROM_HEADER_SIZE) return { valid: false, reason: 'the complete 0x300-byte GFH is unavailable' };
  const g = BROM_DEVICE_SIZE;
  const fileInfo = u32(g);
  if ((fileInfo & 0xffffff) !== GFH_MAGIC) return { valid: false, reason: 'GFH FILE_INFO magic is absent' };
  if (fileInfo >>> 24 !== 1) return { valid: false, reason: `GFH FILE_INFO version ${fileInfo >>> 24} unsupported` };
  if (u8(g + 26) === 2) return { valid: false, reason: 'GFH flash type is NAND, outside the generic subset' };
  if (u8(g + 27) === 0) {
    return { valid: false, reason: 'GFH declares GFH_SIG_TYPE_NONE, which this producer never writes (unsupported)' };
  }
  const gfhLoadAddress = u32(g + 28);
  if (gfhLoadAddress === 0xfffffd00) {
    return { valid: false, reason: 'GFH implies a load address of zero, which the producer refuses' };
  }
  if (u32(g + 36) !== totalSize) return { valid: false, reason: 'GFH max_size disagrees with BRLYT total_size' };
  if (u32(g + 32) !== totalSize - BROM_DEVICE_SIZE) {
    return { valid: false, reason: 'GFH total_size is not BRLYT total_size minus the 0x600 device header' };
  }
  const cfgBits = u32(g + 76);
  if (cfgBits !== BROM_CFG_DEFAULT && cfgBits !== BROM_CFG_ARM64) {
    return { valid: false, reason: `GFH BROM_CFG cfg_bits ${hex(cfgBits)} unsupported` };
  }
  const arm64 = cfgBits === BROM_CFG_ARM64;
  const template = gfhTemplate(gfhLoadAddress, totalSize, arm64);
  for (let at = 0; at < BROM_GFH_SIZE; at++) {
    if (u8(g + at) !== template[at]) {
      const record = GFH_RECORDS.filter(([start]) => start <= at).at(-1)?.[1] ?? 'GFH';
      return {
        valid: false,
        reason: `GFH ${record} byte ${hex(at)} differs from the producer's fixed value (unsupported variant)`,
      };
    }
  }
  if (totalSize > remaining) {
    return { valid: false, reason: `declared ${totalSize}-byte BootROM image exceeds the remaining bytes` };
  }
  const digestOffset = totalSize - SHA256_LEN;
  let digestHex = '';
  for (let at = digestOffset; at < totalSize; at++) digestHex += (buf[offset + at] ?? 0).toString(16).padStart(2, '0');
  return {
    valid: true,
    declaredMedia: known.media,
    deviceName: known.deviceName,
    brlytType,
    headerSize: BROM_HEADER_SIZE,
    payloadSize: totalSize - BROM_HEADER_SIZE - SHA256_LEN,
    totalSize,
    loadAddress: (gfhLoadAddress + BROM_GFH_SIZE) >>> 0,
    gfhLoadAddress,
    arm64JumpFlag: arm64,
    digest: {
      algorithm: 'sha256',
      offset: digestOffset,
      length: SHA256_LEN,
      coveredStart: BROM_DEVICE_SIZE,
      coveredEnd: digestOffset,
      hex: digestHex,
      verified: false,
    },
  };
}
