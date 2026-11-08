/**
 * The legacy Realtek `cvimg` 16-byte image header, bounded to the two signatures the SDK host tool writes for its
 * `linux` (`cs6c`) and `linux-ro` (`cr6c`) options under the configurations its own Makefile compiles. Derived
 * clean-room from the vendor-authored `cvimg.c`/`apmib.h` as mirrored (unofficially) at
 * cgoder/openwrt_rtk@d237e45ee480ee7e75c80a4c61e1a335a0a77755, with the consumer side corroborated by the
 * bootcode `rtk.h`/`eth_tftpd.c` mirrored at jameshilliard/WECB-VZ-GPL@adfad80b3144c788efb636d5acfcdd6ed91b3d79.
 * See docs/REALTEK-CVIMG-20261108.md for the field facts and what was NOT established.
 *
 * What a match means is deliberately small: these 16 bytes and the region they declare fit the producer's layout.
 * It is not a chip, device, vendor or architecture attribution — the same tool's `signature` option writes any four
 * characters, so `cs6c` names a producer option, not a platform — and the declared addresses are data, never a
 * claim that anything loads or boots there. The 16-bit checksum's location is reported; its value is NOT verified,
 * so complete declared bytes establish consistency only, never integrity or authenticity.
 *
 * Unsupported on purpose: `csys`/`csro` (the producer's default-config strings, which its Makefile never builds and
 * which collide with unrelated `CSYS`-family usage), `cs6b`/`cr6b`, the `root`/`boot`/`web`/`all` headers, the
 * `vmlinux`/`vmlinuxhdr` paths. `fix_chksum` history is not separately interpreted: compatible even-length
 * outputs can be indistinguishable from an ordinary envelope with trailing bytes. Checksum locations below
 * describe the ordinary-layout convention, not where every possible producer invocation wrote a checksum.
 */

/** sizeof(IMG_HEADER_T): signature[4] + three 32-bit words, `__attribute__((packed))` in apmib.h. */
const HEADER_SIZE = 16;
const CHECKSUM_WIDTH = 2;

/** apmib.h under CONFIG_RTL_8196C (and the other configs that select the same strings): option → signature. */
const SUPPORTED = [
  { signature: 'cs6c', producerOption: 'linux' },
  { signature: 'cr6c', producerOption: 'linux-ro' },
] as const;
type Supported = (typeof SUPPORTED)[number];

/** Named only so a refusal can say why; never matched by the scanner. */
const KNOWN_UNSUPPORTED = new Set(['csys', 'csro', 'cs6b', 'cr6b']);

export type RealtekCvimgHeaderResult =
  | { valid: false; reason: string }
  | {
      valid: true;
      signature: Supported['signature'];
      /** The cvimg CLI option that writes this signature. A producer setting, not a platform. */
      producerOption: Supported['producerOption'];
      /** Declared start address (`start-addr` argument). Data only: no load, memory-map or boot claim. */
      startAddress: number;
      /** Declared burn address (`burn-addr` argument). Data only: no flash-layout or device claim. */
      burnAddress: number;
      /** `len`: payload + optional pad byte + 2-byte checksum, as written by the producer. */
      declaredLength: number;
      /** Header plus declared region. Bytes beyond it are not constrained (they may be another image). */
      totalSize: number;
      /**
       * `len - 2`: the input bytes plus, for an odd input, one zero pad byte. The header cannot tell an odd input
       * from an even one ending in zero, so this is body length, never the exact original payload size.
       */
      bodyLength: number;
      /**
       * Where the ordinary producer path writes its 16-bit checksum (last two declared bytes) and the region the
       * consumer source sums. Compatible alternate producer histories cannot be distinguished from these bytes;
       * this is the ordinary-layout location, not proof of an actual checksum write. `verified` is always false.
       */
      checksum: { width: 2; offset: number; summedStart: number; summedEnd: number; verified: false };
    };

/**
 * Parse one header at a buffer-relative offset, reading only inside the Uint8Array view. Constant time: no payload
 * byte is read. Words are big-endian, the byte order `DWORD_SWAP` writes on a little-endian build host.
 */
export function parseRealtekCvimgHeader(buf: Uint8Array, offset = 0): RealtekCvimgHeaderResult {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > buf.length) {
    return { valid: false, reason: 'cvimg header offset is outside this buffer' };
  }
  const remaining = buf.length - offset;
  if (remaining < HEADER_SIZE) return { valid: false, reason: 'the complete 16-byte cvimg header is unavailable' };
  const view = new DataView(buf.buffer, buf.byteOffset + offset, HEADER_SIZE);
  const signature = String.fromCharCode(view.getUint8(0), view.getUint8(1), view.getUint8(2), view.getUint8(3));
  const supported = SUPPORTED.find((entry) => entry.signature === signature);
  if (!supported) {
    return {
      valid: false,
      reason: KNOWN_UNSUPPORTED.has(signature)
        ? `cvimg signature ${signature} is outside the supported cs6c/cr6c subset (unsupported)`
        : 'signature is not a supported cvimg linux/linux-ro value',
    };
  }
  const declaredLength = view.getUint32(12, false);
  // The producer sets len = size - 16 with size = input + 16 + 2, rounded up to even: at least 2, never odd.
  if (declaredLength < CHECKSUM_WIDTH) {
    return { valid: false, reason: `declared length ${declaredLength} cannot hold the 2-byte checksum` };
  }
  if (declaredLength % 2 !== 0) {
    return { valid: false, reason: `declared length ${declaredLength} is odd; the producer pads it to even` };
  }
  // Subtraction keeps the comparison in safe-integer range; never form 16 + len through 32-bit arithmetic.
  if (declaredLength > remaining - HEADER_SIZE) {
    return { valid: false, reason: `declared ${declaredLength}-byte cvimg region exceeds the remaining bytes` };
  }
  const totalSize = HEADER_SIZE + declaredLength;
  return {
    valid: true,
    signature: supported.signature,
    producerOption: supported.producerOption,
    startAddress: view.getUint32(4, false),
    burnAddress: view.getUint32(8, false),
    declaredLength,
    totalSize,
    bodyLength: declaredLength - CHECKSUM_WIDTH,
    checksum: {
      width: CHECKSUM_WIDTH,
      offset: totalSize - CHECKSUM_WIDTH,
      summedStart: HEADER_SIZE,
      summedEnd: totalSize,
      verified: false,
    },
  };
}
