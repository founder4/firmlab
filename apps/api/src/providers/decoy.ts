/**
 * Corrupt / decoy-image detector — turns a silent empty into an honest verdict.
 *
 * The Asus-Router.bin in the re-run is a HOLLOW image: it presents an intact TP-Link/Squashfs header, but 93% of
 * the file is 0x00 and the filesystem's data blocks are destroyed, so extraction recovers nothing. The app
 * returned "0 findings", which reads as "clean" — exactly the failure mode docs/AUTONOMOUS-WORKERS.md §4 warns
 * about. This pure detector fires when a filesystem was CLAIMED (a strong signature / a Linux class) but no rootfs
 * was recovered AND the image is mostly zeros: the honest conclusion is "payload unextractable — likely corrupt
 * or a decoy", not silence.
 *
 * Pure and unit-tested; the caller (opacidad's extract stage) passes the image bytes plus the two facts it already
 * knows (was a filesystem claimed, was a rootfs recovered).
 *
 * Closes docs/AUTONOMOUS-WORKERS.md §9 gap #6.
 */
import type { FindingDraft } from '../findings-normalize.js';

/** Zero fraction above this, with a claimed-but-unextractable filesystem, means the payload is hollow. */
const ZERO_FRACTION_DECOY = 0.8;
/** Sample stride cap — count zeros over at most this many samples so a huge image is cheap. */
const MAX_SAMPLES = 1_000_000;

export interface DecoyAssessment {
  isDecoy: boolean;
  zeroFraction: number;
  reason: string;
}

/** Pure: fraction of sampled bytes that are 0x00 (evenly strided across the whole buffer). */
export function zeroFraction(buf: Uint8Array): number {
  if (buf.length === 0) return 0;
  const stride = Math.max(1, Math.ceil(buf.length / MAX_SAMPLES));
  let zeros = 0;
  let samples = 0;
  for (let i = 0; i < buf.length; i += stride) {
    if (buf[i] === 0) zeros++;
    samples++;
  }
  return samples > 0 ? zeros / samples : 0;
}

/**
 * Pure: decide whether a firmware whose extraction produced no rootfs is a corrupt/decoy image. A hollow image is
 * one that CLAIMED a filesystem (a strong signature fired / W0 called it Linux) yet yielded no rootfs and is mostly
 * zeros — the header is intact but the payload is gone. When a rootfs WAS recovered, or nothing claimed a
 * filesystem (e.g. a legitimately headerless encrypted blob), this is not a decoy and returns isDecoy:false.
 */
export function assessDecoy(buf: Uint8Array, opts: { fsClaimed: boolean; rootfsRecovered: boolean }): DecoyAssessment {
  const zf = zeroFraction(buf);
  if (opts.rootfsRecovered || !opts.fsClaimed || zf < ZERO_FRACTION_DECOY) {
    return { isDecoy: false, zeroFraction: zf, reason: 'not a hollow image' };
  }
  return {
    isDecoy: true,
    zeroFraction: zf,
    reason: `${(zf * 100).toFixed(0)}% of the image is 0x00 with a claimed-but-unextractable filesystem`,
  };
}

/**
 * Pure: the finding for a detected corrupt/decoy image. MEDIUM / `static_confirmed` — the zero-density and the
 * failed extraction are facts about the bytes. The point is that "0 findings" here means "the payload is
 * destroyed", NOT "the firmware is clean".
 */
export function decoyFinding(a: DecoyAssessment): FindingDraft[] {
  if (!a.isDecoy) return [];
  return [
    {
      kind: 'corrupt-decoy',
      title: `Corrupt / decoy image: payload unextractable (${(a.zeroFraction * 100).toFixed(0)}% zeros)`,
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { zeroFraction: Number(a.zeroFraction.toFixed(4)) },
      rationale:
        'A filesystem header is present but no rootfs could be extracted and most of the image is 0x00 — the ' +
        'payload is hollow (a corrupted dump or a deliberate decoy). "0 findings" here means the content is ' +
        'destroyed, NOT that the firmware is clean. A static fact about the bytes.',
    },
  ];
}
