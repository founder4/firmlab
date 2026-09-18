/**
 * Loader-derived flash-key detection — the "the key is in the bootloader, not in flash" reflex, made mechanical.
 *
 * A firmware whose kernel/rootfs partitions are encrypted is routinely NOT a dead end: the decryption key is not
 * stored in flash but *derived at boot* by the bootloader from constants baked into the loader itself (a factory
 * seed + a salt, hashed and truncated to a key). Recovering it is pure static work on the loader — no hardware, no
 * device. The entropy gate already tells us a body is encrypted; what was missing is noticing that the loader
 * carries the recipe to undo it, which turns a `blocked_by_security` wall into a `needs_runtime_reproduction`
 * lead.
 *
 * This is detection, not derivation. It reports that the *ingredients* of a key-derivation routine are present in
 * the loader strings — a derivation/decrypt anchor, a crypto primitive, and short constant-like tokens that are
 * candidate seed/salt material — with their offsets. It NEVER computes, guesses or emits a key: the returned
 * `candidateConstants` are verbatim strings already in the image, and the caller (an operator or the agent) does
 * the actual derivation. Honest by construction: co-occurrence of a recipe, not a claim of what it produces.
 *
 * Pure and unit-tested. Bytes/strings in, structured data out; no I/O, no tool.
 */
import { scanStrings } from './strings.js';
import type { StringHit } from './types.js';

/** A verbatim string from the loader, kept with its offset so a caller can seek to it in the bytes. */
export interface LoaderStringHit {
  value: string;
  offset: number;
}

/** The recipe found in a bootloader: an anchor + a crypto primitive + candidate seed/salt constants. */
export interface LoaderKeyDerivation {
  /** Strings naming a key-derivation / partition-decrypt routine (symbol names, help text). */
  anchors: LoaderStringHit[];
  /** The crypto primitive token that decides the derivation (e.g. `sha256`, `AES-128`). */
  primitive: string;
  /** Every string the primitive was seen in, with offsets. */
  primitiveHits: LoaderStringHit[];
  /**
   * Short identifier-like tokens near the recipe that are candidate seed/salt material. Verbatim input strings —
   * the caller derives the key; this module never does.
   */
  candidateConstants: LoaderStringHit[];
  /** Candidates before the display cap. */
  candidateTotal: number;
  /** Candidates omitted by the display cap. */
  candidateDropped: number;
  /** `high` when a candidate constant was also found; `medium` when only the anchor + primitive co-occur. */
  confidence: 'high' | 'medium';
}

// A derivation/decrypt anchor: the loader naming what it does. `derive…key`, `flash_key`, `*_decrypt`, a decrypt
// of a partition/firmware/image, or the per-partition container magic `ENC1` (also appears inside decrypt help).
const ANCHOR_RE =
  /derive.{0,8}key|flash.?key|_decrypt\b|decrypt.{0,24}(partition|firmware|image|kernel|rootfs)|\bENC1\b/i;

// A crypto primitive whose presence in a loader that also decrypts a partition is the key-derivation tell.
const PRIMITIVE_RE = /\b(sha-?512|sha-?256|sha-?1|md5|aes(?:-?128|-?256|-?192)?|hmac|pbkdf2|scrypt)\b/i;

// How far (bytes) a candidate constant may sit from an anchor/primitive to count as "part of the recipe". Rodata
// string pools are scattered, so this is generous, not tight.
const PROXIMITY = 0x10000;
// Cap the returned candidate list, keeping the ones nearest the recipe. A real U-Boot rodata blob holds thousands
// of tokens; an unbounded, arrival-ordered list would bury the two constants that matter.
const CANDIDATE_CAP = 24;

/**
 * A vendor/seed/salt-shaped constant: length-bounded, only identifier characters (letters, digits, `-`, `_`), and
 * — the discriminator that matters on a real binary — a hyphen joining mixed-case tokens. That is the shape of
 * `NX820-boot` / `Tarlogic-HW-2026` and it rejects the flood of generic U-Boot vocabulary a proximity window pulls
 * in (`USER_26`, `LAN9115`, `AArch64`, `sd-uhs-sdr12`, …).
 *
 * ponytail: hyphen + mixed-case is a deliberately tight shape. It can miss a seed that is a single lowercase token
 * or a base64 salt; when it does, the finding still fires on the anchor + primitive (medium confidence, no
 * constants) — the lead lands, only the bonus hint degrades. Widen with a scored rank if a corpus shows misses.
 */
function looksLikeConstant(v: string): boolean {
  if (v.length < 6 || v.length > 40) return false;
  if (!/^[A-Za-z0-9_-]+$/.test(v)) return false;
  if (!v.includes('-')) return false;
  return /[a-z]/.test(v) && /[A-Z]/.test(v);
}

/** Least distance from `off` to any recipe offset — the rank key for candidate constants. */
function distanceToRecipe(off: number, recipeOffsets: number[]): number {
  let best = Number.POSITIVE_INFINITY;
  for (const r of recipeOffsets) best = Math.min(best, Math.abs(off - r));
  return best;
}

/**
 * Detect a loader-derived flash key from a bootloader's strings. Returns the recipe, or `null` when the anchor
 * and primitive do not co-occur (the gate that keeps this low-noise). Never derives or returns a key — only the
 * verbatim strings that a derivation would consume.
 */
export function detectLoaderDerivedKey(hits: StringHit[]): LoaderKeyDerivation | null {
  const allAnchors: LoaderStringHit[] = [];
  const allPrimitives: Array<{ hit: LoaderStringHit; primitive: string }> = [];

  for (const h of hits) {
    if (ANCHOR_RE.test(h.value)) allAnchors.push({ value: h.value, offset: h.offset });
    const pm = h.value.match(PRIMITIVE_RE);
    if (pm) {
      allPrimitives.push({ hit: { value: h.value, offset: h.offset }, primitive: pm[1] ?? pm[0] });
    }
  }

  // Global co-presence in a multi-megabyte loader is not co-occurrence: U-Boot commonly carries unrelated hash
  // self-tests and decrypt help. Pair only nearby strings, prefer a KDF/hash over the AES cipher name, then choose
  // the closest pair. The output remains a lead; proximity still does not prove data flow.
  const pairs: Array<{
    anchor: LoaderStringHit;
    primitiveHit: LoaderStringHit;
    primitive: string;
    distance: number;
    strength: number;
  }> = [];
  for (const anchor of allAnchors) {
    for (const candidate of allPrimitives) {
      const distance = Math.abs(anchor.offset - candidate.hit.offset);
      if (distance > PROXIMITY) continue;
      pairs.push({
        anchor,
        primitiveHit: candidate.hit,
        primitive: candidate.primitive,
        distance,
        strength: /^aes/i.test(candidate.primitive) ? 0 : 1,
      });
    }
  }
  if (pairs.length === 0) return null;
  pairs.sort(
    (a, b) =>
      b.strength - a.strength ||
      a.distance - b.distance ||
      a.anchor.offset - b.anchor.offset ||
      a.primitiveHit.offset - b.primitiveHit.offset,
  );
  const selected = pairs[0] as (typeof pairs)[number];
  const primitive = selected.primitive;
  const selectedPrimitive = primitive.toLowerCase();
  const primitiveHits = allPrimitives
    .filter((candidate) => candidate.primitive.toLowerCase() === selectedPrimitive)
    .map((candidate) => candidate.hit)
    .filter((hit) => allAnchors.some((anchor) => Math.abs(anchor.offset - hit.offset) <= PROXIMITY));
  const anchors = allAnchors.filter((anchor) =>
    primitiveHits.some((hit) => Math.abs(anchor.offset - hit.offset) <= PROXIMITY),
  );

  const recipeOffsets = [...anchors, ...primitiveHits].map((h) => h.offset);
  const seen = new Set<string>();
  const ranked: { hit: LoaderStringHit; dist: number }[] = [];
  for (const h of hits) {
    if (!looksLikeConstant(h.value)) continue;
    if (ANCHOR_RE.test(h.value) || PRIMITIVE_RE.test(h.value)) continue; // the recipe words are not constants
    const dist = distanceToRecipe(h.offset, recipeOffsets);
    if (dist > PROXIMITY) continue;
    if (seen.has(h.value)) continue;
    seen.add(h.value);
    ranked.push({ hit: { value: h.value, offset: h.offset }, dist });
  }
  // Nearest to the recipe first, then bounded — the two constants that matter must not be truncated by offset order.
  ranked.sort((a, b) => a.dist - b.dist);
  const candidateTotal = ranked.length;
  const candidateConstants = ranked.slice(0, CANDIDATE_CAP).map((r) => r.hit);
  const candidateDropped = candidateTotal - candidateConstants.length;

  return {
    anchors,
    primitive,
    primitiveHits,
    candidateConstants,
    candidateTotal,
    candidateDropped,
    confidence: candidateConstants.length > 0 ? 'high' : 'medium',
  };
}

/** Convenience: scan every string in the supplied bounded buffer and detect the recipe in one call. */
export function detectLoaderDerivedKeyInBytes(buf: Uint8Array): LoaderKeyDerivation | null {
  return detectLoaderDerivedKey(scanStrings(buf, { minLength: 4, maxStrings: Number.MAX_SAFE_INTEGER }).hits);
}
