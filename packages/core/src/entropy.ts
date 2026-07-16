/**
 * Shannon-entropy profiling of a firmware image.
 *
 * Entropy is the single most useful tool-independent signal in firmware analysis: compressed and encrypted
 * data sit near 8.0 bits/byte, code and structured data sit lower, and long uniform runs (padding, erased
 * flash) sit near 0. A whole-image high-entropy plateau is the classic signature of an encrypted image that
 * must be decrypted before any extractor can touch it. This module is pure (Buffer in, numbers out) so it is
 * fast and fully unit-testable without any external tool.
 */
import type { EntropyProfile, EntropyRegion, EntropySample } from './types.js';

const LOG2 = Math.log(2);

/** Shannon entropy (bits/byte, 0..8) of a single byte window using a 256-bucket histogram. */
export function windowEntropy(buf: Uint8Array, start: number, end: number): number {
  const counts = new Uint32Array(256);
  let total = 0;
  for (let i = start; i < end; i++) {
    const byte = buf[i];
    if (byte === undefined) break;
    counts[byte] = (counts[byte] ?? 0) + 1;
    total++;
  }
  if (total === 0) return 0;

  let entropy = 0;
  for (let b = 0; b < 256; b++) {
    const c = counts[b] ?? 0;
    if (c === 0) continue;
    const p = c / total;
    entropy -= p * (Math.log(p) / LOG2);
  }
  // Clamp tiny floating error so a perfectly uniform window reads as exactly 8.0.
  return Math.min(8, Math.max(0, entropy));
}

export interface EntropyOptions {
  /** Bytes per window. Larger = smoother, coarser. Default 4096. */
  windowSize?: number;
  /** Distance between window starts. Defaults to windowSize (non-overlapping). */
  step?: number;
  /** Windows at or above this mean entropy are treated as compressed/encrypted. Default 7.2. */
  highThreshold?: number;
}

/**
 * Build a full entropy profile: one sample per window, aggregate stats, and contiguous high-entropy regions.
 * Non-overlapping windows by default so the sample count stays bounded for large images.
 */
export function computeEntropyProfile(buf: Uint8Array, options: EntropyOptions = {}): EntropyProfile {
  const windowSize = Math.max(1, options.windowSize ?? 4096);
  const step = Math.max(1, options.step ?? windowSize);
  const highThreshold = options.highThreshold ?? 7.2;

  const samples: EntropySample[] = [];
  let sum = 0;
  let max = 0;
  let min = 8;

  for (let offset = 0; offset < buf.length; offset += step) {
    const end = Math.min(offset + windowSize, buf.length);
    const entropy = windowEntropy(buf, offset, end);
    samples.push({ offset, entropy });
    sum += entropy;
    if (entropy > max) max = entropy;
    if (entropy < min) min = entropy;
  }

  if (samples.length === 0) {
    return {
      windowSize,
      step,
      samples: [],
      mean: 0,
      max: 0,
      min: 0,
      highEntropyRegions: [],
      likelyEncrypted: false,
      likelyCompressed: false,
    };
  }

  const mean = sum / samples.length;
  const highEntropyRegions = findHighEntropyRegions(samples, step, windowSize, highThreshold);

  // Heuristic: a single high-entropy region covering most of the image with a very high floor is the
  // encrypted-whole-image signature. Multiple smaller high-entropy regions are the normal signature of a
  // compressed filesystem/kernel embedded among lower-entropy structure.
  const coveredBytes = highEntropyRegions.reduce((acc, r) => acc + (r.end - r.start), 0);
  const coverage = buf.length > 0 ? coveredBytes / buf.length : 0;
  const likelyEncrypted = coverage > 0.85 && mean > 7.4 && min > 6.5;
  const likelyCompressed = !likelyEncrypted && highEntropyRegions.length > 0;

  return {
    windowSize,
    step,
    samples,
    mean,
    max,
    min,
    highEntropyRegions,
    likelyEncrypted,
    likelyCompressed,
  };
}

/** Merge consecutive above-threshold windows into contiguous regions with their mean entropy. */
function findHighEntropyRegions(
  samples: EntropySample[],
  step: number,
  windowSize: number,
  threshold: number,
): EntropyRegion[] {
  const regions: EntropyRegion[] = [];
  let runStart: number | null = null;
  let runSum = 0;
  let runCount = 0;
  let lastOffset = 0;

  function close(endOffset: number): void {
    if (runStart === null || runCount === 0) return;
    regions.push({
      start: runStart,
      end: endOffset,
      meanEntropy: runSum / runCount,
    });
    runStart = null;
    runSum = 0;
    runCount = 0;
  }

  for (const sample of samples) {
    if (sample.entropy >= threshold) {
      if (runStart === null) runStart = sample.offset;
      runSum += sample.entropy;
      runCount++;
    } else {
      close(lastOffset + windowSize);
    }
    lastOffset = sample.offset;
  }
  close(lastOffset + windowSize);

  // Drop trivially short regions (single small window) that are just noise.
  return regions.filter((r) => r.end - r.start >= windowSize);
}
