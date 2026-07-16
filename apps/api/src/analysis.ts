/**
 * API-side wrapper around @firmlab/core static analysis. Picks an entropy window sized to the image so the
 * returned profile stays around a few thousand points regardless of image size (a 4 KB fixed window on a
 * 500 MB image would yield 128k points — too many to ship to a browser). Everything else is delegated to core.
 */
import { type StaticAnalysis, analyzeBuffer } from '@firmlab/core';

const TARGET_SAMPLES = 2048;
const MIN_WINDOW = 256;

/** Choose a non-overlapping window that yields ~TARGET_SAMPLES points for this image size. */
export function chooseEntropyWindow(size: number): number {
  const window = Math.ceil(size / TARGET_SAMPLES);
  return Math.max(MIN_WINDOW, nextPow2(window));
}

function nextPow2(n: number): number {
  let p = 1;
  while (p < n) p *= 2;
  return p;
}

export function analyzeImageBuffer(buf: Uint8Array): StaticAnalysis {
  const windowSize = chooseEntropyWindow(buf.length);
  return analyzeBuffer(buf, { entropy: { windowSize } });
}
