/**
 * Render a standalone SVG poster of an image's static analysis (structure ribbon + entropy curve + identity)
 * using the real @firmlab/core engine. Verifies the visualization data and gives a shareable picture without
 * running the web dev server.
 *
 *   node scripts/render-preview.mjs <firmware-file> [out.svg]
 */
import fs from 'node:fs';
import { analyzeBuffer } from '../packages/core/dist/index.js';

const input = process.argv[2] ?? 'samples/demo-router.bin';
const out = process.argv[3] ?? 'samples/demo-router.preview.svg';

const buf = fs.readFileSync(input);
const windowSize = Math.max(256, 1 << Math.ceil(Math.log2(Math.ceil(buf.length / 2048))));
const a = analyzeBuffer(buf, { entropy: { windowSize } });

const CAT = {
  filesystem: '#4db5ff',
  compression: '#f5b642',
  executable: '#7c5cff',
  bootloader: '#37d19a',
  kernel: '#ff9d5c',
  container: '#5cc8ff',
  crypto: '#ff5d6c',
  certificate: '#ff3b5b',
  image: '#b06cff',
  other: '#4a5468',
};
const W = 900;
const H = 420;
const PAD = 40;
const plotW = W - PAD * 2;

// Structure ribbon
let ribbon = '';
let x = PAD;
for (const seg of a.structure) {
  const w = ((seg.end - seg.start) / a.size) * plotW;
  ribbon += `<rect x="${x.toFixed(1)}" y="70" width="${Math.max(0.5, w).toFixed(1)}" height="46" fill="${CAT[seg.category] ?? CAT.other}" opacity="0.92"/>`;
  x += w;
}

// Entropy curve
const eTop = 150;
const eH = 200;
const pts = a.entropy.samples.map((s) => {
  const px = PAD + (s.offset / a.size) * plotW;
  const py = eTop + (1 - s.entropy / 8) * eH;
  return `${px.toFixed(1)},${py.toFixed(1)}`;
});
const curve = `M${pts.join(' L')}`;
const thresholdY = eTop + (1 - 7.2 / 8) * eH;

// High-entropy shading
let shade = '';
for (const r of a.entropy.highEntropyRegions) {
  const x1 = PAD + (r.start / a.size) * plotW;
  const x2 = PAD + (r.end / a.size) * plotW;
  shade += `<rect x="${x1.toFixed(1)}" y="${eTop}" width="${Math.max(1, x2 - x1).toFixed(1)}" height="${eH}" fill="#f5b642" opacity="0.09"/>`;
}

const legendCats = [...new Set(a.structure.map((s) => s.category))];
let legend = '';
legendCats.forEach((c, i) => {
  const lx = PAD + i * 130;
  legend += `<rect x="${lx}" y="${H - 26}" width="11" height="11" rx="2" fill="${CAT[c] ?? CAT.other}"/><text x="${lx + 17}" y="${H - 17}" font-size="12" fill="#8a93a6" font-family="monospace">${c}</text>`;
});

const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" font-family="ui-monospace,monospace">
  <rect width="${W}" height="${H}" fill="#0b0e14"/>
  <text x="${PAD}" y="32" font-size="16" fill="#d7dce6" font-weight="600">FirmLab · ${input.split('/').pop()}</text>
  <text x="${PAD}" y="52" font-size="12" fill="#8a93a6">${a.identity.firmwareClass} · ${a.identity.arch}/${a.identity.endianness} · fs: ${a.identity.filesystems.join(', ') || 'none'} · ${(a.size / 1024).toFixed(0)} KB · ${a.secrets.length} secrets</text>
  <text x="${PAD}" y="66" font-size="10" fill="#5b6577">STRUCTURE MAP</text>
  ${ribbon}
  <text x="${PAD}" y="146" font-size="10" fill="#5b6577">ENTROPY (0–8 bits/byte, dashed = 7.2 compressed/encrypted floor)</text>
  ${shade}
  <line x1="${PAD}" y1="${thresholdY}" x2="${W - PAD}" y2="${thresholdY}" stroke="#f5b642" stroke-dasharray="4 4" opacity="0.6"/>
  <path d="${curve}" fill="none" stroke="#4db5ff" stroke-width="1.2"/>
  ${legend}
</svg>`;

fs.writeFileSync(out, svg);
console.log(
  `wrote ${out}  (${a.structure.length} segments, ${a.entropy.samples.length} entropy samples, mean H=${a.entropy.mean.toFixed(2)})`,
);
