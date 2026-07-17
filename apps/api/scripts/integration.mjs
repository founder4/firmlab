/**
 * End-to-end integration test — exercises the full tool-backed provider chain against a synthetic firmware in
 * the firmware image (needs binwalk, squashfs-tools, syft, grype, gitleaks, radare2). It builds a tiny rootfs,
 * packs it into a SquashFS "firmware", then runs extract → sbom → gitleaks → decompile and asserts each stage.
 *
 * Run (from the repo root):
 *   docker run --rm firmlab-firmware node apps/api/scripts/integration.mjs
 * (or with a fresh build mounted over the image's dist during development).
 *
 * Exits 0 on success, 1 on the first failed assertion.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HERE = new URL('.', import.meta.url);
const dist = (p) => new URL(`../dist/${p}`, HERE).href;

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-it-'));
process.env.FIRMLAB_DATA_DIR = path.join(work, 'data');

let failures = 0;
function check(name, cond) {
  if (cond) {
    console.log(`  ✓ ${name}`);
  } else {
    console.error(`  ✗ ${name}`);
    failures++;
  }
}

function buildSampleFirmware() {
  const rootfs = path.join(work, 'rootfs');
  for (const d of ['bin', 'sbin', 'etc', 'var/lib/dpkg']) fs.mkdirSync(path.join(rootfs, d), { recursive: true });
  fs.copyFileSync('/bin/ls', path.join(rootfs, 'bin', 'prog')); // a real ELF to triage
  fs.copyFileSync('/bin/cat', path.join(rootfs, 'sbin', 'svc'));
  fs.copyFileSync('/var/lib/dpkg/status', path.join(rootfs, 'var/lib/dpkg/status')); // real packages for syft
  fs.writeFileSync(path.join(rootfs, 'etc', 'passwd'), 'root:x:0:0:root:/root:/bin/sh\n');
  fs.writeFileSync(path.join(rootfs, 'etc', 'creds.env'), 'GH_TOKEN=ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\n');
  const img = path.join(work, 'sample.squashfs');
  execFileSync('mksquashfs', [rootfs, img, '-noappend', '-quiet'], { stdio: 'inherit' });
  return img;
}

async function main() {
  console.log('FirmLab integration test');
  const img = buildSampleFirmware();
  check('built SquashFS sample firmware', fs.existsSync(img));

  const { insertImage } = await import(dist('store.js'));
  const { runExtraction } = await import(dist('providers/extract.js'));
  const { runSbom } = await import(dist('providers/sbom.js'));
  const { runGitleaks } = await import(dist('providers/gitleaks.js'));
  const { runDecompile } = await import(dist('providers/decompile.js'));

  const id = 'itsample';
  insertImage({
    id,
    filename: 'sample.squashfs',
    path: img,
    size: fs.statSync(img).size,
    sha256: 'test',
    uploadedAt: Date.now(),
    status: 'ready',
    identityJson: JSON.stringify({
      firmwareClass: 'embedded-linux',
      arch: 'unknown',
      endianness: 'unknown',
      filesystems: ['squashfs'],
    }),
    analysisJson: null,
    tags: null,
  });

  const handle = { id, log: () => {} };

  console.log('extract:');
  const ex = await runExtraction(id, img, handle);
  check('rootfs recovered', Boolean(ex.rootfsPath));
  check('filesystem tree built', Boolean(ex.tree));
  check(
    'architecture detected from rootfs ELF',
    ex.detectedArch === 'arm64' || ex.detectedArch === 'x86_64' || Boolean(ex.detectedArch),
  );
  const rootfs = ex.rootfsPath;
  if (!rootfs) return finish();

  console.log('sbom:');
  const sbom = await runSbom(id, rootfs, handle);
  check('syft available + packages found', sbom.available && sbom.packageCount > 0);
  check('grype ran (counts present)', sbom.grypeAvailable && typeof sbom.counts.Critical === 'number');

  console.log('gitleaks:');
  const gl = await runGitleaks(rootfs, handle);
  check('gitleaks available', gl.available);
  check('planted token found', gl.findingCount >= 1);
  check(
    'match is redacted',
    gl.findings.every((f) => !f.match.includes('q7R8') || f.match.includes('…')),
  );

  console.log('decompile:');
  const dec = await runDecompile(rootfs, 'bin/prog', handle);
  check('radare2 triage available', dec.available);
  check('binary info parsed', Boolean(dec.info.arch));
  check('imports/strings extracted', dec.imports.length > 0 && dec.strings.length > 0);

  finish();
}

function finish() {
  fs.rmSync(work, { recursive: true, force: true });
  if (failures > 0) {
    console.error(`\nFAILED: ${failures} assertion(s).`);
    process.exit(1);
  }
  console.log('\nPASSED: full provider chain works end-to-end.');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
