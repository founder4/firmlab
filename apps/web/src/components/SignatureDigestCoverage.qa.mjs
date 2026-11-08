/**
 * Production Chromium QA with a GET-only in-memory loopback server; never starts the real API/store.
 * Usage: node apps/web/src/components/SignatureDigestCoverage.qa.mjs <external-output-dir> <inert-mkimage.bin>
 * The caller must supply an existing inert mkimage fixture, not real firmware. Analysis is produced offline
 * by the compiled API wrapper/core; all outer image metadata and compatibility mutations are synthetic.
 * Mobile input is synthesized Chromium touch. Native picker selection is explicitly NOT claimed.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { analyzeBuffer } from '../../../../packages/core/dist/index.js';
import { analyzeImageBuffer } from '../../../api/dist/analysis.js';

const [outDir, inertFixture] = process.argv.slice(2);
assert.ok(outDir && inertFixture, 'Supply the external artifact directory and an existing inert mkimage fixture');
await mkdir(outDir, { recursive: true });
const bytes = new Uint8Array(await readFile(inertFixture));
const full = analyzeImageBuffer(bytes);
assert.equal(full.signatureDigests.matched, 1, 'Expected one supported, matching inert mkimage envelope');
const repeated = new Uint8Array(bytes.length * 10);
for (let i = 0; i < 10; i++) repeated.set(bytes, i * bytes.length);
const mismatchBytes = bytes.slice();
mismatchBytes[0x900] ^= 1;
const legacy = structuredClone(full);
legacy.signatureDigests = undefined;
const malformed = structuredClone(full);
malformed.signatureDigests.completed = undefined;
malformed.signatureDigests.maxBytes = 'future-malformed-value';
const sha256 = (input) => createHash('sha256').update(input).digest();
const fixtures = {
  full,
  partial: analyzeImageBuffer(repeated),
  unavailable: analyzeBuffer(bytes),
  legacy,
  malformed,
  zero: analyzeImageBuffer(new Uint8Array(128)),
  mismatch: analyzeImageBuffer(mismatchBytes),
  byteBudget: analyzeBuffer(bytes, { signatureDigests: { sha256, maxBytes: 1024 } }),
  thrown: analyzeBuffer(bytes, {
    signatureDigests: {
      sha256: () => {
        throw new Error('Synthetic internal capability failure');
      },
    },
  }),
};
assert.equal(fixtures.partial.signatureDigests.skippedExecutionBudget, 2);
assert.equal(fixtures.unavailable.signatureDigests.unavailable, 1);
assert.equal(fixtures.mismatch.signatureDigests.mismatched, 1);
assert.equal(fixtures.byteBudget.signatureDigests.skippedByteBudget, 1);
assert.equal(fixtures.thrown.signatureDigests.bytesSubmitted, 1025);
assert.equal(fixtures.thrown.signatureDigests.bytesCompleted, 0);
await writeFile(join(outDir, 'fixture-analyses.json'), JSON.stringify(fixtures, null, 2));
await writeFile(
  join(outDir, 'fixture-provenance.json'),
  JSON.stringify(
    {
      input: inertFixture,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      size: bytes.length,
      fullPartialMismatchZero: 'Compiled API analyzeImageBuffer, offline, no HTTP or database',
      unavailableByteBudgetThrown: 'Compiled core analyzeBuffer with internal capability/limit fixtures',
      legacyMalformed: 'Explicitly synthetic persisted compatibility mutations of API-produced analysis',
      outerMetadata: 'Synthetic image id, filename, timestamps, hash label and empty related API responses',
      realFirmware: false,
      physicalDevice: false,
    },
    null,
    2,
  ),
);

const dist = fileURLToPath(new URL('../../dist/', import.meta.url));
let mode = 'partial';
const requests = [];
const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  requests.push({ method: req.method, path });
  if (req.method !== 'GET') {
    res.writeHead(405);
    res.end();
    return;
  }
  const json = (value) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(value));
  };
  const image = {
    id: 'synthetic-digest',
    filename: 'synthetic-inert-mkimage-ui.bin',
    size: fixtures[mode].size,
    sha256: 'synthetic-outer-metadata-no-real-firmware',
    uploadedAt: 0,
    status: 'ready',
    identity: fixtures[mode].identity,
    tags: ['synthetic UI fixture'],
  };
  if (path === '/health') return json({ status: 'ok', exposedToNetwork: false });
  if (path === '/api/images') return json({ images: [image] });
  if (path === '/api/images/synthetic-digest') return json({ image });
  if (path === '/api/images/synthetic-digest/analysis') return json({ analysis: fixtures[mode] });
  if (path === '/api/images/synthetic-digest/jobs') return json({ jobs: [] });
  if (path === '/api/images/synthetic-digest/runs') return json({ runs: [], total: 0 });
  if (path === '/api/images/synthetic-digest/findings') return json({ findings: [] });
  if (path === '/api/images/synthetic-digest/emulation') return json({ runs: [], recipes: [], available: false });
  if (path === '/api/images/synthetic-digest/updatepath') return json({ result: null });
  if (path === '/api/settings/flags') return json({ flags: [], appliesImmediately: true });
  if (path === '/api/agent/config') return json({ enabled: false });
  try {
    const file = path === '/' ? 'index.html' : decodeURIComponent(path.slice(1));
    assert.ok(!file.includes('..'));
    const data = await readFile(join(dist, file));
    res.setHeader(
      'Content-Type',
      { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html' }[extname(file)] ??
        'application/octet-stream',
    );
    res.end(data);
  } catch {
    res.statusCode = 404;
    res.end();
  }
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const results = [];
// Capture from document top without element auto-scrolling under the workbench's sticky header.
async function captureRegion(page, region, path) {
  await page.evaluate(() => window.scrollTo(0, 0));
  const clip = await region.boundingBox();
  assert.ok(clip && clip.y > 0);
  await page.screenshot({ path, fullPage: true, clip });
}

const metricLabels = {
  en: {
    listed: 'Listed supported hits',
    planned: 'Planned valid candidates',
    attempted: 'Attempts',
    completed: 'Completed digests',
    matched: 'Matches',
    mismatched: 'Mismatches',
    unavailable: 'Unavailable results',
    invalidCandidates: 'Invalid candidates',
    skipped: 'Budget skips',
    skippedExecutionBudget: 'Execution-budget skips',
    skippedByteBudget: 'Byte-budget skips',
    bytesPlanned: 'Bytes planned',
    bytesSubmitted: 'Bytes submitted',
    bytesCompleted: 'Bytes completed',
    maxExecutions: 'Applied execution limit',
    maxBytes: 'Applied byte limit',
  },
  es: {
    listed: 'Coincidencias compatibles listadas',
    planned: 'Candidatos válidos planificados',
    attempted: 'Intentos',
    completed: 'Resúmenes completados',
    matched: 'Coincidentes',
    mismatched: 'No coincidentes',
    unavailable: 'Resultados no disponibles',
    invalidCandidates: 'Candidatos inválidos',
    skipped: 'Omitidos por presupuesto',
    skippedExecutionBudget: 'Omitidos por tope de ejecuciones',
    skippedByteBudget: 'Omitidos por tope de bytes',
    bytesPlanned: 'Bytes planificados',
    bytesSubmitted: 'Bytes enviados al cálculo',
    bytesCompleted: 'Bytes completados',
    maxExecutions: 'Límite de ejecuciones aplicado',
    maxBytes: 'Límite de bytes aplicado',
  },
};

try {
  for (const locale of ['en', 'es']) {
    for (const theme of ['dark', 'light']) {
      for (const width of [1440, 320, 390]) {
        const context = await browser.newContext({ viewport: { width, height: 1000 }, hasTouch: width < 400 });
        await context.addInitScript(
          (settings) => {
            localStorage.setItem('firmlab.tour.done', '1');
            localStorage.setItem('firmlab.locale', settings.locale);
            localStorage.setItem('firmlab.theme', settings.theme);
          },
          { locale, theme },
        );
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', (e) => errors.push(e.message));
        page.on('console', (m) => {
          if (m.type() === 'error') errors.push(m.text());
        });
        page.on('response', (r) => {
          if (r.status() >= 400) errors.push(`${r.status()} ${r.url()}`);
        });
        page.on('requestfailed', (r) => errors.push(`${r.method()} ${r.url()}: ${r.failure()?.errorText}`));
        const scenarios = ['partial', 'full', 'unavailable', 'legacy'];
        if (width === 1440) scenarios.push('malformed', 'zero', 'mismatch', 'byteBudget', 'thrown');
        for (const scenario of scenarios) {
          mode = scenario;
          await page.goto(`${base}/#/image/synthetic-digest/structure`, { waitUntil: 'networkidle' });
          if (scenario !== 'partial') await page.reload({ waitUntil: 'networkidle' });
          const region = page.getByRole('region', {
            name: locale === 'en' ? 'Recorded SHA-256 coverage' : 'Cobertura SHA-256 registrada',
          });
          await region.waitFor({ state: 'visible' });
          assert.ok((await region.innerText()).includes('0x600'));
          assert.ok((await region.innerText()).includes('GFH/payload'));
          assert.equal(await region.getByRole('progressbar').count(), 0);
          const summary = region.locator('summary');
          let interactions = null;
          if (scenario === 'legacy') {
            assert.equal(await region.locator('dd').count(), 0);
            assert.ok((await region.innerText()).includes(locale === 'en' ? 'not recorded' : 'no registró'));
          } else {
            const c = fixtures[scenario].signatureDigests;
            for (const key of Object.keys(metricLabels[locale]).slice(0, 9)) {
              const row = region
                .locator('dl > div')
                .filter({ has: page.getByText(metricLabels[locale][key], { exact: true }) });
              const expected = c[key] === undefined ? (locale === 'en' ? 'Unknown' : 'Desconocido') : String(c[key]);
              assert.equal(await row.locator('dd').innerText(), expected);
            }
            await summary.focus();
            assert.equal(await summary.evaluate((el) => document.activeElement === el), true);
            await page.keyboard.press('Enter');
            assert.equal(await region.locator('details').getAttribute('open'), '');
            const summaryHeight = await summary.evaluate((el) => el.getBoundingClientRect().height);
            assert.ok(summaryHeight >= 44);
            for (const key of Object.keys(metricLabels[locale]).slice(9)) {
              const row = region
                .locator('dl > div')
                .filter({ has: page.getByText(metricLabels[locale][key], { exact: true }) });
              const known = typeof c[key] === 'number';
              assert.equal(
                await row.locator('dd').innerText(),
                known ? String(c[key]) : locale === 'en' ? 'Unknown' : 'Desconocido',
              );
            }
            if (scenario === 'partial') {
              await captureRegion(page, region, join(outDir, `${scenario}-open-${locale}-${theme}-${width}.png`));
            }
            await page.keyboard.press('Enter');
            assert.equal(await region.locator('details').getAttribute('open'), null);
            let syntheticTouch = null;
            if (width < 400) {
              await summary.tap();
              assert.equal(await region.locator('details').getAttribute('open'), '');
              await summary.tap();
              assert.equal(await region.locator('details').getAttribute('open'), null);
              syntheticTouch = 'native disclosure opened and closed by synthesized Chromium tap';
            }
            interactions = { keyboardDisclosureEnter: true, keyboardFocus: true, summaryHeight, syntheticTouch };
          }
          // Native inspector is unchanged. Focus is real; selectOption separately tests its change handler.
          const bands = page.locator('div[aria-hidden="true"] > div[title]');
          assert.equal(await bands.count(), fixtures[scenario].structure.length);
          for (const [index, segment] of fixtures[scenario].structure.entries()) {
            const percentage = await bands.nth(index).evaluate((el) => Number.parseFloat(el.style.width));
            assert.ok(Math.abs(percentage - ((segment.end - segment.start) / fixtures[scenario].size) * 100) < 0.0001);
          }
          const select = page.getByRole('combobox', {
            name: locale === 'en' ? 'Inspect a segment' : 'Inspeccionar un segmento',
          });
          if (await select.count()) {
            assert.ok((await select.boundingBox()).height >= 44);
            await select.focus();
            assert.equal(await select.evaluate((el) => document.activeElement === el), true);
            await select.selectOption('0');
            const details = page.getByRole('region', {
              name: locale === 'en' ? 'Segment details' : 'Detalles del segmento',
            });
            const digestIndex = fixtures[scenario].structure.findIndex((segment) => segment.meta?.digest !== undefined);
            if (digestIndex >= 0) {
              await select.selectOption(String(digestIndex));
              assert.ok((await details.innerText()).includes('digest='));
            } else {
              assert.ok((await details.innerText()).includes(fixtures[scenario].structure[0].label));
            }
          }
          const layout = await region.evaluate((el) => {
            const contrast = (node) => {
              const rgb = (s) =>
                s
                  .match(/[0-9.]+/g)
                  .slice(0, 3)
                  .map(Number);
              const lum = (v) =>
                v
                  .map((n) => (n / 255 <= 0.04045 ? n / 255 / 12.92 : ((n / 255 + 0.055) / 1.055) ** 2.4))
                  .reduce((sum, n, i) => sum + n * [0.2126, 0.7152, 0.0722][i], 0);
              let bgNode = node;
              while (getComputedStyle(bgNode).backgroundColor === 'rgba(0, 0, 0, 0)' && bgNode.parentElement)
                bgNode = bgNode.parentElement;
              const a = lum(rgb(getComputedStyle(node).color));
              const b = lum(rgb(getComputedStyle(bgNode).backgroundColor));
              return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
            };
            return {
              viewport: document.documentElement.clientWidth,
              scroll: document.documentElement.scrollWidth,
              regionWidth: el.getBoundingClientRect().width,
              proseMeasure: getComputedStyle(el).maxWidth,
              textContrast: Math.min(...[...el.querySelectorAll('p, dt, dd, h3, summary')].map(contrast)),
              overflow: [...el.querySelectorAll('*')]
                .filter((node) => node.scrollWidth > node.clientWidth + 2)
                .map((node) => node.tagName),
            };
          });
          assert.ok(layout.scroll <= layout.viewport + 2, JSON.stringify(layout));
          assert.deepEqual(layout.overflow, []);
          assert.ok(layout.textContrast >= 4.5, JSON.stringify(layout));
          assert.deepEqual(errors, []);
          await captureRegion(page, region, join(outDir, `${scenario}-${locale}-${theme}-${width}.png`));
          if (scenario === 'partial') {
            await page.evaluate(() => window.scrollTo(0, 0));
            await page.screenshot({ path: join(outDir, `page-${locale}-${theme}-${width}.png`), fullPage: true });
          }
          results.push({
            locale,
            theme,
            width,
            scenario,
            layout,
            interactions,
            errors,
            nativePickerSelection: 'not proven; selectOption checks change handler only',
          });
        }
        await context.close();
      }
    }
  }
} finally {
  await browser.close();
  server.close();
  await writeFile(join(outDir, 'requests.json'), JSON.stringify(requests, null, 2));
  await writeFile(join(outDir, 'results.json'), JSON.stringify(results, null, 2));
}
assert.ok(requests.every((r) => r.method === 'GET'));
console.log(
  JSON.stringify(
    {
      scenarios: results.length,
      requests: requests.length,
      errors: results.flatMap((r) => r.errors),
      minContrast: Math.min(...results.map((r) => r.layout.textContrast)),
    },
    null,
    2,
  ),
);
