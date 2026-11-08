/**
 * Chromium validation for native structure selection and recorded segment metadata.
 * Uses an ephemeral in-memory HTTP server and synthetic responses (no deployed server or live DB).
 * Uses emulated 320/390/1440 viewports in English and Spanish; mobile taps are synthesized Chromium input.
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const outDir = process.argv[2] ?? '/tmp/firmlab-structure-qa';
await mkdir(outDir, { recursive: true });

const dist = fileURLToPath(new URL('../../dist/', import.meta.url));

let mode = 'listed';
const listed = [
  {
    start: 0,
    end: 4096,
    label: 'Synthetic MediaTek envelope',
    category: 'container',
    confidence: 'high',
    meta: {
      digest: 'not_verified',
      payloadSize: 257,
      scope: 'Synthetic recorded metadata; no firmware or hash execution in this UI fixture.',
    },
  },
  {
    start: 8192,
    end: 8193,
    label: 'Narrow embedded boundary',
    category: 'bootloader',
    confidence: 'medium',
    meta: { digest: 'mismatch', coveredStart: 9728, note: 'long_recorded_value_'.repeat(16) },
  },
];
const analysis = () => ({
  size: 16384,
  identity: { firmwareClass: 'unknown', arch: 'unknown', endianness: 'unknown', filesystems: [] },
  entropy: { blocks: [] },
  signatures: [],
  secrets: [],
  structure:
    mode === 'empty'
      ? []
      : mode === 'legacy'
        ? [{ start: 0, end: 4096, label: 'Legacy recorded segment', category: 'container', confidence: 'high' }]
        : listed,
});
const requests = [];
const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  requests.push({ method: req.method, path });
  assert.equal(req.method, 'GET');
  const json = (val, status = 200) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(val));
  };

  const mockImage = {
    id: 'synthetic-structure',
    filename: 'synthetic-structure-ui.bin',
    size: 16384,
    sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    uploadedAt: Date.now(),
    status: 'ready',
    identity: {
      firmwareClass: 'unknown',
      arch: 'unknown',
      endian: 'little',
      confidence: 1.0,
      reasons: [],
    },
    tags: [],
  };

  if (path === '/health') return json({ status: 'ok', exposedToNetwork: false });
  if (path === '/api/images') {
    return json({ images: [mockImage] });
  }
  if (path === '/api/images/synthetic-structure') {
    return json({ image: mockImage });
  }
  if (path === '/api/images/synthetic-structure/analysis') {
    return json({ analysis: analysis() });
  }
  if (path === '/api/images/synthetic-structure/jobs') return json({ jobs: [] });
  if (path === '/api/images/synthetic-structure/runs') {
    return json({ runs: [], total: 0 });
  }
  if (path === '/api/images/synthetic-structure/findings') {
    return json({ findings: [] });
  }
  if (path === '/api/images/synthetic-structure/emulation') {
    return json({ runs: [], recipes: [], available: false });
  }
  if (path === '/api/images/synthetic-structure/updatepath') {
    return json({ result: null });
  }
  if (path === '/api/settings/flags') return json({ flags: [], appliesImmediately: true });
  if (path === '/api/agent/config') {
    return json({ enabled: false });
  }

  // Static files from dist
  try {
    const file = path === '/' ? 'index.html' : path.slice(1);
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
try {
  for (const { locale, theme } of [
    { locale: 'en', theme: 'dark' },
    { locale: 'es', theme: 'dark' },
    { locale: 'en', theme: 'light' },
    { locale: 'es', theme: 'light' },
  ]) {
    for (const width of [1440, 320, 390]) {
      mode = 'listed';
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
      page.on('pageerror', (error) => errors.push(error.message));
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(message.text());
      });
      page.on('response', (response) => {
        if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
      });
      page.on('requestfailed', (request) =>
        errors.push(`${request.method()} ${request.url()}: ${request.failure()?.errorText}`),
      );
      await page.goto(`${base}/#/image/synthetic-structure/structure`, { waitUntil: 'networkidle' });
      const label = locale === 'en' ? 'Inspect a segment' : 'Inspeccionar un segmento';
      const regionName = locale === 'en' ? 'Segment details' : 'Detalles del segmento';
      const select = page.getByRole('combobox', { name: label });
      const details = page.getByRole('region', { name: regionName });
      try {
        await select.waitFor({ state: 'visible', timeout: 10000 });
      } catch (e) {
        console.error(JSON.stringify({ errors, requests, body: await page.locator('body').innerText() }, null, 2));
        await page.screenshot({ path: join(outDir, 'diagnostic.png'), fullPage: true });
        throw e;
      }
      assert.equal(await select.locator('option').count(), 3);
      await select.focus();
      assert.equal(await select.evaluate((el) => document.activeElement === el), true);
      await page.keyboard.press('Tab');
      assert.equal(await select.evaluate((el) => document.activeElement === el), false);
      // macOS Chromium automation does not commit native menu keyboard choices, even on an isolated select.
      // Verify real keyboard focus independently, and use Playwright's explicit select action for change handling.
      await select.selectOption('0');
      assert.ok((await details.innerText()).includes('digest=not_verified'));
      await select.selectOption('1');
      assert.ok((await details.innerText()).includes('digest=mismatch'));
      assert.ok((await details.innerText()).includes('9728'));
      const controlHeight = await select.evaluate((el) => el.getBoundingClientRect().height);
      assert.ok(controlHeight >= 44, `select height ${controlHeight}`);
      const band = page.locator('div[aria-hidden="true"] > div[title]').first();
      await band.hover();
      assert.ok((await details.innerText()).includes('digest=not_verified'));
      await page.mouse.move(0, 0);
      assert.ok((await details.innerText()).includes('digest=mismatch'));
      let syntheticTouchFocused = null;
      if (width < 400) {
        await select.tap();
        syntheticTouchFocused = await select.evaluate((el) => document.activeElement === el);
        assert.equal(syntheticTouchFocused, true);
        await page.keyboard.press('Escape');
      }
      // This separately exercises the change handler; it is not a physical native picker test.
      await select.selectOption('1');
      assert.ok((await details.innerText()).includes('digest=mismatch'));
      const contrast = await select.evaluate((el) => {
        const rgb = (s) =>
          s
            .match(/[0-9.]+/g)
            .slice(0, 3)
            .map(Number);
        const light = (v) =>
          v
            .map((n) => {
              const x = n / 255;
              return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
            })
            .reduce((a, x, i) => a + x * [0.2126, 0.7152, 0.0722][i], 0);
        const style = getComputedStyle(el);
        const a = light(rgb(style.color));
        const b = light(rgb(style.backgroundColor));
        return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      });
      assert.ok(contrast >= 4.5, `select contrast ${contrast}`);
      const dimensions = await page.evaluate(() => ({
        viewport: document.documentElement.clientWidth,
        scroll: document.documentElement.scrollWidth,
      }));
      assert.ok(dimensions.scroll <= dimensions.viewport + 2, JSON.stringify(dimensions));
      assert.deepEqual(errors, []);
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: join(outDir, `structure-${locale}-${theme}-${width}.png`), fullPage: true });
      mode = 'legacy';
      await page.reload({ waitUntil: 'networkidle' });
      await select.selectOption('0');
      assert.ok((await details.innerText()).includes('Legacy recorded segment'));
      assert.ok(!/undefined|NaN|digest=|verified/.test(await details.innerText()));
      mode = 'empty';
      await page.reload({ waitUntil: 'networkidle' });
      assert.equal(await page.getByRole('combobox', { name: label }).count(), 0);
      assert.ok(
        (await details.innerText()).includes(
          locale === 'en' ? 'No segment details are listed.' : 'No hay detalles de segmentos listados.',
        ),
      );
      assert.deepEqual(errors, []);
      results.push({
        locale,
        theme,
        width,
        dimensions,
        errors,
        selectContrast: contrast,
        controlHeight,
        keyboardFocus: true,
        nativeKeyboardMenuSelection: 'not proven on this macOS Chromium automation',
        syntheticTouchFocused,
        legacy: true,
        empty: true,
      });
      await context.close();
    }
  }
} finally {
  await browser.close();
  server.close();
}
assert.ok(requests.every((r) => r.method === 'GET'));
await writeFile(join(outDir, 'requests.json'), JSON.stringify(requests, null, 2));
await writeFile(join(outDir, 'results.json'), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
