/** Real built UI against a local API: table containment and keyboard scrolling at shipped viewports. GET only. */
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';

const base = process.env.FIRMLAB_UI ?? 'http://127.0.0.1:8899';
const out = process.argv[2] ?? '/tmp/firmlab-capabilities-qa';
await mkdir(out, { recursive: true });
const browser = await chromium.launch();
const results = [];
try {
  for (const [width, locale, theme] of [
    [320, 'en', 'light'],
    [390, 'es', 'dark'],
    [1440, 'en', 'dark'],
    [1440, 'es', 'light'],
  ]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 }, colorScheme: theme });
    const errors = [];
    await context.addInitScript(
      ({ locale, theme }) => {
        localStorage.setItem('firmlab.locale', locale);
        localStorage.setItem('firmlab.theme', theme);
        localStorage.setItem('firmlab.tour.done', '1');
      },
      { locale, theme },
    );
    await context.route('**/*', (route) => {
      const request = route.request();
      assert.equal(request.method(), 'GET');
      assert.equal(new URL(request.url()).origin, new URL(base).origin);
      return route.continue();
    });
    const page = await context.newPage();
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text());
    });
    page.on('response', (response) => {
      if (response.status() >= 400) errors.push(`${response.status()} ${new URL(response.url()).pathname}`);
    });
    await page.goto(`${base}/#/capabilities`, { waitUntil: 'networkidle' });
    await page.getByText('radare2', { exact: true }).waitFor();
    const geometry = await page.evaluate(() => ({
      width: innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    await page.screenshot({ path: `${out}/${width}-${locale}-${theme}.png`, fullPage: true });
    assert.ok(geometry.scrollWidth <= width + 1, `page overflow: ${JSON.stringify(geometry)}`);
    const scrolls = page.locator('.capability-table-scroll');
    assert.ok((await scrolls.count()) > 1);
    let keyboardScrolls = 0;
    for (const scroll of await scrolls.all()) {
      assert.equal(
        await page.getByRole('region', { name: await scroll.getAttribute('aria-label'), exact: true }).count(),
        1,
      );
      assert.ok(await scroll.getAttribute('aria-label'));
      const overflow = await scroll.evaluate((element) => element.scrollWidth > element.clientWidth + 1);
      if (!overflow) continue;
      await scroll.focus();
      await page.keyboard.press('ArrowRight');
      await page.waitForFunction((element) => element.scrollLeft > 0, await scroll.elementHandle());
      keyboardScrolls++;
    }
    if (width < 500) assert.ok(keyboardScrolls > 0, 'wide tables must stay reachable by keyboard');
    assert.deepEqual(errors, []);
    results.push({ width, locale, theme, geometry, keyboardScrolls, errors });
    await context.close();
  }
} finally {
  await browser.close();
  await writeFile(`${out}/results.json`, `${JSON.stringify(results, null, 2)}\n`);
}
console.log(JSON.stringify({ scenarios: results.length, result: 'passed', evidence: out }));
