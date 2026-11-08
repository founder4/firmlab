/**
 * Chromium browser validation for Renode RAM refusal and readable FreeRTOS wait-list editing.
 * Uses an ephemeral in-memory HTTP server and synthetic responses (no deployed server or live DB).
 * Uses emulated 320/390/768/1440 viewports in English and Spanish; mobile taps are synthesized Chromium input.
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const outDir = process.argv[2] ?? '/tmp/firmlab-rtos-qa';
await mkdir(outDir, { recursive: true });

const dist = fileURLToPath(new URL('../../dist/', import.meta.url));

const refusalReason = 'Renode not installed (opt-in layer).';
const ramCaptureResponse = {
  available: false,
  captured: false,
  reason: refusalReason,
  proofState: 'blocked_by_platform',
};

const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  const json = (val, status = 200) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(val));
  };

  const mockImage = {
    id: 'synth-rtos-01',
    filename: 'synth-freertos.bin',
    size: 65536,
    sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    uploadedAt: Date.now(),
    status: 'ready',
    identity: {
      firmwareClass: 'rtos',
      arch: 'arm',
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
  if (path === '/api/images/synth-rtos-01') {
    return json({ image: mockImage });
  }
  if (path === '/api/images/synth-rtos-01/analysis') {
    return json({
      analysis: {
        identity: { firmwareClass: 'rtos', arch: 'arm', endian: 'little' },
        entropy: { blocks: [] },
        findings: [],
      },
    });
  }
  if (path === '/api/images/synth-rtos-01/rtos/ram-capture') {
    return json({ result: ramCaptureResponse });
  }
  if (path === '/api/images/synth-rtos-01/rtos/tasks') {
    return json({ result: null });
  }
  if (path === '/api/images/synth-rtos-01/rtos/elf-symbols') {
    return json({ result: null });
  }
  if (path === '/api/images/synth-rtos-01/jobs') {
    return json({ jobs: [] });
  }
  if (path === '/api/images/synth-rtos-01/runs') {
    return json({ runs: [], total: 0 });
  }
  if (path === '/api/images/synth-rtos-01/findings') {
    return json({ findings: [] });
  }
  if (path === '/api/images/synth-rtos-01/emulation') {
    return json({ runs: [], recipes: [], available: false });
  }
  if (path === '/api/images/synth-rtos-01/updatepath') {
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
const testResults = [];

try {
  for (const locale of ['en', 'es']) {
    for (const viewport of [
      { width: 320, height: 844 },
      { width: 390, height: 844 },
      { width: 768, height: 1000 },
      { width: 1440, height: 1000 },
    ]) {
      const context = await browser.newContext({ viewport, hasTouch: viewport.width <= 390 });
      await context.addInitScript((lang) => {
        localStorage.setItem('firmlab.tour.done', '1');
        localStorage.setItem('firmlab.locale', lang);
      }, locale);

      const page = await context.newPage();
      const consoleErrors = [];
      const failedRequests = [];
      page.on('requestfailed', (req) =>
        failedRequests.push(`${req.method()} ${req.url()}: ${req.failure()?.errorText}`),
      );
      page.on('response', (response) => {
        if (response.status() >= 400) failedRequests.push(`${response.status()} ${response.url()}`);
      });
      page.on('console', (m) => {
        if (m.type() === 'error') consoleErrors.push(m.text());
      });
      page.on('pageerror', (e) => consoleErrors.push(e.message));

      await page.goto(`${base}/#/image/synth-rtos-01/bootloader`, { waitUntil: 'networkidle' });

      // Locate the section
      const sectionHeading =
        locale === 'en'
          ? 'RAM snapshot from Renode emulation (optional)'
          : 'Instantánea de RAM desde emulación Renode (opcional)';
      const section = page.getByRole('region', { name: sectionHeading });
      try {
        await section.waitFor({ timeout: 5000 });
      } catch (err) {
        console.error('Page URL:', page.url());
        console.error('Page text:', (await page.locator('body').innerText()).slice(0, 1000));
        console.error('Console errors:', consoleErrors);
        throw err;
      }

      // Verify the refusal reason is shown
      await section.getByText(refusalReason).waitFor({ timeout: 5000 });

      // Verify duplicate warning is suppressed:
      // The generic notAvailable warning is "Renode is not available on this bench." (en)
      // or "Renode no está disponible en este banco." (es)
      const notAvailableText =
        locale === 'en' ? 'Renode is not available on this bench.' : 'Renode no está disponible en este banco.';
      const notAvailableCount = await section.getByText(notAvailableText).count();
      assert.equal(
        notAvailableCount,
        0,
        `Duplicate warning '${notAvailableText}' should NOT be displayed when explicit refusal is present`,
      );

      // Verify banner count in section: exactly 1 warning banner
      const banners = await section.locator('.banner-warn').count();
      assert.equal(banners, 1, `Expected exactly 1 warning banner in section, found ${banners}`);

      // Exercise the new wait-list row, rather than only its initially empty fieldset. The
      // old four-column grid passed page-overflow checks while reducing each text input to 60px.
      const addWait = page.getByRole('button', {
        name: locale === 'en' ? 'Add wait list' : 'Añadir lista de espera',
        exact: true,
      });
      if (viewport.width <= 390) await addWait.tap();
      else await addWait.click();
      const waitName = page.getByRole('textbox', {
        name: locale === 'en' ? 'Object.member name 1' : 'Nombre objeto.miembro 1',
        exact: true,
      });
      await waitName.fill('fixtureQueue.xTasksWaitingToReceive');
      const waitRow = waitName.locator('..').locator('..');
      const waitAddress = waitRow.getByRole('textbox', {
        name: locale === 'en' ? 'List address 1' : 'Dirección de la lista 1',
        exact: true,
      });
      await waitAddress.fill('0x200001a0');
      const nameBounds = await waitName.boundingBox();
      const addressBounds = await waitAddress.boundingBox();
      assert.ok(nameBounds && nameBounds.width >= 200, 'Object.member field must remain readable');
      assert.ok(addressBounds && addressBounds.width >= 120, 'Full hexadecimal address must fit');
      await waitName.focus();
      await page.keyboard.press('Tab');
      assert.equal(await waitAddress.evaluate((el) => el === document.activeElement), true);
      await waitRow.screenshot({ path: join(outDir, `rtos-wait-row-${locale}-${viewport.width}.png`) });

      // Verify no horizontal overflow in panel
      const overflowCheck = await page.evaluate(() => {
        const bodyWidth = document.body.clientWidth;
        const scrollWidth = document.documentElement.scrollWidth;
        return {
          bodyWidth,
          scrollWidth,
          hasOverflow: scrollWidth > bodyWidth + 2,
          offenders: [...document.querySelectorAll('body *')]
            .filter((el) => {
              const rect = el.getBoundingClientRect();
              return rect.width > 0 && rect.right > bodyWidth + 2 && getComputedStyle(el).position !== 'fixed';
            })
            .filter((el) => el.closest('form'))
            .slice(0, 20)
            .map((el) => ({
              tag: el.tagName,
              className: el.className,
              width: el.getBoundingClientRect().width,
              text: el.textContent.slice(0, 100),
            })),
        };
      });
      if (overflowCheck.hasOverflow) {
        await writeFile(
          join(outDir, `overflow-${locale}-${viewport.width}.json`),
          JSON.stringify(overflowCheck, null, 2),
        );
        await page.screenshot({ path: join(outDir, `overflow-${locale}-${viewport.width}.png`), fullPage: true });
      }
      assert.ok(
        !overflowCheck.hasOverflow,
        `Layout overflow detected at viewport ${viewport.width}x${viewport.height}`,
      );

      // Check console errors
      assert.equal(consoleErrors.length, 0, `Console errors encountered: ${consoleErrors.join(', ')}`);
      assert.deepEqual(failedRequests, [], 'No failed fixture or asset requests');

      // Screenshot
      const shotFile = `rtos-ram-refusal-${locale}-${viewport.width}x${viewport.height}.png`;
      const shotPath = join(outDir, shotFile);
      await page.screenshot({ path: shotPath, fullPage: true });

      testResults.push({
        locale,
        viewport: `${viewport.width}x${viewport.height}`,
        shotPath,
        banners,
        waitNameWidth: nameBounds.width,
        waitAddressWidth: addressBounds.width,
        input: viewport.width <= 390 ? 'synthesized touch + keyboard' : 'mouse + keyboard',
        overflow: overflowCheck.hasOverflow,
        status: 'passed',
      });
      await context.close();
    }
  }
} finally {
  await browser.close();
  server.close();
}

console.log(JSON.stringify({ ok: true, results: testResults }, null, 2));
