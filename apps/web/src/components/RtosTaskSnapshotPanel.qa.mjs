/**
 * Chromium browser validation for RtosTaskSnapshotPanel Renode RAM capture warning deduplication.
 * Uses an ephemeral in-memory HTTP server and synthetic responses (no deployed server or live DB).
 * Validates viewports 390x844 and 1440x1000 in English and Spanish.
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, readFile } from 'node:fs/promises';
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
      { width: 390, height: 844 },
      { width: 1440, height: 1000 },
    ]) {
      const context = await browser.newContext({ viewport });
      await context.addInitScript((lang) => {
        localStorage.setItem('firmlab.tour.done', '1');
        localStorage.setItem('firmlab.locale', lang);
      }, locale);

      const page = await context.newPage();
      const consoleErrors = [];
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

      // Verify no horizontal overflow in panel
      const overflowCheck = await page.evaluate(() => {
        const bodyWidth = document.body.clientWidth;
        const scrollWidth = document.documentElement.scrollWidth;
        return {
          bodyWidth,
          scrollWidth,
          hasOverflow: scrollWidth > bodyWidth + 2,
        };
      });
      assert.ok(
        !overflowCheck.hasOverflow,
        `Layout overflow detected at viewport ${viewport.width}x${viewport.height}`,
      );

      // Check console errors
      assert.equal(consoleErrors.length, 0, `Console errors encountered: ${consoleErrors.join(', ')}`);

      // Screenshot
      const shotFile = `rtos-ram-refusal-${locale}-${viewport.width}x${viewport.height}.png`;
      const shotPath = join(outDir, shotFile);
      await page.screenshot({ path: shotPath, fullPage: true });

      testResults.push({
        locale,
        viewport: `${viewport.width}x${viewport.height}`,
        shotPath,
        banners,
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
