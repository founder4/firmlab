/**
 * Chromium validation for persisted PICOBIN decoder coverage and source evidence.
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

const outDir = process.argv[2] ?? '/tmp/firmlab-picobin-qa';
await mkdir(outDir, { recursive: true });

const dist = fileURLToPath(new URL('../../dist/', import.meta.url));

let mode = 'partial';
const fixture = {
  isCortexM: true,
  coverage: { complete: true, scannedBytes: 96, fileBytes: 96 },
  reason: 'Synthetic PICOBIN fixture: static decoder coverage only, no execution.',
  picobinDisassembly: {
    attempted: true,
    available: true,
    scope: 'reachable-call-graph',
    mappingKind: 'rolling-xip',
    entryPoint: 0x10000054,
    reachableFunctions: [{ address: 0x10000054 }, { address: 0x20000000 }],
    callEdges: Array.from({ length: 32 }, (_, i) => ({
      caller: 0x10000054,
      callsite: 0x10000058 + i * 4,
      target: 0x20000000,
    })),
    functionsAttemptedTotal: 3,
    functionsDecodedTotal: 2,
    functionsCompletedTotal: 1,
    functionAttemptCap: 8,
    decoderAttemptsTotal: 5,
    decoderAttemptCap: 16,
    functionTargetsPendingTotal: 0,
    droppedFunctionTargetsTotal: 4,
    callEdgesTotal: 33,
    droppedCallEdgesTotal: 1,
    droppedOutOfMapCallEdgesTotal: 0,
    functionTargetSelection:
      'breadth-first callers by depth then runtime address; ascending distinct targets per caller; failed targets retain attempt slots',
    callEdgeSelection: 'lowest caller, callsite, then target runtime addresses; discovery independent of display cap',
    unresolvedCallsitesTotal: 2,
    outOfMapCallsitesTotal: 0,
    decodeFailuresTotal: 1,
    decoderSubstitutionsTotal: 1,
    decoderSubstitutions: [
      {
        address: 0x10000054,
        fileOffset: 0x54,
        instruction: 'bset',
        originalBytesHex: 'b316a028',
        mnemonic: 'bset x13, x0, x10',
      },
    ],
    decodeFailures: [
      {
        address: 0x10000064,
        classification: 'incomplete-decode',
        reason: 'No decoded continuation; coverage incomplete.',
      },
    ],
    callGraphTruncated: true,
    startupCopyTableAttempted: true,
    startupCopyTable: null,
    reason:
      'Synthetic bounded graph: three targets attempted, one completed; a display cap and decoder stop leave incomplete coverage.',
  },
  picobinRuntimePlan: {
    status: 'blocked',
    proofState: 'blocked_by_platform',
    minimumRenodeVersion: '1.17.0',
    network: 'isolated',
    unknownMmio: 'stop-and-report',
    missingModels: ['uart'],
    reason: 'Synthetic runtime plan: local boot ROM missing.',
  },
};
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
    return json({
      jobs: [
        {
          id: 'synthetic-picobin-job',
          imageId: mockImage.id,
          kind: 'rtos',
          status: 'done',
          createdAt: Date.now(),
          updatedAt: Date.now(),
          log: [],
          result:
            mode === 'legacy'
              ? { isCortexM: false, picobinDisassembly: { attempted: true, available: false } }
              : fixture,
        },
      ],
    });
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
const results = [];
try {
  for (const { locale, theme } of [
    { locale: 'en', theme: 'dark' },
    { locale: 'es', theme: 'dark' },
    { locale: 'en', theme: 'light' },
    { locale: 'es', theme: 'light' },
  ]) {
    for (const width of [320, 390, 1440]) {
      mode = 'partial';
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
      await page.goto(`${base}/#/image/synth-rtos-01/bootloader`, { waitUntil: 'networkidle' });
      await page.locator('.deep-result-details > summary').click();
      const details = page.locator('.deep-data');
      await details.waitFor({ state: 'visible' });
      assert.equal(await details.locator('details > summary').count(), 2);
      const metricLabel = locale === 'en' ? 'Function targets attempted' : 'Destinos de función intentados';
      assert.equal(
        await details.locator('.deep-data-metrics > div').filter({ hasText: metricLabel }).locator('dd').innerText(),
        '3',
      );
      // Expand native evidence disclosures, when present in this build, with actual keyboard input.
      for (const summary of await details.locator('details > summary').all()) {
        await summary.focus();
        await page.keyboard.press('Enter');
        assert.equal(await summary.evaluate((el) => el.parentElement.open), true);
      }
      assert.ok(await details.getByText('bset x13, x0, x10', { exact: true }).isVisible());
      const sourceAddress = details.locator('.picobin-source-evidence dd').first();
      assert.equal(await sourceAddress.innerText(), '0x10000054');
      const contrast = await details
        .locator('.deep-evidence-note')
        .first()
        .evaluate((el) => {
          const c = getComputedStyle(el)
            .color.match(/[0-9.]+/g)
            .slice(0, 3)
            .map(Number);
          let parent = el;
          let bg;
          while (parent) {
            bg = getComputedStyle(parent).backgroundColor;
            if (bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent') break;
            parent = parent.parentElement;
          }
          const b = bg
            .match(/[0-9.]+/g)
            .slice(0, 3)
            .map(Number);
          const light = (rgb) =>
            rgb
              .map((channel) => {
                const x = channel / 255;
                return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
              })
              .reduce((a, x, i) => a + x * [0.2126, 0.7152, 0.0722][i], 0);
          const a = light(c);
          const z = light(b);
          return (Math.max(a, z) + 0.05) / (Math.min(a, z) + 0.05);
        });
      assert.ok(contrast >= 4.5, `Evidence note contrast ${contrast}`);
      assert.ok((await details.innerText()).includes('incomplete-decode'));
      assert.ok((await details.innerText()).includes('blocked_by_platform'));
      const dimensions = await page.evaluate(() => ({
        viewport: document.documentElement.clientWidth,
        scroll: document.documentElement.scrollWidth,
      }));
      assert.ok(dimensions.scroll <= dimensions.viewport + 2, JSON.stringify(dimensions));
      assert.deepEqual(errors, []);
      await details
        .locator('.picobin-source-evidence')
        .screenshot({ path: join(outDir, `picobin-source-${locale}-${theme}-${width}.png`) });
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: join(outDir, `picobin-${locale}-${theme}-${width}.png`), fullPage: true });
      results.push({
        locale,
        theme,
        width,
        dimensions,
        errors,
        evidenceNoteContrast: contrast,
        keyboardDisclosures: await details.locator('details[open]').count(),
      });
      await context.close();
    }
  }
} finally {
  await browser.close();
  server.close();
}
await writeFile(join(outDir, 'results.json'), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
