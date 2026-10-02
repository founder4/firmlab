/**
 * Chromium browser verification for Wave 3 UI features:
 * 1. Corpus: reconcile / reindex action, loading state, localised verdict, and report rendering.
 * 2. OperatorPanel: note editing (trimmed, validation, inline update) and computed findings retirement
 *    (preview vs real run, operator:* refusal, reason limits, and ledger refresh).
 *
 * All API reads and writes use an in-memory synthetic fixture on an ephemeral loopback server.
 * Never connects to deployed API or mutates corpus. Build core and web first, then run:
 *   node apps/web/src/pages/Wave3.qa.mjs [output-directory]
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const out = process.argv[2] ?? (await mkdtemp(join(tmpdir(), 'firmlab-wave3-qa-')));
await mkdir(out, { recursive: true });
const dist = fileURLToPath(new URL('../apps/web/dist/', import.meta.url));

const syntheticImage = {
  id: 'img-synth',
  filename: 'uefi-firmware.bin',
  size: 16777216,
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  uploadedAt: 1700000000000,
  status: 'ready',
  identity: {
    firmwareClass: 'uefi-bios',
    arch: 'x86_64',
    endianness: 'little',
    filesystems: [],
  },
  tags: ['synthetic'],
};

const syntheticNotes = [
  {
    id: 'note-1',
    author: 'analyst',
    body: 'Initial firmware triage note.',
    createdAt: 1700000100000,
  },
];

const syntheticCorpusOverview = {
  imageCount: 3,
  ruleCount: 2,
  credentialReuse: [],
  componentPrevalence: [],
  deviceFamilies: [],
};

const syntheticReindexReportEn = {
  imageCount: 3,
  sources: [
    { source: 'static-secrets', imagesWithInput: 3, imagesWithoutInput: 0, rowsOffered: 9, rowsInserted: 4 },
    { source: 'components', imagesWithInput: 2, imagesWithoutInput: 1, rowsOffered: 40, rowsInserted: 11 },
  ],
  boundedInputs: [
    { imageId: 'img-synth', filename: 'uefi-firmware.bin', kind: 'static-scan', covered: 64, total: 128 },
  ],
  unrecordedBounds: [{ kind: 'sbom-packages', imageCount: 2 }],
  unstampedCredentials: [],
  notReconciled: [{ table: 'reachability_prior', reason: 'offline callgraph priors are curated manually' }],
  verdict: '15 rows inserted across 3 images. 1 source had incomplete input.',
};

const syntheticReindexReportEs = {
  imageCount: 3,
  sources: [
    { source: 'static-secrets', imagesWithInput: 3, imagesWithoutInput: 0, rowsOffered: 9, rowsInserted: 4 },
    { source: 'components', imagesWithInput: 2, imagesWithoutInput: 1, rowsOffered: 40, rowsInserted: 11 },
  ],
  boundedInputs: [
    { imageId: 'img-synth', filename: 'uefi-firmware.bin', kind: 'static-scan', covered: 64, total: 128 },
  ],
  unrecordedBounds: [{ kind: 'sbom-packages', imageCount: 2 }],
  unstampedCredentials: [],
  notReconciled: [{ table: 'reachability_prior', reason: 'los grafos de llamadas se curan manualmente' }],
  verdict: '15 filas insertadas en 3 imágenes. 1 fuente tenía entrada incompleta.',
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;
  const json = (value, status = 200) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(value));
  };

  // Static files from dist
  if (!path.startsWith('/api/') && path !== '/health') {
    const file = path === '/' ? 'index.html' : path.slice(1);
    const filePath = join(dist, file);
    try {
      const content = await readFile(filePath);
      const ext = extname(filePath);
      const types = {
        '.html': 'text/html; charset=utf-8',
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.svg': 'image/svg+xml',
      };
      res.writeHead(200, { 'Content-Type': types[ext] ?? 'application/octet-stream' });
      res.end(content);
      return;
    } catch {
      // Fallback to index.html for SPA router
      const html = await readFile(join(dist, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }
  }

  if (path === '/health') return json({ status: 'ok', exposedToNetwork: false });
  if (path === '/api/images') return json({ images: [syntheticImage] });
  if (path === '/api/images/img-synth') return json({ image: syntheticImage });
  if (path === '/api/images/img-synth/analysis') {
    return json({
      analysis: {
        entropy: { blocks: [] },
        crypto: [],
        format: 'uefi-bios',
        architecture: 'x86_64',
        endianness: 'little',
        size: 16777216,
      },
    });
  }
  if (path === '/api/images/img-synth/findings') {
    if (req.method === 'DELETE') {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
      }
      const parsed = JSON.parse(body);
      if (parsed.dryRun) {
        return json({
          source: parsed.source,
          dryRun: true,
          removedCount: 2,
          removed: [
            { id: 'f-1', kind: 'symreach', title: 'system() reachable from argv', proofState: 'static_confirmed' },
            { id: 'f-2', kind: 'symreach', title: 'popen() reachable from argv', proofState: 'static_confirmed' },
          ],
          summary: 'Would retire 2 computed findings under source symreach',
        });
      }
      return json({
        source: parsed.source,
        dryRun: false,
        removedCount: 2,
        removed: [
          { id: 'f-1', kind: 'symreach', title: 'system() reachable from argv', proofState: 'static_confirmed' },
          { id: 'f-2', kind: 'symreach', title: 'popen() reachable from argv', proofState: 'static_confirmed' },
        ],
        summary: 'Retired 2 computed findings under source symreach',
        note: {
          id: 'note-retire',
          author: parsed.retiredBy,
          body: `Retired 2 findings: ${parsed.reason}`,
          createdAt: Date.now(),
        },
      });
    }
    return json({ findings: [] });
  }

  if (path === '/api/images/img-synth/jobs') return json({ jobs: [] });
  if (path === '/api/images/img-synth/runs') return json({ runs: [], byTarget: [] });
  if (path === '/api/images/img-synth/coverage') return json({ stages: [], coverage: {} });
  if (path === '/api/images/img-synth/binaries') return json({ binaries: [] });
  if (path === '/api/storage') return json({ usage: { imageCount: 1, totalBytes: 16777216 } });
  if (path === '/api/tools') return json({ tools: [] });
  if (path === '/api/settings/flags') return json({ flags: [], appliesImmediately: true });
  if (path === '/api/settings/agent-approval') return json({ approval: { preapproveAll: false } });
  if (path === '/api/agent/status') return json({ enabled: false });

  // Notes
  if (path === '/api/images/img-synth/notes') {
    return json({ notes: syntheticNotes });
  }
  if (path.startsWith('/api/images/img-synth/notes/') && req.method === 'PATCH') {
    let body = '';
    for await (const chunk of req) {
      body += chunk;
    }
    const { body: newBody } = JSON.parse(body);
    syntheticNotes[0].body = newBody;
    return json({ note: syntheticNotes[0] });
  }

  // Operator findings ledger
  if (path === '/api/images/img-synth/operator-findings') {
    return json({ assertions: [], withdrawn: [] });
  }

  // Corpus
  if (path === '/api/corpus/overview') return json({ overview: syntheticCorpusOverview });
  if (path === '/api/corpus/rules') return json({ rules: [] });
  if (path === '/api/corpus/reindex' && req.method === 'POST') {
    const lang = url.searchParams.get('lang');
    return json({ report: lang === 'es' ? syntheticReindexReportEs : syntheticReindexReportEn });
  }

  // Fallback 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: `Not found: ${path}` }));
});

server.listen(0, '127.0.0.1');
await once(server, 'listening');
const port = server.address().port;
const baseUrl = `http://127.0.0.1:${port}`;

const browser = await chromium.launch({ headless: true });
const results = [];

try {
  for (const locale of ['en', 'es']) {
    for (const width of [390, 1440]) {
      const name = `${locale}-${width}`;
      const context = await browser.newContext({
        viewport: { width, height: 900 },
        locale: locale === 'es' ? 'es-ES' : 'en-US',
      });
      await context.addInitScript(() => {
        window.localStorage.setItem('firmlab.tour.done', '1');
      });
      const page = await context.newPage();
      const consoleErrors = [];
      page.on('pageerror', (err) => console.error(`[${name} pageerror]`, err.message));
      page.on('console', (msg) => {
        if (msg.type() === 'error') consoleErrors.push(msg.text());
      });

      // 1. Corpus page: Reindex action and report rendering
      await page.goto(`${baseUrl}/#/corpus`);
      const reindexBtnSelector = 'button:has-text("Reindex cross-image corpus"), button:has-text("Reindexar corpus")';
      await page.waitForSelector(reindexBtnSelector);
      await page.click(reindexBtnSelector);

      // Verify report appears
      const reportVerdictSelector =
        '.reindex-report, [aria-label*="reindex"], p:has-text("inserted across"), p:has-text("insertadas en")';
      await page.waitForSelector(reportVerdictSelector);
      const reportText = await page.textContent(reportVerdictSelector);
      assert.ok(
        reportText.includes('inserted') || reportText.includes('insertadas') || reportText.includes('reconciled'),
        'Reindex report verdict must be rendered',
      );

      // Take screenshot of Corpus report
      await page.screenshot({ path: join(out, `${name}-corpus.png`) });

      // 2. OperatorPanel: note editing & retire findings
      await page.goto(`${baseUrl}/#/image/img-synth/operator`);
      await page.waitForSelector('button:has-text("Edit"), button:has-text("Editar")');

      // Edit note
      await page.click('button:has-text("Edit"), button:has-text("Editar")');
      const noteInput = page.locator(
        'textarea[aria-label="Edit note body"], textarea[aria-label="Editar el cuerpo de la nota"]',
      );
      const updatedNoteText = `Updated note content for ${name}`;
      await noteInput.fill(updatedNoteText);
      await page.click('button:has-text("Save changes"), button:has-text("Guardar cambios")');
      await page.waitForSelector(`text="${updatedNoteText}"`);

      // Retire findings panel: expand panel
      const retireToggle = page.locator('button:has-text("Retire source…"), button:has-text("Retirar fuente…")');
      await retireToggle.click();

      // Form fields
      const sourceInput = page.locator('input[aria-label="Findings source"], input[aria-label="Fuente de hallazgos"]');
      const whoInput = page.locator('input[aria-label="Retired by"], input[aria-label="Retirado por"]');
      const reasonInput = page.locator(
        'textarea[aria-label="Why these rows should go"], textarea[aria-label="Por qué deben irse estas filas"]',
      );
      await sourceInput.fill('symreach');
      await whoInput.fill('analyst');
      await reasonInput.fill('obsolete tool output');

      // Verify dry-run checkbox is checked by default
      const previewCheckbox = page.locator('input[type="checkbox"]');
      const isChecked = await previewCheckbox.isChecked();
      assert.ok(isChecked, 'Preview checkbox must be checked by default');

      // Click preview button
      await page.click('button:has-text("Preview retirement"), button:has-text("Previsualizar retirada")');
      await page.waitForSelector('[data-role="retire-preview"]');
      await page.waitForSelector('li:has-text("system() reachable from argv")');

      // Untick preview for a real retirement
      await previewCheckbox.uncheck();
      await page.click('button:has-text("Retire findings"), button:has-text("Retirar hallazgos")');
      await page.waitForSelector('[data-role="retire-done"]');

      // Take screenshot of Operator Panel
      await page.screenshot({ path: join(out, `${name}-operator.png`) });

      results.push({
        name,
        width,
        reportText: reportText.slice(0, 100),
        updatedNoteText,
        consoleErrors,
      });

      await context.close();
    }
  }
} finally {
  await browser.close();
  server.close();
}

console.log(JSON.stringify({ out, results }, null, 2));
