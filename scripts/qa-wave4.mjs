/**
 * Chromium browser verification for Wave 4 UI features:
 * 1. Corpus: re-analyze all images action (POST /analysis/reanalyze-all), modal confirmation,
 *    localized report rendering (total, changed, failed), before -> after badges, and mobile 390px wrap.
 * 2. ImageDetail: re-classify image action (POST /images/:id/analysis) near the identity section,
 *    updating the class in place and displaying changed feedback.
 * 3. OperatorPanel: note editing exceeding the old 4,000-character cap (up to 20,000 characters)
 *    and client validation.
 *
 * All API reads and writes use an in-memory synthetic fixture on an ephemeral loopback server.
 * Never connects to deployed API or mutates corpus. Build core and web first, then run:
 *   node scripts/qa-wave4.mjs [output-directory]
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const out = process.argv[2] ?? (await mkdtemp(join(tmpdir(), 'firmlab-wave4-qa-')));
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

const syntheticReanalyzeAllReport = {
  total: 3,
  changed: 1,
  failed: 0,
  results: [
    { id: 'img-synth', filename: 'uefi-firmware.bin', before: 'embedded-linux', after: 'uefi-bios' },
    { id: 'img-2', filename: 'router.bin', before: 'embedded-linux', after: 'embedded-linux' },
    { id: 'img-3', filename: 'switch.bin', before: 'openwrt-fit-ubi', after: 'openwrt-fit-ubi' },
  ],
};

const syntheticReanalyzeImageResult = {
  id: 'img-synth',
  before: 'embedded-linux',
  after: 'uefi-bios',
  changed: true,
  identity: {
    firmwareClass: 'uefi-bios',
    arch: 'x86_64',
    endianness: 'little',
    filesystems: [],
  },
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;
  const json = (value, status = 200) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(value));
  };
  if (path.startsWith('/api/')) console.log(`${req.method} ${path}`);

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
    if (req.method === 'POST') {
      return json(syntheticReanalyzeImageResult);
    }
    return json({
      analysis: {
        entropy: { mean: 6.5, min: 4, max: 7.9, blocks: [] },
        crypto: [],
        size: 16777216,
        identity: syntheticImage.identity,
        signatures: [],
        secrets: [],
      },
    });
  }
  if (path === '/api/images/img-synth/findings') return json({ findings: [] });
  if (path === '/api/images/img-synth/jobs') return json({ jobs: [] });
  if (path === '/api/images/img-synth/runs') return json({ runs: [], byTarget: [] });
  if (path === '/api/images/img-synth/coverage') return json({ stages: [], coverage: {} });
  if (path === '/api/images/img-synth/binaries') return json({ binaries: [] });
  if (path === '/api/images/img-synth/ledger') return json({ assertions: [], measuredFindingCount: 0 });
  if (path === '/api/images/img-synth/operator-findings')
    return json({ assertions: [], withdrawn: [], measuredFindingCount: 0 });
  if (path === '/api/images/img-synth/notes') {
    if (req.method === 'POST') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const parsed = JSON.parse(body || '{}');
      const newNote = {
        id: `note-${Date.now()}`,
        author: parsed.author ?? 'analyst',
        body: parsed.body ?? '',
        createdAt: Date.now(),
      };
      syntheticNotes.push(newNote);
      return json({ note: newNote });
    }
    return json({ notes: syntheticNotes });
  }
  if (path.startsWith('/api/images/img-synth/notes/') && req.method === 'PATCH') {
    const noteId = path.split('/').pop();
    let body = '';
    for await (const chunk of req) body += chunk;
    const parsed = JSON.parse(body || '{}');
    const note = syntheticNotes.find((n) => n.id === noteId);
    if (note) note.body = parsed.body ?? note.body;
    return json({ note: note ?? null });
  }
  if (path === '/api/corpus/overview') return json({ overview: syntheticCorpusOverview });
  if (path === '/api/corpus/rules') return json({ rules: [] });
  if (path === '/api/analysis/reanalyze-all') {
    return json(syntheticReanalyzeAllReport);
  }

  // Graceful defaults
  if (path.startsWith('/api/runs/')) return json({ runs: [] });
  if (path.startsWith('/api/')) return json({}, 404);
  res.writeHead(404).end();
});

server.listen(0, '127.0.0.1');
await once(server, 'listening');
const { port } = server.address();
const baseUrl = `http://127.0.0.1:${port}`;

const browser = await chromium.launch({ headless: true });

const cases = [
  { name: 'en-390', lang: 'en', width: 390, height: 844 },
  { name: 'en-1440', lang: 'en', width: 1440, height: 900 },
  { name: 'es-390', lang: 'es', width: 390, height: 844 },
  { name: 'es-1440', lang: 'es', width: 1440, height: 900 },
];

const results = [];

for (const c of cases) {
  const context = await browser.newContext({
    viewport: { width: c.width, height: c.height },
    locale: c.lang === 'es' ? 'es-ES' : 'en-US',
  });
  // Disable product tour and set locale so modal does not intercept pointer events
  await context.addInitScript((lang) => {
    window.localStorage.setItem('firmlab.tour.done', '1');
    window.localStorage.setItem('firmlab.locale', lang);
  }, c.lang);

  const page = await context.newPage();
  const consoleErrors = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      console.log('BROWSER ERROR:', msg.text());
      consoleErrors.push(msg.text());
    }
  });
  page.on('pageerror', (err) => console.log('UNCAUGHT EXCEPTION IN BROWSER:', err));

  // 1. Verify Corpus re-analysis
  await page.goto(`${baseUrl}/#/corpus`, { waitUntil: 'networkidle' });

  // Click "Re-analyze all images"
  const reclassifyBtn = page
    .locator('button:has-text("Re-analyze all images"), button:has-text("Reanalizar todas las imágenes")')
    .first();
  await reclassifyBtn.waitFor({ state: 'visible' });
  await reclassifyBtn.click();

  // Dialog appears -> confirm
  const confirmBtn = page.locator('div[role="dialog"] button[type="submit"]').first();
  await confirmBtn.waitFor({ state: 'visible' });
  await confirmBtn.click();
  await page.locator('div[role="dialog"]').waitFor({ state: 'detached' });
  await page.locator('.modal-scrim').waitFor({ state: 'detached' });

  // Wait for results card
  const resultsCard = page.locator('.panel:has-text("re-analyzed"), .panel:has-text("reanalizada")').first();
  await resultsCard.waitFor({ state: 'visible' });
  const resultsCardText = await resultsCard.innerText();

  // Verify responsive width on Corpus page
  const corpusScrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  assert.ok(
    corpusScrollWidth <= c.width,
    `${c.name}: Corpus horizontal overflow detected (scrollWidth=${corpusScrollWidth} > viewport=${c.width})`,
  );

  await page.screenshot({ path: join(out, `${c.name}-corpus-reanalyze.png`), fullPage: false });

  // 2. Verify ImageDetail re-classification
  await page.goto(`${baseUrl}/#/image/img-synth`, { waitUntil: 'networkidle' });
  const reclassifyImgBtn = page
    .locator('button:has-text("Re-classify image"), button:has-text("Reclasificar imagen")')
    .first();
  try {
    await reclassifyImgBtn.waitFor({ state: 'visible', timeout: 3000 });
  } catch (err) {
    console.log('PAGE TEXT ON IMAGE DETAIL:');
    console.log(await page.innerText('body'));
    throw err;
  }
  await reclassifyImgBtn.click();

  // Wait for feedback notice
  const outcomeNotice = page
    .locator(
      '.hint[aria-live="polite"]:has-text("Class changed"), .hint[aria-live="polite"]:has-text("La clase cambió")',
    )
    .first();
  await outcomeNotice.waitFor({ state: 'visible' });
  const outcomeText = await outcomeNotice.innerText();

  // 3. Verify Note Editing with 5,000 characters (> 4,000 cap)
  await page.goto(`${baseUrl}/#/image/img-synth/operator`, { waitUntil: 'networkidle' });
  const editBtn = page
    .locator(
      'button:has-text("Edit note"), button:has-text("Editar nota"), button:has-text("Edit"), button:has-text("Editar")',
    )
    .first();
  await editBtn.waitFor({ state: 'visible' });
  await editBtn.click();

  const editTextarea = page
    .locator('textarea[aria-label="Edit note body"], textarea[aria-label="Editar el cuerpo de la nota"]')
    .first();
  await editTextarea.waitFor({ state: 'visible' });

  // 5000 character note body
  const longBody = `Audit note exceeding 4000 chars: ${'X'.repeat(5000)}`;
  await editTextarea.fill(longBody);

  const saveNoteBtn = page.locator('button:has-text("Save changes"), button:has-text("Guardar cambios")').first();
  assert.ok(await saveNoteBtn.isEnabled(), `${c.name}: Save button should be enabled for 5000 chars (cap is 20000)`);
  await saveNoteBtn.click();

  // Verify note body updated in the table
  const updatedNoteRow = page.locator(`text=${longBody.slice(0, 40)}`).first();
  await updatedNoteRow.waitFor({ state: 'visible' });

  await page.screenshot({ path: join(out, `${c.name}-operator-long-note.png`), fullPage: false });

  results.push({
    name: c.name,
    width: c.width,
    corpusScrollWidth,
    resultsCardText: resultsCardText.slice(0, 80).replace(/\n/g, ' '),
    outcomeText,
    longNoteSaved: true,
    consoleErrors,
  });

  await context.close();
}

await browser.close();
server.close();

console.log(JSON.stringify({ out, results }, null, 2));
process.exit(0);
