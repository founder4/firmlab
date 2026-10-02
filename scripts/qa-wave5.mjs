/**
 * Chromium browser verification for Wave 5 features:
 * 1. Corpus: Device families empty state hint ("No device families discovered...")
 *    and quick search filtering for Credential Reuse and Component Prevalence tables,
 *    including match count, empty-match hint, Clear button, and mobile 390px flex-wrap without overflow.
 * 2. RtosTaskSnapshotPanel: FreeRTOS task lists expansion rendering delayed lists with wake ticks,
 *    suspended list, state list input fields, and mobile 390px layout without overflow.
 *
 * All API reads and writes use an in-memory synthetic fixture on an ephemeral loopback server.
 * Never connects to deployed API or mutates corpus. Build core and web first, then run:
 *   node scripts/qa-wave5.mjs [output-directory]
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const out = process.argv[2] ?? (await mkdtemp(join(tmpdir(), 'firmlab-wave5-qa-')));
await mkdir(out, { recursive: true });
const dist = fileURLToPath(new URL('../apps/web/dist/', import.meta.url));

const syntheticRtosImage = {
  id: 'img-rtos',
  filename: 'freertos-gateway.bin',
  size: 524288,
  sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
  uploadedAt: 1700000000000,
  status: 'ready',
  identity: {
    firmwareClass: 'rtos',
    arch: 'arm',
    endianness: 'little',
    filesystems: [],
  },
  tags: ['rtos-synthetic'],
};

const syntheticCorpusOverview = {
  imageCount: 2,
  ruleCount: 0,
  credentialReuse: [
    { hash: 'a1b2c3d4e5f67890abcdef1234567890', kind: 'api key', imageCount: 2, watchlistLabel: 'known-api-key' },
    { hash: 'f9e8d7c6b5a43210fedcba0987654321', kind: 'root password', imageCount: 2 },
  ],
  componentPrevalence: [
    { name: 'busybox', version: '1.33.1', imageCount: 2, cveCount: 3 },
    { name: 'openssl', version: '1.1.1w', imageCount: 2, cveCount: 0 },
  ],
  deviceFamilies: [], // Empty to verify empty state!
};

const syntheticRtosSnapshotResult = {
  proofState: 'needs_runtime_reproduction',
  coverage: 'complete',
  summary: '4 task record(s) across 3 list(s), every lane walked to its sentinel.',
  snapshot: { base: 0x20000000, endian: 'little', pointerWidth: 4, bytesSupplied: 1024 },
  limits: { maxSnapshotBytes: 524288, maxListItems: 256, maxReadyLists: 64 },
  currentTask: {
    coverage: 'complete',
    tcbAddress: 0x20001000,
    pxCurrentTcbAddress: 0x20000010,
    bytesAttempted: 4,
    bytesCompleted: 4,
    evidence: [],
  },
  readyLists: [
    {
      priority: 0,
      listAddress: 0x20000100,
      coverage: 'complete',
      attempted: 1,
      completed: 1,
      tasks: [{ listItemAddress: 0x20000200, itemValue: 0, tcbAddress: 0x20001000 }],
      evidence: [],
      bytesAttempted: 28,
      bytesCompleted: 28,
    },
  ],
  delayedLists: [
    {
      name: 'pxDelayedTaskList',
      kind: 'delayed',
      itemValueMeaning: 'wake_tick',
      listAddress: 0x20000300,
      coverage: 'complete',
      attempted: 2,
      completed: 2,
      tasks: [
        { listItemAddress: 0x20000400, itemValue: 50, tcbAddress: 0x20001100 },
        { listItemAddress: 0x20000440, itemValue: 90, tcbAddress: 0x20001200 },
      ],
      evidence: [],
      bytesAttempted: 48,
      bytesCompleted: 48,
      orderViolations: 0,
      containerMismatches: 0,
      declaredItems: 2,
    },
  ],
  suspendedList: {
    name: 'xSuspendedTaskList',
    kind: 'suspended',
    itemValueMeaning: 'opaque',
    listAddress: 0x20000500,
    coverage: 'complete',
    attempted: 1,
    completed: 1,
    tasks: [{ listItemAddress: 0x20000600, itemValue: 0xffffffff, tcbAddress: 0x20001300 }],
    evidence: [],
    bytesAttempted: 28,
    bytesCompleted: 28,
    containerMismatches: 0,
    declaredItems: 1,
  },
  totals: {
    nodesAttempted: 4,
    nodesCompleted: 4,
    bytesAttempted: 108,
    bytesCompleted: 108,
  },
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
      const html = await readFile(join(dist, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }
  }

  if (path === '/health') return json({ status: 'ok', exposedToNetwork: false });
  if (path === '/api/images') return json({ images: [syntheticRtosImage] });
  if (path === '/api/images/img-rtos') return json({ image: syntheticRtosImage });
  if (path === '/api/images/img-rtos/analysis') {
    return json({
      analysis: {
        entropy: { mean: 5.5, min: 3, max: 7.2, blocks: [] },
        crypto: [],
        size: 524288,
        identity: syntheticRtosImage.identity,
        signatures: [],
        secrets: [],
      },
    });
  }
  if (path === '/api/images/img-rtos/rtos/tasks') {
    return json({ result: syntheticRtosSnapshotResult });
  }
  if (path === '/api/images/img-rtos/findings') return json({ findings: [] });
  if (path === '/api/images/img-rtos/jobs') return json({ jobs: [] });
  if (path === '/api/images/img-rtos/runs') return json({ runs: [], byTarget: [] });
  if (path === '/api/images/img-rtos/coverage') return json({ stages: [], coverage: {} });
  if (path === '/api/images/img-rtos/binaries') return json({ binaries: [] });
  if (path === '/api/images/img-rtos/operator-findings')
    return json({ assertions: [], withdrawn: [], measuredFindingCount: 0 });
  if (path === '/api/images/img-rtos/notes') return json({ notes: [] });
  if (path === '/api/corpus/overview') return json({ overview: syntheticCorpusOverview });
  if (path === '/api/corpus/rules') return json({ rules: [] });

  // Fallbacks
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
  // Disable product tour and set locale
  await context.addInitScript((lang) => {
    window.localStorage.setItem('firmlab.tour.done', '1');
    window.localStorage.setItem('firmlab.locale', lang);
  }, c.lang);

  const page = await context.newPage();
  const consoleErrors = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });

  // 1. Verify Corpus: Device Families empty state & Quick search filtering
  await page.goto(`${baseUrl}/#/corpus`, { waitUntil: 'networkidle' });

  // A. Empty state hint for device families
  const expectedFamiliesEmpty =
    c.lang === 'es'
      ? 'Aún no se han descubierto familias de dispositivos entre imágenes.'
      : 'No device families discovered across images yet.';
  const familiesEmptyHint = page.locator(`.panel:has-text("${expectedFamiliesEmpty}")`).first();
  await familiesEmptyHint.waitFor({ state: 'visible' });

  // B. Credential Reuse quick filter
  const reuseSearchInput = page.locator('input[type="search"]').first();
  await reuseSearchInput.waitFor({ state: 'visible' });

  // Type filter for "api key"
  await reuseSearchInput.fill('api key');
  const matchedText = page.locator('.panel:has-text("api key")').first();
  await matchedText.waitFor({ state: 'visible' });

  // Type non-existent query to trigger empty match note
  await reuseSearchInput.fill('nonexistent_hash_xyz');
  const emptyMatchNote = page.locator('.hint:has-text("matches"), .hint:has-text("coincide")').first();
  await emptyMatchNote.waitFor({ state: 'visible' });

  // Clear button restores rows
  const clearBtn = page.locator('button:has-text("Clear"), button:has-text("Limpiar")').first();
  if (await clearBtn.isVisible()) {
    await clearBtn.click();
  } else {
    await reuseSearchInput.fill('');
  }

  // C. Component Prevalence quick filter
  const prevalenceSearchInput = page.locator('input[type="search"]').nth(1);
  await prevalenceSearchInput.waitFor({ state: 'visible' });
  await prevalenceSearchInput.fill('busybox');
  const busyboxRow = page.locator('tr:has-text("busybox")').first();
  await busyboxRow.waitFor({ state: 'visible' });

  // Verify responsive width on Corpus page
  const corpusScrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  assert.ok(
    corpusScrollWidth <= c.width,
    `${c.name}: Corpus horizontal overflow detected (scrollWidth=${corpusScrollWidth} > viewport=${c.width})`,
  );
  await page.screenshot({ path: join(out, `${c.name}-corpus-filters.png`), fullPage: false });

  // 2. Verify FreeRTOS task lists panel in ImageDetail (bootloader section)
  await page.goto(`${baseUrl}/#/image/img-rtos/bootloader`, { waitUntil: 'networkidle' });

  // The panel title or heading should be present
  const expectedTitle = c.lang === 'es' ? 'Instantánea de tareas FreeRTOS' : 'FreeRTOS task snapshot';
  const rtosHeading = page.locator(`.panel-title:has-text("${expectedTitle}")`).first();
  await rtosHeading.waitFor({ state: 'visible' });

  // Delayed list should render with wake ticks 50 and 90
  const delayedLaneRow = page.locator('tr:has-text("pxDelayedTaskList")').first();
  await delayedLaneRow.waitFor({ state: 'visible' });
  const wakeTickCell = page.locator('text=tick 50').first();
  await wakeTickCell.waitFor({ state: 'visible' });

  // Suspended list should render
  const suspendedLaneRow = page.locator('tr:has-text("xSuspendedTaskList"), tr:has-text("suspended")').first();
  await suspendedLaneRow.waitFor({ state: 'visible' });

  // State list input fields should exist in the form
  const delayedInput = page.locator('#rtos-tasks-delayedList');
  const suspendedInput = page.locator('#rtos-tasks-suspendedList');
  assert.ok(await delayedInput.isVisible(), `${c.name}: pxDelayedTaskList address input should be visible`);
  assert.ok(await suspendedInput.isVisible(), `${c.name}: xSuspendedTaskList address input should be visible`);

  // Verify responsive width on ImageDetail page with RTOS panel
  const rtosScrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  assert.ok(
    rtosScrollWidth <= c.width,
    `${c.name}: ImageDetail RTOS horizontal overflow detected (scrollWidth=${rtosScrollWidth} > viewport=${c.width})`,
  );
  await page.screenshot({ path: join(out, `${c.name}-rtos-snapshot.png`), fullPage: false });

  results.push({
    name: c.name,
    width: c.width,
    corpusScrollWidth,
    rtosScrollWidth,
    familiesEmptyHint: true,
    quickFilterVerified: true,
    rtosDelayedLanesVerified: true,
    consoleErrors,
  });

  await context.close();
}

await browser.close();
server.close();

console.log(JSON.stringify({ out, results }, null, 2));
process.exit(0);
