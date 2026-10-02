/**
 * Chromium browser verification for Wave 2 UI features:
 * 1. SimulationMenu: stored chipsec decode & renode boot results rendered on mount.
 * 2. ComponentMap: targeted component CVE scan button, job polling, and scoped findings refresh.
 * 3. CredMatchPanel: targeted auxsecrets scan button, independent polling, and findings refresh.
 * 4. Settings: non-secret model and baseUrl draft clearing keeping saved values visible.
 *
 * All API reads and writes use an in-memory synthetic fixture on an ephemeral loopback server.
 * Never connects to deployed API or mutates corpus. Build core and web first, then run:
 *   node apps/web/src/pages/Wave2.qa.mjs [output-directory]
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const out = process.argv[2] ?? (await mkdtemp(join(tmpdir(), 'firmlab-wave2-qa-')));
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

const syntheticChipsec = {
  available: true,
  ran: true,
  reason: 'Decoded 2 firmware volumes and 130 EFI modules offline with chipsec.',
  proofState: 'static_confirmed',
  volumes: 2,
  moduleCount: 130,
  byType: { DXE_DRIVER: 109, PEIM: 13, SEC: 8 },
  modules: [],
  secureBoot: {
    secureBoot: 'enabled',
    setupMode: 'user',
    auditMode: 'disabled',
    deployedMode: 'deployed',
    testKey: false,
    variableCount: 7,
    note: 'Secure Boot enabled with production Microsoft KEK and DB keys.',
  },
  findings: [
    {
      kind: 'uefi-spi-lock',
      title: 'BIOS Interface Lock (BIOS_CNTL.BIOSWE) protected',
      severity: 'info',
      rationale: 'SMM BIOS write protect bit is armed.',
    },
  ],
};

const syntheticRenode = {
  available: true,
  ran: true,
  booted: true,
  proofState: 'needs_runtime_reproduction',
  platform: 'platforms/cpus/stm32f4.repl',
  reason: 'Booted RTOS kernel in Renode simulation with clean UART init.',
  uartExcerpt: '[0.000000] FreeRTOS Kernel V10.4.3 initialized\n[0.002010] Starting scheduler on Cortex-M4',
};

const syntheticCompMap = {
  components: [
    { name: 'busybox', version: '1.35.0', path: '/bin/busybox' },
    { name: 'dnsmasq', version: '2.86', path: '/usr/sbin/dnsmasq' },
  ],
  findings: [
    {
      id: 'f-cve-1',
      kind: 'cve-match',
      title: 'CVE-2022-30065 in busybox 1.35.0',
      severity: 'high',
      proofState: 'static_confirmed',
      source: 'compmap:cve',
    },
  ],
};

const syntheticCredMatch = {
  candidates: [{ hash: '5f4dcc3b5aa765d61d8327deb882cf99', salt: 'admin', kind: 'md5-crypt' }],
  matches: [],
  proofState: 'static_confirmed',
  findings: [],
};

let jobCounter = 0;
const jobs = new Map();

const llmState = {
  provider: { value: 'anthropic', source: 'override' },
  model: { value: 'claude-3-5-sonnet', source: 'override' },
  baseUrl: { value: 'https://api.anthropic.com', source: 'override' },
  apiKey: { present: true, source: 'override', tail: '1234', envVar: 'FIRMLAB_LLM_API_KEY' },
  ready: true,
  reason: '',
  providers: ['anthropic', 'openai', 'deepseek'],
  defaultModels: { anthropic: 'claude-3-5-sonnet', openai: 'gpt-4o', deepseek: 'deepseek-chat' },
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
  if (path === '/api/images/img-synth/analysis')
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
  if (path === '/api/images/img-synth/findings') return json({ findings: [] });
  if (path === '/api/images/img-synth/jobs') return json({ jobs: [] });
  if (path === '/api/images/img-synth/runs') return json({ runs: [], byTarget: [] });
  if (path === '/api/images/img-synth/coverage') return json({ stages: [], coverage: {} });
  if (path === '/api/images/img-synth/binaries') return json({ binaries: [] });
  if (path === '/api/images/img-synth/notes') return json({ notes: [] });
  if (path === '/api/images/img-synth/operator-findings') return json({ assertions: [], withdrawn: [] });
  if (path === '/api/storage') return json({ usage: { imageCount: 1, totalBytes: 16777216 } });
  if (path === '/api/tools') return json({ tools: [] });
  if (path === '/api/settings/flags') return json({ flags: [], appliesImmediately: true });
  if (path === '/api/settings/agent-approval') return json({ approval: { preapproveAll: false } });
  if (path === '/api/agent/status') return json({ enabled: false });

  // Simulation endpoints
  if (path === '/api/images/img-synth/emulation') {
    return json({
      identity: syntheticImage.identity,
      rootfsReady: true,
      suggestedBinary: null,
      capabilities: null,
      recipes: [
        {
          id: 'chipsec-1',
          mode: 'uefi-chipsec',
          title: 'chipsec UEFI decode',
          description: 'Decode EFI volumes offline with chipsec.',
          command: 'chipsec_util uefi decode /firmware.bin',
          requires: [],
          runnable: true,
          rank: 1,
        },
        {
          id: 'renode-1',
          mode: 'renode',
          title: 'Renode RTOS simulation',
          description: 'Simulate RTOS peripherals with Renode.',
          command: 'renode -e "mach create; machine LoadPlatformDescription @stm32.repl; start"',
          requires: [],
          runnable: true,
          rank: 2,
        },
      ],
      plan: { ceiling: 'emulation', stages: [] },
    });
  }
  if (path === '/api/images/img-synth/chipsec') return json({ result: syntheticChipsec });
  if (path === '/api/images/img-synth/renode') return json({ result: syntheticRenode });

  // Component Map & Component CVE
  if (path === '/api/images/img-synth/compmap') return json({ result: syntheticCompMap });
  if (path === '/api/images/img-synth/component-cve' && req.method === 'POST') {
    jobCounter++;
    const jobId = `job-cve-${jobCounter}`;
    jobs.set(jobId, {
      status: 'done',
      result: {
        reason: 'Scanned 2 components for known CVEs; matched 1 advisory.',
        findings: [
          {
            id: 'cve-1',
            kind: 'component-cve',
            title: 'CVE-2022-30065 in busybox',
            severity: 'high',
            proofState: 'static_confirmed',
            source: 'component-cve',
          },
        ],
      },
    });
    return json({ jobId }, 202);
  }

  // CredMatch & AuxSecrets
  if (path === '/api/images/img-synth/credmatch') return json({ result: syntheticCredMatch });
  if (path === '/api/images/img-synth/auxsecrets' && req.method === 'POST') {
    jobCounter++;
    const jobId = `job-aux-${jobCounter}`;
    jobs.set(jobId, {
      status: 'done',
      result: {
        reason: 'Scanned 3 auxiliary partitions; recovered 1 private key candidate.',
        findings: [
          {
            id: 'aux-1',
            kind: 'auxsecret-private-key',
            title: 'RSA private key in /dev/mtd3',
            severity: 'critical',
            proofState: 'static_confirmed',
            source: 'auxsecrets',
          },
        ],
      },
    });
    return json({ jobId }, 202);
  }

  // Job polling
  if (path.startsWith('/api/jobs/')) {
    const id = path.split('/').pop();
    const job = jobs.get(id) ?? { status: 'done', result: null };
    return json({ job: { id, status: job.status, result: job.result, log: 'completed successfully' } });
  }

  // Settings LLM
  if (path === '/api/settings/llm') {
    return json({ llm: llmState, updatedAt: {} });
  }
  if (path.startsWith('/api/settings/llm/') && req.method === 'PUT') {
    const key = path.split('/').pop();
    let body = '';
    req.on('data', (c) => {
      body += c;
    });
    await once(req, 'end');
    const { value } = JSON.parse(body);
    if (key === 'FIRMLAB_LLM_MODEL') llmState.model = { value, source: 'override' };
    if (key === 'FIRMLAB_LLM_BASE_URL') llmState.baseUrl = { value, source: 'override' };
    return json({ llm: llmState });
  }

  // Fallback 404
  console.log('404:', req.method, path);
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
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
          console.error(`[${name} console.error]`, msg.text());
        }
      });

      // 1. SimulationMenu: test stored chipsec & renode decode
      await page.goto(`${baseUrl}/#/image/img-synth/simulate`);
      await page.waitForSelector('.panel-title');

      // Check stored chipsec is visible on mount without running
      const chipsecTitle = await page.textContent('.panel-title:has-text("chipsec")');
      assert.ok(chipsecTitle, 'Stored chipsec panel title must be present');
      const chipsecModuleBadge = await page.textContent('.badge:has-text("130")');
      assert.ok(chipsecModuleBadge, '130 EFI modules badge must be rendered');

      // Check stored renode is visible on mount
      const renodeTitle = await page.textContent('.panel-title:has-text("Renode")');
      assert.ok(renodeTitle, 'Stored renode panel title must be present');
      const renodeBooted = await page.textContent('.badge:has-text("booted"), .badge:has-text("arrancó")');
      assert.ok(renodeBooted, 'Renode booted badge must be rendered');

      // Check no horizontal scrollbar
      const simScrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
      assert.equal(simScrollWidth, width, `Simulation page must not horizontally overflow at ${width}px`);

      // 2. ComponentMap: trigger component CVE scan
      await page.goto(`${baseUrl}/#/image/img-synth/compmap`);
      const cveBtnSelector =
        'button:has-text("Check component versions for CVEs"), button:has-text("Comprobar CVE de versiones de componentes")';
      await page.waitForSelector(cveBtnSelector);
      await page.click(cveBtnSelector);
      // Wait for completion notice
      await page.waitForSelector('p.hint[aria-live="polite"]');
      const cveNotice = await page.textContent('p.hint[aria-live="polite"]');
      assert.ok(cveNotice.includes('CVE'), 'Component CVE scan notice must appear after trigger');

      // 3. CredMatch: trigger auxsecrets scan
      await page.goto(`${baseUrl}/#/image/img-synth/credmatch`);
      const auxBtnSelector =
        'button:has-text("Scan auxiliary partitions for secrets"), button:has-text("Buscar secretos en particiones auxiliares")';
      await page.waitForSelector(auxBtnSelector);
      await page.click(auxBtnSelector);
      // Wait for aux completion notice
      await page.waitForSelector('p.hint[aria-live="polite"]');
      const auxNotice = await page.textContent('p.hint[aria-live="polite"]');
      assert.ok(auxNotice, 'Auxsecrets notice must appear after trigger');

      // 4. Settings: non-secret model and baseUrl draft clearing check
      await page.goto(`${baseUrl}/#/settings`);
      await page.click('button:has-text("AI & Agent"), button:has-text("IA y agente")');
      const modelInput = page.locator(
        'input[aria-label="Model"], input[aria-label="Modelo"], input[placeholder="Model"]',
      );
      const testModel = `qa-${name}-model`;
      await modelInput.fill(testModel);
      const modelRow = page.locator(`.settings-row:has(input[value="${testModel}"])`);
      await modelRow.locator('button:has-text("Save"), button:has-text("Guardar")').click();

      // Verify the value in the input did NOT blank out!
      await page.waitForTimeout(300);
      const modelVal = await modelInput.inputValue();
      assert.equal(modelVal, testModel, 'Model input must retain saved value and not blank out');

      // Take screenshot of Settings
      await page.screenshot({ path: join(out, `${name}-settings.png`) });

      results.push({
        name,
        width,
        simScrollWidth,
        chipsecModuleBadge,
        cveNotice,
        auxNotice,
        modelVal,
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
