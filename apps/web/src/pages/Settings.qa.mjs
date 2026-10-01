/**
 * Chromium regression for the built Settings page. All API reads and writes use an in-memory fixture on an
 * ephemeral loopback server; this never connects to the deployed API or stores credentials. Build core and web
 * first, then run `node apps/web/src/pages/Settings.qa.mjs [output-directory]`.
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const out = process.argv[2] ?? (await mkdtemp(join(tmpdir(), 'firmlab-settings-')));
await mkdir(out, { recursive: true });
const dist = fileURLToPath(new URL('../../dist/', import.meta.url));
const original = {
  provider: { value: 'deepseek', source: 'override' },
  model: { value: `model-${'long-identifier-'.repeat(8)}`, source: 'environment' },
  baseUrl: { value: 'https://example.invalid/v1', source: 'default' },
  apiKey: { present: true, source: 'override', tail: 'test', envVar: 'FIRMLAB_LLM_API_KEY' },
  ready: true,
  reason: '',
  providers: ['deepseek', 'openai', 'anthropic'],
  defaultModels: { deepseek: 'deepseek-chat', openai: '', anthropic: 'fixture-model' },
};
let llm = structuredClone(original);
const approval = { preapproveAll: false, source: 'default', environmentValue: false };
const writes = [];
const unexpected = [];
const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  const json = (value) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(value));
  };
  if (path === '/api/images') return json({ images: [] });
  if (path === '/health') return json({ status: 'ok', exposedToNetwork: false });
  if (path === '/api/agent/config') {
    return json({
      enabled: true,
      provider: 'deepseek',
      model: original.model.value,
      budget: { maxSteps: 12, maxTokens: 100000, maxUsd: 0, maxWallMs: 600000 },
      approval,
    });
  }
  if (path === '/api/storage') return json({ usage: { imageCount: 0, totalBytes: 0 } });
  if (path === '/api/settings/flags') return json({ flags: [], appliesImmediately: true });
  if (path === '/api/settings/llm') return json({ llm, updatedAt: {} });
  if (path.startsWith('/api/settings/llm/')) {
    const key = path.split('/').at(-1);
    const fields = {
      FIRMLAB_LLM_PROVIDER: 'provider',
      FIRMLAB_LLM_MODEL: 'model',
      FIRMLAB_LLM_BASE_URL: 'baseUrl',
      FIRMLAB_LLM_API_KEY: 'apiKey',
    };
    assert.ok(fields[key], `Unexpected setting: ${key}`);
    assert.ok(['PUT', 'DELETE'].includes(req.method));
    let body = '';
    for await (const chunk of req) body += chunk;
    const value = body ? JSON.parse(body).value : undefined;
    writes.push({ method: req.method, key });
    const field = fields[key];
    llm[field] =
      req.method === 'DELETE'
        ? { ...original[field], source: 'environment' }
        : field === 'apiKey'
          ? { present: true, tail: value.slice(-4), envVar: 'FIRMLAB_LLM_API_KEY', source: 'override' }
          : { value, source: 'override' };
    return json({ llm });
  }
  if (path.startsWith('/api/')) {
    unexpected.push(`${req.method} ${path}`);
    res.statusCode = 404;
    return json({ error: 'No synthetic route' });
  }
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
  for (const locale of ['en', 'es']) {
    for (const viewport of [
      { width: 390, height: 844 },
      { width: 1440, height: 1000 },
    ]) {
      llm = structuredClone(original);
      const context = await browser.newContext({ viewport });
      await context.addInitScript((language) => {
        localStorage.setItem('firmlab.tour.done', '1');
        localStorage.setItem('firmlab.locale', language);
      }, locale);
      await context.route('**/*', (route) => {
        if (route.request().url().startsWith(base)) return route.continue();
        unexpected.push(`Outbound request: ${route.request().url()}`);
        return route.abort();
      });
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', (error) => errors.push(error.message));
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(message.text());
      });
      await page.goto(`${base}/#/settings`);
      await page.getByRole('button', { name: locale === 'en' ? 'AI & Agent' : 'IA y agente', exact: true }).click();
      await page.locator('input[type=password]').waitFor();
      const metrics = await page.evaluate(() => ({
        viewport: innerWidth,
        scrollWidth: document.documentElement.scrollWidth,
        overflowing: [...document.querySelectorAll('.panel *')]
          .filter((el) => el.getBoundingClientRect().right > innerWidth)
          .map((el) => ({ tag: el.tagName, text: el.textContent.slice(0, 80) })),
      }));
      const name = `${locale}-${viewport.width}`;
      await page.screenshot({ path: join(out, `${name}.png`), fullPage: true });
      const controls = await page
        .locator('.settings-agent input, .settings-agent select, .settings-agent button')
        .evaluateAll((elements) =>
          elements.map((el) => {
            const rect = el.getBoundingClientRect();
            return { tag: el.tagName, left: rect.left, right: rect.right, width: rect.width };
          }),
        );
      for (const control of controls) {
        assert.ok(control.left >= 0 && control.right <= viewport.width, `${name}: control outside viewport`);
        if (control.tag === 'INPUT') assert.ok(control.width >= 200, `${name}: unreadably narrow input`);
      }
      const model = page.getByRole('textbox', { name: locale === 'en' ? 'Model' : 'Modelo', exact: true });
      const modelRow = page.locator('.settings-row').filter({ has: model });
      const positions = await modelRow.evaluate((row) => ({
        label: row.querySelector('.settings-row-label').getBoundingClientRect().bottom,
        field: row.querySelector('input').getBoundingClientRect().top,
      }));
      assert.equal(positions.field >= positions.label, viewport.width === 390, `${name}: responsive row direction`);
      const saveName = locale === 'en' ? 'Save' : 'Guardar';
      for (const [field, value] of [
        [model, 'synthetic-model'],
        [
          page.getByRole('textbox', { name: locale === 'en' ? 'Base URL' : 'URL base', exact: true }),
          'https://synthetic.invalid/v1',
        ],
      ]) {
        await field.fill(value);
        const row = page.locator('.settings-row').filter({ has: field });
        await row.getByRole('button', { name: saveName, exact: true }).click();
        await row.getByRole('button', { name: locale === 'en' ? 'Clear' : 'Borrar', exact: true }).waitFor();
      }
      await page.getByRole('combobox').selectOption('anthropic');
      await page.waitForFunction(() => !document.querySelector('.settings-agent select').disabled);
      const key = page.locator('input[type=password]');
      assert.equal(await key.inputValue(), '');
      const keyRow = page.locator('.settings-row').filter({ has: key });
      await key.fill('synthetic-only-key-5678');
      await keyRow.getByRole('button', { name: saveName, exact: true }).click();
      await keyRow.getByText(/…5678/).waitFor();
      assert.equal(await key.inputValue(), '');
      assert.ok(await keyRow.getByRole('button', { name: saveName, exact: true }).isDisabled());
      await keyRow.getByRole('button', { name: locale === 'en' ? 'Clear' : 'Borrar', exact: true }).click();
      await keyRow.getByText(locale === 'en' ? 'from the environment' : 'del entorno', { exact: true }).waitFor();
      assert.equal(await key.inputValue(), '');
      assert.ok(!(await page.locator('body').innerText()).includes('synthetic-only-key-5678'));
      assert.equal(llm.provider.value, 'anthropic');
      assert.equal(llm.model.value, 'synthetic-model');
      assert.equal(llm.baseUrl.value, 'https://synthetic.invalid/v1');
      assert.equal(llm.apiKey.source, 'environment');
      const afterScrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
      assert.ok(afterScrollWidth <= viewport.width, `${name}: overflow after saves`);
      await page.screenshot({ path: join(out, `${name}-saved.png`), fullPage: true });
      results.push({ name, ...metrics, afterScrollWidth, controls, errors });
      await context.close();
    }
  }
  await writeFile(join(out, 'results.json'), JSON.stringify({ results, unexpected, writes }, null, 2));
  console.log(JSON.stringify({ out, results, unexpected }, null, 2));
  assert.equal(writes.length, 20, 'Each viewport/locale must exercise four saves and one reset');
  assert.deepEqual(unexpected, []);
  for (const result of results) {
    assert.deepEqual(result.errors, []);
    assert.ok(result.scrollWidth <= result.viewport, `${result.name}: ${result.scrollWidth} > ${result.viewport}`);
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
