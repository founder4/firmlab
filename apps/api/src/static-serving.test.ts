/**
 * The security override moves @fastify/static's glob dependency to a patched major. Exercise the real plugin
 * against disposable files so dependency upgrades cannot pass the unit suite while breaking production assets.
 * No store, firmware, network listener, or production data is involved.
 */
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import fastifyStatic from '@fastify/static';
import Fastify from 'fastify';
import { expect, it } from 'vitest';

it.each([true, false])('serves assets and sendFile with wildcard=%s and patched glob', async (wildcard) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'firmlab-static-'));
  const app = Fastify();
  try {
    await mkdir(path.join(root, 'assets', 'nested'), { recursive: true });
    await writeFile(path.join(root, 'index.html'), '<html>FirmLab fixture</html>');
    await writeFile(path.join(root, 'assets', 'nested', 'app.js'), 'export const loaded = true;');
    await app.register(fastifyStatic, { root, wildcard });
    app.get('/spa-fixture', (_req, reply) => reply.sendFile('index.html'));

    const asset = await app.inject('/assets/nested/app.js?v=1');
    expect(asset.statusCode).toBe(200);
    expect(asset.headers['content-type']).toContain('javascript');
    expect(asset.body).toBe('export const loaded = true;');

    const index = await app.inject('/spa-fixture');
    expect(index.statusCode).toBe(200);
    expect(index.headers['content-type']).toContain('text/html');
    expect(index.body).toBe('<html>FirmLab fixture</html>');

    const missing = await app.inject('/assets/missing.js');
    expect(missing.statusCode).toBe(404);
  } finally {
    await app.close();
    await rm(root, { recursive: true, force: true });
  }
});
