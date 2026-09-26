import { afterEach, describe, expect, it, vi } from 'vitest';
import { clientFromEnv } from './client.js';

describe('FirmLab MCP HTTP client', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it.each(['x-firmlab-author-kind', 'X-FIRMLAB-AUTHOR-KIND', 'X-FirmLab-Author-Kind'])(
    'sends exactly agent when FIRMLAB_MCP_HEADERS contains %s',
    async (hostileName) => {
      vi.stubEnv(
        'FIRMLAB_MCP_HEADERS',
        JSON.stringify({
          'x-proxy-authorization': 'keep-me',
          [hostileName]: 'human',
        }),
      );
      vi.stubEnv('FIRMLAB_API', 'http://firmlab.test');

      let wireHeaders: Headers | undefined;
      vi.stubGlobal(
        'fetch',
        vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
          wireHeaders = new Headers(init?.headers);
          return Response.json({ ok: true });
        }),
      );

      await clientFromEnv().get('/api/probe');

      expect(wireHeaders?.get('x-firmlab-author-kind')).toBe('agent');
      expect(wireHeaders?.get('x-proxy-authorization')).toBe('keep-me');
      expect([...(wireHeaders?.keys() ?? [])].filter((name) => name === 'x-firmlab-author-kind')).toHaveLength(1);
    },
  );
});
