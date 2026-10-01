import { afterEach, describe, expect, it, vi } from 'vitest';
import { FirmLabClient, type JobView, clientFromEnv } from './client.js';

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

it('returns cancelled jobs immediately while keeping pending cancellation active', async () => {
  const client = new FirmLabClient('http://firmlab.test');
  vi.spyOn(client, 'post').mockResolvedValue({ jobId: 'j' });
  const read = vi
    .spyOn(client, 'job')
    .mockResolvedValueOnce({ id: 'j', status: 'cancelling', result: null, error: null, log: '' } as JobView)
    .mockResolvedValue({ id: 'j', status: 'cancelled', result: null, error: null, log: '' } as JobView);
  expect((await client.runJob('/start', {}, 1000, 1)).status).toBe('cancelled');
  expect(read).toHaveBeenCalledTimes(2);
});
