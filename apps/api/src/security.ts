/**
 * Defense-in-depth for the API, so a misconfigured reverse proxy isn't the only guard. Everything here is
 * conservative and mostly opt-in, keeping the default pure-local / behind-auth-proxy deployment unchanged:
 *
 *   (always) security response headers: nosniff, no-referrer, frame denial.
 *   FIRMLAB_STRICT_CSP=1   send a full Content-Security-Policy for the served SPA (default: only frame-ancestors).
 *   FIRMLAB_RATE_LIMIT=N   per-IP request cap per minute on /api (0/unset = off). In-memory sliding window.
 *   FIRMLAB_API_TOKEN=…    require this token (x-firmlab-token header or Bearer) on /api — for HEADLESS use; it
 *                          also gates the bundled UI's own /api calls, so only enable it when driving the API
 *                          programmatically, not through the web workbench.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

const STRICT_CSP = process.env.FIRMLAB_STRICT_CSP === '1';
const RATE_LIMIT = Math.max(0, Number(process.env.FIRMLAB_RATE_LIMIT ?? 0));
const API_TOKEN = process.env.FIRMLAB_API_TOKEN?.trim() || null;

// A Vite SPA: bundled module scripts (self), inline style attributes (unsafe-inline styles), data: icons.
const FULL_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
].join('; ');

function tokenFrom(req: FastifyRequest): string | null {
  const header = req.headers['x-firmlab-token'];
  if (typeof header === 'string' && header) return header;
  const auth = req.headers.authorization;
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

/** Register security hooks. Call once, before the route plugins. */
export function registerSecurity(app: FastifyInstance): void {
  app.addHook('onSend', async (_req, reply: FastifyReply, payload) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('x-frame-options', 'DENY');
    reply.header('content-security-policy', STRICT_CSP ? FULL_CSP : "frame-ancestors 'none'");
    return payload;
  });

  if (API_TOKEN) {
    app.addHook('onRequest', async (req, reply) => {
      if (!req.url.startsWith('/api')) return; // /health + static SPA stay open
      if (tokenFrom(req) !== API_TOKEN) {
        return reply.status(401).send({ error: 'Unauthorized' });
      }
    });
  }

  if (RATE_LIMIT > 0) {
    const hits = new Map<string, number[]>();
    app.addHook('onRequest', async (req, reply) => {
      if (!req.url.startsWith('/api')) return;
      const now = Date.now();
      const ip = req.ip || 'unknown';
      const recent = (hits.get(ip) ?? []).filter((t) => now - t < 60_000);
      recent.push(now);
      hits.set(ip, recent);
      if (recent.length > RATE_LIMIT) {
        return reply.status(429).send({ error: 'Rate limit exceeded' });
      }
    });
    // Bound memory: prune idle IPs periodically.
    setInterval(() => {
      const now = Date.now();
      for (const [ip, times] of hits) {
        if (times.every((t) => now - t >= 60_000)) hits.delete(ip);
      }
    }, 60_000).unref();
  }
}
