/**
 * W9 re-planning — lead resolution. Turns a completed worker's output into `Lead`s that re-plan the agenda. Two
 * sources produce leads today: service enumeration (each autostart network daemon → decompile it) and web-taint
 * (the httpd that serves a tainted handler → decompile it). A lead only survives if its binary actually resolves
 * to a regular file inside the rootfs — so W9 never schedules a decompile of a daemon that isn't really there.
 */
import { resolveInsideRootfs } from './providers/decompile.js';
import type { Lead } from './opacidad-plan.js';
import type { Service } from './providers/servicemap.js';
import type { HandlerAnalysis } from './providers/webtaint.js';

/**
 * Resolve a service's binary token to a rootfs-relative path that exists as a regular file, or null. Handles the
 * three shapes servicemap yields: an absolute path (`/usr/sbin/dropbear` → strip the leading slash), a
 * rootfs-relative path, and a bare name (`httpd` → probe the conventional bin dirs). `internal`/empty → null.
 */
export function resolveDaemonBinary(rootfsPath: string, token: string): string | null {
  if (!token || token === 'internal') return null;
  const rel = token.replace(/^\/+/, '');
  const candidates = rel.includes('/')
    ? [rel]
    : ['usr/sbin', 'usr/bin', 'sbin', 'bin', 'usr/libexec'].map((d) => `${d}/${rel}`);
  for (const c of candidates) {
    if (resolveInsideRootfs(rootfsPath, c)) return c;
  }
  return null;
}

/** Leads from service enumeration: each autostart network daemon whose binary resolves → decompile it (deduped). */
export function daemonLeads(services: Service[], rootfsPath: string): Lead[] {
  const leads: Lead[] = [];
  const seen = new Set<string>();
  for (const s of services) {
    if (!(s.network && s.autostart)) continue;
    const bin = resolveDaemonBinary(rootfsPath, s.binary);
    if (!bin || seen.has(bin)) continue;
    seen.add(bin);
    leads.push({
      kind: 'decompile-binary',
      target: bin,
      reason: `network daemon ${s.name} (autostart) — decompile for memory-safety sinks`,
    });
  }
  return leads;
}

/** The httpd daemons that could serve a tainted web handler, most-specific first. */
const HTTPD_DAEMONS = ['oui-httpd', 'uhttpd', 'lighttpd', 'nginx', 'httpd', 'goahead', 'boa'];

/** Leads from web-taint: if any handler is tainted, decompile THE httpd that serves it (the most-specific match). */
export function handlerLeads(handlers: HandlerAnalysis[], rootfsPath: string): Lead[] {
  if (!handlers.some((h) => h.tainted)) return [];
  for (const name of HTTPD_DAEMONS) {
    const bin = resolveDaemonBinary(rootfsPath, name);
    if (bin) {
      return [
        {
          kind: 'decompile-binary',
          target: bin,
          reason: `serves tainted web handlers — decompile ${name} for the sink internals`,
        },
      ];
    }
  }
  return [];
}
