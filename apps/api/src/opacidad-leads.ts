/**
 * W9 re-planning — lead resolution. Turns a completed worker's output into `Lead`s that re-plan the agenda. Three
 * sources produce leads today: service enumeration (each autostart network daemon → decompile it), web-taint (the
 * httpd that serves a tainted handler → decompile it), and the binary-vuln sweep (each stack-overflow candidate →
 * ask angr whether its sinks are actually reachable). A lead only survives if its binary actually resolves to a
 * regular file inside the rootfs — so W9 never schedules work on a daemon that isn't really there.
 */
import type { FindingDraft } from './findings-normalize.js';
import type { Lead } from './opacidad-plan.js';
import { resolveInsideRootfs } from './providers/decompile.js';
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

/**
 * How many candidates get the expensive treatment. Symbolic execution costs real wall-clock per binary, and a busy
 * rootfs yields dozens of candidates; asking about the first few keeps an autonomous scan bounded. The overflow is
 * NOT silently dropped — `runBinVuln`'s candidate count stays in the findings, so the unasked ones remain visible
 * as candidates, they simply keep their needs-reproduction state.
 */
export const REACHABILITY_LEAD_CAP = 3;

/**
 * Leads from the binary-vuln sweep: each stack-overflow candidate becomes one reachability question. The candidate
 * finding already carries the binary path and the unbounded-copy functions it imports, which is exactly the input
 * the symbolic probe needs — so this reads the drafts rather than re-walking the rootfs.
 */
export function reachabilityLeads(candidates: FindingDraft[], rootfsPath: string): Lead[] {
  const leads: Lead[] = [];
  const seen = new Set<string>();
  for (const f of candidates) {
    if (f.kind !== 'binary-pwnable-candidate') continue;
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const target = typeof ev.path === 'string' ? ev.path : '';
    const sinks = Array.isArray(ev.unsafeFns) ? ev.unsafeFns.filter((s): s is string => typeof s === 'string') : [];
    if (!target || sinks.length === 0 || seen.has(target)) continue;
    if (!resolveInsideRootfs(rootfsPath, target)) continue;
    seen.add(target);
    leads.push({
      kind: 'prove-reachability',
      target,
      sinks,
      reason: `stack-overflow candidate (${sinks.join('/')}, no canary) — prove whether the sink is on a live path`,
    });
    if (leads.length >= REACHABILITY_LEAD_CAP) break;
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
