/**
 * W9 re-planning — lead resolution. Turns a completed worker's output into `Lead`s that re-plan the agenda. Four
 * sources produce leads today: service enumeration (each autostart network daemon → decompile it), web-taint (the
 * httpd that serves a tainted handler → decompile it, AND the native helpers a tainted handler execs → ask angr
 * whether their unsafe sinks are reachable), and the binary-vuln sweep (each stack-overflow candidate → the same
 * reachability question, from a much weaker premise). A lead only survives if its binary actually resolves to a
 * regular file inside the rootfs — so W9 never schedules work on a daemon that isn't really there.
 */
import type { FindingDraft } from './findings-normalize.js';
import type { Lead } from './opacidad-plan.js';
import { isElfFile } from './providers/binvuln.js';
import { resolveInsideRootfs } from './providers/decompile.js';
import type { Service } from './providers/servicemap.js';
import { type HandlerAnalysis, describeSource } from './providers/webtaint.js';

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

/** Size of the binary a candidate names; one that does not carry it sorts last rather than jumping the queue. */
function leadSize(f: FindingDraft): number {
  const ev = (f.evidence ?? {}) as Record<string, unknown>;
  return typeof ev.size === 'number' ? ev.size : Number.MAX_SAFE_INTEGER;
}

/** Path of the binary a candidate names — the deterministic tiebreak between equal-sized binaries. */
function leadPath(f: FindingDraft): string {
  const ev = (f.evidence ?? {}) as Record<string, unknown>;
  return typeof ev.path === 'string' ? ev.path : '';
}

/**
 * Leads from the binary-vuln sweep: each stack-overflow candidate becomes one reachability question. The candidate
 * finding already carries the binary path, its size and the unbounded-copy functions it imports, which is exactly
 * the input the symbolic probe needs — so this reads the drafts rather than re-walking the rootfs.
 */
export function reachabilityLeads(
  candidates: FindingDraft[],
  rootfsPath: string,
  budget = REACHABILITY_LEAD_CAP,
): Lead[] {
  const leads: Lead[] = [];
  const seen = new Set<string>();
  if (budget <= 0) return leads;
  // Smallest binary first, and explicitly — not inherited from the sweep's ordering, so this holds however the
  // caller assembled the list. The budget buys a handful of probes; bounded symbolic execution converges on small
  // binaries and reliably times out on large ones, so spending the allowance in the order the filesystem happened
  // to be walked spends it on the questions least likely to come back with an answer. Measured on the real DVRF
  // rootfs: that order put all three probes into usr/sbin daemons and never reached the 7 KB pwnable that does
  // crash. Ties break on path so a re-run schedules the same probes.
  const ordered = candidates
    .filter((f) => f.kind === 'binary-pwnable-candidate')
    .sort((a, b) => leadSize(a) - leadSize(b) || leadPath(a).localeCompare(leadPath(b)));
  for (const f of ordered) {
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
    if (leads.length >= budget) break;
  }
  return leads;
}

// === W4 → reachability: the good questions ===

/** Shell wrappers that prefix the real program in an exec string — step past them to the actual binary. */
const SHELL_WRAPPERS = new Set(['sh', 'bash', 'ash', 'dash', 'env', 'sudo', 'busybox', 'nohup', 'exec']);

/**
 * Commands the shell resolves as BUILTINS, not as the ELF of the same name.
 *
 * Caught validating on the real GL.iNet BE3600 4.9.0: the tainted `tor` handler's injection primitive is
 * `os.execute("echo \"ExitNodes " .. countries .. "\" >> /etc/tor/torrc")`. Reading `echo` as the program is a
 * correct parse, but `os.execute` runs through `/bin/sh`, which executes its own `echo` builtin — the coreutil at
 * `bin/echo` never runs. Asking angr whether `strcpy` is reachable in that ELF answers a question about a program
 * that was not executed, and the injection there is into the shell command line (the concatenation and the `>>`
 * redirect), not into any argv the prober models. So these are dropped: the taint chain is still reported by W4,
 * it simply does not become a reachability question it cannot honestly answer.
 */
const SHELL_BUILTINS = new Set([
  'echo',
  'printf',
  'cd',
  'export',
  'eval',
  'set',
  'unset',
  'read',
  'test',
  'true',
  'false',
  'pwd',
  'umask',
  'wait',
  'shift',
  'source',
  'local',
  'return',
  ':',
  '.',
]);

/**
 * Pure: the program a shell/exec sink actually runs, read off the literal prefix of its argument.
 *
 * A tainted handler's sink looks like `os.execute("/usr/sbin/gl-tor " .. params.enable)`. The part BEFORE the
 * concatenation is a constant, so the program name is statically known even though its arguments are not — which
 * is precisely the shape worth extracting: a native binary receiving attacker-controlled argv. Returns null when
 * the command itself is interpolated (`os.execute(cmd .. " x")`), because then the program is not statically
 * known and guessing one would be fabrication — and when it resolves to a shell builtin, where the named ELF is
 * not the thing that runs at all.
 */
export function execTargetFromSnippet(snippet: string): string | null {
  // The first string literal in the call — the constant head of the command. Each quote style is matched
  // independently so a nested shell quote (`os.execute("sh -c '/usr/bin/x " .. v)`) does not defeat the match.
  const lit = /"([^"]*)"|'([^']*)'/.exec(snippet);
  if (!lit) return null;
  const literal = (lit[1] ?? lit[2]) as string;
  // A literal that does not start the command (the sink's arg begins with a variable) tells us nothing reliable.
  const beforeLiteral = snippet.slice(0, lit.index);
  if (!/[({,]\s*$/.test(beforeLiteral)) return null;

  const tokens = literal
    .trim()
    .split(/[\s;|&><]+/)
    // A shell quote around the inner command is punctuation, not part of the program name.
    .map((t) => t.replace(/^["']+|["']+$/g, ''))
    .filter(Boolean);
  for (const tok of tokens) {
    if (tok.startsWith('-')) continue; // an option, e.g. `sh -c`
    if (tok.includes('=')) continue; // a leading `VAR=value` assignment
    // Interpolation, a format specifier or a glob means the program name is not statically known — say nothing.
    if (/[$`*?~%]/.test(tok)) return null;
    if (!/^[A-Za-z0-9._/-]+$/.test(tok) || !/[A-Za-z]/.test(tok)) return null;
    const base = tok.split('/').pop() as string;
    if (SHELL_WRAPPERS.has(base)) continue; // step past `sh -c`, `sudo`, `busybox foo`
    // A bare builtin is the shell's, not the ELF's. An ABSOLUTE path does name the binary (`/bin/echo x` really
    // does exec the coreutil), so only the unqualified form is dropped.
    if (!tok.includes('/') && SHELL_BUILTINS.has(base)) return null;
    return tok;
  }
  return null;
}

/**
 * Leads from W4: for each tainted handler, ask angr about the NATIVE binary that handler execs.
 *
 * This is a strictly better question than the binvuln sweep's. That sweep's premise is syntactic — "imports strcpy,
 * has no canary" — and says nothing about whether input ever gets there; that is exactly why its candidates stay
 * `needs_runtime_reproduction`. W4's premise is a resolved chain: web param → (uci) → shell → this program, running
 * as root. The prober seeds symbolic argv, which is precisely the channel the handler taints, so a `reached` verdict
 * here lands on a path an attacker actually controls the input to.
 *
 * Note what is deliberately NOT scheduled: the httpd binary that serves the handler. Its attacker input arrives on
 * a socket, and the probe models argv/stdin — a "reached" under an input model that does not match the real channel
 * would be a reachability claim about the wrong thing. The httpd keeps its decompile lead (`handlerLeads`), which
 * makes no claim the evidence cannot carry.
 */
export function taintReachabilityLeads(
  handlers: HandlerAnalysis[],
  rootfsPath: string,
  budget = REACHABILITY_LEAD_CAP,
): Lead[] {
  const leads: Lead[] = [];
  const seen = new Set<string>();
  if (budget <= 0) return leads;

  for (const h of handlers) {
    if (!h.tainted) continue;
    for (const sink of h.sinks) {
      if (!sink.concat || sink.argvArray) continue;
      const token = execTargetFromSnippet(sink.snippet);
      if (!token) continue;
      const bin = resolveDaemonBinary(rootfsPath, token);
      if (!bin || seen.has(bin)) continue;
      // A shell script cannot be loaded symbolically. Skipping it is honest — the chain is still reported by W4.
      const abs = resolveInsideRootfs(rootfsPath, bin);
      if (!abs || !isElfFile(abs)) continue;
      seen.add(bin);
      leads.push({
        kind: 'prove-reachability',
        target: bin,
        // Empty = derive the sinks from the binary's own unbounded-copy imports (runSymReach does this).
        sinks: [],
        reason: `tainted handler ${h.object} execs it with web input in argv (${describeSource(h)} → ${sink.sink}${
          h.runsAsRoot ? ' as root' : ''
        }) — prove whether an unsafe copy is on a live path`,
      });
      if (leads.length >= budget) return leads;
    }
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

/**
 * Leads from symbolic reachability: a sink PROVEN reachable is the one worth actually running.
 *
 * This is the rung that was missing. `symreach` establishes that the call site is on a live path and stops there,
 * correctly — reachability is not a bug, and its finding says so. But a reachable sink is exactly the candidate
 * where running the binary is cheap and decisive, and where a crash would move the claim from an assertion about
 * bytes to an observed fault. The `sink-reachable` finding already carries the binary, the sink and the call-site
 * ADDRESSES angr resolved, which is precisely what a breakpoint needs, so this reads the drafts rather than
 * re-deriving anything.
 *
 * Only `reached` sinks qualify. An inconclusive one has no address worth breaking on and no reason to expect the
 * path to be taken.
 */
export function reproductionLeads(drafts: FindingDraft[], rootfsPath: string, budget = REPRODUCTION_LEAD_CAP): Lead[] {
  const leads: Lead[] = [];
  const seen = new Set<string>();
  if (budget <= 0) return leads;
  for (const f of drafts) {
    if (f.kind !== 'sink-reachable') continue;
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const target = typeof ev.binary === 'string' ? ev.binary : '';
    const sink = typeof ev.sink === 'string' ? ev.sink : '';
    const addresses = Array.isArray(ev.addresses)
      ? ev.addresses.filter((a): a is string => typeof a === 'string' && /^0x[0-9a-fA-F]+$/.test(a))
      : [];
    const key = `${target}#${sink}`;
    if (!target || !sink || addresses.length === 0 || seen.has(key)) continue;
    if (!resolveInsideRootfs(rootfsPath, target)) continue;
    seen.add(key);
    leads.push({
      kind: 'reproduce-crash',
      target,
      sink,
      addresses,
      reason: `${sink} proven reachable from the entry point — run it and see whether it actually faults`,
    });
    if (leads.length >= budget) break;
  }
  return leads;
}

/**
 * How many binaries get run per scan. Each is an emulator plus a debugger under a timeout, so it is bounded the
 * same way the angr budget is — and, like that one, the unattempted candidates stay visible as candidates.
 */
export const REPRODUCTION_LEAD_CAP = 3;
