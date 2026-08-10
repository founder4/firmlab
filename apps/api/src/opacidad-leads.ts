/**
 * W9 re-planning — lead resolution. Turns a completed worker's output into `Lead`s that re-plan the agenda. Four
 * sources produce leads today: service enumeration (each autostart network daemon → decompile it), web-taint (the
 * httpd that serves a tainted handler → decompile it, AND the native helpers a tainted handler execs → ask angr
 * whether their unsafe sinks are reachable), and the binary-vuln sweep (each stack-overflow candidate → the same
 * reachability question, from a much weaker premise). A lead only survives if its binary actually resolves to a
 * regular file inside the rootfs — so W9 never schedules work on a daemon that isn't really there.
 *
 * The sources are not independent: the exposure the first two establish is also what ranks the third's questions,
 * so the expensive probes go to binaries some other worker already had a reason to care about. See
 * `interestingBinaries` and the ordering note on `reachabilityLeads`.
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

/**
 * The exposure rule W3's leads are built on: the binary is a known network daemon AND init really starts it. Named
 * because the probe ranking below reuses it — "interesting" there must mean exactly what "worth decompiling" means
 * here, or the two would drift into disagreeing about the same rootfs.
 */
function exposedDaemon(s: Service): boolean {
  return s.network && s.autostart;
}

/** Leads from service enumeration: each autostart network daemon whose binary resolves → decompile it (deduped). */
export function daemonLeads(services: Service[], rootfsPath: string): Lead[] {
  const leads: Lead[] = [];
  const seen = new Set<string>();
  for (const s of services) {
    if (!exposedDaemon(s)) continue;
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

/** Is the candidate a program the probes can actually run? Absent flag ⇒ assume yes, never disqualify on silence. */
function leadRunnable(f: FindingDraft): boolean {
  const ev = (f.evidence ?? {}) as Record<string, unknown>;
  return ev.runnable !== false;
}

/**
 * What the earlier workers already established about the binaries this sweep is about to rank. Every field is
 * OPTIONAL, and an empty one means "nobody looked", never "nothing is exposed": a caller that cannot supply the
 * signal gets exactly the smallest-first order this function has always produced, rather than a ranking built on
 * a silence read as a negative.
 */
export interface ProbeInterest {
  /** W3's service map. Which entries count is decided by `daemonLeads`' own rule, not by a second one here. */
  services?: Service[];
  /** W4's handler analysis. Which binaries count is whatever `taintReachabilityLeads` would ask about. */
  handlers?: HandlerAnalysis[];
  /**
   * W9's live agenda (`RunCtx.planned`). A binary W4 has ALREADY scheduled a probe for is exposed and already
   * asked; `replan` would drop the duplicate lead anyway, so the slot it occupied would silently buy nothing.
   * Dropping it here is what makes that slot available to the next candidate instead.
   */
  planned?: ReadonlySet<string>;
}

/**
 * Rootfs-relative binary path → the clause saying why it is worth asking about ahead of its size.
 *
 * Deliberately a PROJECTION of the two lead builders in this module rather than a third rule of its own: what
 * counts as exposed for the ranking is exactly what W3 decompiles and what W4 probes, so the rank cannot drift
 * into disagreeing with the leads that justify it. W4's clause wins when a binary is both, because a resolved
 * source→sink→exec chain is a stronger statement than a listening socket.
 */
export function interestingBinaries(rootfsPath: string, interest: ProbeInterest = {}): Map<string, string> {
  const why = new Map<string, string>();
  // Unbounded on purpose: the question here is WHICH binaries a tainted handler feeds, not how many probes the
  // run can afford — that budget is spent by the caller of `taintReachabilityLeads`, not by this map.
  for (const l of taintReachabilityLeads(interest.handlers ?? [], rootfsPath, Number.MAX_SAFE_INTEGER)) {
    why.set(l.target, 'a tainted web handler execs it with web input in its argv');
  }
  for (const s of interest.services ?? []) {
    if (!exposedDaemon(s)) continue;
    const bin = resolveDaemonBinary(rootfsPath, s.binary);
    if (!bin || why.has(bin)) continue;
    why.set(bin, `it is an autostart network daemon (${s.name})`);
  }
  return why;
}

/**
 * Leads from the binary-vuln sweep: each stack-overflow candidate becomes one reachability question. The candidate
 * finding already carries the binary path, its size and the unbounded-copy functions it imports, which is exactly
 * the input the symbolic probe needs — so this reads the drafts rather than re-walking the rootfs.
 *
 * The allowance is spent along TWO axes, because size answers only one of them.
 *
 * Size measures ANSWERABILITY — weakly, which is the point. Measured on the real DVRF rootfs: walk order put all
 * three probes into `usr/sbin` daemons and never reached the 7 KB pwnable that does crash. Smallest-first fixed
 * that — and then showed its own limit on the same image, which is why this is not a pure size sort any more: the
 * budget went to `store_domain_sid` and `store_machine_password`, two 4 KB samba helpers that both came back
 * inconclusive, while `stack_bof_01` — the one binary in that rootfs known to crash — sat at 7 KB behind them.
 * Across the 22 probes the corpus has actually run, small is a weak predictor even of resolving: 6 of 18 under
 * 20 KB reached a sink, and IMOU's 7.9 MB `sonia` reached `strcpy` in 39 steps. Small is at best a claim about
 * which questions RESOLVE, and none at all about which are worth asking.
 *
 * So INTEREST is the second axis, and it is not a new signal: a candidate is interesting exactly when W3 or W4
 * already said so for their own leads (`interestingBinaries`). The two queues are drawn ROUND-ROBIN, interest
 * first, each still smallest-first internally — the same shape `selectFindings` uses so that one kind cannot
 * crowd out another. Alternating rather than sorting on interest is the whole point: a pure interest ranking
 * would hand the first slots to a 900 KB daemon that times out, which is the previous failure in the other
 * direction. Half the allowance buys questions that matter, half buys questions that come back.
 *
 * MEASURED before being enabled, because the fear it was written against — that promoting a large exposed daemon
 * would spend half the allowance on probes that time out — was a prediction, not a result. Driven over the seven
 * rootfs-bearing images in the corpus on their REAL binvuln/servicemap/webtaint output, then angr run on what each
 * ordering would actually have asked (2026-07-29):
 *
 *   • On FIVE images the order is byte-identical, because the interest map and the candidate set do not intersect
 *     at all. DVRF enumerates no services whatever; GL.iNet's three exposed daemons (dnsmasq/dropbear/uhttpd) are
 *     none of its four candidates; Tenda and IMOU expose nothing that the sweep flagged. On the WDR3600 the
 *     exposed 1.7 MB `usr/bin/httpd` IS a candidate — and `selectFindings`' 45-item listing cap, which ranks
 *     equal-severity candidates smallest-first, drops it before this function is handed the list.
 *   • On the TWO where it reorders, the promoted binary is `usr/bin/httpd` both times. On the MR3220v2 that turns
 *     a measured 0-of-3 (libutil.so, apstart, libcrypt.so, all inconclusive) into `strcpy` PROVEN REACHABLE in the
 *     router's web server — 63 steps, 8.6 s, reproduced — at the cost of a `libcrypt` stub that exhausts its
 *     search space in 1.6 s having answered nothing. On the WR940Nv6 it trades one inconclusive for another and
 *     costs 4.6 s.
 *
 * So the price is real but small, and the feared timeout did not happen on any image: every promoted probe
 * finished in 8.6–15 s against a 90 s budget, because a big binary tends to exhaust angr's SEARCH SPACE early
 * rather than run long. What pure smallest-first buys on those images is the cheapest possible non-answer — a 4 KB
 * uClibc stub whose search space is done in a single step. The queues stay alternated rather than interest being
 * preferred outright: that half of the budget is what still reaches the small binaries that do resolve.
 *
 * What this ranking does NOT claim: that a promoted binary is likelier to be vulnerable, or that an unpromoted
 * one is not. Interest is exposure the earlier workers happened to establish; where they said nothing, the
 * candidate is ranked on answerability alone and never disqualified for it. The candidates the budget never
 * reaches keep their `needs_runtime_reproduction` state and stay visible as unasked, exactly as before — the
 * rank changes which questions get asked first, not what an unasked candidate means.
 *
 * Shared libraries are dropped, not because they are uninteresting but because the question cannot be put to
 * them: there is no entry point to be reachable FROM, and the reproduction rung cannot execute a .so either.
 * They stay in the ledger as candidates — unasked, which is what they are — rather than being cleared by a probe
 * that never happened. (A candidate carrying no `runnable` flag predates the field; unknown must not disqualify.)
 */
export function reachabilityLeads(
  candidates: FindingDraft[],
  rootfsPath: string,
  budget = REACHABILITY_LEAD_CAP,
  interest: ProbeInterest = {},
): Lead[] {
  const leads: Lead[] = [];
  if (budget <= 0) return leads;
  const exposed = interestingBinaries(rootfsPath, interest);
  const seen = new Set<string>();
  // Smallest binary first, and explicitly — not inherited from the sweep's ordering, so this holds however the
  // caller assembled the list. Ties break on path so a re-run schedules the same probes.
  const ordered = candidates
    .filter((f) => f.kind === 'binary-pwnable-candidate' && leadRunnable(f))
    .sort((a, b) => leadSize(a) - leadSize(b) || leadPath(a).localeCompare(leadPath(b)));
  const promoted: Lead[] = [];
  const plain: Lead[] = [];
  for (const f of ordered) {
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const target = typeof ev.path === 'string' ? ev.path : '';
    const sinks = Array.isArray(ev.unsafeFns) ? ev.unsafeFns.filter((s): s is string => typeof s === 'string') : [];
    if (!target || sinks.length === 0 || seen.has(target)) continue;
    // `specKey` in opacidad-plan.ts keys a reachability spec `symreach:<target>`; already asked ⇒ not asked again.
    if (interest.planned?.has(`symreach:${target}`)) continue;
    if (!resolveInsideRootfs(rootfsPath, target)) continue;
    seen.add(target);
    const why = exposed.get(target);
    const head = `stack-overflow candidate (${sinks.join('/')}, no canary)`;
    // The promotion states itself in the lead, which is what carries it into the trace and the spec's `trigger`:
    // a probe scheduled ahead of a smaller one has to say on whose authority it jumped the queue.
    const reason = why
      ? `${head}, ranked ahead of smaller candidates because ${why} — prove whether the sink is on a live path`
      : `${head} — prove whether the sink is on a live path`;
    (why ? promoted : plain).push({ kind: 'prove-reachability', target, sinks, reason });
  }
  for (let i = 0; leads.length < budget && (i < promoted.length || i < plain.length); i++) {
    const p = promoted[i];
    if (p) leads.push(p);
    if (leads.length >= budget) break;
    const q = plain[i];
    if (q) leads.push(q);
  }
  return leads;
}

/**
 * Its own cap, deliberately small, and it does NOT come out of `REACHABILITY_LEAD_CAP`.
 *
 * Two probes rather than three because this is the newer question and the older one has a measured record; and its
 * own budget rather than a share of the existing one because a "new lead kind" that halves the allowance of the
 * kind already there is a cut disguised as an addition.
 */
export const CMDEXEC_LEAD_CAP = 2;

/**
 * Command-exec sinks as reachability questions — the class the scan could not ask, measured before it was built.
 *
 * **The population, counted over the deployed corpus (2026-08-10, 1315 findings).** 127 `binary-cmdexec-sink` rows
 * across 7 images. Of those, **121 come from a real `dynsym` import** and 6 from the strings superset; 41 are
 * libraries; **80 are an imported sink in something that is not a `.so`** — the genuinely askable set. And 40 of
 * those 80 are ALSO `binary-pwnable-candidate`, which is why this question needed its own spec key rather than
 * riding the existing one: on half the population the two would have collided on one binary.
 *
 * **Does it pay? Asked of the real prober on 8 of them, before writing a line of this.** `system` came back
 * `reached` on **4 of 8** — `usr/sbin/generate_pin`, `sbin/diag_tracertbutton`, `usr/bin/factory`, and
 * `usr/bin/httpd` on the WR940N, the 1.9 MB router program that is the whole exposed daemon — in **1 to 14
 * seconds** against a 90 s budget. Nothing timed out. The rest returned an honest `not_reached_in_budget`.
 *
 * **Three refusals.**
 * 1. A sink read from the strings superset is not asked about. angr resolves a sink by SYMBOL, so a binary that
 *    merely contains the text `system` gives the prober nothing to break on, and the question would come back
 *    `absent` — a non-answer that costs a slot and reads like a negative.
 * 2. A library is not asked. Same reason the unbounded-copy queue drops them: there is no entry point to be
 *    reachable FROM. `runnable` absent means the row predates the field, and unknown must not disqualify.
 * 3. `reached` will mean the call site is on a live path, and nothing about attacker control. The sinks are its own
 *    row's `execFns` rather than a fixed pair, so no probe spends its budget on a `popen` the binary never imports.
 */
export function cmdexecLeads(
  candidates: FindingDraft[],
  rootfsPath: string,
  budget = CMDEXEC_LEAD_CAP,
  interest: ProbeInterest = {},
): Lead[] {
  const leads: Lead[] = [];
  if (budget <= 0) return leads;
  const exposed = interestingBinaries(rootfsPath, interest);
  const seen = new Set<string>();
  const ordered = candidates
    .filter((f) => f.kind === 'binary-cmdexec-sink' && leadRunnable(f) && fromDynsym(f))
    .sort((a, b) => leadSize(a) - leadSize(b) || leadPath(a).localeCompare(leadPath(b)));
  const promoted: Lead[] = [];
  const plain: Lead[] = [];
  for (const f of ordered) {
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const target = typeof ev.path === 'string' ? ev.path : '';
    const sinks = Array.isArray(ev.execFns) ? ev.execFns.filter((s): s is string => typeof s === 'string') : [];
    if (!target || sinks.length === 0 || seen.has(target)) continue;
    if (interest.planned?.has(`symreach:${target}#cmdexec`)) continue;
    if (!resolveInsideRootfs(rootfsPath, target)) continue;
    seen.add(target);
    const why = exposed.get(target);
    const head = `command-exec sink (${sinks.join('/')}, imported)`;
    const reason = why
      ? `${head}, ranked ahead of smaller candidates because ${why} — prove whether the call site is on a live path`
      : `${head} — prove whether the call site is on a live path`;
    (why ? promoted : plain).push({ kind: 'prove-cmdexec-reachability', target, sinks, reason });
  }
  // Exposure first, then size — the same two-queue round-robin the unbounded-copy leads use, and the measurement
  // is why: the one binary in the sample that is an exposed daemon (`usr/bin/httpd`, 1.9 MB) is also the one whose
  // answer is worth the most, and a pure smallest-first order would have put it last.
  for (let i = 0; leads.length < budget && (i < promoted.length || i < plain.length); i++) {
    const p = promoted[i];
    if (p) leads.push(p);
    if (leads.length >= budget) break;
    const q = plain[i];
    if (q) leads.push(q);
  }
  return leads;
}

/** Was this row's symbol read from the real dynamic symbol table? Absent = an older row; treated as not proven. */
function fromDynsym(f: FindingDraft): boolean {
  return ((f.evidence ?? {}) as Record<string, unknown>).symbolSource === 'dynsym';
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
