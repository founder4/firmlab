/**
 * Taint scaffold (Phase 4, deterministic) — the honest, byte-derived input to the zero-day node ④. It does NOT
 * decide that a vulnerability exists; it lays out, from a binary's radare2 triage, the dangerous SINKS it imports
 * (command exec, unbounded copies, tainted-format), the attacker-controlled SOURCES it imports (network reads,
 * CGI env, NVRAM), and CGI/HTTP hints in its strings. The agent reasons over this scaffold about a plausible
 * source→sink path; the mechanics (which imports exist) stay deterministic. No LLM here.
 */
import type { DecompileResult } from './decompile.js';

export type SinkClass = 'command-exec' | 'buffer-overflow' | 'format-string' | 'path-traversal';
export type SourceClass = 'network' | 'cgi-env' | 'nvram' | 'stdin';

/** Imported symbols that are dangerous when they consume attacker-controlled data. */
const SINKS: Record<string, SinkClass> = {
  system: 'command-exec',
  popen: 'command-exec',
  execl: 'command-exec',
  execlp: 'command-exec',
  execle: 'command-exec',
  execv: 'command-exec',
  execvp: 'command-exec',
  execve: 'command-exec',
  doSystem: 'command-exec',
  twsystem: 'command-exec',
  strcpy: 'buffer-overflow',
  strcat: 'buffer-overflow',
  stpcpy: 'buffer-overflow',
  sprintf: 'buffer-overflow',
  vsprintf: 'buffer-overflow',
  gets: 'buffer-overflow',
  memcpy: 'buffer-overflow',
  bcopy: 'buffer-overflow',
  sscanf: 'buffer-overflow',
  printf: 'format-string',
  fprintf: 'format-string',
  vprintf: 'format-string',
  snprintf: 'format-string',
  syslog: 'format-string',
  fopen: 'path-traversal',
  unlink: 'path-traversal',
};

/** Imported symbols that introduce attacker-controlled data. */
const SOURCES: Record<string, SourceClass> = {
  recv: 'network',
  recvfrom: 'network',
  read: 'network',
  accept: 'network',
  websGetVar: 'network',
  nvram_get: 'nvram',
  nvram_bufget: 'nvram',
  bcm_nvram_get: 'nvram',
  nvram_safe_get: 'nvram',
  getenv: 'cgi-env',
  cgiGetValue: 'cgi-env',
  fgets: 'stdin',
  fread: 'stdin',
  scanf: 'stdin',
};

const CGI_HINT = /QUERY_STRING|CONTENT_LENGTH|REQUEST_METHOD|REMOTE_ADDR|HTTP_|\/cgi-bin\/|boundary=/;

/** Normalize a radare2 import name (`sym.imp.strcpy`, `strcpy@plt`, `_system`) to its bare symbol. */
export function normalizeImport(name: string): string {
  return name
    .replace(/^sym\.imp\./, '')
    .replace(/^imp\./, '')
    .replace(/@.*$/, '')
    .replace(/^_+/, '');
}

export interface TaintScaffold {
  binary: string;
  arch: string | undefined;
  hardening: { nx?: boolean; canary?: boolean; pic?: boolean };
  sinks: { name: string; class: SinkClass }[];
  sources: { name: string; class: SourceClass }[];
  cgiHints: string[];
  /** Both a sink and a source are present — the minimal precondition for a taint hypothesis. */
  hasTaintSurface: boolean;
}

/** Pure: derive the taint scaffold from a binary's decompile triage. Empty/degraded triage → empty scaffold. */
export function buildTaintScaffold(decompile: DecompileResult): TaintScaffold {
  const seenSink = new Map<string, SinkClass>();
  const seenSource = new Map<string, SourceClass>();
  for (const imp of decompile.imports) {
    const n = normalizeImport(imp.name);
    const sink = SINKS[n];
    if (sink && !seenSink.has(n)) seenSink.set(n, sink);
    const source = SOURCES[n];
    if (source && !seenSource.has(n)) seenSource.set(n, source);
  }
  const cgiHints = Array.from(
    new Set(
      decompile.strings
        .map((s) => s.value)
        .filter((v) => CGI_HINT.test(v))
        .slice(0, 12),
    ),
  );
  const sinks = [...seenSink.entries()].map(([name, cls]) => ({ name, class: cls }));
  const sources = [...seenSource.entries()].map(([name, cls]) => ({ name, class: cls }));
  const hardening: TaintScaffold['hardening'] = {
    ...(typeof decompile.info.nx === 'boolean' ? { nx: decompile.info.nx } : {}),
    ...(typeof decompile.info.canary === 'boolean' ? { canary: decompile.info.canary } : {}),
    ...(typeof decompile.info.pic === 'boolean' ? { pic: decompile.info.pic } : {}),
  };
  return {
    binary: decompile.binary,
    arch: decompile.info.arch,
    hardening,
    sinks,
    sources,
    cgiHints,
    hasTaintSurface: sinks.length > 0 && (sources.length > 0 || cgiHints.length > 0),
  };
}
