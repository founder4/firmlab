/**
 * W4 — Web attack-surface (static taint). The two headline bugs of the autonomous pass were web-handler command
 * injections that a secrets-regex + single-binary Ghidra view can never see: the GL.iNet Tor `os.execute`
 * string-concat gated only by a permissive lua-pattern validator, and the WR940N httpd cmdi. This worker reads
 * the rpcd/oui-httpd/luci/cgi handlers straight from an extracted rootfs and models the taint the way the
 * autonomous agent did: a **web param → uci config value → shell sink** flow, whether the object's validator
 * actually blocks the metacharacters, whether the method needs auth, and the config-restore path that bypasses
 * the RPC validator entirely (docs/AUTONOMOUS-WORKERS.md §3.2(3a)/(4), §7.1, W4).
 *
 * The parse is PURE and unit-tested (source strings in, structured taint out); the runner only walks the rootfs
 * and reads the handler bytes. Findings are `static_confirmed` code facts (the concat sink reading web input is
 * literally present) with the source→sink→privilege chain in evidence — on-device reproduction is the dynamic
 * webprobe's job, named honestly, not claimed here.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings.js';

// === Handler parse (pure) ===

/** Shell/exec sinks: the string form is injectable; an argv-array (`{...}`) form is the hardened control. */
const SINK_RE =
  /\b(os\.execute|io\.popen|posix\.exec|posix\.system|luci\.sys\.call|luci\.util\.exec|ngx\.pipe\.spawn)\s*\(/;

export interface SinkHit {
  sink: string;
  line: number;
  /** The argument is built with `..` string concatenation involving a variable — the injectable form. */
  concat: boolean;
  /** The argument is an argv array (`{ "cmd", arg }`) — no shell, the hardened form. */
  argvArray: boolean;
  snippet: string;
}

export type SourceKind = 'param' | 'uci' | 'cgi-env';
export interface SourceHit {
  kind: SourceKind;
  name: string;
  line: number;
}

export interface HandlerAnalysis {
  handler: string;
  object: string;
  sinks: SinkHit[];
  sources: SourceHit[];
  /** A concat sink AND an attacker-controlled source in the same handler — the taint precondition. */
  tainted: boolean;
  /** The tainted value flows through a uci config value → a config-restore/uci-import writer bypasses the validator. */
  fromUci: boolean;
  /** The handler acts on root-owned system paths (writes /etc, restarts init.d) → runs as root. */
  runsAsRoot: boolean;
}

/** Strip Lua line comments and string literals so concat/identifier detection isn't fooled by string contents. */
function stripStringsAndComments(line: string): string {
  const noComment = line.replace(/--.*$/, '');
  return noComment.replace(/"(\\.|[^"\\])*"/g, '""').replace(/'(\\.|[^'\\])*'/g, "''");
}

/** The argument text from a sink's `(` to end-of-line — enough for the common single-line handler call. */
function sinkArg(line: string, openParenIdx: number): string {
  return line.slice(openParenIdx + 1);
}

/**
 * Pure: analyze one handler's source. Detects exec sinks (flagging the injectable string-concat form vs a
 * hardened argv-array), attacker-controlled sources (`params.*`, `uci:get`, CGI env), whether the value flows
 * through uci, and whether the handler touches root-owned paths. `object` defaults to the file basename.
 */
export function parseHandler(source: string, handlerPath: string): HandlerAnalysis {
  const object = path.basename(handlerPath).replace(/\.(lua|cgi|sh)$/, '');
  const lines = source.split('\n');
  const sinks: SinkHit[] = [];
  const sources: SourceHit[] = [];

  lines.forEach((raw, i) => {
    const line = i + 1;
    const clean = stripStringsAndComments(raw);

    const m = SINK_RE.exec(raw);
    if (m) {
      const argClean = sinkArg(stripStringsAndComments(raw), stripStringsAndComments(raw).indexOf('(', m.index));
      const firstArgChar = sinkArg(raw, raw.indexOf('(', m.index)).trimStart()[0];
      const argvArray = firstArgChar === '{';
      const concat = /\.\./.test(argClean) && /[A-Za-z_]\w*/.test(argClean);
      sinks.push({ sink: m[1] as string, line, concat, argvArray, snippet: raw.trim().slice(0, 200) });
    }

    for (const pm of clean.matchAll(/\bparams\s*(?:\.\s*(\w+)|\[\s*['"]?(\w+))/g)) {
      sources.push({ kind: 'param', name: (pm[1] ?? pm[2]) as string, line });
    }
    if (/\b(?:uci|cursor|c|x)\s*[:.]\s*get\s*\(/.test(clean) || /\buci\.get\b/.test(clean)) {
      sources.push({ kind: 'uci', name: 'uci:get', line });
    }
    const cgi = /getenv\s*\(\s*['"](QUERY_STRING|CONTENT_LENGTH|REQUEST_METHOD|HTTP_\w+)/.exec(raw);
    if (cgi) sources.push({ kind: 'cgi-env', name: cgi[1] as string, line });
  });

  const concatSink = sinks.some((s) => s.concat && !s.argvArray);
  const hasSource = sources.length > 0;
  const fromUci = sources.some((s) => s.kind === 'uci');
  const runsAsRoot = /\/etc\/|init\.d|\/etc\/config|torrc|uci[:.]commit/.test(source);

  return {
    handler: handlerPath,
    object,
    sinks,
    sources,
    tainted: concatSink && hasSource,
    fromUci,
    runsAsRoot,
  };
}

// === Validator resolution (pure) ===

export interface ValidatorInfo {
  /** Path of the default `valid_rpc_args` validator, when found. */
  path: string | null;
  /** The extracted lua-pattern the validator enforces. */
  pattern: string | null;
  /** The pattern permits a newline (its char-class includes `%s`, or it isn't anchored) → directive injection. */
  permitsNewline: boolean;
}

/**
 * Pure: extract the anchored lua-pattern a `valid_rpc_args`-style validator enforces (e.g. `^[%w%.%s%-_:#/]-$`).
 * Returns null when the source has no such pattern.
 */
export function extractRpcArgPattern(validatorSource: string): string | null {
  const m = /(["'])(\^\[[^"']*?\][%\-*+]?\$?)\1/.exec(validatorSource);
  return m ? (m[2] as string) : null;
}

/**
 * Pure: does a validator pattern permit a newline? In Lua patterns `%s` matches ALL whitespace including `\n`, so
 * an allow-list char-class containing `%s` (or `.`, or an unanchored pattern) lets a newline through — which is
 * exactly the GL.iNet torrc-directive-injection primitive. A class WITHOUT `%s`/`.` and anchored `^…$` blocks it.
 */
export function patternPermitsNewline(pattern: string | null): boolean {
  if (!pattern) return true; // no validator found → nothing constrains the input
  const anchored = pattern.startsWith('^') && pattern.endsWith('$');
  if (!anchored) return true; // unanchored → the tail can carry a newline
  const cls = /\[(.*)\]/.exec(pattern)?.[1];
  // Anchored allow-list char-class: a newline gets through only if the class admits whitespace (`%s` matches \n).
  if (cls !== undefined) return cls.includes('%s');
  // No char-class: a bare `.` wildcard (Lua `.` matches newline) permits it; a `%w`/literal-only pattern does not.
  return /(^|[^%])\./.test(pattern);
}

// === Findings (pure) ===

/** Describe the source of a handler's taint for the attack-path chain. */
function describeSource(h: HandlerAnalysis): string {
  const param = h.sources.find((s) => s.kind === 'param');
  if (h.fromUci && param) return `params.${param.name} → uci`;
  if (param) return `params.${param.name} (web RPC param)`;
  if (h.fromUci) return 'uci config value (web-writable)';
  const cgi = h.sources.find((s) => s.kind === 'cgi-env');
  return cgi ? `${cgi.name} (CGI env)` : 'web input';
}

/**
 * Pure: turn a tainted handler + the resolved validator/auth into honest findings. The command-injection finding
 * carries the source→sink→privilege chain (keys `source`/`sink`/`privilege`, so W9's attack-path composer renders
 * it); when the value flows through uci it also emits the config-restore→uci bypass (which sidesteps the RPC
 * validator entirely). A handler whose only sinks are argv-array/no-concat is NOT flagged.
 */
export function buildTaintFindings(
  h: HandlerAnalysis,
  validator: ValidatorInfo,
  auth: 'authenticated' | 'unauthenticated' | 'unknown',
  perObjectValidator: string | null,
): FindingDraft[] {
  if (!h.tainted) return [];
  const findings: FindingDraft[] = [];
  const sink = h.sinks.find((s) => s.concat && !s.argvArray) as SinkHit;
  const privilege = h.runsAsRoot ? 'root (handler writes root-owned paths)' : 'the httpd service user';
  const newlineInjectable = perObjectValidator ? false : validator.permitsNewline;

  // Severity: unauthenticated or a validator that lets the metachar through is critical; an authenticated,
  // per-object-validated path is a lead to verify.
  const severity = auth === 'unauthenticated' || newlineInjectable ? 'critical' : 'high';
  findings.push({
    kind: 'web-taint-cmdi',
    title: `Command injection: ${h.object} ${sink.sink} — ${describeSource(h)} → shell${h.runsAsRoot ? ' as root' : ''}`,
    severity,
    proofState: 'static_confirmed',
    evidence: {
      source: describeSource(h),
      sink: `${sink.sink} (string-concat)`,
      privilege,
      handler: h.handler,
      line: sink.line,
      snippet: sink.snippet,
      auth,
      validator: perObjectValidator
        ? `per-object validator at ${perObjectValidator}`
        : validator.pattern
          ? `default valid_rpc_args ${validator.pattern}${newlineInjectable ? ' (permits newline → directive injection)' : ''}`
          : 'no validator found (input unconstrained)',
    },
    rationale: `An exec sink is built by string-concatenation with attacker-controlled input; the resolved validator does ${
      newlineInjectable
        ? 'not block the shell/newline metacharacters, so the concatenated command is injectable. '
        : 'constrain the input — verify it blocks every metacharacter before relying on it. '
    }The source→sink→privilege chain is derived statically from the handler bytes; on-device reproduction is the dynamic webprobe step, not claimed here.`,
  });

  if (h.fromUci) {
    findings.push({
      kind: 'web-taint-restore-bypass',
      title: `Config-restore bypass: ${h.object} reads a uci value into ${sink.sink} — uci import/restore sidesteps the RPC validator`,
      severity: 'critical',
      proofState: 'static_confirmed',
      evidence: {
        source: 'config backup/restore or uci import (bypasses the RPC arg validator)',
        sink: `${sink.sink} (string-concat) via uci`,
        privilege,
        handler: h.handler,
        line: sink.line,
      },
      rationale:
        'The sink reads its input from a uci config value, not directly from the validated RPC argument. Any other ' +
        'writer of that uci key — config backup/restore, uci import — reaches the sink WITHOUT passing the RPC ' +
        'validator, so even a strict validator does not protect this path.',
    });
  }

  return findings;
}

// === Runner (walks the rootfs) ===

export interface WebTaintResult {
  available: boolean;
  handlers: HandlerAnalysis[];
  validator: ValidatorInfo;
  findings: FindingDraft[];
  reason: string;
}

/** Subtrees that hold web handlers, relative to the rootfs. */
const HANDLER_DIRS = [
  'usr/lib/oui-httpd/rpc',
  'usr/lib/lua/oui/rpc',
  'usr/libexec/rpcd',
  'www/cgi-bin',
  'www/luci-static',
  'usr/lib/lua/luci/controller',
  'www',
];
const HANDLER_EXT = /\.(lua|cgi|sh)$/;
const MAX_FILES = 400;
const MAX_FILE_SIZE = 512 * 1024;

/** Recursively list handler files under a rootfs subtree (bounded). */
function listHandlers(root: string): string[] {
  const out: string[] = [];
  const walk = (abs: string, rel: string): void => {
    if (out.length >= MAX_FILES) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (out.length >= MAX_FILES) return;
      const childAbs = path.join(abs, e.name);
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(childAbs, childRel);
      else if (
        e.isFile() &&
        (HANDLER_EXT.test(e.name) || rel.includes('oui-httpd/rpc') || rel.includes('libexec/rpcd'))
      )
        out.push(childRel);
    }
  };
  for (const d of HANDLER_DIRS) {
    const abs = path.join(root, d);
    if (fs.existsSync(abs)) walk(abs, d);
  }
  return Array.from(new Set(out));
}

/** Read the default `valid_rpc_args` validator pattern from the rootfs, if present. */
function resolveValidator(root: string): ValidatorInfo {
  for (const rel of ['usr/lib/lua/oui/rpc.lua', 'usr/share/rpcd/validator.lua', 'usr/lib/lua/rpc.lua']) {
    const abs = path.join(root, rel);
    try {
      const src = fs.readFileSync(abs, 'utf8');
      const pattern = extractRpcArgPattern(src);
      if (pattern) return { path: rel, pattern, permitsNewline: patternPermitsNewline(pattern) };
    } catch {
      /* not here */
    }
  }
  return { path: null, pattern: null, permitsNewline: true };
}

/** Collect the method names listed as needing no auth (oui-httpd `no-auth-methods` / an rpcd ACL). */
function resolveNoAuthMethods(root: string): Set<string> {
  const methods = new Set<string>();
  const candidates = [
    'usr/share/oui-httpd/no-auth.json',
    'etc/config/oui-httpd',
    'usr/share/rpcd/acl.d',
    'etc/config/rpcd',
  ];
  for (const rel of candidates) {
    const abs = path.join(root, rel);
    try {
      const stat = fs.statSync(abs);
      const files = stat.isDirectory() ? fs.readdirSync(abs).map((f) => path.join(abs, f)) : [abs];
      for (const f of files) {
        const src = fs.readFileSync(f, 'utf8');
        for (const m of src.matchAll(/no[_-]auth[_-]methods?["'\s:=\[]+([^\]}\n]*)/gi)) {
          for (const tok of (m[1] as string).matchAll(/[\w.]+/g)) methods.add(tok[0]);
        }
      }
    } catch {
      /* not here */
    }
  }
  return methods;
}

/** Does the rootfs carry a per-object validator for this object (gl-validator.d/<object>.lua)? */
function perObjectValidator(root: string, object: string): string | null {
  const rel = `usr/share/gl-validator.d/${object}.lua`;
  return fs.existsSync(path.join(root, rel)) ? rel : null;
}

/**
 * Statically taint-analyze the web handlers in an extracted rootfs. Pure analysis over the handler bytes — always
 * `available`; when the rootfs has no recognizable web handlers it degrades honestly to an empty result with a
 * reason. Each tainted handler yields the command-injection chain (and the config-restore bypass when the value
 * flows through uci); a hardened argv-array handler is correctly NOT flagged.
 */
export function runWebTaint(rootfsPath: string | null): WebTaintResult {
  if (!rootfsPath) {
    return {
      available: false,
      handlers: [],
      validator: { path: null, pattern: null, permitsNewline: true },
      findings: [],
      reason: 'no extracted rootfs',
    };
  }
  const rels = listHandlers(rootfsPath);
  if (rels.length === 0) {
    return {
      available: true,
      handlers: [],
      validator: { path: null, pattern: null, permitsNewline: true },
      findings: [],
      reason: 'no rpcd/oui-httpd/luci/cgi handlers found in the rootfs',
    };
  }

  const validator = resolveValidator(rootfsPath);
  const noAuth = resolveNoAuthMethods(rootfsPath);
  const handlers: HandlerAnalysis[] = [];
  const findings: FindingDraft[] = [];

  for (const rel of rels) {
    let src: string;
    try {
      const abs = path.join(rootfsPath, rel);
      if (fs.statSync(abs).size > MAX_FILE_SIZE) continue;
      src = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    const h = parseHandler(src, rel);
    handlers.push(h);
    if (!h.tainted) continue;
    const auth = noAuth.has(h.object) ? 'unauthenticated' : noAuth.size ? 'authenticated' : 'unknown';
    findings.push(...buildTaintFindings(h, validator, auth, perObjectValidator(rootfsPath, h.object)));
  }

  const tainted = handlers.filter((h) => h.tainted).length;
  return {
    available: true,
    handlers,
    validator,
    findings,
    reason: `Scanned ${handlers.length} web handlers, ${tainted} tainted (web-param → shell). Validator: ${validator.pattern ?? 'none found'}${validator.permitsNewline ? ' (permits newline)' : ''}. Static taint over the handler bytes — on-device reproduction is the dynamic webprobe step.`,
  };
}
