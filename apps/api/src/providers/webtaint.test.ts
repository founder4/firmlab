import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  buildTaintFindings,
  extractRpcArgPattern,
  parseHandler,
  patternPermitsNewline,
  runWebTaint,
} from './webtaint.js';

// The real GL.iNet Tor RPC handler shape: params → uci → os.execute string-concat, running as root.
const TOR_HANDLER = `
local M = {}
local uci = require("uci").cursor()

function M.set_config(params)
    uci:set("tor", "global", "countries", params.countries)
    uci:commit("tor")
end

function replace_country()
    local countries = uci:get("tor", "global", "countries")
    os.execute("echo \\"ExitNodes " .. countries .. "\\" >> /etc/tor/torrc")
    os.execute("/etc/init.d/tor restart")
end

return M
`;

// The hardened diag handler: an argv-array spawn, no shell, no string concat — the negative control.
const DIAG_HANDLER = `
local M = {}
function M.ping(params)
    local host = params.host
    local proc = ngx.pipe.spawn({"ping", "-c", "1", host})
    return proc:wait()
end
return M
`;

const VALIDATOR = `
local function valid_rpc_args(args)
    for _, v in pairs(args) do
        if not tostring(v):match("^[%w%.%s%-_:#/]-$") then
            return false
        end
    end
    return true
end
`;

describe('parseHandler', () => {
  it('flags the Tor handler as tainted: concat exec sink + web/uci source, running as root', () => {
    const h = parseHandler(TOR_HANDLER, 'usr/lib/oui-httpd/rpc/tor.lua');
    expect(h.object).toBe('tor');
    expect(h.tainted).toBe(true);
    expect(h.fromUci).toBe(true);
    expect(h.runsAsRoot).toBe(true);
    expect(h.sinks.some((s) => s.sink === 'os.execute' && s.concat && !s.argvArray)).toBe(true);
    expect(h.sources.some((s) => s.kind === 'param' && s.name === 'countries')).toBe(true);
  });

  it('does NOT flag the hardened argv-array diag handler', () => {
    const h = parseHandler(DIAG_HANDLER, 'usr/lib/oui-httpd/rpc/diag.lua');
    expect(h.tainted).toBe(false);
    expect(h.sinks.some((s) => s.argvArray)).toBe(true);
  });

  it('does not treat a pure string-literal exec as tainted', () => {
    const h = parseHandler('os.execute("reboot")', 'x.lua');
    expect(h.tainted).toBe(false);
  });
});

describe('extractRpcArgPattern / patternPermitsNewline', () => {
  it('extracts the anchored valid_rpc_args lua-pattern', () => {
    expect(extractRpcArgPattern(VALIDATOR)).toBe('^[%w%.%s%-_:#/]-$');
  });

  it('models %s as permitting a newline (the torrc-injection primitive)', () => {
    expect(patternPermitsNewline('^[%w%.%s%-_:#/]-$')).toBe(true);
  });

  it('an anchored allow-list without %s blocks the newline', () => {
    expect(patternPermitsNewline('^[%w%-_]+$')).toBe(false);
  });

  it('no validator → nothing constrains the input', () => {
    expect(patternPermitsNewline(null)).toBe(true);
  });
});

describe('buildTaintFindings', () => {
  const h = parseHandler(TOR_HANDLER, 'usr/lib/oui-httpd/rpc/tor.lua');
  const validator = { path: 'usr/lib/lua/oui/rpc.lua', pattern: '^[%w%.%s%-_:#/]-$', permitsNewline: true };
  const findings = buildTaintFindings(h, validator, 'authenticated', null);

  it('emits a critical cmdi finding with the source→sink→privilege chain in evidence', () => {
    const cmdi = findings.find((f) => f.kind === 'web-taint-cmdi');
    expect(cmdi?.severity).toBe('critical');
    expect(cmdi?.proofState).toBe('static_confirmed');
    const ev = cmdi?.evidence as { source: string; sink: string; privilege: string };
    expect(ev.source).toContain('uci');
    expect(ev.sink).toContain('os.execute');
    expect(ev.privilege).toContain('root');
  });

  it('emits the config-restore→uci bypass finding', () => {
    expect(findings.some((f) => f.kind === 'web-taint-restore-bypass')).toBe(true);
  });

  it('downgrades to high when a per-object validator is present', () => {
    const f = buildTaintFindings(h, validator, 'authenticated', 'usr/share/gl-validator.d/tor.lua');
    expect(f.find((x) => x.kind === 'web-taint-cmdi')?.severity).toBe('high');
  });
});

describe('runWebTaint (over a synthetic GL.iNet rootfs)', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-webtaint-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

  const write = (rel: string, content: string): void => {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  };
  write('usr/lib/oui-httpd/rpc/tor.lua', TOR_HANDLER);
  write('usr/lib/oui-httpd/rpc/diag.lua', DIAG_HANDLER);
  write('usr/lib/lua/oui/rpc.lua', VALIDATOR);
  write('usr/share/oui-httpd/no-auth.json', '{"no-auth-methods":["challenge","login"]}');

  const res = runWebTaint(root);

  it('flags the Tor handler and not the diag handler', () => {
    expect(res.available).toBe(true);
    expect(res.handlers.find((h) => h.object === 'tor')?.tainted).toBe(true);
    expect(res.handlers.find((h) => h.object === 'diag')?.tainted).toBe(false);
    expect(res.findings.some((f) => f.kind === 'web-taint-cmdi')).toBe(true);
    expect(res.findings.some((f) => f.kind === 'web-taint-restore-bypass')).toBe(true);
  });

  it('resolves the default validator and models it permitting a newline', () => {
    expect(res.validator.pattern).toBe('^[%w%.%s%-_:#/]-$');
    expect(res.validator.permitsNewline).toBe(true);
  });

  it('degrades honestly when there is no rootfs', () => {
    expect(runWebTaint(null).available).toBe(false);
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-empty-'));
    expect(runWebTaint(empty).findings).toHaveLength(0);
    fs.rmSync(empty, { recursive: true, force: true });
  });
});
