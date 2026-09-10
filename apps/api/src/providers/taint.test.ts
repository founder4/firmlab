import { describe, expect, it } from 'vitest';
import type { DecompileResult } from './decompile.js';
import { buildTaintScaffold, normalizeImport } from './taint.js';

const decompile = (over: Partial<DecompileResult>): DecompileResult => {
  const imports = over.imports ?? [];
  const strings = over.strings ?? [];
  return {
    available: true,
    binary: 'sbin/httpd',
    info: { arch: 'mips', nx: false, canary: false, pic: false },
    functionCount: 10,
    symbols: [],
    imports,
    importsTotal: imports.length,
    strings,
    stringsTotal: strings.length,
    ...over,
  };
};

describe('normalizeImport', () => {
  it('strips r2 prefixes, plt suffixes and leading underscores', () => {
    expect(normalizeImport('sym.imp.strcpy')).toBe('strcpy');
    expect(normalizeImport('system@plt')).toBe('system');
    expect(normalizeImport('_popen')).toBe('popen');
    expect(normalizeImport('imp.getenv')).toBe('getenv');
  });
});

describe('buildTaintScaffold', () => {
  it('classifies coexisting sinks and sources into a taint surface', () => {
    const s = buildTaintScaffold(
      decompile({
        imports: [
          { name: 'sym.imp.system' },
          { name: 'strcpy@plt' },
          { name: 'recv' },
          { name: 'nvram_get' },
          { name: 'malloc' },
        ],
      }),
    );
    expect(s.sinks.map((x) => x.name).sort()).toEqual(['strcpy', 'system']);
    expect(s.sinks.find((x) => x.name === 'system')?.class).toBe('command-exec');
    expect(s.sources.map((x) => x.name).sort()).toEqual(['nvram_get', 'recv']);
    expect(s.hasTaintSurface).toBe(true);
    expect(s.surfaceState).toBe('present');
  });

  it('a sink with only CGI string hints still counts as a taint surface', () => {
    const s = buildTaintScaffold(
      decompile({
        imports: [{ name: 'system' }],
        strings: [
          { addr: '0x1', value: 'QUERY_STRING' },
          { addr: '0x2', value: '/cgi-bin/admin' },
        ],
      }),
    );
    expect(s.cgiHints).toContain('QUERY_STRING');
    expect(s.hasTaintSurface).toBe(true);
  });

  it('sinks without any source or CGI hint are not yet a taint surface', () => {
    const s = buildTaintScaffold(decompile({ imports: [{ name: 'strcpy' }] }));
    expect(s.sinks).toHaveLength(1);
    expect(s.hasTaintSurface).toBe(false);
    expect(s.surfaceState).toBe('absent');
  });

  it('degraded (empty) triage yields an empty scaffold, never a guess', () => {
    const s = buildTaintScaffold(decompile({ imports: [], strings: [] }));
    expect(s.sinks).toHaveLength(0);
    expect(s.sources).toHaveLength(0);
    expect(s.hasTaintSurface).toBe(false);
    expect(s.surfaceState).toBe('absent');
  });

  it('calls an empty result unknown when the persisted import list was capped', () => {
    const s = buildTaintScaffold(decompile({ imports: [], importsTotal: 401 }));
    expect(s.hasTaintSurface).toBe(false);
    expect(s.surfaceState).toBe('unknown');
    expect(s.coverage.imports).toEqual({ listed: 0, total: 401, complete: false });
  });

  it('keeps legacy results without denominators unknown rather than backfilling completeness', () => {
    const legacy: DecompileResult = {
      available: true,
      binary: 'sbin/httpd',
      info: {},
      functionCount: 0,
      symbols: [],
      imports: [],
      strings: [],
    };
    expect(buildTaintScaffold(legacy).surfaceState).toBe('unknown');
  });
});
