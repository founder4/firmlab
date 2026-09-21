import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  type ChannelEvent,
  buildCrossTaintFindings,
  extractChannelEvents,
  findSinkMentions,
  linkChannels,
  normalizeChannelKey,
  rankAndCapChannels,
  runCrossTaint,
} from './cross-taint.js';

describe('extractChannelEvents', () => {
  it('reads the KEY=VALUE form of nvram set', () => {
    const { events } = extractChannelEvents('bin/cgi', 'nvram set lan_ipaddr=192.168.1.1');
    expect(events).toEqual([
      expect.objectContaining({ kind: 'nvram', op: 'write', key: 'lan_ipaddr', rawKey: 'lan_ipaddr' }),
    ]);
  });

  it('reads the two-arg (space-separated) form of nvram set, without double-matching the = form', () => {
    const { events } = extractChannelEvents('etc/init.d/S50wifi', 'nvram set lan_ipaddr 192.168.1.1');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ kind: 'nvram', op: 'write', key: 'lan_ipaddr' });
  });

  it('reads nvram get', () => {
    const { events } = extractChannelEvents('etc/init.d/S60boot', 'ip addr add $(nvram get lan_ipaddr)/24 dev br0');
    expect(events).toEqual([expect.objectContaining({ kind: 'nvram', op: 'read', key: 'lan_ipaddr' })]);
  });

  it('reads the nvram_get/nvram_set C-call literal forms', () => {
    const { events: w } = extractChannelEvents('usr/sbin/httpd', 'nvram_set("http_passwd", user_input)');
    expect(w).toEqual([expect.objectContaining({ kind: 'nvram', op: 'write', key: 'http_passwd' })]);
    const { events: r } = extractChannelEvents('usr/sbin/telnetd', 'char *p = nvram_get("http_passwd");');
    expect(r).toEqual([expect.objectContaining({ kind: 'nvram', op: 'read', key: 'http_passwd' })]);
  });

  it('reads uci set/get with a package.section.option address', () => {
    const { events: w } = extractChannelEvents('www/cgi-bin/luci', 'uci set network.lan.ipaddr=192.168.1.1');
    expect(w).toEqual([expect.objectContaining({ kind: 'uci', op: 'write', key: 'network.lan.ipaddr' })]);
    const { events: r } = extractChannelEvents('etc/init.d/network', 'uci -q get network.lan.ipaddr');
    expect(r).toEqual([expect.objectContaining({ kind: 'uci', op: 'read', key: 'network.lan.ipaddr' })]);
  });

  it('reads the Lua uci:get/uci:set cursor form with its explicit key', () => {
    const { events: r } = extractChannelEvents('usr/lib/lua/rpcd/network.lua', 'uci:get("network", "lan", "ipaddr")');
    expect(r).toEqual([expect.objectContaining({ kind: 'uci', op: 'read', key: 'network.lan.ipaddr' })]);
    const { events: w } = extractChannelEvents(
      'usr/lib/lua/rpcd/network.lua',
      'cursor.set("network", "lan", "ipaddr")',
    );
    expect(w).toEqual([expect.objectContaining({ kind: 'uci', op: 'write', key: 'network.lan.ipaddr' })]);
  });

  it('caps events per file and says so', () => {
    const text = Array.from({ length: 80 }, (_, i) => `nvram get key${i}`).join('\n');
    const { events, capped } = extractChannelEvents('etc/many', text, 64);
    expect(events).toHaveLength(64);
    expect(capped).toBe(true);
  });

  it('does not cap when the file stays under the bound', () => {
    const { capped } = extractChannelEvents('etc/one', 'nvram get foo', 64);
    expect(capped).toBe(false);
  });
});

describe('normalizeChannelKey', () => {
  it('trims whitespace and strips surrounding quotes', () => {
    expect(normalizeChannelKey('  "foo_bar"  ')).toBe('foo_bar');
    expect(normalizeChannelKey("'foo'")).toBe('foo');
  });
});

describe('linkChannels', () => {
  const ev = (path: string, kind: 'nvram' | 'uci', op: 'write' | 'read', key: string): ChannelEvent => ({
    path,
    kind,
    op,
    key,
    rawKey: key,
    snippet: `${op} ${key}`,
  });

  it('bridges a producer and a consumer on the exact same key', () => {
    const { channels, totalPairs } = linkChannels([
      ev('usr/sbin/httpd', 'nvram', 'write', 'lan_ipaddr'),
      ev('etc/init.d/network', 'nvram', 'read', 'lan_ipaddr'),
    ]);
    expect(totalPairs).toBe(1);
    expect(channels).toEqual([
      expect.objectContaining({
        kind: 'nvram',
        key: 'lan_ipaddr',
        producer: expect.objectContaining({ path: 'usr/sbin/httpd' }),
        consumer: expect.objectContaining({ path: 'etc/init.d/network' }),
      }),
    ]);
  });

  it('keeps nvram and uci as separate namespaces — the same key text never bridges across kinds', () => {
    const { channels, totalPairs } = linkChannels([
      ev('usr/sbin/httpd', 'nvram', 'write', 'foo'),
      ev('etc/init.d/other', 'uci', 'read', 'foo'),
    ]);
    expect(totalPairs).toBe(0);
    expect(channels).toEqual([]);
  });

  it('never links a file to itself — no same-binary duplication', () => {
    const { channels, totalPairs } = linkChannels([
      ev('usr/sbin/httpd', 'nvram', 'write', 'lan_ipaddr'),
      ev('usr/sbin/httpd', 'nvram', 'read', 'lan_ipaddr'),
      ev('etc/init.d/network', 'nvram', 'read', 'lan_ipaddr'),
    ]);
    expect(totalPairs).toBe(1);
    expect(channels).toHaveLength(1);
    expect(channels[0]?.consumer.path).toBe('etc/init.d/network');
  });

  it('produces the full cross product across multiple producers and consumers, deterministically ordered', () => {
    const { channels, totalPairs } = linkChannels([
      ev('b/writer', 'nvram', 'write', 'k'),
      ev('a/writer', 'nvram', 'write', 'k'),
      ev('z/reader', 'nvram', 'read', 'k'),
      ev('y/reader', 'nvram', 'read', 'k'),
    ]);
    expect(totalPairs).toBe(4);
    expect(channels.map((c) => `${c.producer.path}->${c.consumer.path}`)).toEqual([
      'a/writer->y/reader',
      'a/writer->z/reader',
      'b/writer->y/reader',
      'b/writer->z/reader',
    ]);
  });
});

describe('findSinkMentions', () => {
  it('finds a command-exec sink mentioned as a call', () => {
    const sinks = findSinkMentions('int main() { system(cmd); return 0; }');
    expect(sinks).toEqual([{ name: 'system', class: 'command-exec' }]);
  });

  it('finds a variable-driven shell backtick/eval, not a static one', () => {
    expect(findSinkMentions('x=`echo $val`')).toEqual([{ name: 'backtick-exec', class: 'command-exec' }]);
    expect(findSinkMentions('x=`date`')).toEqual([]); // no variable — not flagged
    expect(findSinkMentions('eval "$cmd"')).toEqual([{ name: 'eval', class: 'command-exec' }]);
  });

  it('finds nothing in ordinary text', () => {
    expect(findSinkMentions('hello world, this is a firmware banner')).toEqual([]);
  });

  it('respects the cap deterministically', () => {
    const text = 'system(a); popen(b); strcpy(c,d); strcat(e,f); sprintf(g,h); gets(i); execve(j); fopen(k)';
    const sinks = findSinkMentions(text, 3);
    expect(sinks).toHaveLength(3);
    expect(sinks).toEqual(findSinkMentions(text, 3)); // stable across calls
  });
});

describe('rankAndCapChannels + buildCrossTaintFindings', () => {
  const chan = (key: string, producer: string, consumer: string) => ({
    kind: 'nvram' as const,
    key,
    producer: { path: producer, snippet: `nvram set ${key}=1` },
    consumer: { path: consumer, snippet: `nvram get ${key}` },
  });

  it('never overclaims proof state, and marks sanitization unevaluated', () => {
    const channels = [chan('foo', 'a', 'b')];
    const findings = buildCrossTaintFindings(channels, new Map());
    expect(findings).toHaveLength(1);
    expect(findings[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(findings[0]?.kind).toBe('cross-binary-taint-channel');
    expect(findings[0]?.severity).toBe('low');
    expect((findings[0]?.evidence as Record<string, unknown>).sanitizationEvaluated).toBe(false);
    expect(findings[0]?.rationale).toMatch(/NOT a claim about execution order/);
    expect(findings[0]?.rationale).toMatch(/NOT a claim about sanitization/);
  });

  it('raises severity, never proof state, when the consumer mentions a dangerous sink', () => {
    const channels = [chan('foo', 'a', 'b')];
    const sinksByPath = new Map([['b', [{ name: 'system', class: 'command-exec' as const }]]]);
    const findings = buildCrossTaintFindings(channels, sinksByPath);
    expect(findings[0]?.kind).toBe('cross-binary-taint-channel-sink');
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(findings[0]?.rationale).toMatch(/system \(command-exec\)/);
  });

  it('caps deterministically, ranks sink-bearing channels first, and states the true denominator', () => {
    const channels = [chan('a', 'p1', 'c1'), chan('b', 'p2', 'c2'), chan('c', 'p3', 'c3')];
    const sinksByPath = new Map([['c3', [{ name: 'system', class: 'command-exec' as const }]]]);
    const { kept, dropped } = rankAndCapChannels(channels, sinksByPath, 2);
    expect(dropped).toBe(1);
    expect(kept.map((c) => c.key)).toEqual(['c', 'a']); // sink-bearing first, then key order
  });
});

describe('runCrossTaint (end to end over a real rootfs directory)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cross-taint-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('degrades honestly with no rootfs', () => {
    const r = runCrossTaint(null);
    expect(r.available).toBe(false);
    expect(r.findings).toEqual([]);
  });

  it('finds the bridge, attaches the consumer sink, and reports exact-key evidence end to end', () => {
    const root = path.join(tmp, 'rootfs-basic');
    fs.mkdirSync(path.join(root, 'www/cgi-bin'), { recursive: true });
    fs.mkdirSync(path.join(root, 'etc/init.d'), { recursive: true });
    fs.writeFileSync(path.join(root, 'www/cgi-bin/wan.cgi'), '#!/bin/sh\nnvram set wan_pppoe_pass="$1"\n');
    fs.writeFileSync(
      path.join(root, 'etc/init.d/pppoe'),
      '#!/bin/sh\np=$(nvram get wan_pppoe_pass)\nsystem("pppd password $p")\n',
    );

    const r = runCrossTaint(root);
    expect(r.available).toBe(true);
    expect(r.eventsFound).toBe(2);
    expect(r.channelsFound).toBe(1);
    const f = r.findings.find((x) => x.kind === 'cross-binary-taint-channel-sink');
    expect(f).toBeTruthy();
    const ev = f?.evidence as Record<string, unknown>;
    expect(ev.key).toBe('wan_pppoe_pass');
    expect((ev.producer as Record<string, unknown>).path).toBe('www/cgi-bin/wan.cgi');
    expect((ev.consumer as Record<string, unknown>).path).toBe('etc/init.d/pppoe');
  });

  it('does not link a script that only reads its own key — no same-binary duplication end to end', () => {
    const root = path.join(tmp, 'rootfs-self');
    fs.mkdirSync(path.join(root, 'etc/init.d'), { recursive: true });
    fs.writeFileSync(path.join(root, 'etc/init.d/solo'), 'nvram set foo=1\nnvram get foo\n');

    const r = runCrossTaint(root);
    expect(r.eventsFound).toBe(2);
    expect(r.channelsFound).toBe(0);
    expect(r.findings).toEqual([]);
  });

  it('reports zero findings, not an error, when no rootfs file mentions nvram/uci', () => {
    const root = path.join(tmp, 'rootfs-clean');
    fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(root, 'bin/hello'), 'echo hello world\n');
    const r = runCrossTaint(root);
    expect(r.available).toBe(true);
    expect(r.eventsFound).toBe(0);
    expect(r.findings).toEqual([]);
  });
});
