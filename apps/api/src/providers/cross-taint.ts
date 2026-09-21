/**
 * Cross-binary taint scaffold — a bounded, deterministic answer to the one question a single-binary view cannot
 * ask: does a firmware's persistent key-value stores (nvram / UCI) connect a binary or script that WRITES a key to
 * a different binary or script that READS the very same key? `taint.ts` (Phase 4) and `webtaint.ts` (W4) both stop
 * at one file's own source/sink pair; a router's actual attack surface routinely crosses a process boundary
 * through nvram or UCI instead — a CGI handler writes `lan_ipaddr`, and a completely different init script or
 * daemon reads it straight into a shell command. Neither existing provider can see that link because neither one
 * looks at a SECOND file.
 *
 * The evidence this scans for is deliberately narrow: literal `nvram get/set`, `nvram_get`/`nvram_set`, `uci
 * get/set` and the Lua `uci:get`/`uci:set` cursor calls `webtaint.ts` already recognises as a UCI source — the
 * shapes a shell script or an embedded command string in an ELF's own bytes can carry UNAMBIGUOUSLY. A binary that
 * merely IMPORTS `nvram_get` (which `taint.ts` already reports) tells you nothing about WHICH key, so it is not
 * evidence for this module; only a literal key string is.
 *
 * What a channel finding claims, and what it refuses to: the SAME normalized key is written in one file and read
 * in a DIFFERENT file — nothing more. It does NOT claim the write happens before the read (there is no execution
 * trace here, and the same key may be read on a boot before it is ever written), does NOT claim the read value
 * reaches whatever dangerous sink the consumer's own bytes separately mention (that would be a resolved call graph,
 * which this module does not build), and does NOT claim anything about sanitization on either side. Every channel
 * therefore stays `needs_runtime_reproduction`, unconditionally — this is a lead generator, not a verdict, exactly
 * like `symreach`'s reachability claim is bounded to reachability and no further.
 *
 * Producer/consumer linking, the consumer-side sink scan and the cap/rank are pure and unit-tested; `runCrossTaint`
 * only walks the rootfs and reads bounded file prefixes — no external tool, no network, nothing written back to
 * the corpus. Deliberately out of scope for this scaffold: wiring a `cross-taint` stage into `specsForClass` (the
 * plan DAG, `coverage.ts` and the W9 executor switch are a materially larger change than a bounded scaffold asks
 * for); a future pass can add that once this shape has been run against real corpus images. What IS wired is the
 * one opacidad lead this module's own output justifies — see `crossTaintDecompileLeads` in `opacidad-leads.ts`.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';
import { SINKS, type SinkClass } from './taint.js';

// === Channel events (pure) ===

export type ChannelKind = 'nvram' | 'uci';
export type ChannelOp = 'write' | 'read';

export interface ChannelEvent {
  path: string;
  kind: ChannelKind;
  op: ChannelOp;
  /** Normalized — what linking matches on. */
  key: string;
  /** As it appeared in the text, before normalization. */
  rawKey: string;
  /** A bounded excerpt around the match, so a reader can see the literal command without opening the file. */
  snippet: string;
}

/** Most events kept per file — a firmware script touching hundreds of keys is not plausible; a runaway regex is. */
export const MAX_EVENTS_PER_SOURCE = 64;

/** An nvram/UCI key token: letters, digits, `_ . : -`, starting with a letter or underscore. */
const KEY_TOKEN = '[A-Za-z_][\\w.:-]{0,63}';
/** A UCI address: `package.section` or `package.section.option` — the two forms `uci get/set` actually accept. */
const UCI_ADDR = '[A-Za-z_][\\w-]*\\.[A-Za-z_][\\w-]*(?:\\.[A-Za-z_][\\w-]*)?';

const NVRAM_SET_EQ_RE = new RegExp(`\\bnvram\\s+set\\s+(${KEY_TOKEN})=`, 'g');
const NVRAM_SET_SP_RE = new RegExp(`\\bnvram\\s+set\\s+(${KEY_TOKEN})\\s+\\S`, 'g');
const NVRAM_SET_FN_RE = new RegExp(`\\bnvram_set\\s*\\(\\s*["'](${KEY_TOKEN})["']`, 'g');
const NVRAM_GET_RE = new RegExp(`\\bnvram\\s+get\\s+(${KEY_TOKEN})\\b`, 'g');
const NVRAM_GET_FN_RE = new RegExp(`\\bnvram_(?:bufget|safe_get|get)\\s*\\(\\s*["'](${KEY_TOKEN})["']`, 'g');

const UCI_SET_RE = new RegExp(`\\buci\\s+(?:-q\\s+)?set\\s+(${UCI_ADDR})\\s*=`, 'g');
const UCI_GET_RE = new RegExp(`\\buci\\s+(?:-q\\s+)?get\\s+(${UCI_ADDR})\\b`, 'g');
/** The Lua cursor form `webtaint.ts` already recognises as a bare `uci:get` source — recovered here WITH its key. */
const UCI_CURSOR_RE =
  /\b(?:uci|cursor)[:.](get|set)\s*\(\s*["']([\w-]+)["']\s*,\s*["']([\w-]+)["'](?:\s*,\s*["']([\w-]+)["'])?/g;

/** Pure: normalize a raw key for matching — trim and strip the quotes a regex sometimes leaves at the edges. */
export function normalizeChannelKey(rawKey: string): string {
  return rawKey.trim().replace(/^["']+|["']+$/g, '');
}

function snippetAt(text: string, index: number, matchLen: number): string {
  const start = Math.max(0, index - 8);
  const end = Math.min(text.length, index + matchLen + 40);
  return text
    .slice(start, end)
    .replace(/[\r\n\t]+/g, ' ')
    .trim()
    .slice(0, 160);
}

/**
 * Pure: scan one file's text (a shell/Lua script read verbatim, or an ELF's raw bytes decoded as latin1 so an
 * embedded command string reads unmangled) for literal nvram/UCI read/write commands. Capped per file — see
 * `MAX_EVENTS_PER_SOURCE` — and `capped` says whether the bound actually cut anything, rather than the caller
 * having to infer it from the array length matching the cap by coincidence.
 */
export function extractChannelEvents(
  sourcePath: string,
  text: string,
  cap = MAX_EVENTS_PER_SOURCE,
): { events: ChannelEvent[]; capped: boolean } {
  const out: ChannelEvent[] = [];
  let overflow = false;
  const push = (kind: ChannelKind, op: ChannelOp, rawKey: string, index: number, matchLen: number): void => {
    const key = normalizeChannelKey(rawKey);
    if (!key) return;
    if (out.length >= cap) {
      overflow = true;
      return;
    }
    out.push({ path: sourcePath, kind, op, key, rawKey, snippet: snippetAt(text, index, matchLen) });
  };

  for (const m of text.matchAll(NVRAM_SET_EQ_RE)) push('nvram', 'write', m[1] as string, m.index ?? 0, m[0].length);
  for (const m of text.matchAll(NVRAM_SET_SP_RE)) push('nvram', 'write', m[1] as string, m.index ?? 0, m[0].length);
  for (const m of text.matchAll(NVRAM_SET_FN_RE)) push('nvram', 'write', m[1] as string, m.index ?? 0, m[0].length);
  for (const m of text.matchAll(NVRAM_GET_RE)) push('nvram', 'read', m[1] as string, m.index ?? 0, m[0].length);
  for (const m of text.matchAll(NVRAM_GET_FN_RE)) push('nvram', 'read', m[1] as string, m.index ?? 0, m[0].length);

  for (const m of text.matchAll(UCI_SET_RE)) push('uci', 'write', m[1] as string, m.index ?? 0, m[0].length);
  for (const m of text.matchAll(UCI_GET_RE)) push('uci', 'read', m[1] as string, m.index ?? 0, m[0].length);
  for (const m of text.matchAll(UCI_CURSOR_RE)) {
    const op: ChannelOp = m[1] === 'set' ? 'write' : 'read';
    const addr = m[4] ? `${m[2]}.${m[3]}.${m[4]}` : `${m[2]}.${m[3]}`;
    push('uci', op, addr, m.index ?? 0, m[0].length);
  }

  return { events: out, capped: overflow };
}

// === Linking (pure) ===

export interface CrossBinaryChannel {
  kind: ChannelKind;
  key: string;
  producer: { path: string; snippet: string };
  consumer: { path: string; snippet: string };
}

/**
 * Pure: pair every WRITE of a key with every READ of the SAME normalized key in a DIFFERENT file. Namespace is
 * part of the match key (`kind:key`), so an nvram key and a UCI key that happen to share the same text never
 * link — an nvram `lan_ipaddr` and a UCI `network.lan.ipaddr` are different stores and this never claims they are
 * the same value. A file that both writes and reads a key is excluded from its own pairing (`p === c` below):
 * that is one file's own read-after-write, already `taint.ts`/`webtaint.ts` territory, not a cross-binary channel.
 *
 * Deterministic regardless of the order `events` arrives in: events are sorted before grouping, so which producer
 * snippet a channel carries (when several writers exist for one key) is a function of the key set alone, never of
 * a filesystem walk order. `totalPairs` is the TRUE count before any cap — the denominator a bound must be read
 * against.
 */
export function linkChannels(events: ChannelEvent[]): { channels: CrossBinaryChannel[]; totalPairs: number } {
  const sorted = [...events].sort(
    (a, b) => a.path.localeCompare(b.path) || a.kind.localeCompare(b.kind) || a.key.localeCompare(b.key),
  );
  const groups = new Map<string, { writes: Map<string, ChannelEvent>; reads: Map<string, ChannelEvent> }>();
  for (const e of sorted) {
    const gk = `${e.kind}:${e.key}`;
    let g = groups.get(gk);
    if (!g) {
      g = { writes: new Map(), reads: new Map() };
      groups.set(gk, g);
    }
    const bucket = e.op === 'write' ? g.writes : g.reads;
    if (!bucket.has(e.path)) bucket.set(e.path, e);
  }

  const channels: CrossBinaryChannel[] = [];
  let totalPairs = 0;
  for (const gk of [...groups.keys()].sort()) {
    const g = groups.get(gk) as { writes: Map<string, ChannelEvent>; reads: Map<string, ChannelEvent> };
    const producers = [...g.writes.keys()].sort();
    const consumers = [...g.reads.keys()].sort();
    for (const p of producers) {
      for (const c of consumers) {
        if (p === c) continue; // no same-binary duplication
        totalPairs++;
        const wEvt = g.writes.get(p) as ChannelEvent;
        const rEvt = g.reads.get(c) as ChannelEvent;
        channels.push({
          kind: wEvt.kind,
          key: wEvt.key,
          producer: { path: p, snippet: wEvt.snippet },
          consumer: { path: c, snippet: rEvt.snippet },
        });
      }
    }
  }
  return { channels, totalPairs };
}

// === Consumer-side dangerous sinks (pure) ===

export type SinkMention = { name: string; class: SinkClass };

/** Most sink mentions kept per consumer file — enough to be useful, small enough to stay a summary. */
export const MAX_SINK_MENTIONS = 8;

/**
 * Shell dynamic-execution primitives, restricted to the VARIABLE-driven form (a literal `` `date` `` or `$(date)`
 * with no `$` inside is a fixed command and not a plausible sink for a value read moments earlier) — the same
 * "only flag when built from a variable" discipline `webtaint.ts`'s `concat` check already uses for Lua sinks.
 */
const SHELL_DYNAMIC_EXEC: { name: string; class: SinkClass; re: RegExp }[] = [
  { name: 'eval', class: 'command-exec', re: /\beval\s+["']?\$/ },
  { name: 'backtick-exec', class: 'command-exec', re: /`[^`]*\$[^`]*`/ },
  { name: 'command-substitution', class: 'command-exec', re: /\$\([^)]*\$[^)]*\)/ },
];

/**
 * Pure: does this file's own text separately mention a dangerous sink? Reuses `taint.ts`'s `SINKS` vocabulary as a
 * TEXTUAL match (`\bsystem\s*\(`, not an import-table lookup) plus the three shell primitives above. This is
 * weaker evidence than `taint.ts`'s import-based classification — a string mentioning `system(` is not proof the
 * binary calls it, exactly as `binvuln.ts`'s strings-superset fallback already documents for the same reason — and
 * it is NOT a claim that the sink consumes the key this file read; the finding built from it says so explicitly.
 */
export function findSinkMentions(text: string, cap = MAX_SINK_MENTIONS): SinkMention[] {
  const out: SinkMention[] = [];
  for (const name of Object.keys(SINKS).sort()) {
    if (out.length >= cap) break;
    if (new RegExp(`\\b${name}\\s*\\(`).test(text)) out.push({ name, class: SINKS[name] as SinkClass });
  }
  for (const s of SHELL_DYNAMIC_EXEC) {
    if (out.length >= cap) break;
    if (s.re.test(text)) out.push({ name: s.name, class: s.class });
  }
  return out;
}

// === Rank + cap (pure) ===

export const MAX_CHANNELS = 150;

/**
 * Pure: order channels worth listing first, then cut at `cap`. A channel whose consumer mentions a dangerous sink
 * ranks first — it is the stronger lead — then ties break on kind/key/producer/consumer, a total order over the
 * channel set itself and never over the order the walk happened to find its files in (the same discipline
 * `binvuln.ts`'s `selectFindings` documents at length: a bound must not be an artifact of directory layout).
 */
export function rankAndCapChannels(
  channels: CrossBinaryChannel[],
  sinksByPath: ReadonlyMap<string, SinkMention[]>,
  cap = MAX_CHANNELS,
): { kept: CrossBinaryChannel[]; dropped: number } {
  const hasSink = (c: CrossBinaryChannel): boolean => (sinksByPath.get(c.consumer.path)?.length ?? 0) > 0;
  const ordered = [...channels].sort(
    (a, b) =>
      Number(hasSink(b)) - Number(hasSink(a)) ||
      a.kind.localeCompare(b.kind) ||
      a.key.localeCompare(b.key) ||
      a.producer.path.localeCompare(b.producer.path) ||
      a.consumer.path.localeCompare(b.consumer.path),
  );
  const boundedCap = Math.max(0, cap);
  const kept = ordered.slice(0, boundedCap);
  return { kept, dropped: Math.max(0, channels.length - kept.length) };
}

// === Findings (pure) ===

/**
 * Pure: one finding per kept channel. Always `needs_runtime_reproduction` — see the module header for the three
 * things this deliberately does not claim (order, control-flow linkage to the sink, sanitization). Severity is
 * `medium` only when the consumer separately mentions a dangerous sink (still a lead, never a proof); a bare
 * channel with no sink mention is `low` — a persistent link worth knowing about, not yet a danger.
 */
export function buildCrossTaintFindings(
  channels: CrossBinaryChannel[],
  sinksByPath: ReadonlyMap<string, SinkMention[]>,
): FindingDraft[] {
  return channels.map((c) => {
    const sinks = sinksByPath.get(c.consumer.path) ?? [];
    const hasSink = sinks.length > 0;
    return {
      kind: hasSink ? 'cross-binary-taint-channel-sink' : 'cross-binary-taint-channel',
      title: `${c.kind} key '${c.key}': written by ${c.producer.path}, read by ${c.consumer.path}${
        hasSink ? ` (consumer mentions ${sinks.map((s) => s.name).join('/')})` : ''
      }`,
      severity: hasSink ? 'medium' : 'low',
      proofState: 'needs_runtime_reproduction',
      evidenceChannel: 'static_bytes',
      evidence: {
        channelKind: c.kind,
        key: c.key,
        producer: c.producer,
        consumer: { path: c.consumer.path, snippet: c.consumer.snippet, sinks },
        sanitizationEvaluated: false,
      },
      rationale: [
        `${c.producer.path} writes the ${c.kind} key '${c.key}' (\`${c.producer.snippet}\`) and ${c.consumer.path} `,
        `reads the SAME normalized key (\`${c.consumer.snippet}\`) in a different binary/script — a persistent `,
        `cross-binary channel through the ${c.kind} key-value store. `,
        hasSink
          ? `${c.consumer.path}'s own bytes also mention ${sinks
              .map((s) => `${s.name} (${s.class})`)
              .join(', ')}, so a dangerous sink is present in the same file that reads this key. `
          : 'No dangerous-sink mention was found in the consumer, so this is reported as a bare channel. ',
        'This is NOT a claim about execution order (the read may run before the key is ever written, on a different ',
        'boot, or never at all), NOT a claim that the read value reaches the sink in control flow (the sink mention ',
        'is a textual fact about the file, not a resolved call graph), and NOT a claim about sanitization on either ',
        'side (unevaluated and unknown). It is a lead needing runtime reproduction to settle any of the three.',
      ].join(''),
    };
  });
}

// === Runner ===

export interface CrossTaintResult {
  available: boolean;
  reason: string;
  filesScanned: number;
  eventsFound: number;
  /** Producer/consumer pairs found across different files, before the cap — the denominator `capped` reads against. */
  channelsFound: number;
  findings: FindingDraft[];
  capped: boolean;
}

const WALK_CAP = 12000;
const FILE_SCAN_CAP = 4000;
const FILE_READ_CAP = 2 * 1024 * 1024;

function unavailable(reason: string): CrossTaintResult {
  return { available: false, reason, filesScanned: 0, eventsFound: 0, channelsFound: 0, findings: [], capped: false };
}

/** Read a bounded prefix of a file as latin1 — decodes both plain scripts and an ELF's raw bytes without mangling. */
function readBoundedText(abs: string): string {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      const len = Math.min(size, FILE_READ_CAP);
      if (len === 0) return '';
      const b = Buffer.allocUnsafe(len);
      fs.readSync(fd, b, 0, len, 0);
      return b.toString('latin1');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

/**
 * Walk an extracted rootfs, extract nvram/UCI channel events from every regular file (bounded prefix, no tool
 * shelled out to), link producers to consumers, attach each consumer's own dangerous-sink mentions, and compose
 * findings for what survives the cap. Honest at every bound: no rootfs → `available:false`; the walk, per-file
 * event and channel caps are all named in `reason` when they actually cut something, never silently.
 */
export function runCrossTaint(rootfsPath: string | null): CrossTaintResult {
  if (!rootfsPath) return unavailable('No extracted rootfs.');
  const root = path.resolve(rootfsPath);
  try {
    if (!fs.statSync(root).isDirectory()) throw new Error('not a dir');
  } catch {
    return unavailable('No extracted rootfs.');
  }

  const eventsBySource = new Map<string, ChannelEvent[]>();
  const textBySource = new Map<string, string>();
  let walked = 0;
  let filesScanned = 0;
  let filesWithCappedEvents = 0;
  const stack: string[] = [root];
  while (stack.length > 0 && walked < WALK_CAP && filesScanned < FILE_SCAN_CAP) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    // Sorted so which files fit under FILE_SCAN_CAP is a fact about the rootfs, not about the walking machine.
    entries.sort((a, b) => a.name.localeCompare(b.name));
    const subdirs: string[] = [];
    for (const e of entries) {
      if (walked >= WALK_CAP || filesScanned >= FILE_SCAN_CAP) break;
      walked++;
      if (e.isSymbolicLink()) continue; // never followed — see binvuln.ts for why
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        subdirs.push(abs);
        continue;
      }
      if (!e.isFile()) continue;
      filesScanned++;
      const rel = path.relative(root, abs).split(path.sep).join('/');
      const text = readBoundedText(abs);
      if (!text) continue;
      const { events, capped } = extractChannelEvents(rel, text);
      if (capped) filesWithCappedEvents++;
      if (events.length > 0) {
        eventsBySource.set(rel, events);
        textBySource.set(rel, text);
      }
    }
    for (let i = subdirs.length - 1; i >= 0; i--) stack.push(subdirs[i] as string);
  }

  const allEvents = [...eventsBySource.values()].flat();
  const { channels, totalPairs } = linkChannels(allEvents);

  const sinksByPath = new Map<string, SinkMention[]>();
  for (const c of channels) {
    if (sinksByPath.has(c.consumer.path)) continue;
    sinksByPath.set(c.consumer.path, findSinkMentions(textBySource.get(c.consumer.path) ?? ''));
  }

  const { kept, dropped } = rankAndCapChannels(channels, sinksByPath);
  const findings = buildCrossTaintFindings(kept, sinksByPath);
  const withSink = kept.filter((c) => (sinksByPath.get(c.consumer.path)?.length ?? 0) > 0).length;

  const capNote =
    dropped > 0
      ? ` The ${MAX_CHANNELS}-channel cap lists ${kept.length} of ${totalPairs} producer/consumer pair(s) and drops ${dropped} — pairs whose consumer mentions a dangerous sink are kept first, then ordered by key and path, never by walk order.`
      : '';
  const eventCapNote =
    filesWithCappedEvents > 0
      ? ` ${filesWithCappedEvents} file(s) hit the ${MAX_EVENTS_PER_SOURCE}-event-per-file cap; further events in those files were not read.`
      : '';
  const walkNote =
    walked >= WALK_CAP
      ? ` The ${WALK_CAP}-entry walk budget was exhausted; entries beyond it were never reached.`
      : filesScanned >= FILE_SCAN_CAP
        ? ` The ${FILE_SCAN_CAP}-file scan budget was exhausted; files beyond it were never opened.`
        : '';

  return {
    available: true,
    filesScanned,
    eventsFound: allEvents.length,
    channelsFound: totalPairs,
    findings,
    capped: dropped > 0,
    reason: `Cross-binary taint scaffold: ${filesScanned} file(s) scanned, ${allEvents.length} nvram/UCI event(s), ${totalPairs} producer/consumer pair(s) across different binaries/scripts (${withSink} with a consumer-side dangerous-sink mention).${capNote}${eventCapNote}${walkNote} Every channel stays needs_runtime_reproduction: no execution order, control-flow link to the sink, or sanitization is asserted — only that the same normalized key is written in one file and read in another.`,
  };
}
