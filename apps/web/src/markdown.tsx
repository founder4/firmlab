/**
 * A small, dependency-free Markdown renderer for the prose the LLM lanes produce.
 *
 * Three surfaces in this workbench show text that is *authored* as Markdown and was being shown as its source:
 * the research brief (`research/`), the copilot interpretation, and the autonomous scan's narrative — and the
 * narrative is Markdown even with every LLM flag off, because `composeDeterministicNarrative` writes headings,
 * bullets and `code` spans by hand. So this is not a nicety for the AI lanes; the deterministic path needed it too.
 *
 * **Why hand-rolled.** The web package has three runtime dependencies (react, react-dom, react-router) and no
 * chart library — visuals are hand-drawn SVG. A Markdown pipeline (`marked` + a sanitiser, or `react-markdown`
 * with the unified/remark tree) is a large transitive surface to accept for four panels of prose in a tool whose
 * selling point is that it runs with no network and nothing it did not bring itself.
 *
 * **Why it never touches `innerHTML`.** This renders text a language model wrote, and on the research lane that
 * text is *derived from documents fetched off the internet*. `dangerouslySetInnerHTML` would make a sanitiser
 * mandatory and make one missed escape a script injection into a page holding firmware analysis. Emitting React
 * elements makes that class of bug unreachable: every leaf is a JSX string, so any HTML the model emits is shown
 * verbatim, as the source it is, which is also the honest thing to do with a model's output.
 *
 * Link hrefs are the one place a string becomes a capability, so `safeHref` allows only `http(s):` and `mailto:`
 * — a `javascript:` URL renders as inert label text. A bare `#` fragment is refused for a second reason: this app
 * is a HashRouter, so a `#` href is not an anchor here, it is a route change that would throw the reader out of
 * the panel they were reading (the brief in the live corpus emits exactly that, as `[[OSV](#)]`).
 *
 * The grammar is the subset these three producers actually emit — ATX headings, fenced code, blockquotes, bullet
 * and ordered lists (nested), pipe tables, thematic breaks, and inline code/strong/em/strike/link/autolink. It is
 * deliberately not CommonMark. The one place it follows the spec closely is intraword `_`, because this codebase's
 * prose is full of `needs_runtime_reproduction` and `wg_client`, and a naive `_…_` rule renders those in italics
 * with the underscores eaten — which corrupts a proof state, the one string the workbench must never restate.
 */
import { Fragment, type JSX, type ReactNode } from 'react';

// ---------------------------------------------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------------------------------------------

export type Inline =
  | { k: 'text'; v: string }
  | { k: 'code'; v: string }
  | { k: 'strong'; v: Inline[] }
  | { k: 'em'; v: Inline[] }
  | { k: 'del'; v: Inline[] }
  | { k: 'link'; v: Inline[]; href: string };

export type Block =
  | { k: 'h'; level: number; text: string }
  | { k: 'p'; text: string }
  | { k: 'list'; ordered: boolean; start: number; items: Block[][] }
  | { k: 'quote'; blocks: Block[] }
  | { k: 'code'; text: string; lang: string }
  | { k: 'hr' }
  | { k: 'table'; head: string[]; align: ('left' | 'right' | 'center')[]; rows: string[][] };

// ---------------------------------------------------------------------------------------------------------------
// Block parsing
// ---------------------------------------------------------------------------------------------------------------

const RE_FENCE = /^ {0,3}(`{3,}|~{3,})[ \t]*([^\s`]*)[ \t]*$/;
const RE_HR = /^ {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/;
const RE_HEADING = /^ {0,3}(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$/;
const RE_QUOTE = /^ {0,3}>[ \t]?(.*)$/;
const RE_ITEM = /^([ \t]*)([-*+]|\d{1,9}[.)])[ \t]+(.*)$/;
const RE_DELIM_ROW = /^ {0,3}\|?[ \t]*:?-+:?[ \t]*(\|[ \t]*:?-+:?[ \t]*)*\|?[ \t]*$/;

/** A tab is four columns here; the exact width only has to be consistent for nested-list indent comparisons. */
const indentOf = (s: string): number => s.replace(/\t/g, '    ').length;

const splitRow = (line: string): string[] =>
  line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((c) => c.trim());

/**
 * Parse Markdown into blocks. Exported because this is the half worth testing: the renderer below is a switch,
 * the grammar is where a proof state gets eaten by an emphasis rule.
 */
export function parseBlocks(src: string): Block[] {
  const lines = src.replace(/\r\n?/g, '\n').split('\n');
  const out: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i] ?? '';
    if (!line.trim()) {
      i++;
      continue;
    }

    const fence = RE_FENCE.exec(line);
    if (fence) {
      const marker = fence[1] ?? '```';
      const closer = new RegExp(`^ {0,3}\\${marker[0]}{${marker.length},}[ \t]*$`);
      const body: string[] = [];
      i++;
      while (i < lines.length && !closer.test(lines[i] ?? '')) {
        body.push(lines[i] ?? '');
        i++;
      }
      // An unclosed fence runs to the end of the document — the same forgiveness every renderer shows, and the
      // one a truncated model response actually produces.
      if (i < lines.length) i++;
      out.push({ k: 'code', text: body.join('\n'), lang: fence[2] ?? '' });
      continue;
    }

    // Before the list rule: `---` and `***` are thematic breaks, and `- - -` would otherwise parse as a bullet.
    if (RE_HR.test(line)) {
      out.push({ k: 'hr' });
      i++;
      continue;
    }

    const heading = RE_HEADING.exec(line);
    if (heading) {
      out.push({ k: 'h', level: (heading[1] ?? '#').length, text: heading[2] ?? '' });
      i++;
      continue;
    }

    if (RE_QUOTE.test(line)) {
      const body: string[] = [];
      while (i < lines.length) {
        const q = RE_QUOTE.exec(lines[i] ?? '');
        if (q) {
          body.push(q[1] ?? '');
          i++;
        } else if ((lines[i] ?? '').trim() && !RE_HR.test(lines[i] ?? '')) {
          body.push(lines[i] ?? ''); // lazy continuation of the quoted paragraph
          i++;
        } else break;
      }
      out.push({ k: 'quote', blocks: parseBlocks(body.join('\n')) });
      continue;
    }

    const table = readTable(lines, i);
    if (table) {
      out.push(table.block);
      i = table.next;
      continue;
    }

    if (RE_ITEM.test(line)) {
      const list = readList(lines, i);
      out.push(list.block);
      i = list.next;
      continue;
    }

    // Paragraph: consecutive lines up to a blank line or the start of another block. The newlines are KEPT and
    // rendered as breaks (GFM's `breaks`, which is what every chat surface does) rather than collapsed to spaces:
    // a model writing an email header as four consecutive `> **To:** …` lines means four lines, and CommonMark's
    // "one newline is a space" rule turns that into a run-on. Inline spans still cross the newlines, so an
    // emphasis a producer wrapped over two source lines still closes.
    const para: string[] = [];
    while (i < lines.length) {
      const l = lines[i] ?? '';
      if (!l.trim() || RE_FENCE.test(l) || RE_HR.test(l) || RE_HEADING.test(l) || RE_QUOTE.test(l) || RE_ITEM.test(l))
        break;
      para.push(l.trim());
      i++;
    }
    out.push({ k: 'p', text: para.join('\n') });
  }

  return out;
}

/** A pipe table only exists if the line under the header is a delimiter row with the same number of cells. */
function readTable(lines: string[], start: number): { block: Block; next: number } | null {
  const head = lines[start] ?? '';
  const delim = lines[start + 1] ?? '';
  if (!head.includes('|') || !RE_DELIM_ROW.test(delim)) return null;
  const cols = splitRow(head);
  const spec = splitRow(delim);
  if (cols.length < 2 || spec.length !== cols.length) return null;

  const align = spec.map((s) =>
    s.startsWith(':') && s.endsWith(':') ? 'center' : s.endsWith(':') ? 'right' : 'left',
  ) as ('left' | 'right' | 'center')[];

  const rows: string[][] = [];
  let i = start + 2;
  while (i < lines.length && (lines[i] ?? '').includes('|') && (lines[i] ?? '').trim()) {
    const cells = splitRow(lines[i] ?? '');
    // Ragged rows are normal in generated Markdown; pad or clip to the header so the table stays rectangular.
    rows.push(Array.from({ length: cols.length }, (_, c) => cells[c] ?? ''));
    i++;
  }
  return { block: { k: 'table', head: cols, align, rows }, next: i };
}

/** One list, with each item's text collected (and dedented) so it can be parsed as blocks in its own right. */
function readList(lines: string[], start: number): { block: Block; next: number } {
  const first = RE_ITEM.exec(lines[start] ?? '');
  const marker = first?.[2] ?? '-';
  const ordered = /\d/.test(marker);
  const baseIndent = indentOf(first?.[1] ?? '');
  const startNum = ordered ? Number.parseInt(marker, 10) : 1;

  const items: Block[][] = [];
  let buf: string[] = [];
  let contentIndent = 0;
  let i = start;
  let blanks = 0;

  const flush = (): void => {
    if (buf.length) items.push(parseBlocks(buf.join('\n')));
    buf = [];
  };

  while (i < lines.length) {
    const line = lines[i] ?? '';
    if (!line.trim()) {
      blanks++;
      // Two blank lines end any list; one may still be a paragraph break inside an item.
      if (blanks > 1) break;
      buf.push('');
      i++;
      continue;
    }
    const item = RE_ITEM.exec(line);
    const ind = indentOf(/^[ \t]*/.exec(line)?.[0] ?? '');

    if (item && indentOf(item[1] ?? '') <= baseIndent) {
      // A different marker family at the same level starts a NEW list, not another item of this one.
      const sameFamily = /\d/.test(item[2] ?? '') === ordered;
      if (!sameFamily) break;
      flush();
      contentIndent = indentOf(item[1] ?? '') + (item[2] ?? '').length + 1;
      buf.push(item[3] ?? '');
      blanks = 0;
      i++;
      continue;
    }

    if (ind >= contentIndent) {
      buf.push(line.slice(Math.min(contentIndent, line.length - line.trimStart().length)));
      blanks = 0;
      i++;
      continue;
    }

    // Lazy continuation: an unindented plain line still belongs to the open item; anything else ends the list.
    if (blanks === 0 && !item && !RE_HR.test(line) && !RE_HEADING.test(line) && !RE_FENCE.test(line)) {
      buf.push(line.trim());
      i++;
      continue;
    }
    break;
  }
  flush();
  return { block: { k: 'list', ordered, start: Number.isFinite(startNum) ? startNum : 1, items }, next: i };
}

// ---------------------------------------------------------------------------------------------------------------
// Inline parsing
// ---------------------------------------------------------------------------------------------------------------

/**
 * The alternatives are ordered by precedence, and code spans come first so nothing inside backticks is
 * reinterpreted — which is what keeps `**` inside a `code` span, and a path with underscores, literal.
 *
 * The link label admits one level of bracket nesting on purpose: the research brief cites sources as
 * `[[NVD](https://…)]`, and a label of `[^\]]*` would swallow the outer bracket into the anchor text.
 *
 * It is a `g` regex shared by a RECURSIVE parser, so `lastIndex` is assigned immediately before every `exec`
 * below — a nested `parseInline` call for a strong/em body leaves it pointing anywhere.
 */
const RE_INLINE = new RegExp(
  [
    '(`+)([\\s\\S]*?)\\1', // 1,2  code span
    '\\*\\*([\\s\\S]+?)\\*\\*', // 3    strong
    '__([\\s\\S]+?)__', // 4    strong
    '~~([\\s\\S]+?)~~', // 5    strike
    '\\*([^\\s*][\\s\\S]*?)\\*', // 6    em
    '_([^\\s_][\\s\\S]*?)_', // 7    em (guarded against intraword use below)
    '\\[((?:[^\\[\\]]|\\[[^\\]]*\\])*)\\]\\([ \\t]*<?([^\\s)>]*)>?(?:[ \\t]+"[^"]*")?[ \\t]*\\)', // 8,9  link
    '<((?:https?://|mailto:)[^>\\s]+)>', // 10   autolink
    '(https?://[^\\s<>()\\[\\]]*[^\\s<>()\\[\\].,;:!?\'"])', // 11   bare URL
  ].join('|'),
  'g',
);

const isWordChar = (c: string | undefined): boolean => c !== undefined && /[A-Za-z0-9]/.test(c);

/**
 * The first `_` at or after `from` that is allowed to CLOSE an emphasis span: not preceded by whitespace, and not
 * followed by a word character.
 *
 * This exists because the lazy regex alone gets `_needs_runtime_reproduction_` wrong in the one way that matters
 * here. It matches the shortest span, `_needs_`, whose closing `_` is intraword and therefore invalid — and
 * "invalid" cannot mean "give up", or the outer underscores end up on screen around a proof state. CommonMark
 * pairs the opener with the LAST underscore, so the span is scanned for explicitly.
 */
function closingUnderscore(src: string, from: number): number {
  for (let j = from; j < src.length; j++) {
    if (src[j] !== '_') continue;
    if (/\s/.test(src[j - 1] ?? ' ')) continue;
    if (!isWordChar(src[j + 1])) return j;
  }
  return -1;
}

/**
 * A `mailto:` or `http(s):` URL, or null for everything else — including a bare `#`, which under HashRouter is a
 * navigation away from the panel rather than an in-page anchor. A refused href renders as its label text.
 */
export function safeHref(raw: string): string | null {
  const url = raw.trim();
  if (/^https?:\/\/[^\s]+$/i.test(url)) return url;
  if (/^mailto:[^\s]+$/i.test(url)) return url;
  return null;
}

/** Parse the inline span grammar. Exported for the same reason `parseBlocks` is. */
export function parseInline(src: string): Inline[] {
  const out: Inline[] = [];
  const push = (v: string): void => {
    if (!v) return;
    const last = out[out.length - 1];
    if (last?.k === 'text') last.v += v;
    else out.push({ k: 'text', v });
  };

  RE_INLINE.lastIndex = 0;
  let cursor = 0;
  let m: RegExpExecArray | null = RE_INLINE.exec(src);
  while (m !== null) {
    const at = m.index;

    // `_` emphasis is resolved by hand, under CommonMark's intraword rule: an underscore with a word character on
    // its left cannot open, and the span runs to the first underscore that can legally close. Both halves are
    // load-bearing on this prose — `wg_client` must not italicise, and `_needs_runtime_reproduction_` must.
    if (m[7] !== undefined) {
      const close = isWordChar(src[at - 1]) ? -1 : closingUnderscore(src, at + 2);
      if (close === -1) {
        push(src.slice(cursor, at + 1));
        cursor = at + 1;
      } else {
        push(src.slice(cursor, at));
        out.push({ k: 'em', v: parseInline(src.slice(at + 1, close)) });
        cursor = close + 1;
      }
      RE_INLINE.lastIndex = cursor;
      m = RE_INLINE.exec(src);
      continue;
    }

    push(src.slice(cursor, at));
    cursor = at + m[0].length;

    if (m[2] !== undefined) out.push({ k: 'code', v: m[2].replace(/^ (.*) $/, '$1') });
    else if (m[3] !== undefined) out.push({ k: 'strong', v: parseInline(m[3]) });
    else if (m[4] !== undefined) out.push({ k: 'strong', v: parseInline(m[4]) });
    else if (m[5] !== undefined) out.push({ k: 'del', v: parseInline(m[5]) });
    else if (m[6] !== undefined) out.push({ k: 'em', v: parseInline(m[6]) });
    // group 7 (`_…_`) never reaches here — it is resolved above.
    else if (m[8] !== undefined) {
      const href = safeHref(m[9] ?? '');
      const label = parseInline(m[8]);
      if (href) out.push({ k: 'link', v: label, href });
      else out.push(...(label.length ? label : [{ k: 'text', v: m[8] } as Inline]));
    } else if (m[10] !== undefined) {
      const href = safeHref(m[10]);
      if (href) out.push({ k: 'link', v: [{ k: 'text', v: m[10] }], href });
      else push(m[10]);
    } else if (m[11] !== undefined) {
      const href = safeHref(m[11]);
      if (href) out.push({ k: 'link', v: [{ k: 'text', v: m[11] }], href });
      else push(m[11]);
    }

    RE_INLINE.lastIndex = cursor;
    m = RE_INLINE.exec(src);
  }
  push(src.slice(cursor));
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------------------------------

function renderInline(nodes: Inline[], keyBase: string): ReactNode[] {
  return nodes.map((n, i) => {
    const key = `${keyBase}.${i}`;
    switch (n.k) {
      case 'text': {
        // A newline inside a text run is a soft break the producer meant (see the paragraph rule above).
        // Fragments, not spans: a brief is ~230 text runs and none of them needs an element of its own.
        const parts = n.v.split('\n');
        return (
          <Fragment key={key}>
            {parts.map((part, p) => (
              <Fragment key={`${key}.b${p}`}>
                {p > 0 && <br />}
                {part}
              </Fragment>
            ))}
          </Fragment>
        );
      }
      case 'code':
        return <code key={key}>{n.v}</code>;
      case 'strong':
        return <strong key={key}>{renderInline(n.v, key)}</strong>;
      case 'em':
        return <em key={key}>{renderInline(n.v, key)}</em>;
      case 'del':
        return <del key={key}>{renderInline(n.v, key)}</del>;
      case 'link':
        return (
          <a key={key} href={n.href} target="_blank" rel="noreferrer">
            {renderInline(n.v, key)}
          </a>
        );
    }
  });
}

/** Text with inline spans applied — the leaf of every block. */
function Text({ src, k }: { src: string; k: string }): JSX.Element {
  return <>{renderInline(parseInline(src), k)}</>;
}

function renderBlocks(blocks: Block[], keyBase: string): ReactNode[] {
  return blocks.map((b, i) => {
    const key = `${keyBase}.${i}`;
    switch (b.k) {
      case 'h': {
        // The heading level is clamped to h2–h6: these blocks are panel CONTENT, and the page already owns h1.
        const Tag = `h${Math.min(6, Math.max(2, b.level + 1))}` as 'h2';
        return (
          <Tag key={key}>
            <Text src={b.text} k={key} />
          </Tag>
        );
      }
      case 'p':
        return (
          <p key={key}>
            <Text src={b.text} k={key} />
          </p>
        );
      case 'hr':
        return <hr key={key} />;
      case 'code':
        return (
          <pre key={key} className={b.lang ? `md-code lang-${b.lang}` : 'md-code'}>
            <code>{b.text}</code>
          </pre>
        );
      case 'quote':
        return <blockquote key={key}>{renderBlocks(b.blocks, key)}</blockquote>;
      case 'list': {
        const items = b.items.map((item, j) => {
          const ikey = `${key}.${j}`;
          // A tight item — its text plus at most a nested list — drops the <p> wrapper, so `- a` followed by an
          // indented `- b` reads as one bullet with a sub-bullet rather than as a paragraph above a list.
          const lead = item[0];
          const tight = lead?.k === 'p' && item.filter((x) => x.k === 'p').length === 1;
          return (
            <li key={ikey}>
              {tight && lead.k === 'p' ? (
                <>
                  <Text src={lead.text} k={ikey} />
                  {renderBlocks(item.slice(1), `${ikey}.r`)}
                </>
              ) : (
                renderBlocks(item, ikey)
              )}
            </li>
          );
        });
        return b.ordered ? (
          <ol key={key} start={b.start}>
            {items}
          </ol>
        ) : (
          <ul key={key}>{items}</ul>
        );
      }
      case 'table':
        return (
          <div key={key} className="md-table">
            <table>
              <thead>
                <tr>
                  {b.head.map((h, c) => (
                    <th key={`${key}.h${c}`} style={{ textAlign: b.align[c] ?? 'left' }}>
                      <Text src={h} k={`${key}.h${c}`} />
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {b.rows.map((row, r) => (
                  <tr key={`${key}.r${r}`}>
                    {row.map((cell, c) => (
                      <td key={`${key}.r${r}.${c}`} style={{ textAlign: b.align[c] ?? 'left' }}>
                        <Text src={cell} k={`${key}.r${r}.${c}`} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
    }
  });
}

/**
 * Render Markdown prose. `className` is appended to `md`, which carries the type scale, the measure and — the
 * part that is not cosmetic — `overflow-wrap: anywhere`, so a 90-character advisory URL wraps instead of pushing
 * the panel past the right margin.
 */
export function Markdown({ text, className }: { text: string; className?: string }): JSX.Element {
  return <div className={className ? `md ${className}` : 'md'}>{renderBlocks(parseBlocks(text), 'md')}</div>;
}
