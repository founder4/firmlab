import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Markdown, parseBlocks, parseInline, safeHref } from './markdown';

/**
 * The grammar is the half worth testing, and two of these cases are the reason the renderer is hand-written at
 * all: a proof state must survive the emphasis rules verbatim, and no path from model output to the DOM may
 * produce markup.
 */

const kinds = (src: string): string[] => parseBlocks(src).map((b) => b.k);

describe('parseBlocks', () => {
  it('reads the block grammar the narrative composer emits', () => {
    const src = [
      '# Autonomous scan — fw.bin',
      '',
      '**Class:** `openwrt-fit-ubi`',
      '',
      '## Workers',
      '- ✓ **W1** — extraction (3 findings)',
      '- ▢ **W7** — not built',
      '',
      '---',
      '',
      '> quoted advice',
    ].join('\n');
    expect(kinds(src)).toEqual(['h', 'p', 'h', 'list', 'hr', 'quote']);
  });

  it('keeps one paragraph one paragraph, with an emphasis span that closes across its source lines', () => {
    const src = '_Findings are proof-stated:\nno claim is made about the device._';
    expect(parseBlocks(src)).toEqual([
      { k: 'p', text: '_Findings are proof-stated:\nno claim is made about the device._' },
    ]);
    const { container } = render(<Markdown text={src} />);
    expect(container.querySelectorAll('p')).toHaveLength(1);
    expect(container.querySelector('em')?.textContent).toBe(
      'Findings are proof-stated:no claim is made about the device.',
    );
  });

  it('renders a newline inside a paragraph as a break, so an email header is not a run-on', () => {
    const { container } = render(<Markdown text={'> **To:** the vendor\n> **Subject:** advisory'} />);
    expect(container.querySelectorAll('blockquote p')).toHaveLength(1);
    expect(container.querySelectorAll('br')).toHaveLength(1);
  });

  it('keeps a thematic break a thematic break, not a bullet', () => {
    expect(kinds('---')).toEqual(['hr']);
    expect(kinds('***')).toEqual(['hr']);
    expect(kinds('- item')).toEqual(['list']);
  });

  it('nests a sub-list inside its item instead of flattening it', () => {
    const blocks = parseBlocks('- outer\n  - inner\n- second');
    const list = blocks[0];
    if (list?.k !== 'list') throw new Error('expected a list');
    expect(list.items).toHaveLength(2);
    expect(list.items[0]?.map((b) => b.k)).toEqual(['p', 'list']);
  });

  it('numbers an ordered list from its own first marker', () => {
    const blocks = parseBlocks('3. third\n4. fourth');
    expect(blocks[0]).toMatchObject({ k: 'list', ordered: true, start: 3 });
  });

  it('takes a fenced block literally, including the markup inside it', () => {
    const blocks = parseBlocks('```sh\n# not a heading\n**not bold**\n```');
    expect(blocks[0]).toMatchObject({ k: 'code', lang: 'sh', text: '# not a heading\n**not bold**' });
  });

  it('runs an unclosed fence to the end rather than dropping the rest of the document', () => {
    expect(parseBlocks('```\nstill here')[0]).toMatchObject({ k: 'code', text: 'still here' });
  });

  it('needs a delimiter row before it will call something a table', () => {
    expect(kinds('| a | b |\n| --- | --- |\n| 1 | 2 |')).toEqual(['table']);
    expect(kinds('| a | b |\n| 1 | 2 |')).toEqual(['p']);
  });

  it('pads a ragged table row to the header so the table stays rectangular', () => {
    const t = parseBlocks('| a | b | c |\n|---|---|---|\n| 1 |')[0];
    expect(t).toMatchObject({ k: 'table', rows: [['1', '', '']] });
  });
});

describe('parseInline', () => {
  it('leaves an intraword underscore alone — a proof state is a code, not italics', () => {
    expect(parseInline('needs_runtime_reproduction')).toEqual([{ k: 'text', v: 'needs_runtime_reproduction' }]);
    expect(parseInline('the wg_client module')).toEqual([{ k: 'text', v: 'the wg_client module' }]);
  });

  it('still emphasises a properly delimited underscore span', () => {
    expect(parseInline('a _real_ span')).toEqual([
      { k: 'text', v: 'a ' },
      { k: 'em', v: [{ k: 'text', v: 'real' }] },
      { k: 'text', v: ' span' },
    ]);
  });

  it('emphasises a span whose CONTENT is an intraword-underscore code, closing at the last underscore', () => {
    // The deterministic narrative writes exactly this. Closing at the first `_` would leave the outer
    // underscores on screen and cut the proof state in half.
    expect(parseInline('— _needs_runtime_reproduction_ (sbom)')).toEqual([
      { k: 'text', v: '— ' },
      { k: 'em', v: [{ k: 'text', v: 'needs_runtime_reproduction' }] },
      { k: 'text', v: ' (sbom)' },
    ]);
  });

  it('leaves an unclosable underscore as the character it is', () => {
    expect(parseInline('a_b_c')).toEqual([{ k: 'text', v: 'a_b_c' }]);
    expect(parseInline('_dangling and nothing to close it')).toEqual([
      { k: 'text', v: '_dangling and nothing to close it' },
    ]);
  });

  it('does not reinterpret anything inside a code span', () => {
    expect(parseInline('`**a_b**`')).toEqual([{ k: 'code', v: '**a_b**' }]);
  });

  it('links only the inner brackets of a citation, leaving the outer pair as text', () => {
    const nodes = parseInline('[[NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-48174)]');
    expect(nodes[0]).toEqual({ k: 'text', v: '[' });
    expect(nodes[1]).toMatchObject({ k: 'link', href: 'https://nvd.nist.gov/vuln/detail/CVE-2022-48174' });
    expect(nodes[2]).toEqual({ k: 'text', v: ']' });
  });

  it('autolinks a bare URL without swallowing the sentence punctuation after it', () => {
    const nodes = parseInline('see https://openwrt.org/, then stop');
    expect(nodes[1]).toMatchObject({ k: 'link', href: 'https://openwrt.org/' });
    expect(nodes[2]).toEqual({ k: 'text', v: ', then stop' });
  });
});

describe('safeHref', () => {
  it('admits http(s) and mailto and nothing else', () => {
    expect(safeHref('https://nvd.nist.gov/x')).toBe('https://nvd.nist.gov/x');
    expect(safeHref('mailto:security@openwrt.org')).toBe('mailto:security@openwrt.org');
    expect(safeHref('javascript:alert(1)')).toBeNull();
    expect(safeHref('data:text/html,<script>')).toBeNull();
    // A HashRouter turns a bare fragment into a route change, and the live brief emits `[[OSV](#)]`.
    expect(safeHref('#')).toBeNull();
  });
});

describe('Markdown', () => {
  it('renders the spans as elements rather than as their source', () => {
    const { container } = render(<Markdown text={'## Provenance\n\n- **Vendor:** `openwrt`'} />);
    expect(container.querySelector('h3')?.textContent).toBe('Provenance');
    expect(container.querySelector('li strong')?.textContent).toBe('Vendor:');
    expect(container.querySelector('li code')?.textContent).toBe('openwrt');
    expect(container.textContent).not.toContain('**');
    expect(container.textContent).not.toContain('##');
  });

  it('never turns the model’s output into markup', () => {
    const { container } = render(<Markdown text={'<img src=x onerror="alert(1)"> and <b>bold</b>'} />);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    expect(screen.getByText(/onerror/)).toBeTruthy();
  });

  it('refuses a javascript: href and shows the label as inert text', () => {
    const { container } = render(<Markdown text="[click](javascript:alert(1))" />);
    expect(container.querySelector('a')).toBeNull();
    expect(container.textContent).toContain('click');
  });

  it('opens an accepted link in a new tab without leaking the referrer', () => {
    const { container } = render(<Markdown text="[NVD](https://nvd.nist.gov/x)" />);
    const a = container.querySelector('a');
    expect(a?.getAttribute('href')).toBe('https://nvd.nist.gov/x');
    expect(a?.getAttribute('target')).toBe('_blank');
    expect(a?.getAttribute('rel')).toBe('noreferrer');
  });

  it('puts a table in its own scroll container so a wide one cannot widen the panel', () => {
    const { container } = render(<Markdown text={'| a | b |\n|---|---|\n| 1 | 2 |'} />);
    expect(container.querySelector('.md-table > table')).toBeTruthy();
    expect(container.querySelectorAll('tbody td')).toHaveLength(2);
  });

  it('carries the caller’s class alongside the prose class', () => {
    const { container } = render(<Markdown text="x" className="copilot-output" />);
    expect(container.querySelector('.md.copilot-output')).toBeTruthy();
  });
});
