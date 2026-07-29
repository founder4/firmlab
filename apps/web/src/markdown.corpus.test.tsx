import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import researchBrief from './__fixtures__/research-brief.md?raw';
import scanNarrative from './__fixtures__/scan-narrative.md?raw';
import { Markdown } from './markdown';

/**
 * The grammar tests above are written from the same assumptions as the parser, which is exactly how a green
 * suite ends up proving nothing (see the fixtures note in CLAUDE.md). These two files are the REAL prose the
 * deployed container is holding right now for GL.iNet-BE3600_4.9.0.bin — a deepseek research brief and a
 * deepseek scan narrative — so what they assert is that production input renders, and that no marker survives
 * into the reader's view.
 *
 * Regenerate with:
 *   docker exec firmlab curl -fsS http://127.0.0.1:8799/api/images/<id>/research   → .synthesis.text
 *   docker exec firmlab curl -fsS http://127.0.0.1:8799/api/images/<id>/opacidad   → .narrative
 */
describe('Markdown against the live corpus', () => {
  it('renders a research brief as structure, leaving no source markers on screen', () => {
    const { container } = render(<Markdown text={researchBrief} />);
    const text = container.textContent ?? '';

    expect(container.querySelectorAll('h3, h4, h5, h6').length).toBeGreaterThan(10);
    expect(container.querySelectorAll('li').length).toBeGreaterThan(20);
    expect(container.querySelectorAll('code').length).toBeGreaterThan(20);
    expect(container.querySelectorAll('blockquote').length).toBe(1);
    expect(container.querySelectorAll('hr').length).toBeGreaterThan(5);
    expect(container.querySelectorAll('a[href^="https://nvd.nist.gov/"]').length).toBeGreaterThan(5);

    for (const marker of ['**', '### ', '](http', '__', '~~']) expect(text).not.toContain(marker);
    // Every anchor points somewhere real: the brief's `[[OSV](#)]` must not become a route change.
    for (const a of container.querySelectorAll('a')) expect(a.getAttribute('href')).toMatch(/^https?:\/\//);
  });

  it('renders a scan narrative without corrupting a proof state into emphasis', () => {
    const { container } = render(<Markdown text={scanNarrative} />);
    const text = container.textContent ?? '';

    expect(container.querySelectorAll('p').length).toBeGreaterThan(3);
    expect(container.querySelectorAll('strong').length).toBeGreaterThan(3);
    expect(container.querySelectorAll('code').length).toBeGreaterThan(3);
    expect(text).not.toContain('**');
    // The codes survive verbatim, underscores and all — the whole reason the emphasis rule is spec-accurate.
    expect(text).toContain('static_confirmed');
    expect(text).toContain('needs_runtime_reproduction');
    expect(container.querySelectorAll('em')).toHaveLength(0);
  });
});
