/**
 * StepTimeline — the strip that is on screen for every image, and the one place a half-translated shell was most
 * visible: it rendered `Entropy · Extraction · Bootloader · Binaries · Emulation · Findings` in English across the
 * top of fully Spanish panels, because the labels were a second copy kept in the component.
 *
 * So the property under test is not "the strip is in Spanish" — that would pass on a second Spanish copy, which is
 * the same defect with a different symptom. It is that the timeline reads the SHARED sections catalogue: every step
 * label equals `sections[<step id>]`, in both languages, for the same list of ids. A copy reintroduced here fails
 * the moment its wording drifts from the heading of the page the step navigates to.
 */
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { type Locale, setLocale } from '../i18n';
import { catalogues } from '../locales';
import { mockedApi } from '../test-api-mock';
import { ANALYSIS_STEPS, StepTimeline } from './StepTimeline';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const emulation = (strategy: string) => ({
  identity: { firmwareClass: 'embedded-linux', arch: 'mips', endianness: 'big', filesystems: ['squashfs'] },
  rootfsReady: true,
  suggestedBinary: null,
  recipes: [],
  capabilities: { strategy },
});

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
  mockApi.jobs.mockResolvedValue([]);
  mockApi.findings.mockResolvedValue([]);
  mockApi.emulation.mockResolvedValue(emulation('qemu-user'));
});

const timeline = (): HTMLElement => {
  render(
    <MemoryRouter>
      <StepTimeline imageId="img1" active="entropy" ready={true} />
    </MemoryRouter>,
  );
  return screen.getByRole('navigation');
};

const labelsOf = (nav: HTMLElement): string[] =>
  [...nav.querySelectorAll('.steptl-label')].map((n) => n.textContent ?? '');

describe('StepTimeline — the labels are the sections catalogue, not a copy of it', () => {
  it.each<Locale>(['en', 'es'])('names every step exactly as the sections namespace does (%s)', async (locale) => {
    setLocale(locale);
    const nav = timeline();
    await waitFor(() => expect(mockApi.jobs).toHaveBeenCalled());

    const expected = ANALYSIS_STEPS.map((id) => catalogues[locale].sections[id]);
    expect(labelsOf(nav)).toEqual(expected);
    // The list is the pipeline, in flow order — a step dropped from it would still satisfy the equality above.
    expect(ANALYSIS_STEPS).toEqual([
      'overview',
      'entropy',
      'filesystem',
      'bootloader',
      'sbom',
      'binaries',
      'simulate',
      'findings',
    ]);
  });

  it('renders no English label under the Spanish locale — the mixed line that was the bug', async () => {
    setLocale('es');
    const nav = timeline();
    await waitFor(() => expect(mockApi.jobs).toHaveBeenCalled());

    expect(labelsOf(nav)).toContain('Entropía');
    expect(labelsOf(nav)).toContain('Extracción');
    for (const stale of ['Entropy', 'Extraction', 'Binaries', 'Emulation', 'Findings']) {
      expect(labelsOf(nav)).not.toContain(stale);
    }
    // The strip's own accessible name is chrome too, and a screen reader announces it before any of the buttons.
    expect(nav.getAttribute('aria-label')).toBe(catalogues.es.shell.timeline.label);
  });

  it('states each node’s state in the tooltip, in the reader’s language', async () => {
    setLocale('es');
    const nav = timeline();
    await waitFor(() => expect(mockApi.jobs).toHaveBeenCalled());

    // `ready` makes General and Entropy done; nothing has run, so Extraction is still pending.
    const titles = [...nav.querySelectorAll('.steptl-step')].map((n) => n.getAttribute('title'));
    expect(titles).toContain('Entropía — hecha');
    expect(titles).toContain('Extracción — pendiente');
  });

  /**
   * `blocked` on this strip means this deployment cannot emulate the architecture — the question cannot be asked
   * here. It is a UI state and it translates; `blocked_by_platform`, the proof state, is an identifier and does not.
   */
  it('says an unemulatable architecture is blocked, in the reader’s language', async () => {
    setLocale('es');
    mockApi.emulation.mockResolvedValue(emulation('unsupported-arch'));
    const nav = timeline();

    await waitFor(() => expect(nav.querySelector('.steptl-step.blocked')).toBeTruthy());
    expect(nav.querySelector('.steptl-step.blocked .steptl-meta')?.textContent).toBe('bloqueada');
  });
});
