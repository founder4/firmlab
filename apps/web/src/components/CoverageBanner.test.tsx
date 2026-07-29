import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CoverageReport, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { CoverageBanner } from './CoverageBanner';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const report = (o: Partial<CoverageReport> = {}): CoverageReport => ({
  firmwareClass: 'embedded-linux',
  applicable: 3,
  executed: 1,
  findingCount: 0,
  stages: [
    { worker: 'W1 · Extraction', reason: 'recover the rootfs', status: 'degraded', detail: 'no rootfs' },
    { worker: 'W3 · Credentials', reason: 'weak creds', status: 'no-input', detail: 'no extracted rootfs' },
    { worker: 'W5 · Binary-vuln', reason: 'pwnable candidates', status: 'no-input', detail: 'no extracted rootfs' },
  ],
  verdict: '1 of 3 stages ran and recorded nothing; 2 never ran. Zero findings covers only the stages that ran.',
  ambiguous: true,
  ...o,
});

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
});

describe('CoverageBanner', () => {
  it('states what zero findings actually covers instead of leaving the list to speak for itself', async () => {
    mockApi.coverage.mockResolvedValue(report());
    render(<CoverageBanner imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/Zero findings covers only/)).toBeTruthy());
    expect(screen.getByText(/Coverage · embedded-linux/)).toBeTruthy();
  });

  it('answers "what can run on this image" per stage, on demand', async () => {
    mockApi.coverage.mockResolvedValue(report());
    render(<CoverageBanner imageId="img1" />);
    const toggle = await screen.findByRole('button', { name: /What can run on this image\? \(1\/3\)/ });
    fireEvent.click(toggle);
    await waitFor(() => expect(screen.getByText('W5 · Binary-vuln')).toBeTruthy());
    // The stages that never ran are labelled as such, not left blank as if they were clean.
    expect(screen.getAllByText(/no input/).length).toBe(2);
  });

  it('renders nothing when coverage is unavailable rather than implying full coverage', async () => {
    mockApi.coverage.mockRejectedValue(new Error('offline'));
    const { container } = render(<CoverageBanner imageId="img1" />);
    await waitFor(() => expect(container.querySelector('.banner')).toBeNull());
  });
});

/**
 * The trap this banner exists to close, in the other language: `not-run` and `ran-empty` produce the same empty
 * findings list and are opposite conclusions. A Spanish label that let a stage nobody ran read as a stage that
 * passed would invert the workbench's central claim, so each status is asserted distinct and none of them is
 * allowed to sound like a clean result.
 */
describe('CoverageBanner — Spanish', () => {
  it('labels a stage nobody ran as not run, never as one that came back clean', async () => {
    setLocale('es');
    mockApi.coverage.mockResolvedValue(
      report({
        operatorAssertions: 2,
        stages: [
          { worker: 'W1 · Extraction', reason: 'recover the rootfs', status: 'ran-empty' },
          { worker: 'W5 · Binary-vuln', reason: 'pwnable candidates', status: 'not-run' },
          { worker: 'W7 · Full-system', reason: 'boot it', status: 'not-built' },
        ],
      }),
    );
    render(<CoverageBanner imageId="img1" />);

    expect(await screen.findByText(/Cobertura · embedded-linux/)).toBeTruthy();
    const toggle = screen.getByRole('button', { name: /¿Qué se puede ejecutar sobre esta imagen\? \(1\/3\)/ });
    fireEvent.click(toggle);
    await waitFor(() => expect(screen.getByText('W5 · Binary-vuln')).toBeTruthy());

    // Three different answers, three different labels — and "ran and found nothing" is not "never ran".
    expect(screen.getByText(/ejecutado · nada/)).toBeTruthy();
    expect(screen.getByText(/sin ejecutar/)).toBeTruthy();
    expect(screen.getByText(/sin implementar/)).toBeTruthy();
    // Nothing in the Spanish vocabulary may read as a verdict about the firmware.
    const text = document.body.textContent ?? '';
    expect(text).not.toMatch(/sin problemas|limpio|correcto/i);
    // The assertions covering no stage are counted apart, in Spanish and with agreement.
    expect(text).toContain('Hay 2 filas más que son afirmaciones del operador');
    expect(text).toContain('no cubren ninguna etapa');
    // Each stage's reason belongs to the class plan the scan executes and is printed as the API stated it.
    expect(screen.getByText('pwnable candidates')).toBeTruthy();
  });

  /**
   * The verdict itself. It is composed by the API — from the same class plan the autonomous scan executes, which is
   * why it is not built here — but it is recomputed on every read and describes the analysis RUN, so it is asked
   * for in the active locale and printed. Two things to hold: the request has to carry the locale, and what comes
   * back has to reach the screen unaltered, ids and all.
   */
  it('asks the API for the verdict in the active locale and prints exactly what it answered', async () => {
    setLocale('es');
    const spanish = [
      '1 de 3 etapas se ejecutaron y no registraron nada; 2 nunca se ejecutaron.',
      'Cero hallazgos sólo cubre las etapas que se ejecutaron — no es un certificado de limpieza para este firmware.',
      'Sin cubrir: W3 · Credentials, W5 · Binary-vuln.',
    ].join(' ');
    mockApi.coverage.mockResolvedValue(report({ verdict: spanish }));

    render(<CoverageBanner imageId="img1" />);

    expect(await screen.findByText(/Cero hallazgos sólo cubre las etapas que se ejecutaron/)).toBeTruthy();
    // The locale reached the request, rather than the sentence being translated on this side of the wire.
    expect(mockApi.coverage).toHaveBeenCalledWith('img1', 'es');
    // Stage ids survive inside the Spanish sentence — the reader compares it against the table underneath.
    const text = document.body.textContent ?? '';
    expect(text).toContain('W3 · Credentials');
    expect(text).toContain('W5 · Binary-vuln');
    // And a zero is still not a clean bill in Spanish.
    expect(text).toContain('no es un certificado de limpieza');
  });

  it('re-asks the API when the operator switches language, instead of leaving the sentence behind', async () => {
    mockApi.coverage.mockResolvedValue(report());
    render(<CoverageBanner imageId="img1" />);
    await waitFor(() => expect(mockApi.coverage).toHaveBeenCalledWith('img1', 'en'));
    // Cleared, or the assertion below would be satisfied by a call an earlier test in this file made.
    mockApi.coverage.mockClear();
    act(() => setLocale('es'));
    await waitFor(() => expect(mockApi.coverage).toHaveBeenCalledWith('img1', 'es'));
  });
});
