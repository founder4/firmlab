import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
    // The verdict and each stage's reason are the API's record and are printed as it wrote them.
    expect(screen.getByText(/Zero findings covers only/)).toBeTruthy();
    expect(screen.getByText('pwnable candidates')).toBeTruthy();
  });
});
