import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type WebProbeResult, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { WebProbePanel } from './WebProbePanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

function result(overrides: Partial<WebProbeResult> = {}): WebProbeResult {
  return {
    available: true,
    reason: 'Bounded probe finished.',
    target: 'http://127.0.0.1:8080',
    requests: 20,
    points: 4,
    findings: [],
    ...overrides,
  };
}

beforeEach(() => {
  setLocale('en');
  vi.clearAllMocks();
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
});

describe('WebProbePanel evidence boundaries', () => {
  it('marks a historical result as requiring revalidation and does not display its old confirmation', async () => {
    mockApi.webprobeResult.mockResolvedValue(
      result({
        findings: [
          {
            kind: 'web-command-injection',
            title: 'Legacy command injection',
            severity: 'critical',
            proofState: 'confirmed_in_emulation',
            evidence: {},
            rationale: 'Legacy detector output.',
          },
        ],
      }),
    );
    render(<WebProbePanel imageId="image-1" />);
    expect(
      await screen.findByText(/Historical probe: reflection and coverage controls were not recorded/),
    ).toBeTruthy();
    expect(screen.getByText('Legacy command injection')).toBeTruthy();
    expect(screen.getAllByText('needs_runtime_reproduction').length).toBeGreaterThan(0);
    expect(screen.queryByText('confirmed_in_emulation')).toBeNull();
  });

  it('shows measured coverage and omitted work for a version 2 result', async () => {
    mockApi.webprobeResult.mockResolvedValue(
      result({
        probeVersion: 2,
        coverage: {
          discoveredPoints: 8,
          eligiblePoints: 7,
          plannedPoints: 7,
          attemptedPoints: 4,
          completedPoints: 2,
          skippedUnsupportedMethod: 1,
          skippedPointLimit: 0,
          skippedBudget: 3,
          requestBudget: 20,
          budgetExhausted: true,
          failedRequests: 1,
        },
      }),
    );
    render(<WebProbePanel imageId="image-1" />);
    expect(await screen.findByText(/4 of 7 planned points attempted; 2 completed; 1 failed requests/)).toBeTruthy();
    expect(
      screen.getByText(/Not attempted: 1 unsupported methods, 0 beyond the point limit, 3 beyond the request budget/),
    ).toBeTruthy();
    expect(screen.queryByText(/Historical probe/)).toBeNull();
  });
});
