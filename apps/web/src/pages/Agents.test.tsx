import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type ImageSummary, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { Agents, AgentsRun } from './Agents';

/**
 * The two defects this screen was rebuilt for, pinned.
 *
 *  1. **A click used to leave the section.** Every row navigated to `/image/:id/opacidad` — the static-analysis
 *     shell — so opening a result silently moved the reader to a different part of the workbench, under a
 *     pipeline strip about a different activity, with no route back.
 *  2. **A row stated a status, not an outcome.** `done` says a process finished and says nothing about what was
 *     learned, and a bare finding total is the exact number the coverage discipline exists to qualify.
 */

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const image = (id: string, filename: string): ImageSummary => ({
  id,
  filename,
  size: 4096,
  sha256: 'a'.repeat(64),
  uploadedAt: 1,
  status: 'ready',
  identity: { firmwareClass: 'embedded-linux', arch: 'mips', endianness: 'big', filesystems: ['squashfs'] },
  tags: [],
});

/** A scan whose plan did NOT complete — the case the outcome column exists for. */
const scanResult = (o: { ran: number; notRan: number; findings: number }) => ({
  firmwareClass: 'embedded-linux',
  arch: 'mips',
  plan: [],
  steps: [
    ...Array.from({ length: o.ran }, (_, i) => ({ worker: `W${i} · ran`, status: 'ran', summary: 'did the thing' })),
    ...Array.from({ length: o.notRan }, (_, i) => ({
      worker: `W${9 + i} · unbuilt`,
      status: 'not-built',
      summary: 'nothing was asked of it',
    })),
  ],
  findings: { total: o.findings, bySeverity: {}, byProofState: {}, top: [] },
  attackPath: [],
  narrative: 'n',
  narrativeSource: 'deterministic',
  honestGaps: [],
});

beforeEach(() => {
  setLocale('en');
  mockApi.agentStatus.mockResolvedValue({ enabled: false });
  mockApi.listImages.mockResolvedValue([image('img1', 'router.bin')]);
  mockApi.jobs.mockResolvedValue([]);
  mockApi.agentSession.mockResolvedValue(null);
  mockApi.getImage.mockResolvedValue(image('img1', 'router.bin'));
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
  mockApi.opacidadResult.mockResolvedValue(null);
});

const renderConsole = () =>
  render(
    <MemoryRouter initialEntries={['/agents']}>
      <Routes>
        <Route path="/agents" element={<Agents />} />
        <Route path="/agents/:imageId/:kind" element={<AgentsRun />} />
        <Route path="/image/:id/:section" element={<div>STATIC ANALYSIS SHELL</div>} />
      </Routes>
    </MemoryRouter>,
  );

/**
 * The runs table specifically. The filename appears twice on this screen — once as a run and once as a launch
 * target — so an unscoped query matches both and the failure reads as ambiguity rather than as the fact under
 * test.
 */
const runRow = async (filename: string): Promise<HTMLElement> => {
  const header = await screen.findByText('What came of it');
  const table = header.closest('table');
  if (!table) throw new Error('the runs table has no header row');
  return within(table).getByText(filename);
};

describe('Agents — a run opens inside the section', () => {
  it('never navigates to the static-analysis shell when a run is clicked', async () => {
    mockApi.jobs.mockResolvedValue([
      {
        id: 'j1',
        kind: 'opacidad',
        status: 'done',
        createdAt: 5,
        result: scanResult({ ran: 3, notRan: 0, findings: 2 }),
      },
    ]);
    renderConsole();

    fireEvent.click(await runRow('router.bin'));

    // The run's own view, in this section — and NOT the shell the old console dropped the reader into.
    expect(await screen.findByRole('heading', { name: /Autonomous scan/i })).toBeInTheDocument();
    expect(screen.queryByText('STATIC ANALYSIS SHELL')).not.toBeInTheDocument();
    // …with the way back to where they came from.
    expect(screen.getByRole('link', { name: /All runs/i })).toBeInTheDocument();
  });

  it('offers the image view as ONE labelled link, so leaving is a choice', async () => {
    mockApi.jobs.mockResolvedValue([{ id: 'j1', kind: 'opacidad', status: 'done', createdAt: 5, result: null }]);
    renderConsole();
    fireEvent.click(await runRow('router.bin'));

    const out = await screen.findByRole('link', { name: /Open the full analysis/i });
    expect(out.getAttribute('href')).toBe('/image/img1/dossier');
    // And it says what pressing it does, rather than leaving the reader to find out.
    expect(screen.getByText(/Leaves Agents/i)).toBeInTheDocument();
  });
});

describe('Agents — a row states an outcome', () => {
  it('leads with how much of the plan ran, and names what did not complete', async () => {
    mockApi.jobs.mockResolvedValue([
      {
        id: 'j1',
        kind: 'opacidad',
        status: 'done',
        createdAt: 5,
        result: scanResult({ ran: 12, notRan: 3, findings: 725 }),
      },
    ]);
    renderConsole();

    // The completion comes first: 725 findings is only readable once you know what produced them.
    expect(await screen.findByText('12 of 15 workers')).toBeInTheDocument();
    expect(screen.getByText('725 findings')).toBeInTheDocument();
    // The half a bare total hides, and it must be visible rather than only in a tooltip.
    expect(screen.getByText('3 did not complete')).toBeInTheDocument();
  });

  it('says nothing has been recorded rather than showing an empty outcome', async () => {
    // An empty cell beside `running` reads as "it found nothing", which is the one thing it must not say.
    mockApi.jobs.mockResolvedValue([{ id: 'j1', kind: 'opacidad', status: 'running', createdAt: 5, result: null }]);
    renderConsole();
    expect(await screen.findByText(/no result recorded yet/i)).toBeInTheDocument();
  });

  it('flags an agent waiting on a person as needing them, not as being busy', async () => {
    mockApi.agentSession.mockResolvedValue({
      session: { id: 's1', status: 'awaiting_approval', createdAt: 9, goal: 'g' },
      steps: [{}, {}],
    });
    renderConsole();
    expect(await screen.findByText(/waiting for your approval/i)).toBeInTheDocument();
  });

  it('renders the status verbatim — it crosses the API and lands in SQLite', async () => {
    mockApi.jobs.mockResolvedValue([{ id: 'j1', kind: 'opacidad', status: 'halted', createdAt: 5, result: null }]);
    renderConsole();
    expect(await screen.findByText('halted')).toBeInTheDocument();
  });
});

describe('AgentsRun', () => {
  it('says the target is not here rather than rendering an empty trace', async () => {
    mockApi.getImage.mockRejectedValue(new Error('404'));
    render(
      <MemoryRouter initialEntries={['/agents/gone/scan']}>
        <Routes>
          <Route path="/agents/:imageId/:kind" element={<AgentsRun />} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText(/not in this workspace/i)).toBeInTheDocument());
  });
});
