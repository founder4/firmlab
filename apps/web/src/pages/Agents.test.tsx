import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type ImageSummary, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { Agents, AgentsRun, readAgentSession } from './Agents';

/**
 * The three defects this screen was rebuilt for, pinned.
 *
 *  1. **A click used to leave the section.** Every row navigated to `/image/:id/opacidad` — the static-analysis
 *     shell — so opening a result silently moved the reader to a different part of the workbench, under a
 *     pipeline strip about a different activity, with no route back.
 *  2. **A scan row stated a status, not an outcome.** `done` says a process finished and says nothing about what
 *     was learned, and a bare finding total is the exact number the coverage discipline exists to qualify.
 *  3. **An agent row stated ONLY a status.** `done · 7 steps` was every finished session by construction: over the
 *     corpus's 18 real sessions, one that formed eight zero-day candidates read identically to one that formed
 *     none, and identically again to the eleven that never reached a target at all. The last group is the one that
 *     matters most — their outcome is "there was nothing to analyse", which is neither a pass nor a failure, and a
 *     green `done` is the reading this workbench exists to prevent.
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

/**
 * A session transcript shaped like the ones the orchestrator actually writes — the node sequence, the governor's
 * tally and the budget, so a reading is exercised against the shape it will meet in the database rather than
 * against one invented to suit it.
 */
type NodeRow = { node: string; status?: string; input?: unknown; output?: unknown; rationale?: string };
const agentSession = (o: {
  id?: string;
  status?: string;
  haltReason?: string | null;
  consumedSteps?: number;
  usd?: number;
  nodes: NodeRow[];
}) => ({
  session: {
    id: o.id ?? 's1',
    imageId: 'img1',
    status: o.status ?? 'done',
    goal: null,
    budget: { maxSteps: 8, maxTokens: 120_000, maxUsd: 0.5, maxWallMs: 300_000 },
    consumed: {
      steps: o.consumedSteps ?? 3,
      inputTokens: 0,
      outputTokens: 0,
      usd: o.usd ?? 0.0033,
      elapsedMs: 1,
    },
    haltReason: o.haltReason ?? null,
    createdAt: 9,
    updatedAt: 9,
  },
  steps: o.nodes.map((n, i) => ({ seq: i + 1, status: 'ok', ...n })),
});

/** The eleven: preflight computed a ceiling, target selection came back empty, nothing was ever asked. */
const starvedSession = (strategy = 'uefi-chipsec', reason = 'UEFI/BIOS image — chipsec can decode it offline.') =>
  agentSession({
    id: 's-starved',
    nodes: [
      { node: 'triage' },
      { node: 'preflight', output: { strategy, proofCeiling: 'static_confirmed', reason } },
      { node: 'target-selection', output: { targets: [], emulationPlan: [] } },
      { node: 'synthesis' },
    ],
  });

/** The seven: a target, a zero-day node, the approval gate, and an emulation that ran. */
const gatedSession = (candidates: number, proofState = 'needs_runtime_reproduction') =>
  agentSession({
    id: 's-gated',
    consumedSteps: 4,
    usd: 0.0095,
    nodes: [
      { node: 'triage' },
      {
        node: 'preflight',
        output: { strategy: 'full-system', proofCeiling: 'confirmed_full_system', reason: 'firmadyne kernel present' },
      },
      { node: 'target-selection', output: { targets: [{ path: 'usr/bin/httpd' }], emulationPlan: [{ binary: 'x' }] } },
      { node: 'zero-day', output: { candidates: Array.from({ length: candidates }, (_, i) => ({ sink: `s${i}` })) } },
      { node: 'isolation', status: 'skipped', output: { isolation: 'partial' } },
      { node: 'emulation', input: { binary: 'usr/bin/httpd' }, output: { ran: true, proofState } },
      { node: 'synthesis' },
    ],
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

  /**
   * Colour is what a table is read by, and green is the one signal on this page that says "nothing to see here"
   * without a word. A scan that completed 12 of 15 workers wore the same green `done` as a complete one — the
   * numbers beside it honest, the badge not.
   */
  it('an incomplete scan keeps the word done and loses the green', async () => {
    mockApi.jobs.mockResolvedValue([
      {
        id: 'j1',
        kind: 'opacidad',
        status: 'done',
        createdAt: 5,
        result: scanResult({ ran: 12, notRan: 3, findings: 7 }),
      },
    ]);
    const { container } = renderConsole();
    await screen.findByText('12 of 15 workers');
    const badge = [...container.querySelectorAll('.badge')].find((b) => b.textContent === 'done');
    expect(badge?.className).not.toContain('badge-ok');
    expect(badge?.className).toContain('badge-medium');
  });

  it('keeps the green when the whole plan ran', async () => {
    mockApi.jobs.mockResolvedValue([
      {
        id: 'j2',
        kind: 'opacidad',
        status: 'done',
        createdAt: 5,
        result: scanResult({ ran: 15, notRan: 0, findings: 7 }),
      },
    ]);
    const { container } = renderConsole();
    await screen.findByText('15 of 15 workers');
    const badge = [...container.querySelectorAll('.badge')].find((b) => b.textContent === 'done');
    expect(badge?.className).toContain('badge-ok');
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

describe('readAgentSession — the verdict is read from the transcript, not from the status', () => {
  it('reads a session that never reached a target as BLOCKED, not as done', () => {
    const a = readAgentSession(starvedSession());
    // `blocked` is the deployment saying it could not answer — explicitly not a negative result, and not a pass.
    expect(a?.outcome).toBe('blocked');
    expect(a?.reason).toBe('no-target');
    // The ceiling that bounded it comes from the DETERMINISTIC preflight, so the row says what it was allowed to do.
    expect(a?.strategy).toBe('uefi-chipsec');
  });

  it('reads candidates as a LEAD and never as proof — they are written needs_runtime_reproduction', () => {
    const a = readAgentSession(gatedSession(6));
    expect(a?.outcome).toBe('lead');
    expect(a?.candidates).toBe(6);
    // An emulation that came back needing reproduction must not promote the session to `proven`.
    expect(a?.proofState).toBe('needs_runtime_reproduction');
  });

  it('separates "the node ran and formed nothing" from "the node never ran"', () => {
    // Ran, empty-handed: a result, for that scaffold and that budget.
    expect(readAgentSession(gatedSession(0))?.outcome).toBe('empty');
    // Aimed and not run: the question was never put, which is not the same statement about the binary.
    const skipped = agentSession({
      nodes: [
        { node: 'target-selection', output: { targets: [{ path: 'b' }], emulationPlan: [] } },
        { node: 'zero-day', status: 'skipped', rationale: 'No binary triage (radare2 absent) — nothing invented.' },
      ],
    });
    const a = readAgentSession(skipped);
    expect(a?.outcome).toBe('blocked');
    expect(a?.reason).toBe('no-triage');
    expect(a?.detail).toMatch(/radare2 absent/);
  });

  it('promotes to PROVEN only when an emulation step came back confirmed', () => {
    expect(readAgentSession(gatedSession(2, 'confirmed_in_emulation'))?.outcome).toBe('proven');
    expect(readAgentSession(gatedSession(2, 'blocked_by_platform'))?.outcome).toBe('lead');
  });

  it('reads a governor halt as blocked and an exception as failed, each with its own reason', () => {
    const halted = readAgentSession(
      agentSession({ status: 'halted', haltReason: 'step budget exhausted', nodes: [{ node: 'triage' }] }),
    );
    expect(halted?.outcome).toBe('blocked');
    expect(halted?.detail).toBe('step budget exhausted');
    const broke = readAgentSession(
      agentSession({ status: 'error', haltReason: 'interrupted by restart', nodes: [{ node: 'triage' }] }),
    );
    expect(broke?.outcome).toBe('failed');
  });

  it('says how the approval gate was settled, including the run that needed none', () => {
    expect(readAgentSession(gatedSession(1))?.gate).toBe('approved');
    expect(
      readAgentSession(agentSession({ status: 'awaiting_approval', nodes: [{ node: 'isolation', status: 'skipped' }] }))
        ?.gate,
    ).toBe('pending');
    expect(
      readAgentSession(
        agentSession({ haltReason: 'operator declined emulation', nodes: [{ node: 'isolation', status: 'skipped' }] }),
      )?.gate,
    ).toBe('declined');
    // Contained blast radius: the orchestrator ran it without asking, and the row must say so rather than imply
    // a person signed it off.
    expect(
      readAgentSession(
        agentSession({ nodes: [{ node: 'emulation', input: { autoApproved: true }, output: { ran: true } }] }),
      )?.gate,
    ).toBe('auto');
    expect(
      readAgentSession(
        agentSession({
          nodes: [
            { node: 'authorization', input: { source: 'global-setting' } },
            { node: 'emulation', output: { ran: true } },
          ],
        }),
      )?.gate,
    ).toBe('preapproved');
  });

  it('survives a transcript written by an older build', () => {
    // Step outputs are JSON persisted on a row and re-read for as long as the image exists; a reader that assumes
    // a field exists is the crash this codebase has already paid for once.
    const old = { session: { status: 'done' }, steps: [{ node: 'triage' }, { node: 'target-selection' }] };
    const a = readAgentSession(old);
    expect(a?.outcome).toBe('blocked');
    expect(a?.maxSteps).toBe(0);
    expect(a?.strategy).toBeNull();
  });
});

describe('Agents — an agent row says what the session established', () => {
  it('does not render two sessions that learned different things as the same row', async () => {
    mockApi.listImages.mockResolvedValue([image('img1', 'router.bin'), image('img2', 'camera.bin')]);
    mockApi.agentSession.mockImplementation((id: string) =>
      Promise.resolve(id === 'img1' ? gatedSession(6) : starvedSession()),
    );
    renderConsole();

    expect(await screen.findByText('6 zero-day candidates to reproduce')).toBeInTheDocument();
    expect(screen.getByText('No target was selected — the session had nothing to analyse')).toBeInTheDocument();
    // The verdict words come from the run ledger's vocabulary, not from a second one invented here.
    expect(screen.getByText('lead')).toBeInTheDocument();
    expect(screen.getByText('blocked')).toBeInTheDocument();
  });

  it('states the blocked reading as "could not answer", never as a negative result', async () => {
    mockApi.agentSession.mockResolvedValue(starvedSession('static-only', 'No rootfs extracted yet.'));
    renderConsole();

    const badge = await screen.findByText('blocked');
    expect(badge.getAttribute('title')).toMatch(/NOT a negative result/);
    // What the deployment was allowed to attempt at all, and why — the deterministic ceiling, before any model.
    const preflight = screen.getByText('preflight: static-only');
    expect(preflight.getAttribute('title')).toBe('No rootfs extracted yet.');
  });

  it('refuses to let zero candidates read as a clean image', async () => {
    mockApi.agentSession.mockResolvedValue(gatedSession(0));
    renderConsole();

    expect(
      await screen.findByText('The zero-day node formed no candidate from the scaffold it had — not a clean binary'),
    ).toBeInTheDocument();
    expect(screen.getByText('nothing found').getAttribute('title')).toMatch(/Not a clean bill of health/i);
  });

  it('names the approval gate, the leash it spent and the node it got to', async () => {
    mockApi.agentSession.mockResolvedValue(gatedSession(6));
    renderConsole();

    expect(await screen.findByText('you approved the emulation')).toBeInTheDocument();
    // A spend with no cap beside it states nothing, so both are on the row.
    const leash = screen.getByText('4 of 8 LLM turns');
    expect(leash.getAttribute('title')).toBe('$0.0095 of $0.50 spent · 7 transcript entries');
    expect(screen.getByText('ended at synthesis')).toBeInTheDocument();
    // And what the emulation actually established — capped, glossed, never upgraded.
    expect(screen.getByText('emulation → needs reproduction')).toBeInTheDocument();
  });

  it('keeps the process status on the row — it crosses the API and lands in SQLite', async () => {
    mockApi.agentSession.mockResolvedValue(starvedSession());
    renderConsole();
    expect(await screen.findByText('done')).toBeInTheDocument();
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
