import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  type AgentStatus,
  type GovernorBudget,
  type GovernorConsumed,
  type ImageSummary,
  type OpacidadResult,
  type RunSummary,
  api,
} from '../api';
import { OpacidadPanel } from '../components/OpacidadPanel';
import { type Messages, useMessages } from '../i18n';
import { Icon } from '../icons';
import { toast } from '../toast';
import { AgentPanel } from './ImageDetail';

/**
 * Agents — the console over FirmLab's autonomous engine.
 *
 * **The unit is a RUN, and that is the whole re-architecture.** The previous version listed images and every click
 * navigated to `/image/:id/opacidad`, which is the static-analysis shell: opening a result dropped the reader into
 * a different section, under a pipeline strip about a different activity, with no route back to the console. So
 * the run view lives here (`/agents/:imageId/scan`), reusing the very same panels the image section renders, and
 * leaving for the image is one labelled link rather than the side effect of a click.
 *
 * **A row states an outcome, not a status.** `done` says a process finished and says nothing about what was
 * learned. `725 findings` says less than nothing on its own — it is the exact number the coverage discipline
 * exists to qualify. `summariseRun` therefore leads with how much of the plan actually ran and names the workers
 * that did not, because a total drawn from an incomplete plan is the misreading this workbench is built to
 * prevent, and a console that hides it is where that misreading starts.
 *
 * **That rule held for scans and was broken for agent sessions**, which rendered `run.status` and a step count and
 * nothing else — so `done · 7 steps` was every finished session, by construction. Over the 18 real sessions in the
 * corpus that made a run which formed eight zero-day candidates indistinguishable from one that formed none, and
 * both indistinguishable from the eleven that never reached a target at all. `readAgentSession` reads the outcome
 * back out of the transcript the session already wrote; nothing new is computed and nothing new is claimed.
 *
 * Statuses, filenames, worker ids, node names, preflight strategies, proof-state codes and provider/model names
 * render verbatim: they are records, not chrome.
 */

interface Run {
  key: string;
  type: 'scan' | 'agent';
  imageId: string;
  filename: string;
  status: string;
  at: number;
  /** The stored result, when the run produced one. Absent while queued/running, and after an error. */
  scan?: OpacidadResult;
  /** What the agent session established. Absent for a scan row, and for a session that has recorded nothing. */
  agent?: AgentReading;
}

const STATUS_CLASS: Record<string, string> = {
  done: 'badge-ok',
  running: 'badge-medium',
  queued: 'badge-medium',
  awaiting_approval: 'badge-warn',
  error: 'badge-crit',
  halted: 'badge-crit',
};
const isLive = (s: string): boolean => s === 'running' || s === 'queued';

/** Where a run opens. Inside this section, always. */
const runPath = (r: Pick<Run, 'type' | 'imageId'>): string => `/agents/${r.imageId}/${r.type}`;

const fmtWhen = (ms: number): string => new Date(ms).toISOString().slice(0, 16).replace('T', ' ');

// === What an agent session established ===

/**
 * The run ledger's vocabulary, reused rather than re-invented. Six words for six epistemic states, and this console
 * gets its wording and its colour from the same catalogue the test bench and `RunHistory` read, so a `blocked` run
 * reads as blocked in both places.
 */
type Outcome = RunSummary['outcome'];

/** The proof states this build has a gloss for. Anything else is still a valid record and renders as it is. */
type ProofStateKey = keyof Messages['proofState']['label'];

/** Badge colour per outcome. Mirrors `RunHistory`'s map — it is private there, and this file may not edit it. */
const OUTCOME_CLASS: Record<Outcome, string> = {
  proven: 'run-proven',
  lead: 'run-lead',
  empty: 'run-empty',
  blocked: 'run-blocked',
  failed: 'run-failed',
  running: 'run-running',
};

/** Why the reading came out the way it did — a key the catalogue owns the sentence for. Never prose decided here. */
export type AgentReason =
  | 'confirmed'
  | 'candidates'
  | 'no-candidate'
  | 'no-triage'
  | 'no-target'
  | 'halted'
  | 'failed'
  | 'running';

/** How execution permission was settled. `auto` is isolation; `preapproved` is the explicit global setting. */
export type AgentGate = 'none' | 'pending' | 'approved' | 'declined' | 'auto' | 'preapproved';

export interface AgentReading {
  outcome: Outcome;
  reason: AgentReason;
  /** Zero-day hypotheses the node formed. They are persisted `needs_runtime_reproduction` — leads, never proof. */
  candidates: number;
  /** The engine's own record: a halt reason, an error, a node's note. Renders verbatim. */
  detail: string | null;
  /** The proof state an emulation step came back with. A code — the proof-state catalogue glosses it. */
  proofState: string | null;
  /** The DETERMINISTIC preflight's strategy: what this deployment was allowed to attempt, before any judgment. */
  strategy: string | null;
  /** What the preflight said, for the strategy's tooltip. */
  strategyReason: string | null;
  /** The last node that recorded anything — where the flow actually got to. */
  lastNode: string | null;
  gate: AgentGate;
  /** The governor's leash, as consumed/cap. A bound is not an answer, so the cap is shown beside the spend. */
  steps: number;
  maxSteps: number;
  usd: number;
  maxUsd: number;
  /** Transcript entries — the number this column used to show on its own, kept where it belongs: in the tooltip. */
  entries: number;
}

/**
 * The subset of a session view this reading needs, structurally — every field optional on purpose.
 *
 * A step's `output` is JSON persisted on a row and re-read for as long as the image exists, so it is data written
 * by an OLDER build: any field this reader wants may simply not be there. Declaring one required would put the
 * claim in the type instead of in the check, which is the crash this codebase has already paid for once.
 */
export interface AgentSessionInput {
  session?: {
    status?: string;
    haltReason?: string | null;
    consumed?: Partial<GovernorConsumed>;
    budget?: Partial<GovernorBudget>;
  } | null;
  steps?: { node?: string; status?: string; input?: unknown; output?: unknown; rationale?: string | null }[];
}

const last = <T,>(list: T[]): T | undefined => list[list.length - 1];
const field = (v: unknown, key: string): unknown =>
  typeof v === 'object' && v !== null ? (v as Record<string, unknown>)[key] : undefined;
const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);
const count = (v: unknown): number => (Array.isArray(v) ? v.length : 0);

/**
 * Pure: read a session's transcript into what it ESTABLISHED.
 *
 * Every input is already in the transcript — the halt reason, the approval gate, the governor's tally, the zero-day
 * count, the node it got to. None of it was ever read back, which is why every finished session rendered the same
 * word. The three readings kept deliberately apart are the ones that must never converge:
 *
 * · **no target was ever selected** → `blocked`. The session could not ASK its question. Not a pass, not a failure,
 *   and above all not a clean image — eleven of the corpus's eighteen sessions are this case, and every one of them
 *   used to read `done`.
 * · **the zero-day node ran and formed nothing** → `empty`. A real result, for that scaffold and that budget, and
 *   the shared catalogue's own tooltip refuses to let it read as a clean bill of health.
 * · **candidates exist** → `lead`, never `proven`: they are written `needs_runtime_reproduction` by construction.
 *
 * `proven` is reserved for an emulation step that came back `confirmed_*`, and even that proves the sandbox.
 */
export function readAgentSession(view: AgentSessionInput): AgentReading | null {
  const session = view.session;
  if (!session) return null;
  const steps = view.steps ?? [];
  const nodes = (name: string) => steps.filter((s) => s.node === name);

  const status = session.status ?? '';
  const haltReason = str(session.haltReason);
  const preflight = last(nodes('preflight'));
  const zeroDay = last(nodes('zero-day'));
  const candidates = count(field(zeroDay?.output, 'candidates'));
  const emulations = nodes('emulation');
  // Only a step that actually ran says anything about the target; a `skipped` one is the absence of an attempt.
  const emulated = last(emulations.filter((s) => s.status === 'ok' || s.status === 'error'));
  const proofState = str(field(emulated?.output, 'proofState'));
  const selection = last(nodes('target-selection'));
  const planned = count(field(selection?.output, 'emulationPlan')) + count(field(selection?.output, 'targets'));

  // The gate fired exactly where the orchestrator refused to auto-run: an `isolation` step it could not contain.
  const gateFired = nodes('isolation').some((s) => s.status === 'skipped');
  const preapproved = nodes('authorization').some((s) => field(s.input, 'source') === 'global-setting');
  const declined = Boolean(haltReason && /declin/i.test(haltReason));
  const gate: AgentGate =
    status === 'awaiting_approval'
      ? 'pending'
      : declined
        ? 'declined'
        : preapproved
          ? 'preapproved'
          : gateFired && emulated
            ? 'approved'
            : emulations.some((s) => field(s.input, 'autoApproved') === true)
              ? 'auto'
              : 'none';

  const base = {
    candidates,
    // The decline is already stated by the gate chip, in the reader's language; the raw reason would only repeat it.
    detail: declined ? null : haltReason,
    proofState,
    strategy: str(field(preflight?.output, 'strategy')),
    strategyReason: str(field(preflight?.output, 'reason')),
    lastNode: str(last(steps)?.node),
    gate,
    steps: session.consumed?.steps ?? 0,
    maxSteps: session.budget?.maxSteps ?? 0,
    usd: session.consumed?.usd ?? 0,
    maxUsd: session.budget?.maxUsd ?? 0,
    entries: steps.length,
  };

  if (status === 'running' || status === 'queued' || status === 'awaiting_approval')
    return { ...base, outcome: 'running', reason: 'running' };
  if (status === 'error') return { ...base, outcome: 'failed', reason: 'failed' };
  // A governor cap is a bound, and a bound is not an answer: the run was cut short, so nothing follows from it.
  if (status === 'halted') return { ...base, outcome: 'blocked', reason: 'halted' };
  if (proofState === 'confirmed_in_emulation' || proofState === 'confirmed_full_system')
    return { ...base, outcome: 'proven', reason: 'confirmed' };
  if (candidates > 0) return { ...base, outcome: 'lead', reason: 'candidates' };
  if (zeroDay?.status === 'ok') return { ...base, outcome: 'empty', reason: 'no-candidate' };
  // No usable zero-day node. Either there was nothing to aim it at, or it was aimed and could not be run — and the
  // second one keeps the node's own note, because "radare2 is absent" and "there is no rootfs" need different work.
  if (planned === 0) return { ...base, outcome: 'blocked', reason: 'no-target' };
  return { ...base, outcome: 'blocked', reason: 'no-triage', detail: base.detail ?? str(zeroDay?.rationale) };
}

// === The console ===

export function Agents(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [runs, setRuns] = useState<Run[] | null>(null);
  const nav = useNavigate();
  const t = useMessages();

  useEffect(() => {
    api
      .agentStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  // Assemble the cross-target run list: scans surface as image jobs, the agent as a per-image session.
  const loadRuns = useCallback(async () => {
    const imgs = await api.listImages().catch(() => [] as ImageSummary[]);
    setImages(imgs);
    const collected = await Promise.all(
      imgs.map(async (im) => {
        const out: Run[] = [];
        const [jobs, view] = await Promise.all([
          api.jobs(im.id).catch(() => []),
          api.agentSession(im.id).catch(() => null),
        ]);
        for (const j of jobs.filter((x) => x.kind === 'opacidad')) {
          out.push({
            key: `scan-${j.id}`,
            type: 'scan',
            imageId: im.id,
            filename: im.filename,
            status: j.status,
            at: j.createdAt,
            ...(j.result ? { scan: j.result as OpacidadResult } : {}),
          });
        }
        if (view?.session) {
          const reading = readAgentSession(view);
          out.push({
            key: `agent-${view.session.id}`,
            type: 'agent',
            imageId: im.id,
            filename: im.filename,
            status: view.session.status,
            at: view.session.createdAt,
            ...(reading ? { agent: reading } : {}),
          });
        }
        return out;
      }),
    );
    setRuns(collected.flat().sort((a, b) => b.at - a.at));
  }, []);

  useEffect(() => {
    loadRuns();
  }, [loadRuns]);

  useEffect(() => {
    if (!runs?.some((r) => isLive(r.status))) return;
    const id = setInterval(loadRuns, 4000);
    return () => clearInterval(id);
  }, [runs, loadRuns]);

  const launchScan = useCallback(
    async (im: ImageSummary) => {
      try {
        await api.runOpacidad(im.id);
        toast.success(t.agents.launch.launched(im.filename));
        nav(`/agents/${im.id}/scan`);
      } catch (e) {
        toast.error(e);
      }
    },
    [nav, t],
  );

  const ready = images.filter((i) => i.status === 'ready');
  const liveCount = runs?.filter((r) => isLive(r.status)).length ?? 0;

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">{t.agents.eyebrow}</div>
        <h1 className="page-title">{t.agents.title}</h1>
        <div className="page-desc">{t.agents.desc}</div>
      </div>

      {/* The two engines, as one strip. What each one IS belongs here once; what a run DID belongs in its row. */}
      <div className="engine-strip">
        <div className="engine">
          <div className="engine-head">
            <Icon.shield size={15} />
            <strong>{t.agents.engine.scanName}</strong>
            <span className="badge badge-accent">{t.agents.engine.scanKind}</span>
            <span className="badge badge-ok">{t.agents.engine.scanReady}</span>
          </div>
          <div className="hint">{t.agents.engine.scanWhat}</div>
        </div>
        <div className="engine">
          <div className="engine-head">
            <Icon.agent size={15} />
            <strong>{t.agents.engine.agentName}</strong>
            {status?.enabled ? (
              <span className="badge badge-ok mono">
                {status.provider} · {status.model}
              </span>
            ) : (
              <span className="badge">{t.agents.engine.agentOff}</span>
            )}
          </div>
          <div className="hint">
            {t.agents.engine.agentWhat}
            {!status?.enabled && ` ${t.agents.engine.agentDisabled}`}
          </div>
        </div>
      </div>

      <div className="panel panel-flush" style={{ marginTop: 16 }}>
        <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
            <span className="panel-title" style={{ margin: 0 }}>
              {t.agents.runs.title}
            </span>
            {liveCount > 0 && (
              <span className="badge badge-medium">
                <span className="spinner" style={{ width: 10, height: 10 }} /> {t.agents.runs.live(liveCount)}
              </span>
            )}
          </div>
          <button type="button" className="btn btn-sm btn-ghost" onClick={loadRuns} title={t.agents.runs.refresh}>
            <Icon.refresh size={14} /> {t.agents.runs.refresh}
          </button>
        </div>

        {runs === null ? (
          <div style={{ padding: 16, display: 'grid', gap: 8 }}>
            {[0, 1, 2].map((i) => (
              <div key={i} className="skeleton" style={{ height: 34 }} />
            ))}
          </div>
        ) : runs.length === 0 ? (
          <div className="empty" style={{ padding: 32 }}>
            <div className="empty-mark">
              <Icon.agent size={20} />
            </div>
            <div className="empty-title">{t.agents.runs.emptyTitle}</div>
            <div className="empty-body">{t.agents.runs.emptyBody}</div>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}>
            <table className="data">
              <thead>
                <tr>
                  {/* The target column holds its width. A filename is an identifier, and an outcome cell that grew
                      wide enough to say something must not be what breaks one across two lines — so the column
                      reserves its room here and the cell below refuses to wrap. */}
                  <th style={{ minWidth: 300 }}>{t.agents.runs.colTarget}</th>
                  <th>{t.agents.runs.colOutcome}</th>
                  <th style={{ width: 150 }}>{t.agents.runs.colWhen}</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.key} className="row-link" onClick={() => nav(runPath(r))}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap' }}>
                        <span className="badge">
                          {r.type === 'scan' ? t.agents.runs.kindScan : t.agents.runs.kindAgent}
                        </span>
                        <span className="mono" style={{ color: 'var(--text)' }}>
                          {r.filename}
                        </span>
                      </div>
                    </td>
                    <td>
                      <RunOutcome run={r} />
                    </td>
                    <td className="mono hint" style={{ fontSize: '0.75rem' }}>
                      {fmtWhen(r.at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel panel-flush" style={{ marginTop: 16 }}>
        <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0 }}>
          <span className="panel-title" style={{ margin: 0 }}>
            {t.agents.launch.title}
          </span>
          <span className="mono" style={{ color: 'var(--text-faint)', fontSize: '0.8rem' }}>
            {t.agents.launch.ready(ready.length)}
          </span>
        </div>
        {ready.length === 0 ? (
          <div className="empty" style={{ padding: 28 }}>
            <div className="empty-title">{t.agents.launch.emptyTitle}</div>
            <div className="empty-body">
              {t.agents.launch.emptyLead} <Link to="/analyze">{t.agents.launch.emptyLink}</Link>{' '}
              {t.agents.launch.emptyTail}
            </div>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}>
            <table className="data">
              <tbody>
                {ready.map((im) => (
                  <tr key={im.id}>
                    <td className="mono" style={{ color: 'var(--text)' }}>
                      {im.filename}
                    </td>
                    <td>
                      <span className="badge">{im.identity?.firmwareClass ?? t.common.unknown}</span>
                    </td>
                    <td className="mono hint">{im.identity?.arch ?? '—'}</td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: 6 }}>
                        <button type="button" className="btn btn-sm btn-primary" onClick={() => launchScan(im)}>
                          <Icon.play size={13} /> {t.agents.launch.scan}
                        </button>
                        <Link to={`/agents/${im.id}/agent`} className="btn btn-sm">
                          {t.agents.launch.agent}
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * What came of a run, in the order a reader needs it.
 *
 * The plan's completion comes FIRST and the finding total second, because the total is only readable once you know
 * how much of the plan produced it. `not-built` and `skipped` workers are counted as not completing — they are
 * stages nothing was asked of, never stages that passed, and the whole honest-gaps machinery exists to keep those
 * two apart. A run with no stored result says so rather than rendering an empty cell that reads as "found
 * nothing".
 */
function RunOutcome({ run }: { run: Run }): JSX.Element {
  const t = useMessages();
  const status = (
    <span className={`badge ${STATUS_CLASS[run.status] ?? ''}`}>
      {isLive(run.status) && <span className="spinner" style={{ width: 9, height: 9 }} />}
      {run.status}
    </span>
  );

  if (run.type === 'agent') return <AgentOutcome run={run} status={status} />;

  if (run.status === 'awaiting_approval') {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {status}
        <span style={{ fontSize: 12.5, color: 'var(--sev-medium, #e6b45c)' }}>{t.agents.runs.needsYou}</span>
      </div>
    );
  }

  const scan = run.scan;
  if (!scan) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {status}
        <span className="hint" style={{ fontSize: 12.5 }}>
          {t.agents.runs.pending}
        </span>
      </div>
    );
  }

  const total = scan.steps.length;
  const ran = scan.steps.filter((s) => s.status === 'ran').length;
  const incomplete = total - ran;
  // A scan that completed 6 of 17 workers was getting the SAME green `done` badge as one that ran the whole plan.
  // The numbers beside it were honest and the colour was not, and colour is what a table is read by — green is the
  // one signal on this page that carries "nothing to see here" without a word. An incomplete plan keeps the status
  // word (it is a record) and loses the green.
  const statusBadge =
    incomplete > 0 && run.status === 'done' ? <span className="badge badge-medium">{run.status}</span> : status;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      {statusBadge}
      <span style={{ fontSize: 12.5 }}>{t.agents.runs.workers(ran, total)}</span>
      <span className="hint">·</span>
      <span style={{ fontSize: 12.5 }}>{t.agents.runs.findings(scan.findings.total)}</span>
      {incomplete > 0 && (
        <span
          className="badge badge-medium"
          title={scan.steps
            .filter((s) => s.status !== 'ran')
            .map((s) => s.worker)
            .join(', ')}
        >
          {t.agents.runs.incomplete(incomplete)}
        </span>
      )}
    </div>
  );
}

/** The catalogue's sentence for each reason. The decision is `readAgentSession`'s; only the wording is here. */
function agentHeadline(a: AgentReading, m: Messages['agents']['runs']['agent']): string {
  switch (a.reason) {
    case 'confirmed':
      return m.confirmed;
    case 'candidates':
      return m.candidates(a.candidates);
    case 'no-candidate':
      return m.noCandidate;
    case 'no-triage':
      return m.noTriage;
    case 'no-target':
      return m.noTarget;
    case 'halted':
      return m.halted;
    case 'failed':
      return m.failed;
    default:
      return m.running;
  }
}

/**
 * An agent session's row.
 *
 * The verdict badge leads, and the process status trails in the second line: a green `done` at the head of every
 * row is exactly how a session that could not ask its question came to look like one that answered it. The second
 * line is the audit in one breath — what the emulation established, the ceiling the deterministic preflight set
 * before any model spoke, where the flow got to, and how much of the governor's leash it spent. A session that has
 * recorded nothing says so rather than rendering an empty cell, which reads as "it found nothing".
 */
function AgentOutcome({ run, status }: { run: Run; status: JSX.Element }): JSX.Element {
  const t = useMessages();
  const m = t.agents.runs.agent;
  const a = run.agent;
  if (!a) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {status}
        <span className="hint" style={{ fontSize: 12.5 }}>
          {t.agents.runs.pending}
        </span>
      </div>
    );
  }

  const meta = t.shell.runHistory.outcome[a.outcome];
  const gateLabel =
    a.gate === 'preapproved'
      ? m.gatePreapproved
      : a.gate === 'approved'
        ? m.gateApproved
        : a.gate === 'declined'
          ? m.gateDeclined
          : a.gate === 'auto'
            ? m.gateAuto
            : null;
  // A proof state is a code the API stores; the catalogue glosses the ones it knows and the rest render verbatim,
  // because inventing a gloss for a state this build has not heard of is worse than showing the record itself.
  const proofKey = a.proofState && a.proofState in t.proofState.label ? (a.proofState as ProofStateKey) : null;
  const proofLabel = proofKey ? t.proofState.label[proofKey] : a.proofState;
  const proofMeans = proofKey ? t.proofState.meaning[proofKey] : undefined;
  // A run that reached its own end ENDED at that node; one that is halted, broken or paused STOPPED at it, and the
  // difference is the whole point of naming the node at all.
  const ended = run.status === 'done';

  // Every item but the status is optional, so the separators are interleaved rather than written between pairs.
  const tail: { key: string; node: JSX.Element }[] = [];
  if (proofLabel)
    tail.push({
      key: 'proof',
      node: <span title={proofMeans}>{m.emulation(proofLabel)}</span>,
    });
  if (a.strategy)
    tail.push({
      key: 'preflight',
      node: (
        <span className="mono" title={a.strategyReason ?? undefined}>
          {m.preflight(a.strategy)}
        </span>
      ),
    });
  if (a.detail)
    tail.push({
      key: 'detail',
      node: (
        <span
          title={a.detail}
          style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
        >
          {a.detail}
        </span>
      ),
    });
  if (a.lastNode)
    tail.push({
      key: 'node',
      node: <span className="mono">{ended ? m.endedAt(a.lastNode) : m.stoppedAt(a.lastNode)}</span>,
    });
  // No cap, no fraction: a session row stored before the budget was recorded knows what it spent and not what it
  // was allowed, and `3 of 0 steps` would be a claim about the leash rather than a reading of it.
  if (a.maxSteps > 0)
    tail.push({
      key: 'leash',
      node: <span title={m.leashDetail(a.usd, a.maxUsd, a.entries)}>{m.leash(a.steps, a.maxSteps)}</span>,
    });
  tail.push({ key: 'status', node: status });

  return (
    <div style={{ display: 'grid', gap: 3 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {run.status === 'awaiting_approval' ? (
          <span style={{ fontSize: 12.5, color: 'var(--sev-medium, #e6b45c)' }}>{t.agents.runs.needsYou}</span>
        ) : (
          <>
            <span className={`badge ${OUTCOME_CLASS[a.outcome]}`} title={meta.means}>
              {meta.label}
            </span>
            <span style={{ fontSize: 12.5 }}>{agentHeadline(a, m)}</span>
          </>
        )}
        {gateLabel && <span className="badge">{gateLabel}</span>}
      </div>
      <div className="hint" style={{ fontSize: 11.5, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        {tail.map((it, i) => (
          <span key={it.key} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            {i > 0 && <span aria-hidden="true">·</span>}
            {it.node}
          </span>
        ))}
      </div>
    </div>
  );
}

// === One run, inside this section ===

/**
 * The run view. It renders the SAME panels the image section does — the trace is the trace — inside this
 * section's frame, so opening a result never silently changes which part of the workbench you are in.
 */
export function AgentsRun(): JSX.Element {
  const { imageId = '', kind = 'scan' } = useParams();
  const t = useMessages();
  const [image, setImage] = useState<ImageSummary | null>(null);
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    api
      .getImage(imageId)
      .then(setImage)
      .catch(() => setMissing(true));
  }, [imageId]);

  if (missing) {
    return (
      <div className="empty" style={{ padding: 32 }}>
        <div className="empty-title">{t.agents.run.notFound}</div>
        <div className="empty-body">
          <Link to="/agents">{t.agents.run.back}</Link>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-head">
        <Link to="/agents" className="btn btn-sm btn-ghost" style={{ paddingLeft: 0, marginBottom: 4 }}>
          <Icon.back size={13} /> {t.agents.run.back}
        </Link>
        <h1 className="page-title">{kind === 'agent' ? t.agents.run.agentTitle : t.agents.run.scanTitle}</h1>
        <div className="hint mono" style={{ wordBreak: 'break-all' }}>
          {image?.filename ?? imageId}
          {image?.identity ? ` · ${image.identity.firmwareClass} · ${image.identity.arch}` : ''}
        </div>
      </div>

      {kind === 'agent' ? <AgentPanel imageId={imageId} /> : <OpacidadPanel imageId={imageId} />}

      {/* The one way out, labelled. Leaving for the static-analysis shell is a choice made here, never the
          unannounced result of clicking a row. */}
      <div className="panel" style={{ marginTop: 16 }}>
        <Link to={`/image/${imageId}/dossier`} className="btn btn-sm">
          {t.agents.run.openImage}
        </Link>
        <div className="hint" style={{ marginTop: 6 }}>
          {t.agents.run.openImageHint}
        </div>
      </div>
    </div>
  );
}
