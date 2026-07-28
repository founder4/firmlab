/*
 * StepTimeline — the persistent analysis pipeline for a firmware image. The eight stages read left-to-right the way
 * the analysis actually flows (General → Entropy → Extraction → Bootloader → SBOM → Binaries → Emulation →
 * Findings), and each node carries HONEST state derived from what has actually run: done, running, blocked (e.g.
 * an arch that can't be emulated here), or pending. It stays pinned under the top bar as you move between stages.
 *
 * **Where the labels come from, and why not from here.** A step id IS a section id — it is the URL segment the
 * click navigates to — and the sections catalogue already names every one of them for the shell's context header.
 * This file used to carry a second copy of those names, in English, which is how the strip came to read
 * `Entropy · Extraction · Bootloader · Binaries` across the top of fully Spanish panels. It now reads the shared
 * catalogue, so the timeline and the heading of the page it lands on cannot disagree, in any language, and a stage
 * added to one is named by the other for free.
 *
 * The node STATE is a different kind of word and lives in the shell namespace: `blocked` here means this deployment
 * cannot run that stage. It is not `blocked_by_platform`, which is a proof state, an identifier, and never
 * translated.
 */
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { type Messages, useMessages } from '../i18n';

/** A step is a section: the catalogue owns the word, this file owns the order. */
type StepId = keyof Messages['sections'];

export const ANALYSIS_STEPS: StepId[] = [
  'overview',
  'entropy',
  'filesystem',
  'bootloader',
  'sbom',
  'binaries',
  'simulate',
  'findings',
];

type State = 'done' | 'running' | 'blocked' | 'pending';
// Every job kind the Bootloader step's panel can start. It must list all of them: the step reads `done` from this
// set, so a provider missing here leaves the stage showing `pending` after it has actually run.
const BOOT_KINDS = [
  'uboot',
  'fsaudit',
  'certs',
  'services',
  'rtos',
  'compmap',
  'fcc',
  'kernel',
  'updatepath',
  'devicetree',
];
const EMU_KINDS = ['emulate', 'emulate-system', 'renode', 'chipsec', 'webprobe', 'fuzz'];

export function StepTimeline({
  imageId,
  active,
  ready,
}: {
  imageId: string;
  active: string;
  ready: boolean;
}): JSX.Element {
  const t = useMessages();
  const nav = useNavigate();
  const [jobs, setJobs] = useState<{ kind: string; status: string }[]>([]);
  const [strategy, setStrategy] = useState<string | null>(null);
  const [findingCount, setFindingCount] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    const load = (): void => {
      api
        .jobs(imageId)
        .then((j) => alive && setJobs(j))
        .catch(() => {});
      api
        .emulation(imageId)
        .then((m) => alive && setStrategy(m.capabilities?.strategy ?? null))
        .catch(() => {});
      api
        .findings(imageId)
        .then((f) => alive && setFindingCount(f.length))
        .catch(() => {});
    };
    load();
    // A finished job flips a node to done — poll gently while the view is open.
    const t = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [imageId]);

  const anyDone = (kinds: string[]): boolean => jobs.some((j) => kinds.includes(j.kind) && j.status === 'done');
  const anyRunning = (kinds: string[]): boolean =>
    jobs.some((j) => kinds.includes(j.kind) && (j.status === 'running' || j.status === 'queued'));

  const stateOf = (id: StepId): State => {
    switch (id) {
      case 'overview':
      case 'entropy':
        return ready ? 'done' : 'pending';
      case 'filesystem':
        return anyRunning(['extract']) ? 'running' : anyDone(['extract']) ? 'done' : 'pending';
      case 'bootloader':
        return anyRunning(BOOT_KINDS) ? 'running' : anyDone(BOOT_KINDS) ? 'done' : 'pending';
      case 'sbom':
        return anyRunning(['sbom']) ? 'running' : anyDone(['sbom']) ? 'done' : 'pending';
      case 'binaries':
        return anyDone(['extract']) ? 'done' : 'pending';
      case 'simulate':
        if (strategy === 'static-only' || strategy === 'unsupported-arch') return 'blocked';
        return anyRunning(EMU_KINDS) ? 'running' : anyDone(EMU_KINDS) ? 'done' : 'pending';
      case 'findings':
        return findingCount && findingCount > 0 ? 'done' : 'pending';
      default:
        return 'pending';
    }
  };

  const metaOf = (id: StepId): string | null => {
    // A count is a number in every language; only the word beside the Emulation node is prose.
    if (id === 'findings' && findingCount !== null) return `${findingCount}`;
    if (id === 'simulate' && (strategy === 'static-only' || strategy === 'unsupported-arch'))
      return t.shell.timeline.blocked;
    return null;
  };

  const node = (state: State, index: number): JSX.Element => {
    if (state === 'done') return <span aria-hidden="true">✓</span>;
    if (state === 'running') return <span className="spinner" style={{ width: 12, height: 12 }} />;
    if (state === 'blocked') return <span aria-hidden="true">!</span>;
    return <span>{String(index + 1).padStart(2, '0')}</span>;
  };

  return (
    <nav className="steptl" aria-label={t.shell.timeline.label}>
      {ANALYSIS_STEPS.map((step, i) => {
        const state = stateOf(step);
        const isActive = active === step || (active === 'dossier' && step === 'overview');
        const meta = metaOf(step);
        // The section's own name, from the one catalogue that holds it — never a second copy kept here.
        const label = t.sections[step];
        return (
          <button
            key={step}
            type="button"
            className={`steptl-step ${state} ${isActive ? 'active' : ''}`}
            aria-current={isActive ? 'step' : undefined}
            title={t.shell.timeline.stepTitle(label, t.shell.timeline.state[state])}
            onClick={() => nav(`/image/${imageId}/${step}`)}
          >
            <span className="steptl-node">{node(state, i)}</span>
            <span className="steptl-label">{label}</span>
            <span className="steptl-meta">{meta ?? ' '}</span>
          </button>
        );
      })}
    </nav>
  );
}
