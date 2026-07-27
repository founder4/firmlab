/*
 * StepTimeline — the persistent analysis pipeline for a firmware image. The eight stages read left-to-right the way
 * the analysis actually flows (General → Entropy → Extraction → Bootloader → SBOM → Binaries → Emulation →
 * Findings), and each node carries HONEST state derived from what has actually run: done, running, blocked (e.g.
 * an arch that can't be emulated here), or pending. It stays pinned under the top bar as you move between stages.
 */
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';

export const ANALYSIS_STEPS: { id: string; label: string }[] = [
  { id: 'overview', label: 'General' },
  { id: 'entropy', label: 'Entropy' },
  { id: 'filesystem', label: 'Extraction' },
  { id: 'bootloader', label: 'Bootloader' },
  { id: 'sbom', label: 'SBOM' },
  { id: 'binaries', label: 'Binaries' },
  { id: 'simulate', label: 'Emulation' },
  { id: 'findings', label: 'Findings' },
];

type State = 'done' | 'running' | 'blocked' | 'pending';
const BOOT_KINDS = ['uboot', 'fsaudit', 'certs', 'services', 'rtos', 'compmap', 'fcc'];
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

  const stateOf = (id: string): State => {
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

  const metaOf = (id: string): string | null => {
    if (id === 'findings' && findingCount !== null) return `${findingCount}`;
    if (id === 'simulate' && (strategy === 'static-only' || strategy === 'unsupported-arch')) return 'blocked';
    return null;
  };

  const node = (state: State, index: number): JSX.Element => {
    if (state === 'done') return <span aria-hidden="true">✓</span>;
    if (state === 'running') return <span className="spinner" style={{ width: 12, height: 12 }} />;
    if (state === 'blocked') return <span aria-hidden="true">!</span>;
    return <span>{String(index + 1).padStart(2, '0')}</span>;
  };

  return (
    <nav className="steptl" aria-label="Analysis pipeline">
      {ANALYSIS_STEPS.map((step, i) => {
        const state = stateOf(step.id);
        const isActive = active === step.id || (active === 'dossier' && step.id === 'overview');
        const meta = metaOf(step.id);
        return (
          <button
            key={step.id}
            type="button"
            className={`steptl-step ${state} ${isActive ? 'active' : ''}`}
            aria-current={isActive ? 'step' : undefined}
            title={`${step.label} — ${state}`}
            onClick={() => nav(`/image/${imageId}/${step.id}`)}
          >
            <span className="steptl-node">{node(state, i)}</span>
            <span className="steptl-label">{step.label}</span>
            <span className="steptl-meta">{meta ?? ' '}</span>
          </button>
        );
      })}
    </nav>
  );
}
