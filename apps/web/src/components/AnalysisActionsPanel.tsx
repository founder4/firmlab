/**
 * Deep static-analysis actions — run the offline providers that enrich the dossier. Each runs as a job; its findings
 * land in the dossier's findings ledger. Honest: a provider that has no input (no rootfs, not a UEFI/RTOS image) or a
 * missing tool reports so in its result reason.
 *
 * The providers are GROUPED by the question they answer rather than listed flat, and that is a legibility decision
 * with a threshold behind it: at seven a flat grid scanned fine, and the three that landed on 2026-07-28 (kernel
 * posture, update-path integrity, device tree) take it to ten, at which point "which of these do I want" stops being
 * answerable at a glance. The groups are the reader's own question — how does it boot, what is in the filesystem, how
 * does it update, what is the device — not a taxonomy of our module layout.
 *
 * **What is data here and what is words.** The `AnalysisKind` of each card is an identifier: it is the job kind the
 * POST starts and the row it lands on in SQLite. So this file keeps the ROUTING — which kinds, in which group, in
 * which order, behind which icon — and the catalogue keeps every word, keyed by that same identifier. The tile that
 * says `no findings` and the sentence above it saying a provider degrades honestly when its input or tool is absent
 * are the pair that has to survive translation together: on its own, an empty tile is exactly what a clean result
 * looks like.
 */
import { useCallback, useRef, useState } from 'react';
import { type AnalysisKind, api } from '../api';
import { type Messages, useMessages } from '../i18n';
import { RunHistory } from './RunHistory';

/** The providers this panel offers, and the key under which the catalogue names each one. */
type ProviderKind = keyof Messages['shell']['deep']['provider'] & AnalysisKind;
type GroupId = keyof Messages['shell']['deep']['group'];

const PROVIDER_GROUPS: { id: GroupId; kinds: ProviderKind[] }[] = [
  { id: 'boot', kinds: ['uboot', 'devicetree', 'kernel'] },
  { id: 'filesystem', kinds: ['fsaudit', 'certs', 'services'] },
  { id: 'update', kinds: ['updatepath', 'compmap'] },
  { id: 'device', kinds: ['rtos', 'fcc'] },
];

const ICONS: Record<ProviderKind, string> = {
  uboot: '🧰',
  devicetree: '🗺',
  kernel: '🐧',
  fsaudit: '🔎',
  certs: '📜',
  services: '🌐',
  updatepath: '🔐',
  compmap: '🕸',
  rtos: '🔬',
  fcc: '📡',
};

const PROVIDERS: ProviderKind[] = PROVIDER_GROUPS.flatMap((g) => g.kinds);

type RunState = { status: 'idle' | 'running' | 'done' | 'error'; reason?: string; findings?: number; error?: string };

export function AnalysisActionsPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const [state, setState] = useState<Record<string, RunState>>({});
  /** Bumped when a provider finishes, so the history below re-reads without polling. */
  const [historyKey, setHistoryKey] = useState(0);
  const polls = useRef<Record<string, number>>({});

  const run = useCallback(
    async (kind: AnalysisKind) => {
      setState((s) => ({ ...s, [kind]: { status: 'running' } }));
      try {
        const { jobId } = await api.runAnalysis(imageId, kind);
        polls.current[kind] = window.setInterval(async () => {
          const j = await api.job(jobId);
          if (j.status === 'done' || j.status === 'error') {
            window.clearInterval(polls.current[kind]);
            if (j.status === 'error') {
              setState((s) => ({ ...s, [kind]: { status: 'error', error: j.error ?? t.shell.deep.failed } }));
            } else {
              const res = j.result as { reason?: string; findings?: unknown[] } | null;
              const done: RunState = { status: 'done', findings: res?.findings?.length ?? 0 };
              if (res?.reason) done.reason = res.reason;
              setState((s) => ({ ...s, [kind]: done }));
              setHistoryKey((k) => k + 1);
            }
          }
        }, 700);
      } catch (e) {
        setState((s) => ({ ...s, [kind]: { status: 'error', error: e instanceof Error ? e.message : String(e) } }));
      }
    },
    [imageId, t],
  );

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">{t.shell.deep.title}</div>
      <div className="panel-sub">{t.shell.deep.sub}</div>
      {PROVIDER_GROUPS.map((group) => (
        <section key={group.id} style={{ marginTop: 18 }}>
          <div className="eyebrow" style={{ marginBottom: 8 }}>
            {t.shell.deep.group[group.id]}
          </div>
          <div className="grid grid-2">
            {group.kinds.map((kind) => {
              const st = state[kind] ?? { status: 'idle' };
              const card = t.shell.deep.provider[kind];
              return (
                <div key={kind} className="panel" style={{ margin: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 16 }}>{ICONS[kind]}</span>
                    <strong style={{ fontSize: 13 }}>{card.title}</strong>
                    <button
                      className="btn btn-primary btn-sm"
                      style={{ marginLeft: 'auto' }}
                      disabled={st.status === 'running'}
                      onClick={() => run(kind)}
                    >
                      {st.status === 'running' ? <span className="spinner" /> : t.common.run}
                    </button>
                  </div>
                  <div className="hint">{card.desc}</div>
                  {st.status === 'done' && (
                    <div style={{ marginTop: 8, display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
                      <span className={`badge ${st.findings ? 'badge-ok' : ''}`}>
                        {st.findings ? t.shell.deep.findings(st.findings) : t.shell.deep.noFindings}
                      </span>
                      {st.reason && (
                        <span className="hint" style={{ fontSize: 11.5 }}>
                          {st.reason}
                        </span>
                      )}
                    </div>
                  )}
                  {st.status === 'error' && (
                    <div className="banner banner-warn" style={{ marginTop: 8 }}>
                      {st.error}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      ))}
      {/* Each tile above shows the LAST run of its provider. These are the others — a provider re-run after a fix
          and one that was blocked and later worked are indistinguishable from a single result. */}
      <RunHistory imageId={imageId} kinds={PROVIDERS} runKind="deepAnalysis" refreshKey={historyKey} />
    </div>
  );
}
