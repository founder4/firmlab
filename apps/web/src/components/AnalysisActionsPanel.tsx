/**
 * Deep static-analysis actions — run the offline providers that enrich the dossier: U-Boot bootloader posture,
 * rootfs security audit, embedded X.509 certificates, RTOS/Cortex-M blob analysis, and the component dependency
 * map. Each runs as a job; its findings land in the dossier's findings ledger. Honest: a provider that has no
 * input (no rootfs, not a UEFI/RTOS image) or a missing tool reports so in its result reason.
 */
import { useCallback, useRef, useState } from 'react';
import { type AnalysisKind, api } from '../api';

const PROVIDERS: { kind: AnalysisKind; icon: string; title: string; desc: string }[] = [
  {
    kind: 'uboot',
    icon: '🧰',
    title: 'U-Boot / bootloader',
    desc: 'Decode the U-Boot env and audit boot posture (root-shell args, interruptible autoboot, net-boot).',
  },
  {
    kind: 'fsaudit',
    icon: '🔎',
    title: 'Rootfs security audit',
    desc: 'firmwalker-style checks: weak/empty credentials, root shells, telnetd, permissive service configs, key material.',
  },
  {
    kind: 'certs',
    icon: '📜',
    title: 'Certificates (X.509)',
    desc: 'Parse embedded certificates — expired, weak RSA, test/self-signed, embedded CA.',
  },
  {
    kind: 'rtos',
    icon: '🔬',
    title: 'RTOS / bare-metal blob',
    desc: 'Recover the Cortex-M vector table + memory map and detect the RTOS kernel.',
  },
  {
    kind: 'compmap',
    icon: '🕸',
    title: 'Component map',
    desc: 'Map each rootfs ELF to its shared-library dependencies (needs radare2).',
  },
  {
    kind: 'services',
    icon: '🌐',
    title: 'Service enumeration',
    desc: 'Map the network daemons the rootfs is configured to start (init scripts, inetd, systemd) — the attack surface.',
  },
  {
    kind: 'fcc',
    icon: '📡',
    title: 'FCC ID lookup',
    desc: "Extract FCC IDs and link to the device's public filings (photos, manuals, internal photos, test reports).",
  },
];

type RunState = { status: 'idle' | 'running' | 'done' | 'error'; reason?: string; findings?: number; error?: string };

export function AnalysisActionsPanel({ imageId }: { imageId: string }): JSX.Element {
  const [state, setState] = useState<Record<string, RunState>>({});
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
              setState((s) => ({ ...s, [kind]: { status: 'error', error: j.error ?? 'failed' } }));
            } else {
              const res = j.result as { reason?: string; findings?: unknown[] } | null;
              const done: RunState = { status: 'done', findings: res?.findings?.length ?? 0 };
              if (res?.reason) done.reason = res.reason;
              setState((s) => ({ ...s, [kind]: done }));
            }
          }
        }, 700);
      } catch (e) {
        setState((s) => ({ ...s, [kind]: { status: 'error', error: e instanceof Error ? e.message : String(e) } }));
      }
    },
    [imageId],
  );

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">Deep analysis</div>
      <div className="panel-sub">
        Offline providers that enrich the dossier. Findings are added to the image's findings ledger; each degrades
        honestly when its input or tool is absent.
      </div>
      <div className="grid grid-2" style={{ marginTop: 8 }}>
        {PROVIDERS.map((p) => {
          const st = state[p.kind] ?? { status: 'idle' };
          return (
            <div key={p.kind} className="panel" style={{ margin: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 16 }}>{p.icon}</span>
                <strong style={{ fontSize: 13 }}>{p.title}</strong>
                <button
                  className="btn btn-primary btn-sm"
                  style={{ marginLeft: 'auto' }}
                  disabled={st.status === 'running'}
                  onClick={() => run(p.kind)}
                >
                  {st.status === 'running' ? <span className="spinner" /> : 'Run'}
                </button>
              </div>
              <div className="hint">{p.desc}</div>
              {st.status === 'done' && (
                <div style={{ marginTop: 8, display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
                  <span className={`badge ${st.findings ? 'badge-ok' : ''}`}>
                    {st.findings ? `${st.findings} finding(s)` : 'no findings'}
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
    </div>
  );
}
