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
 */
import { useCallback, useRef, useState } from 'react';
import { type AnalysisKind, api } from '../api';
import { RunHistory } from './RunHistory';

interface ProviderCard {
  kind: AnalysisKind;
  icon: string;
  title: string;
  desc: string;
}

const PROVIDER_GROUPS: { label: string; providers: ProviderCard[] }[] = [
  {
    label: 'Boot & platform',
    providers: [
      {
        kind: 'uboot',
        icon: '🧰',
        title: 'U-Boot / bootloader',
        desc: 'Decode the U-Boot env and audit boot posture (root-shell args, interruptible autoboot, net-boot).',
      },
      {
        kind: 'devicetree',
        icon: '🗺',
        title: 'Device tree',
        desc: 'Read the board description the image carries — SoC, flash map, peripherals and the kernel command line.',
      },
      {
        kind: 'kernel',
        icon: '🐧',
        title: 'Kernel posture',
        desc: 'Kernel version and age, plus KASLR, /dev/kmem, module signing and RWX — each answered on, off, or not determinable.',
      },
    ],
  },
  {
    label: 'Filesystem & configuration',
    providers: [
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
        kind: 'services',
        icon: '🌐',
        title: 'Service enumeration',
        desc: 'Map the network daemons the rootfs is configured to start (init scripts, inetd, systemd) — the attack surface.',
      },
    ],
  },
  {
    label: 'Update & supply chain',
    providers: [
      {
        kind: 'updatepath',
        icon: '🔐',
        title: 'Update-path integrity',
        desc: 'Does the image carry a signature, does the updater verify anything, is there rollback protection?',
      },
      {
        kind: 'compmap',
        icon: '🕸',
        title: 'Component map',
        desc: 'Map each rootfs ELF to its shared-library dependencies (needs radare2).',
      },
    ],
  },
  {
    label: 'Device & radio',
    providers: [
      {
        kind: 'rtos',
        icon: '🔬',
        title: 'RTOS / bare-metal blob',
        desc: 'Recover the Cortex-M vector table + memory map and detect the RTOS kernel.',
      },
      {
        kind: 'fcc',
        icon: '📡',
        title: 'FCC ID lookup',
        desc: "Extract FCC IDs and link to the device's public filings (photos, manuals, internal photos, test reports).",
      },
    ],
  },
];

const PROVIDERS: ProviderCard[] = PROVIDER_GROUPS.flatMap((g) => g.providers);

type RunState = { status: 'idle' | 'running' | 'done' | 'error'; reason?: string; findings?: number; error?: string };

export function AnalysisActionsPanel({ imageId }: { imageId: string }): JSX.Element {
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
              setState((s) => ({ ...s, [kind]: { status: 'error', error: j.error ?? 'failed' } }));
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
    [imageId],
  );

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">Deep analysis</div>
      <div className="panel-sub">
        Offline providers that enrich the dossier. Findings are added to the image's findings ledger; each degrades
        honestly when its input or tool is absent.
      </div>
      {PROVIDER_GROUPS.map((group) => (
        <section key={group.label} style={{ marginTop: 18 }}>
          <div className="eyebrow" style={{ marginBottom: 8 }}>
            {group.label}
          </div>
          <div className="grid grid-2">
            {group.providers.map((p) => {
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
        </section>
      ))}
      {/* Each tile above shows the LAST run of its provider. These are the others — a provider re-run after a fix
          and one that was blocked and later worked are indistinguishable from a single result. */}
      <RunHistory
        imageId={imageId}
        kinds={PROVIDERS.map((p) => p.kind)}
        label="deep-analysis"
        refreshKey={historyKey}
      />
    </div>
  );
}
