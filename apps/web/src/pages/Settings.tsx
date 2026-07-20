import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { type AgentConfig, type StorageUsage, api, fmtBytes } from '../api';
import { Icon } from '../icons';
import { startTour } from '../onboarding';
import { type Density, type ThemePref, setDensity, setTheme, useAppearance } from '../theme';

type Health = { exposedToNetwork: boolean; trustedProxy?: boolean; host?: string; port?: number };
type SettingsTab = 'appearance' | 'analysis' | 'privacy' | 'agent' | 'storage' | 'help';

const TABS: { id: SettingsTab; label: string }[] = [
  { id: 'appearance', label: 'Appearance' },
  { id: 'analysis', label: 'Analysis' },
  { id: 'privacy', label: 'Privacy' },
  { id: 'agent', label: 'Agent' },
  { id: 'storage', label: 'Storage' },
  { id: 'help', label: 'Help' },
];

/** A labeled row of read-only fact + value (the transparency panels are honest mirrors of real backend state). */
function Row({ label, children }: { label: string; children: React.ReactNode }): JSX.Element {
  return (
    <div
      style={{
        display: 'flex',
        gap: 12,
        padding: '9px 0',
        borderBottom: '1px solid var(--border-soft)',
        alignItems: 'baseline',
      }}
    >
      <div style={{ width: 190, flexShrink: 0, color: 'var(--text-dim)', fontSize: 13 }}>{label}</div>
      <div style={{ flex: 1, minWidth: 0 }}>{children}</div>
    </div>
  );
}

export function Settings(): JSX.Element {
  const { theme, density } = useAppearance();
  const [tab, setTab] = useState<SettingsTab>('appearance');
  const [health, setHealth] = useState<Health | null>(null);
  const [agent, setAgent] = useState<AgentConfig | null>(null);
  const [usage, setUsage] = useState<StorageUsage | null>(null);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch(() => setHealth(null));
    api
      .agentConfig()
      .then(setAgent)
      .catch(() => setAgent(null));
    api
      .storage()
      .then(setUsage)
      .catch(() => setUsage(null));
  }, []);

  const posture = !health
    ? { label: 'Unknown', cls: 'badge-medium', note: 'The API is unreachable.' }
    : health.trustedProxy
      ? { label: 'Auth-gated proxy', cls: 'badge-ok', note: 'Reached only through an authenticating reverse proxy.' }
      : health.exposedToNetwork
        ? {
            label: 'Bound to network',
            cls: 'badge-medium',
            note: 'The API is reachable beyond loopback. Consider restricting it.',
          }
        : { label: 'Local-only', cls: 'badge-ok', note: 'Bound to loopback — firmware never leaves this machine.' };

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">System</div>
          <h1 className="page-title">Settings</h1>
          <div className="page-desc">
            Appearance is yours to change here. Analysis, privacy, and agent limits reflect the deployment’s real
            configuration.
          </div>
        </div>
      </div>

      <div className="tabs" style={{ marginBottom: 18 }}>
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`tab ${tab === t.id ? 'active' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'appearance' && (
        <div className="panel" style={{ maxWidth: 640 }}>
          <div className="panel-title">Appearance</div>
          <div className="panel-sub">Applied instantly and remembered on this device.</div>
          <Row label="Theme">
            <div className="segmented">
              {(['light', 'system', 'dark'] as ThemePref[]).map((v) => (
                <button key={v} type="button" className={theme === v ? 'active' : ''} onClick={() => setTheme(v)}>
                  {v === 'light' ? (
                    <Icon.sun size={14} />
                  ) : v === 'dark' ? (
                    <Icon.moon size={14} />
                  ) : (
                    <Icon.monitor size={14} />
                  )}
                  <span style={{ textTransform: 'capitalize' }}>{v}</span>
                </button>
              ))}
            </div>
          </Row>
          <Row label="Density">
            <div className="segmented">
              {(['comfortable', 'compact'] as Density[]).map((v) => (
                <button key={v} type="button" className={density === v ? 'active' : ''} onClick={() => setDensity(v)}>
                  <span style={{ textTransform: 'capitalize' }}>{v}</span>
                </button>
              ))}
            </div>
          </Row>
          <div className="hint" style={{ marginTop: 12 }}>
            Compact density tightens table rows and spacing for dense sessions on large monitors.
          </div>
        </div>
      )}

      {tab === 'analysis' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">Analysis</div>
          <div className="panel-sub">
            The deterministic engine runs on every upload with no configuration. Depth comes from external tools and
            from deployment limits, which are set on the server.
          </div>
          <Row label="External tools">
            <Link to="/capabilities" className="btn btn-sm">
              <Icon.capabilities size={14} /> View detected tools
            </Link>
            <div className="hint" style={{ marginTop: 6 }}>
              binwalk, radare2/Ghidra, syft/grype, gitleaks and QEMU unlock extraction, triage, SBOM/CVEs, deep secret
              scans and emulation when present.
            </div>
          </Row>
          <Row label="Upload limit">
            <span className="hint">
              Max image size is set with <span className="mono">FIRMLAB_MAX_UPLOAD</span> (default 500 MB).
            </span>
          </Row>
          <Row label="Job concurrency">
            <span className="hint">
              Heavy tools are throttled with <span className="mono">FIRMLAB_MAX_CONCURRENT_JOBS</span> (default 2) so a
              burst can’t exhaust the machine.
            </span>
          </Row>
          <div className="hint" style={{ marginTop: 12 }}>
            These are deployment settings rather than per-session preferences, so they live in the environment, not here
            — this panel mirrors them honestly.
          </div>
        </div>
      )}

      {tab === 'privacy' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">Privacy & connectivity</div>
          <div className="panel-sub">
            FirmLab is designed to run locally. Firmware images are analyzed on this machine and are not uploaded.
          </div>
          <Row label="Network posture">
            <span className={`badge ${posture.cls}`}>{posture.label}</span>
            <div className="hint" style={{ marginTop: 6 }}>
              {posture.note}
            </div>
          </Row>
          <Row label="Bind address">
            <span className="mono">{health ? `${health.host}:${health.port}` : '—'}</span>
          </Row>
          <Row label="External copilot / agent">
            {agent?.enabled ? (
              <>
                <span className="badge badge-medium">Enabled</span>
                <div className="hint" style={{ marginTop: 6 }}>
                  When you run the copilot or an agent session, the deterministic analysis context (findings, binary
                  metadata, corpus cross-refs) is sent to <span className="mono">{agent.provider}</span> (
                  <span className="mono">{agent.model}</span>). No raw firmware bytes are sent. Emulation requires your
                  approval.
                </div>
              </>
            ) : (
              <>
                <span className="badge badge-ok">Disabled</span>
                <div className="hint" style={{ marginTop: 6 }}>
                  No external model is configured. Nothing is sent off-machine. Enable it with
                  <span className="mono"> FIRMLAB_AGENT=1</span> and an API key.
                </div>
              </>
            )}
          </Row>
          <div className="banner banner-info" style={{ marginTop: 16, marginBottom: 0 }}>
            <Icon.shield size={16} />
            <span>
              The engine (@firmlab/core) is deterministic and needs no network. External tools and the optional copilot
              are the only things that can reach outside this process.
            </span>
          </div>
        </div>
      )}

      {tab === 'agent' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">Agent (conscious autonomy)</div>
          <div className="panel-sub">
            The agent reasons within a deterministic skeleton and pauses for approval before emulation. These limits are
            enforced by the governor and set via environment variables.
          </div>
          <Row label="Status">
            <span className={`badge ${agent?.enabled ? 'badge-ok' : ''}`}>
              {agent?.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </Row>
          {agent?.enabled && (
            <>
              <Row label="Model">
                <span className="mono">
                  {agent.provider} · {agent.model}
                </span>
              </Row>
              {agent.budget && (
                <>
                  <Row label="Step budget">
                    <span className="mono">{agent.budget.maxSteps}</span>{' '}
                    <span className="hint">FIRMLAB_AGENT_MAX_STEPS</span>
                  </Row>
                  <Row label="Token budget">
                    <span className="mono">{agent.budget.maxTokens.toLocaleString()}</span>{' '}
                    <span className="hint">FIRMLAB_AGENT_MAX_TOKENS</span>
                  </Row>
                  <Row label="Cost ceiling">
                    <span className="mono">{agent.budget.maxUsd > 0 ? `$${agent.budget.maxUsd}` : 'unbounded'}</span>{' '}
                    <span className="hint">FIRMLAB_AGENT_MAX_USD</span>
                  </Row>
                  <Row label="Time budget">
                    <span className="mono">{Math.round(agent.budget.maxWallMs / 1000)}s</span>{' '}
                    <span className="hint">FIRMLAB_AGENT_MAX_SECONDS</span>
                  </Row>
                </>
              )}
              <Row label="Emulation">
                <span className="badge badge-medium">Human approval required</span>
              </Row>
            </>
          )}
          {!agent?.enabled && (
            <div className="hint" style={{ marginTop: 12 }}>
              Set <span className="mono">FIRMLAB_AGENT=1</span> and an LLM API key to enable the decision nodes. With
              the flag off, FirmLab stays local-only and deterministic.
            </div>
          )}
        </div>
      )}

      {tab === 'storage' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">Storage & retention</div>
          <div className="panel-sub">
            Uploaded images and carved rootfs live under the data directory on this machine.
          </div>
          <Row label="On disk">
            <span className="mono">{usage ? fmtBytes(usage.totalBytes) : '—'}</span>
            {usage && usage.quotaBytes > 0 && (
              <div style={{ marginTop: 8, maxWidth: 320 }}>
                <div className="meter">
                  <span
                    style={{ width: `${Math.min(100, (usage.totalBytes / usage.quotaBytes) * 100).toFixed(1)}%` }}
                  />
                </div>
                <div className="hint" style={{ marginTop: 4 }}>
                  {fmtBytes(usage.totalBytes)} of {fmtBytes(usage.quotaBytes)} quota
                </div>
              </div>
            )}
          </Row>
          <Row label="Images">
            <span className="mono">{usage?.imageCount ?? '—'}</span>
          </Row>
          <Row label="Retention">
            <span className="hint">
              {usage && usage.maxAgeDays > 0
                ? `Images older than ${usage.maxAgeDays} days are evicted.`
                : 'No age limit set.'}
              {usage && usage.quotaBytes > 0
                ? ' Oldest images are evicted first when over quota.'
                : ' No size quota set.'}
            </span>
          </Row>
          <div className="hint" style={{ marginTop: 12 }}>
            Manage or bulk-delete images from the <Link to="/">Dashboard</Link>. Retention limits are configured with
            <span className="mono"> FIRMLAB_MAX_IMAGE_AGE_DAYS</span> and{' '}
            <span className="mono">FIRMLAB_MAX_DATA_BYTES</span>.
          </div>
        </div>
      )}

      {tab === 'help' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">Help</div>
          <div className="panel-sub">Learn your way around, or revisit the introduction.</div>
          <Row label="Product tour">
            <button type="button" className="btn btn-sm" onClick={startTour}>
              <Icon.help size={14} /> Restart tour
            </button>
          </Row>
          <Row label="Keyboard">
            <span className="hint">
              Navigate with Tab and Shift+Tab; activate with Enter/Space; dismiss overlays with Esc.
            </span>
          </Row>
          <Row label="Documentation">
            <span className="hint">
              See the project README and docs/ for architecture, the emulation ladder, and the agent design.
            </span>
          </Row>
          <Row label="About">
            <span className="hint">
              FirmLab — local-only firmware analysis workbench. Deterministic engine, optional tool-backed depth.
            </span>
          </Row>
        </div>
      )}
    </div>
  );
}
