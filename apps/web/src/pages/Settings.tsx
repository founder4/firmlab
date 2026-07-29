import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { type AgentConfig, type LaneFlag, type LlmSettings, type StorageUsage, api, fmtBytes } from '../api';
import { LOCALES, type Locale, intlTag, setLocale, useLocale, useMessages } from '../i18n';
import { Icon } from '../icons';
import { startTour } from '../onboarding';
import { type Density, type ThemePref, setDensity, setTheme, useAppearance } from '../theme';
import { toast } from '../toast';
import { Capabilities } from './Capabilities';

type Health = { exposedToNetwork: boolean; trustedProxy?: boolean; host?: string; port?: number };
type SettingsTab = 'appearance' | 'analysis' | 'tools' | 'privacy' | 'agent' | 'storage' | 'help';

/** Order only — the words live in the catalogue, keyed by the same id the view switches on. */
const TAB_IDS: SettingsTab[] = ['appearance', 'analysis', 'tools', 'agent', 'privacy', 'storage', 'help'];

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

/**
 * One switchable lane.
 *
 * The switch is the small part. What earns the space is the sentence underneath: an operator deciding whether to
 * turn on external intelligence needs to know what leaves this machine before they flip it, not after — so the
 * effect and the egress are always visible rather than hidden behind a tooltip or an info icon. The source line
 * exists because an override and the environment can disagree, and the person reading the compose file deserves
 * to be told which one won.
 *
 * `label`, `effect` and `egress` are composed by the API in the locale this page asked for — they are resolved on
 * every read and describe this deployment, so they are interface copy, not a record. The flag NAME beside them is
 * an environment variable and renders verbatim: an operator grepping a compose file for it has to find it.
 */
/**
 * The model provider, editable.
 *
 * It replaced three rows of read-only prose whose only instruction was "edit a YAML file on the host" — and which
 * offered `ollama`, a provider `llm.ts` has never supported. The provider list comes from the SERVER now, so this
 * screen structurally cannot offer one the build would reject.
 *
 * **The key is write-only, and that is a property of the API rather than of this component.** `GET /settings/llm`
 * returns whether a key is present and its last four characters; there is no path that returns the key itself. So
 * the field starts empty always, `keyNeverShown` says why, and a save replaces rather than edits.
 *
 * **Every field says which of the environment and the override is in force**, because an operator who set
 * `FIRMLAB_LLM_MODEL` in compose and sees a different model here has to be told why, not left to guess. That is
 * the same contract the lane toggles above already keep.
 */
function LlmProviderEditor(): JSX.Element {
  const t = useMessages();
  const e = t.settings.agent.edit;
  const [llm, setLlm] = useState<LlmSettings | null>(null);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .llmSettings()
      .then((r) => setLlm(r.llm))
      .catch(() => setLlm(null));
  }, []);
  useEffect(load, [load]);

  const apply = useCallback(
    async (key: string, value: string) => {
      setBusy(key);
      setError(null);
      try {
        setLlm(await api.setLlmSetting(key, value));
        // The draft is dropped rather than kept: what is authoritative now is what the server just reported.
        setDraft((d) => ({ ...d, [key]: '' }));
        toast.success(e.saved);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(null);
      }
    },
    [e],
  );

  const clear = useCallback(
    async (key: string) => {
      setBusy(key);
      setError(null);
      try {
        setLlm(await api.clearLlmSetting(key));
        toast.success(e.cleared);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(null);
      }
    },
    [e],
  );

  if (!llm) return <div className="skeleton" style={{ height: 120 }} />;

  const sourceLabel = (s: 'override' | 'environment' | 'default'): string =>
    s === 'override' ? e.fromOverride : s === 'environment' ? e.fromEnv : e.fromDefault;

  /** A field's provenance chip plus, for an override, the way back to the environment. */
  const Provenance = ({ source, settingKey }: { source: LlmSettings['provider']['source']; settingKey: string }) => (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span className="hint" style={{ fontSize: 11.5 }}>
        {sourceLabel(source)}
      </span>
      {source === 'override' && (
        <button
          type="button"
          className="btn btn-sm btn-ghost"
          disabled={busy === settingKey}
          onClick={() => clear(settingKey)}
        >
          {e.clear}
        </button>
      )}
    </span>
  );

  return (
    <>
      <div className="panel-title" style={{ marginTop: 18 }}>
        {e.title}{' '}
        <span className={`badge ${llm.ready ? 'badge-ok' : 'badge-medium'}`}>{llm.ready ? e.ready : e.notReady}</span>
      </div>
      <div className="panel-sub">{e.sub}</div>

      {/* The sentence that keeps a dropdown choice from silently switching the copilot off. */}
      {!llm.ready && llm.reason && (
        <div className="banner banner-warn" style={{ marginTop: 10 }}>
          {llm.reason}
        </div>
      )}
      {error && (
        <div className="banner banner-warn" style={{ marginTop: 10 }}>
          {error}
        </div>
      )}

      <Row label={e.provider}>
        <select
          className="input"
          style={{ maxWidth: 220 }}
          value={llm.provider.value}
          disabled={busy === 'FIRMLAB_LLM_PROVIDER'}
          onChange={(ev) => apply('FIRMLAB_LLM_PROVIDER', ev.target.value)}
        >
          {/* Provider ids are identifiers and render verbatim, and the list is the SERVER's. */}
          {llm.providers.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>{' '}
        <Provenance source={llm.provider.source} settingKey="FIRMLAB_LLM_PROVIDER" />
      </Row>

      <Row label={e.model}>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            className="input mono"
            style={{ maxWidth: 260 }}
            value={draft.FIRMLAB_LLM_MODEL ?? llm.model.value}
            placeholder={llm.defaultModels[llm.provider.value] || 'model-id'}
            onChange={(ev) => setDraft((d) => ({ ...d, FIRMLAB_LLM_MODEL: ev.target.value }))}
          />
          <button
            type="button"
            className="btn btn-sm"
            disabled={busy === 'FIRMLAB_LLM_MODEL' || !(draft.FIRMLAB_LLM_MODEL ?? '').trim()}
            onClick={() => apply('FIRMLAB_LLM_MODEL', draft.FIRMLAB_LLM_MODEL ?? '')}
          >
            {e.save}
          </button>
          <Provenance source={llm.model.source} settingKey="FIRMLAB_LLM_MODEL" />
        </div>
        <div className="hint" style={{ marginTop: 4 }}>
          {e.modelHint}
        </div>
      </Row>

      <Row label={e.apiKey}>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          <span className={`badge ${llm.apiKey.present ? 'badge-ok' : ''}`}>
            {llm.apiKey.present ? `${e.keySet} · …${llm.apiKey.tail}` : e.keyMissing}
          </span>
          <input
            className="input mono"
            type="password"
            style={{ maxWidth: 260 }}
            autoComplete="off"
            placeholder={e.keyPlaceholder}
            value={draft.FIRMLAB_LLM_API_KEY ?? ''}
            onChange={(ev) => setDraft((d) => ({ ...d, FIRMLAB_LLM_API_KEY: ev.target.value }))}
          />
          <button
            type="button"
            className="btn btn-sm"
            disabled={busy === 'FIRMLAB_LLM_API_KEY' || !(draft.FIRMLAB_LLM_API_KEY ?? '').trim()}
            onClick={() => apply('FIRMLAB_LLM_API_KEY', draft.FIRMLAB_LLM_API_KEY ?? '')}
          >
            {e.save}
          </button>
          <Provenance source={llm.apiKey.source} settingKey="FIRMLAB_LLM_API_KEY" />
        </div>
        {/* What saving a key here CHANGES. Styled as a warning because it is one. */}
        <div className="hint" style={{ marginTop: 6, color: 'var(--sev-medium, #e6b45c)' }}>
          {e.keyWarning}
        </div>
        <div className="hint" style={{ marginTop: 4 }}>
          {e.keyNeverShown} {e.keyInEnv(llm.apiKey.envVar)}
        </div>
      </Row>

      <Row label={e.baseUrl}>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            className="input mono"
            style={{ maxWidth: 300 }}
            value={draft.FIRMLAB_LLM_BASE_URL ?? llm.baseUrl.value}
            onChange={(ev) => setDraft((d) => ({ ...d, FIRMLAB_LLM_BASE_URL: ev.target.value }))}
          />
          <button
            type="button"
            className="btn btn-sm"
            disabled={busy === 'FIRMLAB_LLM_BASE_URL' || !(draft.FIRMLAB_LLM_BASE_URL ?? '').trim()}
            onClick={() => apply('FIRMLAB_LLM_BASE_URL', draft.FIRMLAB_LLM_BASE_URL ?? '')}
          >
            {e.save}
          </button>
          <Provenance source={llm.baseUrl.source} settingKey="FIRMLAB_LLM_BASE_URL" />
        </div>
        <div className="hint" style={{ marginTop: 4 }}>
          {e.baseUrlHint}
        </div>
      </Row>
    </>
  );
}

function LaneToggle({
  flag,
  busy,
  onToggle,
  onClear,
}: {
  flag: LaneFlag;
  busy: boolean;
  onToggle: (enabled: boolean) => void;
  onClear: () => void;
}): JSX.Element {
  const t = useMessages();
  const on = flag.enabled;
  return (
    <div
      style={{
        display: 'flex',
        gap: 14,
        padding: '16px 0',
        borderBottom: '1px solid var(--border-soft)',
        alignItems: 'flex-start',
      }}
    >
      <button
        type="button"
        role="switch"
        aria-checked={on}
        aria-label={flag.label}
        disabled={busy}
        onClick={() => onToggle(!on)}
        style={{
          flexShrink: 0,
          marginTop: 2,
          width: 40,
          height: 22,
          padding: 2,
          borderRadius: 999,
          border: `1px solid ${on ? 'var(--accent-line)' : 'var(--border-soft)'}`,
          background: on ? 'var(--accent-soft)' : 'var(--surface-2)',
          cursor: busy ? 'wait' : 'pointer',
          opacity: busy ? 0.6 : 1,
          transition: 'background 160ms cubic-bezier(0.16, 1, 0.3, 1), border-color 160ms',
        }}
      >
        <span
          style={{
            display: 'block',
            width: 16,
            height: 16,
            borderRadius: 999,
            background: on ? 'var(--accent)' : 'var(--text-dim)',
            transform: `translateX(${on ? 18 : 0}px)`,
            transition: 'transform 160ms cubic-bezier(0.16, 1, 0.3, 1), background 160ms',
          }}
        />
      </button>

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
          <span style={{ fontWeight: 600 }}>{flag.label}</span>
          <span className="mono" style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            {flag.name}
          </span>
          {flag.source === 'override' && (
            <button
              type="button"
              onClick={onClear}
              disabled={busy}
              title={t.settings.lanes.followEnvironmentHint(flag.environmentValue)}
              style={{
                fontSize: 11,
                padding: '1px 7px',
                borderRadius: 999,
                border: '1px solid var(--border-soft)',
                background: 'transparent',
                color: 'var(--text-dim)',
                cursor: 'pointer',
              }}
            >
              {t.settings.lanes.followEnvironment}
            </button>
          )}
        </div>

        <div className="hint" style={{ marginTop: 6 }}>
          {flag.effect}
        </div>
        <div className="hint" style={{ marginTop: 4, color: on && flag.outward ? 'var(--warn)' : 'var(--text-dim)' }}>
          {/* Present tense when it is already happening, conditional when it is not — the difference between
              "this is leaving now" and "this would leave" is the whole reason the line is here. */}
          {on && flag.outward ? t.settings.lanes.leavingNow : t.settings.lanes.ifEnabled}
          {flag.egress}
        </div>

        {flag.inert && (
          <div className="hint" style={{ marginTop: 6, color: 'var(--warn)' }}>
            {t.settings.lanes.inertLead}
            <span className="mono">{flag.requires}</span>
            {t.settings.lanes.inertTail}
          </div>
        )}
      </div>
    </div>
  );
}

export function Settings(): JSX.Element {
  const { theme, density } = useAppearance();
  const t = useMessages();
  const locale = useLocale();
  const [tab, setTab] = useState<SettingsTab>('appearance');
  const [health, setHealth] = useState<Health | null>(null);
  const [agent, setAgent] = useState<AgentConfig | null>(null);
  const [usage, setUsage] = useState<StorageUsage | null>(null);
  const [flags, setFlags] = useState<LaneFlag[] | null>(null);
  const [busyFlag, setBusyFlag] = useState<string | null>(null);
  const [flagError, setFlagError] = useState<string | null>(null);

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
    api
      .flags(locale)
      .then((r) => setFlags(r.flags))
      .catch(() => setFlags(null));
  }, [locale]);

  // A lane change is answered with the whole resolved set, so a dependent flag turning inert shows up in the same
  // paint as the switch that caused it — and the write carries the locale for the same reason the read does, or
  // the panel would repaint into English on the click that changed it.
  const applyFlag = (name: string, run: () => Promise<LaneFlag[]>): void => {
    setBusyFlag(name);
    setFlagError(null);
    run()
      .then(setFlags)
      .catch((e: Error) => setFlagError(e.message))
      .finally(() => setBusyFlag(null));
  };

  // Four states, never three: an unreachable API is its own answer and must not collapse into the local-only one.
  // The badge class is a style token and the words are prose, so only the words come from the catalogue.
  const p = t.settings.privacy.posture;
  const posture = !health
    ? { label: p.unknown, cls: 'badge-medium', note: p.unknownNote }
    : health.trustedProxy
      ? { label: p.proxy, cls: 'badge-ok', note: p.proxyNote }
      : health.exposedToNetwork
        ? { label: p.exposed, cls: 'badge-medium', note: p.exposedNote }
        : { label: p.local, cls: 'badge-ok', note: p.localNote };

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">{t.settings.eyebrow}</div>
          <h1 className="page-title">{t.settings.title}</h1>
          <div className="page-desc">{t.settings.desc}</div>
        </div>
      </div>

      <div className="tabs" style={{ marginBottom: 18 }}>
        {TAB_IDS.map((id) => (
          <button key={id} type="button" className={`tab ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)}>
            {t.settings.tabs[id]}
          </button>
        ))}
      </div>

      {tab === 'appearance' && (
        <div className="panel" style={{ maxWidth: 640 }}>
          <div className="panel-title">{t.settings.appearance.title}</div>
          <div className="panel-sub">{t.settings.appearance.sub}</div>
          <Row label={t.settings.appearance.theme}>
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
                  <span>
                    {v === 'light'
                      ? t.settings.appearance.themeLight
                      : v === 'dark'
                        ? t.settings.appearance.themeDark
                        : t.settings.appearance.themeSystem}
                  </span>
                </button>
              ))}
            </div>
          </Row>
          <Row label={t.settings.appearance.density}>
            <div className="segmented">
              {(['comfortable', 'compact'] as Density[]).map((v) => (
                <button key={v} type="button" className={density === v ? 'active' : ''} onClick={() => setDensity(v)}>
                  <span>
                    {v === 'compact' ? t.settings.appearance.densityCompact : t.settings.appearance.densityComfortable}
                  </span>
                </button>
              ))}
            </div>
          </Row>
          <Row label={t.settings.language.row}>
            <div className="segmented">
              {LOCALES.map((l) => (
                <button
                  key={l.value}
                  type="button"
                  className={locale === l.value ? 'active' : ''}
                  aria-pressed={locale === l.value}
                  onClick={() => setLocale(l.value)}
                >
                  <span>{l.label}</span>
                </button>
              ))}
            </div>
          </Row>
          <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
            {t.settings.appearance.densityHint}
          </div>
          <div className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
            {t.settings.language.hint}
          </div>
          {/* The boundary, stated where the switch is thrown rather than discovered later inside a report. */}
          <div className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
            {t.settings.language.scope}
          </div>
        </div>
      )}

      {tab === 'analysis' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">{t.settings.analysis.title}</div>
          <div className="panel-sub">{t.settings.analysis.sub}</div>
          <Row label={t.settings.analysis.externalTools}>
            <button type="button" className="btn btn-sm" onClick={() => setTab('tools')}>
              <Icon.capabilities size={14} /> {t.settings.analysis.viewTools}
            </button>
            <div className="hint" style={{ marginTop: 6 }}>
              {t.settings.analysis.toolsHint}
            </div>
          </Row>
          {/* The variable names sit outside the sentence in both languages — they are what an operator types. */}
          <Row label={t.settings.analysis.uploadLimit}>
            <span className="hint">
              {t.settings.analysis.uploadLimitLead} <span className="mono">FIRMLAB_MAX_UPLOAD</span>{' '}
              {t.settings.analysis.uploadLimitTail}
            </span>
          </Row>
          <Row label={t.settings.analysis.jobConcurrency}>
            <span className="hint">
              {t.settings.analysis.concurrencyLead} <span className="mono">FIRMLAB_MAX_CONCURRENT_JOBS</span>{' '}
              {t.settings.analysis.concurrencyTail}
            </span>
          </Row>
          <div className="hint" style={{ marginTop: 12 }}>
            {t.settings.analysis.deploymentNote}
          </div>
        </div>
      )}

      {tab === 'tools' && <Capabilities />}

      {tab === 'privacy' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">{t.settings.panels.privacyTitle}</div>
          <div className="panel-sub">{t.settings.privacy.sub}</div>
          <Row label={t.settings.privacy.networkPosture}>
            <span className={`badge ${posture.cls}`}>{posture.label}</span>
            <div className="hint" style={{ marginTop: 6 }}>
              {posture.note}
            </div>
          </Row>
          {/* Host and port are what the server is actually bound to — data, printed as it arrived. */}
          <Row label={t.settings.privacy.bindAddress}>
            <span className="mono">{health ? `${health.host}:${health.port}` : '—'}</span>
          </Row>

          <div style={{ marginTop: 22 }}>
            <div className="panel-title" style={{ marginBottom: 2 }}>
              {t.settings.lanes.title}
            </div>
            <div className="panel-sub">{t.settings.lanes.sub}</div>
            {flagError && (
              <div className="banner banner-warn" style={{ marginTop: 12 }}>
                <Icon.shield size={16} />
                <span>{flagError}</span>
              </div>
            )}
            {flags === null && (
              <div className="hint" style={{ marginTop: 12 }}>
                {t.settings.lanes.loading}
              </div>
            )}
            {flags?.map((f) => (
              <LaneToggle
                key={f.name}
                flag={f}
                busy={busyFlag === f.name}
                onToggle={(enabled) => applyFlag(f.name, () => api.setFlag(f.name, enabled, locale))}
                onClear={() => applyFlag(f.name, () => api.clearFlag(f.name, locale))}
              />
            ))}
          </div>
          <Row label={t.settings.panels.externalAgent}>
            {agent?.enabled ? (
              <>
                <span className="badge badge-medium">{t.settings.state.enabled}</span>
                {/* The provider and the model are ids from /agent/config, printed verbatim in either language. */}
                <div className="hint" style={{ marginTop: 6 }}>
                  {t.settings.privacy.agentSentTo} <span className="mono">{agent.provider}</span> (
                  <span className="mono">{agent.model}</span>). {t.settings.privacy.agentNoBytes}
                </div>
              </>
            ) : (
              <>
                <span className="badge badge-ok">{t.settings.state.disabled}</span>
                <div className="hint" style={{ marginTop: 6 }}>
                  {t.settings.privacy.agentOffLead} <span className="mono">FIRMLAB_AGENT=1</span>{' '}
                  {t.settings.privacy.agentOffTail}
                </div>
              </>
            )}
          </Row>
          <div className="banner banner-info" style={{ marginTop: 16, marginBottom: 0 }}>
            <Icon.shield size={16} />
            <span>{t.settings.privacy.banner}</span>
          </div>
        </div>
      )}

      {tab === 'agent' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">{t.settings.agent.title}</div>
          <div className="panel-sub">{t.settings.agent.sub}</div>
          <Row label={t.settings.agent.activeProvider}>
            {agent?.enabled ? (
              <span className="mono">
                {agent.provider} · {agent.model}
              </span>
            ) : (
              <span className="badge">{t.settings.agent.noneConfigured}</span>
            )}
          </Row>
          {/* Was three rows of read-only prose that told the operator to edit a YAML file on the host — and it
              listed `ollama`, which `llm.ts` has never supported. Editable now, and the provider list comes from
              the server so the screen cannot offer one this build would reject. */}
          <LlmProviderEditor />

          <div className="panel-title" style={{ marginTop: 22 }}>
            {t.settings.agent.governorTitle}
          </div>
          <div className="panel-sub">{t.settings.agent.governorSub}</div>
          <Row label={t.settings.agent.status}>
            <span className={`badge ${agent?.enabled ? 'badge-ok' : ''}`}>
              {agent?.enabled ? t.settings.state.enabled : t.settings.state.disabled}
            </span>
          </Row>
          {agent?.enabled && (
            <>
              <Row label={t.settings.agent.model}>
                <span className="mono">
                  {agent.provider} · {agent.model}
                </span>
              </Row>
              {agent.budget && (
                <>
                  <Row label={t.settings.agent.stepBudget}>
                    <span className="mono">{agent.budget.maxSteps}</span>{' '}
                    <span className="hint">FIRMLAB_AGENT_MAX_STEPS</span>
                  </Row>
                  <Row label={t.settings.agent.tokenBudget}>
                    <span className="mono">{agent.budget.maxTokens.toLocaleString(intlTag(locale))}</span>{' '}
                    <span className="hint">FIRMLAB_AGENT_MAX_TOKENS</span>
                  </Row>
                  {/* No ceiling is not "spend freely" — it is that nothing would stop the run, so it is a word. */}
                  <Row label={t.settings.agent.costCeiling}>
                    <span className="mono">
                      {agent.budget.maxUsd > 0 ? `$${agent.budget.maxUsd}` : t.settings.agent.unbounded}
                    </span>{' '}
                    <span className="hint">FIRMLAB_AGENT_MAX_USD</span>
                  </Row>
                  <Row label={t.settings.agent.timeBudget}>
                    <span className="mono">{Math.round(agent.budget.maxWallMs / 1000)}s</span>{' '}
                    <span className="hint">FIRMLAB_AGENT_MAX_SECONDS</span>
                  </Row>
                </>
              )}
              <Row label={t.settings.agent.emulation}>
                <span className="badge badge-medium">{t.settings.panels.humanApproval}</span>
              </Row>
            </>
          )}
          {!agent?.enabled && (
            <div className="hint" style={{ marginTop: 12 }}>
              {t.settings.agent.offLead} <span className="mono">FIRMLAB_AGENT=1</span> {t.settings.agent.offTail}
            </div>
          )}
        </div>
      )}

      {tab === 'storage' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">{t.settings.panels.storageTitle}</div>
          <div className="panel-sub">{t.settings.storage.sub}</div>
          <Row label={t.settings.storage.onDisk}>
            <span className="mono">{usage ? fmtBytes(usage.totalBytes) : '—'}</span>
            {usage && usage.quotaBytes > 0 && (
              <div style={{ marginTop: 8, maxWidth: 320 }}>
                <div className="meter">
                  <span
                    style={{ width: `${Math.min(100, (usage.totalBytes / usage.quotaBytes) * 100).toFixed(1)}%` }}
                  />
                </div>
                <div className="hint" style={{ marginTop: 4 }}>
                  {t.settings.storage.quotaOf({
                    used: fmtBytes(usage.totalBytes),
                    quota: fmtBytes(usage.quotaBytes),
                  })}
                </div>
              </div>
            )}
          </Row>
          <Row label={t.settings.storage.images}>
            <span className="mono">{usage?.imageCount ?? '—'}</span>
          </Row>
          {/* Two independent limits, each of which may be unset — an absent limit says so rather than staying
              blank, and the two sentences are joined here so neither catalogue has to carry a leading space. */}
          <Row label={t.settings.storage.retention}>
            <span className="hint">
              {[
                usage && usage.maxAgeDays > 0
                  ? t.settings.storage.evictedAfter(usage.maxAgeDays)
                  : t.settings.storage.noAgeLimit,
                usage && usage.quotaBytes > 0 ? t.settings.storage.oldestFirst : t.settings.storage.noQuota,
              ].join(' ')}
            </span>
          </Row>
          <div className="hint" style={{ marginTop: 12 }}>
            {t.settings.storage.manageLead} <Link to="/analyze">{t.settings.panels.localAnalysis}</Link>
            {t.settings.storage.manageMid} <span className="mono">FIRMLAB_MAX_IMAGE_AGE_DAYS</span>{' '}
            {t.settings.storage.manageAnd} <span className="mono">FIRMLAB_MAX_DATA_BYTES</span>.
          </div>
        </div>
      )}

      {tab === 'help' && (
        <div className="panel" style={{ maxWidth: 720 }}>
          <div className="panel-title">{t.settings.help.title}</div>
          <div className="panel-sub">{t.settings.panels.helpSub}</div>
          <Row label={t.settings.help.tour}>
            <button type="button" className="btn btn-sm" onClick={startTour}>
              <Icon.help size={14} /> {t.settings.help.restartTour}
            </button>
          </Row>
          <Row label={t.settings.help.keyboard}>
            <span className="hint">{t.settings.help.keyboardHint}</span>
          </Row>
          <Row label={t.settings.help.documentation}>
            <span className="hint">{t.settings.help.documentationHint}</span>
          </Row>
          <Row label={t.settings.help.about}>
            <span className="hint">{t.settings.help.aboutHint}</span>
          </Row>
        </div>
      )}
    </div>
  );
}
