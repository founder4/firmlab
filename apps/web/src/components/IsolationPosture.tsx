/** Runtime capabilities, scoped to the isolated runner; missing older fields remain unknown. */
import type { AgentConfig } from '../api';
import { useMessages } from '../i18n';

export function IsolationPosture({ phase4 }: { phase4: AgentConfig['phase4'] }): JSX.Element {
  const t = useMessages().settings.agent.isolationPosture;
  const netns = phase4?.netns;
  const network = netns === '-n' || netns === '-rn' ? t.isolated : netns === null ? t.hostNetwork : t.unknown;
  const resources =
    phase4?.resourceLimits === true ? t.available : phase4?.resourceLimits === false ? t.unavailable : t.unknown;
  return (
    <section aria-label={t.title} style={{ marginTop: 16 }}>
      <div className="panel-title">{t.title}</div>
      <div className="panel-sub">{t.scope}</div>
      <dl style={{ margin: '10px 0', fontSize: 13 }}>
        <dt>{t.network}</dt>
        <dd style={{ margin: '4px 0 10px' }}>
          <span className={`badge ${netns === null ? 'badge-medium' : ''}`}>{network}</span>
        </dd>
        <dt>{t.resources}</dt>
        <dd style={{ margin: '4px 0 10px' }}>{resources}</dd>
      </dl>
      <div className="hint">{t.boundary}</div>
    </section>
  );
}
