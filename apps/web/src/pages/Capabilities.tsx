/**
 * Capabilities — what this deployment can and cannot do, read from the binaries actually on the box.
 *
 * The table is half identifiers and half prose, and the split is load-bearing. A tool's name, its binary and its
 * version string are what you would type at a shell; they render verbatim in every language. Everything around them
 * — the groups, the counts, the sentence under the heading — is this page's own words.
 *
 * **A hollow row is not a clean row.** Half of this table will be empty on a lean deployment, and the one reading a
 * translation must not be able to take that as good news: an absent tool is an absent ANSWER, the question was never
 * asked, and the providers that need it say so rather than returning nothing and letting it pass for nothing found.
 * That sentence is on screen, not only in this comment, because it is the whole reason the page exists.
 *
 * What is NOT translated here and could be: `unlocks` is prose the API composes per `ToolSpec`, so it arrives in the
 * language the server wrote it in. Mapping it here by tool id would break the property that a new `ToolSpec` shows
 * up in this page for free, so the column is rendered as the API sends it.
 */
import { useEffect, useState } from 'react';
import { type ToolStatus, api } from '../api';
import { TechniqueCoverage } from '../components/TechniqueCoverage';
import { useMessages } from '../i18n';

export function Capabilities(): JSX.Element {
  const t = useMessages();
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .tools()
      .then((r) => setTools(r.tools))
      .finally(() => setLoading(false));
  }, []);

  const byGroup = tools.reduce<Record<string, ToolStatus[]>>((acc, tool) => {
    if (!acc[tool.group]) acc[tool.group] = [];
    acc[tool.group]?.push(tool);
    return acc;
  }, {});

  const availableCount = tools.filter((tool) => tool.available).length;
  // A group the catalogue does not name falls back to its id — a new `ToolSpec` group must show up, not vanish.
  const groups = t.shell.capabilities.group;
  const groupLabel = (group: string): string => (group in groups ? groups[group as keyof typeof groups] : group);

  return (
    <div>
      <div className="banner banner-info">
        {t.shell.capabilities.engineLead} <strong>{t.shell.capabilities.engineStrong}</strong>.{' '}
        {t.shell.capabilities.engineTail}
      </div>

      <div className="panel">
        <div className="panel-title">{t.shell.capabilities.title}</div>
        {/* Both lines live inside `panel-sub` so they inherit the shell's 72ch measure — the sentence below is the
            longest prose on this page, and at full panel width it would set at more than twice that. */}
        <div className="panel-sub">
          <div>
            {loading ? t.shell.capabilities.probing : t.shell.capabilities.counted(availableCount, tools.length)}
          </div>
          {/* Stated beside the count, where the reader is looking at the empty half of the table — not a footnote. */}
          <div style={{ marginTop: 6, marginBottom: 14 }}>{t.shell.capabilities.absentAnswer}</div>
        </div>

        {Object.entries(byGroup).map(([group, list]) => (
          <div key={group} style={{ marginBottom: 18 }}>
            <div className="nav-section" style={{ margin: '0 0 8px' }}>
              {groupLabel(group)}
            </div>
            <table className="data">
              <tbody>
                {list.map((tool) => (
                  <tr key={tool.id}>
                    <td style={{ width: 30 }}>
                      <span className={`badge ${tool.available ? 'badge-ok' : ''}`}>{tool.available ? '●' : '○'}</span>
                    </td>
                    <td className="mono" style={{ width: 220 }}>
                      {tool.bin}
                    </td>
                    <td>{tool.unlocks}</td>
                    <td className="hint mono">{tool.available ? tool.version : t.shell.capabilities.notFound}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>

      <TechniqueCoverage />
    </div>
  );
}
