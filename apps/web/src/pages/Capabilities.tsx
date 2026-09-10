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
 * `unlocks` is prose the API composes per tool, and it is asked for in the language this page renders. That is not
 * a stored measurement — the tools are probed on every request, and the sentence describes what THIS DEPLOYMENT
 * could be asked, never a property of any firmware — so it is interface copy that happens to be built server-side.
 * It is still keyed by tool id in the API catalogue rather than mapped here, which keeps the property that a new
 * `ToolSpec` shows up in this page for free (and makes an unglossed one a compile error there, not a blank cell).
 */
import { Fragment, useEffect, useState } from 'react';
import { type ToolStatus, api } from '../api';
import { TechniqueCoverage } from '../components/TechniqueCoverage';
import { useLocale, useMessages } from '../i18n';

export function Capabilities(): JSX.Element {
  const t = useMessages();
  const locale = useLocale();
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api
      .tools(locale)
      .then((r) => alive && setTools(r.tools))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [locale]);

  const byGroup = tools.reduce<Record<string, ToolStatus[]>>((acc, tool) => {
    if (!acc[tool.group]) acc[tool.group] = [];
    acc[tool.group]?.push(tool);
    return acc;
  }, {});

  const availableCount = tools.filter((tool) => tool.available).length;
  // Installed, and it did not answer. `available: false` covers this and a genuine absence alike, so the count
  // above cannot distinguish them — and reading a slow tool as one this box does not have is exactly how a
  // provider ends up reporting `blocked_by_platform` for a capability that is right there.
  const unanswered = tools.filter((tool) => !tool.available && tool.outcome && tool.outcome !== 'missing').length;
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
          <div style={{ marginTop: 6, marginBottom: unanswered > 0 ? 6 : 14 }}>{t.shell.capabilities.absentAnswer}</div>
          {unanswered > 0 ? (
            <div style={{ marginBottom: 14 }}>
              <strong>{t.shell.capabilities.unanswered(unanswered)}</strong>
            </div>
          ) : null}
        </div>

        {Object.entries(byGroup).map(([group, list]) => (
          <div key={group} style={{ marginBottom: 18 }}>
            <div className="nav-section" style={{ margin: '0 0 8px' }}>
              {groupLabel(group)}
            </div>
            <table className="data">
              <tbody>
                {list.map((tool) => {
                  // Three marks, because there are three answers. A hollow ring is an absence; the half-filled one
                  // is a tool that is HERE and did not answer, which must not read as the same row.
                  const unanswered = !tool.available && tool.outcome !== undefined && tool.outcome !== 'missing';
                  return (
                    <Fragment key={tool.id}>
                      <tr>
                        <td style={{ width: 30 }}>
                          <span className={`badge ${tool.available ? 'badge-ok' : unanswered ? 'badge-warn' : ''}`}>
                            {tool.available ? '●' : unanswered ? '◐' : '○'}
                          </span>
                        </td>
                        <td className="mono" style={{ width: 220 }}>
                          {tool.bin}
                        </td>
                        <td>{tool.unlocks}</td>
                        {/* A version string is an identifier and stays monospaced; the probe's answer is prose. An
                          API build older than `outcome` sends nothing, and that row keeps the flat wording. */}
                        <td className={tool.available ? 'hint mono' : 'hint'}>
                          {tool.available
                            ? tool.version
                            : tool.outcome
                              ? t.shell.capabilities.probeLabel[tool.outcome]
                              : t.shell.capabilities.notFound}
                        </td>
                      </tr>
                      {/* Its own row, spanning the table. In the last column this sentence set at five short lines
                        against a 150px measure; spanning, it needs the opposite guard — `max-width` on a `td` is
                        ignored under `table-layout: auto`, and the first version of this row ran at 155 characters
                        a line, the exact defect this shell has already paid for once. The measure goes on a block
                        INSIDE the cell, and only looking at the rendered page showed either of the two. */}
                      {unanswered && tool.outcomeReason ? (
                        <tr>
                          <td />
                          <td className="hint" colSpan={3} style={{ paddingTop: 0 }}>
                            <div style={{ maxWidth: '72ch' }}>{tool.outcomeReason}</div>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        ))}
      </div>

      <TechniqueCoverage />
    </div>
  );
}
