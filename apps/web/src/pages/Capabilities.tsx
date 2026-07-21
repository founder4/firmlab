import { useEffect, useState } from 'react';
import { type ToolStatus, api } from '../api';
import { TechniqueCoverage } from '../components/TechniqueCoverage';

const GROUP_LABELS: Record<string, string> = {
  extract: 'Extraction',
  analyze: 'Binary analysis',
  sbom: 'SBOM & CVEs',
  secrets: 'Secret scanning',
  emulate: 'Emulation',
};

export function Capabilities(): JSX.Element {
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .tools()
      .then((r) => setTools(r.tools))
      .finally(() => setLoading(false));
  }, []);

  const byGroup = tools.reduce<Record<string, ToolStatus[]>>((acc, t) => {
    if (!acc[t.group]) acc[t.group] = [];
    acc[t.group]?.push(t);
    return acc;
  }, {});

  const availableCount = tools.filter((t) => t.available).length;

  return (
    <div>
      <div className="banner banner-info">
        FirmLab's static engine (structure map, entropy, strings, identity) needs <strong>no external tools</strong>.
        The tools below are optional enhancements — build the firmware Docker image to unlock extraction, decompilation,
        SBOM/CVEs, and emulation.
      </div>

      <div className="panel">
        <div className="panel-title">Detected tools</div>
        <div className="panel-sub">
          {loading ? 'Probing…' : `${availableCount} of ${tools.length} available in this deployment`}
        </div>

        {Object.entries(byGroup).map(([group, list]) => (
          <div key={group} style={{ marginBottom: 18 }}>
            <div className="nav-section" style={{ margin: '0 0 8px' }}>
              {GROUP_LABELS[group] ?? group}
            </div>
            <table className="data">
              <tbody>
                {list.map((t) => (
                  <tr key={t.id}>
                    <td style={{ width: 30 }}>
                      <span className={`badge ${t.available ? 'badge-ok' : ''}`}>{t.available ? '●' : '○'}</span>
                    </td>
                    <td className="mono" style={{ width: 220 }}>
                      {t.bin}
                    </td>
                    <td>{t.unlocks}</td>
                    <td className="hint mono">{t.available ? t.version : 'not found'}</td>
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
