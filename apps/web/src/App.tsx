import { useEffect, useState } from 'react';
import { HashRouter, NavLink, Route, Routes } from 'react-router-dom';
import { api } from './api';
import { Capabilities } from './pages/Capabilities';
import { Dashboard } from './pages/Dashboard';
import { ImageDetail } from './pages/ImageDetail';

/** Local-only reassurance + API reachability, shown once in the top bar. */
function HealthPill(): JSX.Element {
  const [state, setState] = useState<'ok' | 'exposed' | 'down'>('down');
  useEffect(() => {
    api
      .health()
      .then((h) => setState(h.exposedToNetwork ? 'exposed' : 'ok'))
      .catch(() => setState('down'));
  }, []);
  if (state === 'down') return <span className="badge badge-high">API unreachable</span>;
  if (state === 'exposed') return <span className="badge badge-medium">⚠ bound to network</span>;
  return <span className="badge badge-ok">● local-only</span>;
}

function Sidebar(): JSX.Element {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">F</div>
        <div>
          <div className="brand-name">FirmLab</div>
          <div className="brand-sub">firmware workbench</div>
        </div>
      </div>

      <div className="nav-section">Analysis</div>
      <NavLink to="/" end className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
        <span className="nav-ico">▤</span> Dashboard
      </NavLink>
      <NavLink to="/capabilities" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
        <span className="nav-ico">⚙</span> Capabilities
      </NavLink>

      <div style={{ flex: 1 }} />
      <div className="hint" style={{ padding: '0 10px' }}>
        Local-only firmware analysis. Never expose to the internet.
      </div>
    </aside>
  );
}

export function App(): JSX.Element {
  return (
    <HashRouter>
      <div className="app-shell">
        <Sidebar />
        <div className="main">
          <div className="topbar">
            <strong style={{ fontSize: 14 }}>Firmware Analysis Workbench</strong>
            <HealthPill />
          </div>
          <div className="content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/image/:id" element={<ImageDetail />} />
              <Route path="/capabilities" element={<Capabilities />} />
            </Routes>
          </div>
        </div>
      </div>
    </HashRouter>
  );
}
