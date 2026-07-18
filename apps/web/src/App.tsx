import { useEffect, useState } from 'react';
import { HashRouter, NavLink, Route, Routes, useLocation } from 'react-router-dom';
import { api } from './api';
import { Capabilities } from './pages/Capabilities';
import { Corpus } from './pages/Corpus';
import { Dashboard } from './pages/Dashboard';
import { ImageDetail } from './pages/ImageDetail';
import { Toaster } from './toast';

type HealthState = 'ok' | 'proxied' | 'exposed' | 'down';

/** Local-only reassurance + API reachability, shown once in the top bar. */
function HealthPill(): JSX.Element {
  const [state, setState] = useState<HealthState>('down');
  useEffect(() => {
    api
      .health()
      .then((h) => setState(h.trustedProxy ? 'proxied' : h.exposedToNetwork ? 'exposed' : 'ok'))
      .catch(() => setState('down'));
  }, []);
  if (state === 'down') return <span className="badge badge-high">API unreachable</span>;
  if (state === 'exposed') return <span className="badge badge-medium">⚠ bound to network</span>;
  if (state === 'proxied')
    return (
      <span className="badge badge-ok" title="Reachable only through an authenticating reverse proxy">
        🔒 auth-gated
      </span>
    );
  return <span className="badge badge-ok">● local-only</span>;
}

function SidebarNav({ onNavigate }: { onNavigate: () => void }): JSX.Element {
  return (
    <>
      <div className="brand">
        <div className="brand-mark">F</div>
        <div>
          <div className="brand-name">FirmLab</div>
          <div className="brand-sub">firmware workbench</div>
        </div>
      </div>

      <div className="nav-section">Analysis</div>
      <NavLink to="/" end onClick={onNavigate} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
        <span className="nav-ico">▤</span> Dashboard
      </NavLink>
      <NavLink to="/corpus" onClick={onNavigate} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
        <span className="nav-ico">◈</span> Corpus
      </NavLink>
      <NavLink
        to="/capabilities"
        onClick={onNavigate}
        className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
      >
        <span className="nav-ico">⚙</span> Capabilities
      </NavLink>

      <div style={{ flex: 1 }} />
      <div className="hint" style={{ padding: '0 10px' }}>
        Local-only firmware analysis. Never expose to the internet.
      </div>
    </>
  );
}

/** App shell with a sidebar that collapses into a drawer on narrow (mobile) viewports. */
function Shell(): JSX.Element {
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();

  // Close the mobile drawer whenever the route changes.
  useEffect(() => setNavOpen(false), [location.pathname]);

  return (
    <div className={`app-shell ${navOpen ? 'nav-open' : ''}`}>
      <button
        type="button"
        className="scrim"
        aria-label="Close navigation"
        tabIndex={navOpen ? 0 : -1}
        onClick={() => setNavOpen(false)}
      />
      <aside className="sidebar">
        <SidebarNav onNavigate={() => setNavOpen(false)} />
      </aside>
      <div className="main">
        <div className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="nav-toggle"
              aria-label="Toggle navigation"
              aria-expanded={navOpen}
              onClick={() => setNavOpen((v) => !v)}
            >
              ☰
            </button>
            <strong className="topbar-title">Firmware Analysis Workbench</strong>
          </div>
          <HealthPill />
        </div>
        <div className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/image/:id" element={<ImageDetail />} />
            <Route path="/corpus" element={<Corpus />} />
            <Route path="/capabilities" element={<Capabilities />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

export function App(): JSX.Element {
  return (
    <HashRouter>
      <Shell />
      <Toaster />
    </HashRouter>
  );
}
