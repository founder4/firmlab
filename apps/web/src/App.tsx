import { useEffect, useState } from 'react';
import { HashRouter, NavLink, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { type ImageSummary, api } from './api';
import { type Messages, useMessages } from './i18n';
import { Icon, type IconName } from './icons';
import { Onboarding, startTour } from './onboarding';
import { Agents } from './pages/Agents';
import { Capabilities } from './pages/Capabilities';
import { Capture } from './pages/Capture';
import { Corpus } from './pages/Corpus';
import { Dashboard } from './pages/Dashboard';
import { ImageDetail } from './pages/ImageDetail';
import { Overview } from './pages/Overview';
import { Settings } from './pages/Settings';
import { type ThemePref, setDensity, setTheme, useAppearance } from './theme';
import { Toaster } from './toast';

type HealthState = 'ok' | 'proxied' | 'exposed' | 'down';

/** Local-only reassurance + API reachability. Communicates the security posture, honestly (§14). */
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
  return (
    <span className="badge badge-ok" title="Bound to loopback — nothing leaves this machine">
      ● local-only
    </span>
  );
}

/**
 * The header title for a section id. The ids are route segments and never move; only the labels do, which is what
 * lets a language switch repaint the header without a reload. Falls back to the id — itself a readable slug.
 */
export function sectionLabel(t: Messages, id: string): string {
  return (t.sections as Record<string, string>)[id] ?? id;
}

/** Parse the active firmware id + section out of the route (/image/:id/:section?). */
function useActiveImage(): { id: string | null; section: string } {
  const { pathname } = useLocation();
  const parts = pathname.split('/').filter(Boolean);
  if (parts[0] === 'image' && parts[1]) return { id: parts[1], section: parts[2] ?? 'overview' };
  return { id: null, section: 'overview' };
}

function NavRow({
  to,
  end = false,
  icon,
  label,
  onNavigate,
}: { to: string; end?: boolean; icon: IconName; label: string; onNavigate: () => void }): JSX.Element {
  const Glyph = Icon[icon];
  return (
    <NavLink
      to={to}
      end={end}
      onClick={onNavigate}
      className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
    >
      <span className="nav-ico">
        <Glyph />
      </span>
      {label}
    </NavLink>
  );
}

function Sidebar({ onNavigate }: { onNavigate: () => void }): JSX.Element {
  const { id } = useActiveImage();
  const nav = useNavigate();
  const t = useMessages();
  const [activeName, setActiveName] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return setActiveName(null);
    api
      .getImage(id)
      .then((im) => setActiveName(im.filename))
      .catch(() => setActiveName(id));
  }, [id]);

  return (
    <>
      <div className="brand">
        <div className="brand-mark" aria-hidden="true">
          0x
        </div>
        <div>
          <div className="brand-name">FirmLab</div>
          <div className="brand-sub">{t.nav.brandSub}</div>
        </div>
      </div>

      <NavRow to="/" end icon="dashboard" label={t.nav.dashboard} onNavigate={onNavigate} />
      <NavRow to="/analyze" icon="overview" label={t.nav.localAnalysis} onNavigate={onNavigate} />
      <NavRow to="/agents" icon="agent" label={t.nav.agents} onNavigate={onNavigate} />
      <NavRow to="/updates" icon="capture" label={t.nav.proxyUpdates} onNavigate={onNavigate} />
      <NavRow to="/corpus" icon="corpus" label={t.nav.corpus} onNavigate={onNavigate} />

      {id && (
        <>
          <div className="nav-section">{t.nav.firmware}</div>
          <div className="ctx-card" data-tour="firmware-context">
            <div className="eyebrow">{t.nav.activeImage}</div>
            <div className="ctx-name" title={activeName ?? id}>
              {activeName ?? id}
            </div>
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              style={{ marginTop: 6, paddingLeft: 0 }}
              onClick={() => {
                nav('/analyze');
                onNavigate();
              }}
            >
              <Icon.back size={13} /> {t.nav.allImages}
            </button>
            <div className="hint" style={{ marginTop: 8, fontSize: '0.72rem' }}>
              {t.nav.navigateHint}
            </div>
          </div>
        </>
      )}

      <div style={{ flex: 1, minHeight: 12 }} />
      <div className="nav-section">{t.nav.system}</div>
      <NavRow to="/settings" icon="settings" label={t.nav.settings} onNavigate={onNavigate} />
      <div className="hint" style={{ padding: '10px 10px 2px', display: 'flex', gap: 6, alignItems: 'center' }}>
        <Icon.shield size={13} /> {t.nav.localOnly}
      </div>
    </>
  );
}

const THEME_OPTS: { value: ThemePref; icon: IconName; label: string }[] = [
  { value: 'light', icon: 'sun', label: 'Light theme' },
  { value: 'system', icon: 'monitor', label: 'Match system theme' },
  { value: 'dark', icon: 'moon', label: 'Dark theme' },
];

/** Theme + density controls, mirrored in Settings but always reachable from the header. */
function AppearanceControls(): JSX.Element {
  const { theme, density } = useAppearance();
  return (
    <>
      {/* biome-ignore lint/a11y/useSemanticElements: a segmented button group; a <fieldset> would impose UA styling. */}
      <div className="segmented" role="group" aria-label="Theme" data-tour="appearance">
        {THEME_OPTS.map((o) => {
          const Glyph = Icon[o.icon];
          return (
            <button
              key={o.value}
              type="button"
              className={theme === o.value ? 'active' : ''}
              aria-label={o.label}
              aria-pressed={theme === o.value}
              title={o.label}
              onClick={() => setTheme(o.value)}
            >
              <Glyph size={15} />
            </button>
          );
        })}
      </div>
      <button
        type="button"
        className="icon-btn"
        title={density === 'compact' ? 'Comfortable density' : 'Compact density'}
        aria-label="Toggle density"
        onClick={() => setDensity(density === 'compact' ? 'comfortable' : 'compact')}
      >
        {density === 'compact' ? <Icon.overview size={15} /> : <Icon.binaries size={15} />}
      </button>
      <button
        type="button"
        className="icon-btn"
        title="Help & tour"
        aria-label="Help and tour"
        onClick={() => startTour()}
      >
        <Icon.help size={15} />
      </button>
    </>
  );
}

/** The header's contextual title + firmware switcher (uses the wide desktop space, keeps context visible). */
function ContextHeader(): JSX.Element {
  const { id, section } = useActiveImage();
  const { pathname } = useLocation();
  const nav = useNavigate();
  const t = useMessages();
  const [images, setImages] = useState<ImageSummary[]>([]);

  useEffect(() => {
    api
      .listImages()
      .then(setImages)
      .catch(() => setImages([]));
  }, []);

  if (!id) {
    const title = pathname.startsWith('/analyze')
      ? 'Local analysis'
      : pathname.startsWith('/agents')
        ? 'Agents'
        : pathname.startsWith('/updates') || pathname.startsWith('/capture')
          ? 'Proxy / Updates'
          : pathname.startsWith('/corpus')
            ? 'Corpus'
            : pathname.startsWith('/capabilities')
              ? 'Capabilities'
              : pathname.startsWith('/settings')
                ? 'Settings'
                : 'Dashboard';
    return <strong className="topbar-title">{title}</strong>;
  }

  return (
    <div className="topbar-left" style={{ gap: 8 }}>
      <select
        className="select"
        aria-label="Active firmware"
        value={id}
        onChange={(e) => nav(`/image/${e.target.value}/${section}`)}
        style={{ maxWidth: 260, fontFamily: 'var(--mono)', fontSize: 12.5 }}
      >
        {images.every((im) => im.id !== id) && <option value={id}>{id}</option>}
        {images.map((im) => (
          <option key={im.id} value={im.id}>
            {im.filename}
          </option>
        ))}
      </select>
      <Icon.chevron size={13} />
      <span className="topbar-title" style={{ color: 'var(--text-dim)' }}>
        {sectionLabel(t, section)}
      </span>
    </div>
  );
}

/** App shell — persistent grouped sidebar that becomes a drawer on narrow viewports. */
function Shell(): JSX.Element {
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();

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
      <aside className="sidebar" data-tour="sidebar">
        <Sidebar onNavigate={() => setNavOpen(false)} />
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
            <ContextHeader />
          </div>
          <div className="topbar-actions">
            <span data-tour="health">
              <HealthPill />
            </span>
            <AppearanceControls />
          </div>
        </div>
        <div className="content">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/analyze" element={<Dashboard />} />
            <Route path="/image/:id" element={<ImageDetail />} />
            <Route path="/image/:id/:section" element={<ImageDetail />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/updates" element={<Capture />} />
            <Route path="/capture" element={<Capture />} />
            <Route path="/corpus" element={<Corpus />} />
            <Route path="/capabilities" element={<Capabilities />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

export function App(): JSX.Element {
  return (
    // The v7 flags are opted into explicitly rather than left to warn on every dev boot. Both are inert here
    // and that is the point of taking them now: there are no splat routes for relativeSplatPath to re-resolve,
    // and startTransition only marks router state updates non-urgent, which this shell already tolerates —
    // so the upgrade is a no-op today and will not become a behavioural surprise on the day v7 lands.
    <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Shell />
      <Onboarding />
      <Toaster />
    </HashRouter>
  );
}
