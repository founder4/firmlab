import { useCallback, useEffect, useRef, useState } from 'react';
import { HashRouter, NavLink, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { type ImageSummary, api } from './api';
import { type Messages, useMessages } from './i18n';
import { Icon, type IconName } from './icons';
import { Onboarding, startTour } from './onboarding';
import { Agents, AgentsRun } from './pages/Agents';
import { Capabilities } from './pages/Capabilities';
import { Capture } from './pages/Capture';
import { Corpus } from './pages/Corpus';
import { Dashboard } from './pages/Dashboard';
import { ImageDetail, SECTION_IDS } from './pages/ImageDetail';
import { Overview } from './pages/Overview';
import { Settings } from './pages/Settings';
import { groupedSections } from './section-index';
import { type ThemePref, setDensity, setTheme, useAppearance } from './theme';
import { Toaster } from './toast';

type HealthState = 'ok' | 'proxied' | 'exposed' | 'down';

/**
 * The deployment's real network posture, read once from `/health`.
 *
 * It is a hook rather than local state in the pill because two places in this shell state the posture and they
 * were not stating the same thing: the pill has always recomputed it from `/health`, while the sidebar printed a
 * fixed sentence — "Local-only. Never expose to the internet." — ten lines below, on a deployment whose own
 * `/health` reports `exposedToNetwork: true`. Two claims about one fact, one of them a constant, is the defect
 * this codebase keeps paying for; there is now one source and both readers share it.
 */
function useHealthPosture(): HealthState {
  const [state, setState] = useState<HealthState>('down');
  useEffect(() => {
    api
      .health()
      .then((h) => setState(h.trustedProxy ? 'proxied' : h.exposedToNetwork ? 'exposed' : 'ok'))
      .catch(() => setState('down'));
  }, []);
  return state;
}

/** Local-only reassurance + API reachability. Communicates the security posture, honestly (§14). */
function HealthPill(): JSX.Element {
  const t = useMessages();
  const state = useHealthPosture();
  if (state === 'down') return <span className="badge badge-high">{t.nav.health.unreachable}</span>;
  if (state === 'exposed') return <span className="badge badge-medium">{t.nav.health.exposed}</span>;
  if (state === 'proxied')
    return (
      <span className="badge badge-ok" title={t.nav.health.proxiedTitle}>
        {t.nav.health.proxied}
      </span>
    );
  return (
    <span className="badge badge-ok" title={t.nav.health.localTitle}>
      {t.nav.health.local}
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

/**
 * The product mark, and the one bit of pure delight in the shell.
 *
 * Everything else here earns its place by saying something true about a firmware. This says nothing, and that is
 * why it is the right place for it: a workbench whose whole job is to refuse to overclaim can afford exactly one
 * corner that is just nice, as long as it is out of the way of the work.
 *
 * Three rules keep it out of the way.
 *
 *  1. **It is still when you are not touching it.** The mark sits in the shell, in view on every screen, all day.
 *     An idle animation there would be the definition of the thing you notice tens of times a day and grow to
 *     hate. It moves on press and never on its own.
 *  2. **It is invisible to assistive tech.** `aria-hidden` and out of the tab order — announcing a control that
 *     does nothing, to someone who cannot see the sparks, is noise dressed as inclusion. "FirmLab" is read from
 *     the heading beside it, once.
 *  3. **`prefers-reduced-motion` removes the motion, not the response.** The tumble and the sparks go; the press
 *     scale stays, because that one is feedback rather than decoration and its absence would read as a dead
 *     control.
 *
 * WAAPI rather than a CSS keyframe: a keyframe restarts from zero when re-triggered, and this is a thing people
 * will click four times in a row. `element.animate` is hardware-accelerated all the same, and cancelling the
 * previous run is one call.
 */
function BrandMark(): JSX.Element {
  const ref = useRef<HTMLButtonElement>(null);
  const spin = useRef<Animation | null>(null);

  const celebrate = useCallback(() => {
    const el = ref.current;
    if (!el || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    // One tumble, ~520ms. Long enough to read as a somersault, short enough that a fourth click is not a queue.
    spin.current?.cancel();
    spin.current = el.animate(
      [
        { transform: 'scale(1.03) rotate(0turn)' },
        { transform: 'scale(0.92) rotate(0.35turn)', offset: 0.35 },
        { transform: 'scale(1.09) rotate(0.8turn)', offset: 0.75 },
        { transform: 'scale(1.03) rotate(1turn)' },
      ],
      { duration: 520, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' },
    );

    // …and three sparks, let loose. Drifting apart so it reads as a puff rather than a column — the chip
    // signalling, not a heart-burst; the mark changed from a mascot to an instrument, and a borrowed heart-emoji
    // trope did not survive that. They are appended to the button and removed when they finish — no state,
    // nothing to leak.
    //
    // The flight is 24px up and wide rather than tall, and that is measured rather than chosen: `.sidebar` has
    // `overflow-y: auto` and 14px of padding, `.brand` adds 6, so there are TWENTY pixels above the mark before
    // the sidebar clips. The first version rose 42px and spent more than half its arc invisible.
    for (let i = 0; i < 3; i++) {
      const pulse = document.createElement('span');
      pulse.className = 'brand-pulse';
      pulse.setAttribute('aria-hidden', 'true');
      el.appendChild(pulse);
      const drift = (i - 1) * 22 + (i === 1 ? 0 : 5);
      pulse
        .animate(
          [
            { transform: 'translate(0, 0) scale(0.5)', opacity: 0 },
            { transform: `translate(${drift * 0.45}px, -11px) scale(1)`, opacity: 1, offset: 0.35 },
            { transform: `translate(${drift}px, -24px) scale(0.8)`, opacity: 0 },
          ],
          { duration: 820 + i * 80, delay: i * 70, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' },
        )
        .finished.catch(() => undefined)
        .finally(() => pulse.remove());
    }
  }, []);

  return (
    <button ref={ref} type="button" className="brand-mark" onClick={celebrate} aria-hidden="true" tabIndex={-1}>
      <img src="/logo.png" alt="" width={44} height={44} draggable={false} />
    </button>
  );
}

/**
 * What this deployment's network posture actually is, at the foot of the nav.
 *
 * It replaces a constant that read "Local-only. Never expose to the internet." — a prohibition, printed
 * unconditionally, and false on any deployment reached through a proxy. Two things are wrong with a constant
 * here and only one of them is the inaccuracy: the sentence also states a *policy* the product has outgrown, on
 * a workbench whose research and capture lanes exist to use the network. So this states the posture and stops.
 * `exposed` is the one case that carries a warning colour, because "on the network with no declared proxy auth"
 * is a fact the operator may not have intended; the other two are reported in the shell's ordinary dim hint.
 *
 * A posture it could not read is said, never assumed: a failed `/health` prints "unknown", not "local-only".
 * Guessing the reassuring one is exactly how the old sentence was wrong.
 */
function PostureLine(): JSX.Element {
  const t = useMessages();
  const state = useHealthPosture();
  const copy = t.nav.posture[state];
  return (
    <div
      className="hint"
      style={{
        padding: '10px 10px 2px',
        display: 'flex',
        gap: 6,
        alignItems: 'flex-start',
        ...(state === 'exposed' ? { color: 'var(--warn)' } : {}),
      }}
      title={copy.title}
    >
      <span style={{ flexShrink: 0, marginTop: 1 }}>
        <Icon.shield size={13} />
      </span>
      <span>{copy.label}</span>
    </div>
  );
}

/**
 * The analysis sections, in the sidebar — the fix for the defect that explains most complaints about this app.
 *
 * Measured on the deployed build before this existed: **nineteen sections, zero of them in the sidebar, eight in
 * the step timeline.** Everything else was reachable from an index inside the dossier page, or by typing a URL.
 * The consequence is not subtle and it is not aesthetic: the component-dependency graph and the SBOM/CVE graph
 * have both been built, rendering and correct for months, and a reader who wanted them had to already know they
 * existed. "I run a scan and I cannot find the results" is the accurate description of that, and it is a
 * navigation defect wearing the costume of a missing feature.
 *
 * What this replaces is worse than nothing: the slot held a hint telling the reader to navigate from the step
 * timeline, a control that reaches eight of the nineteen. A pointer to a control that cannot answer the question
 * answers it wrongly, which is the shape of defect this codebase keeps paying for.
 *
 * **The grouping is not declared here.** It lives in `section-index.ts` beside the rest of the section metadata,
 * because the in-page index renders the same nineteen and two orderings of one list are one commit from
 * disagreeing. Anything no group claims is rendered under its own heading rather than dropped — a section added
 * later and forgotten in the grouping must not silently vanish from the navigation, which is precisely the defect
 * being fixed here, re-introduced by the fix for it.
 */
function SectionNav({
  imageId,
  active,
  onNavigate,
}: { imageId: string; active: string; onNavigate: () => void }): JSX.Element {
  const t = useMessages();
  const labels = t.sections as unknown as Record<string, string>;
  const headings = t.sectionGroups as unknown as Record<string, string>;
  const { groups, ungrouped } = groupedSections(SECTION_IDS);
  // `overview` is the route with no segment and resolves to `dossier`; without this the landing view highlights
  // nothing and the nav reads as though you were nowhere.
  const current = active === 'overview' ? 'dossier' : active;
  const rows = (ids: readonly string[]): JSX.Element[] =>
    ids.map((sid) => (
      <NavLink
        key={sid}
        to={`/image/${imageId}/${sid}`}
        onClick={onNavigate}
        className={`nav-sub ${sid === current ? 'active' : ''}`}
      >
        {labels[sid] ?? sid}
      </NavLink>
    ));
  return (
    <nav className="section-nav" aria-label={t.nav.sectionNavAria}>
      {groups.map((g) => (
        <div key={g.id} className="section-nav-group">
          <div className="nav-subhead">{headings[g.id] ?? g.id}</div>
          {rows(g.sections)}
        </div>
      ))}
      {ungrouped.length > 0 && (
        <div className="section-nav-group">
          <div className="nav-subhead">{t.nav.sectionNavOther}</div>
          {rows(ungrouped)}
        </div>
      )}
    </nav>
  );
}

export function Sidebar({ onNavigate }: { onNavigate: () => void }): JSX.Element {
  const { id, section } = useActiveImage();
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
        <BrandMark />
        <div className="brand-name">FirmLab</div>
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
          </div>
          <SectionNav imageId={id} active={section} onNavigate={onNavigate} />
        </>
      )}

      <div style={{ flex: 1, minHeight: 12 }} />
      <div className="nav-section">{t.nav.system}</div>
      <NavRow to="/settings" icon="settings" label={t.nav.settings} onNavigate={onNavigate} />
      <PostureLine />
    </>
  );
}

/** Order and glyph only — the label a screen reader reads comes from the catalogue, keyed by the same value. */
const THEME_OPTS: { value: ThemePref; icon: IconName }[] = [
  { value: 'light', icon: 'sun' },
  { value: 'system', icon: 'monitor' },
  { value: 'dark', icon: 'moon' },
];

/** Theme + density controls, mirrored in Settings but always reachable from the header. */
function AppearanceControls(): JSX.Element {
  const { theme, density } = useAppearance();
  const t = useMessages();
  return (
    <>
      {/* biome-ignore lint/a11y/useSemanticElements: a segmented button group; a <fieldset> would impose UA styling. */}
      <div className="segmented" role="group" aria-label={t.nav.themeGroup} data-tour="appearance">
        {THEME_OPTS.map((o) => {
          const Glyph = Icon[o.icon];
          const label =
            o.value === 'light' ? t.nav.themeLight : o.value === 'dark' ? t.nav.themeDark : t.nav.themeSystem;
          return (
            <button
              key={o.value}
              type="button"
              className={theme === o.value ? 'active' : ''}
              aria-label={label}
              aria-pressed={theme === o.value}
              title={label}
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
        title={density === 'compact' ? t.nav.densityToComfortable : t.nav.densityToCompact}
        aria-label={t.nav.densityToggle}
        onClick={() => setDensity(density === 'compact' ? 'comfortable' : 'compact')}
      >
        {density === 'compact' ? <Icon.overview size={15} /> : <Icon.binaries size={15} />}
      </button>
      <button
        type="button"
        className="icon-btn"
        title={t.nav.help}
        aria-label={t.nav.helpAria}
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
    // Route prefix → the same label the sidebar shows for it. A table rather than a ternary chain so the two
    // cannot drift: every entry is the nav word, and a page with no entry falls back to the Dashboard title.
    const TITLE_BY_PREFIX: [string, string][] = [
      ['/analyze', t.nav.localAnalysis],
      ['/agents', t.nav.agents],
      ['/updates', t.nav.proxyUpdates],
      ['/capture', t.nav.proxyUpdates],
      ['/corpus', t.nav.corpus],
      ['/capabilities', t.nav.capabilities],
      ['/settings', t.nav.settings],
    ];
    const title = TITLE_BY_PREFIX.find(([prefix]) => pathname.startsWith(prefix))?.[1] ?? t.nav.dashboard;
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
            {/* A run opens INSIDE Agents. The old console navigated to /image/:id/opacidad, which is the
                static-analysis shell — so a click on a result silently changed which section you were in. */}
            <Route path="/agents/:imageId/:kind" element={<AgentsRun />} />
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
    <HashRouter>
      <Shell />
      <Onboarding />
      <Toaster />
    </HashRouter>
  );
}
