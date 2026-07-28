/**
 * Guided tour — an optional, resettable onboarding that spotlights real interface elements (by data-tour
 * attribute) rather than a wall of text. It auto-runs once on first visit, never again unless the user starts
 * it from the header (?) or Settings. A module store drives a single <Onboarding/> mounted in the shell.
 *
 * **Why the steps are not a module constant any more.** They used to be a `STEPS` array of literal English, built
 * once when the module was imported. A tour whose text is frozen at import time opens in the language that happened
 * to be active when the bundle loaded, which is the wrong one for anybody who switches afterwards — and the tour is
 * the only screen you cannot re-read to check. So the module now holds the SHAPE (the order, and which element each
 * step spotlights) and the catalogue holds the words: `buildSteps` maps one onto the other, the mounted component
 * calls it through `useMessages()` on every render, and `startTour` carries no text at all — it flips a flag. The
 * language is therefore resolved at render, so switching locale with the tour open re-renders the open card.
 *
 * `tourSteps()` is the same thing for a caller outside React — module scope, an event handler, a test — and reads
 * the active catalogue through `messages()`, the non-hook accessor, for the same reason.
 *
 * The step this tour exists for is `proof`. It is where an operator meets the proof-state discipline, before they
 * have seen a single finding, and it names the states verbatim because they are identifiers the API and SQLite
 * share. What it must never be softened into is a reassurance: `blocked_by_platform` means the question was asked
 * and could not be answered here, and an empty findings list is not a clean image.
 */
import { type CSSProperties, useEffect, useMemo, useState, useSyncExternalStore } from 'react';
import { type Messages, messages, useMessages } from './i18n';

const DONE_KEY = 'firmlab.tour.done';

interface Step {
  selector?: string;
  title: string;
  body: string;
}

/** A step's entry in the catalogue. Naming them keeps the shape below readable against `locales/en/onboarding`. */
type StepKey = 'welcome' | 'sidebar' | 'health' | 'appearance' | 'upload' | 'proof' | 'end';

/**
 * The tour's shape: the order of the steps and the element each one spotlights. A step with no selector is a
 * concept rather than a control, and its card is centred — which is why `proof` has none.
 */
const ANCHORS: { key: StepKey; selector?: string }[] = [
  { key: 'welcome' },
  { key: 'sidebar', selector: '[data-tour="sidebar"]' },
  { key: 'health', selector: '[data-tour="health"]' },
  { key: 'appearance', selector: '[data-tour="appearance"]' },
  { key: 'upload', selector: '[data-tour="upload"]' },
  { key: 'proof' },
  { key: 'end' },
];

/** Pure: the shape plus a catalogue is the tour. Exported so a test can hold the two to each other. */
export function buildSteps(m: Messages['onboarding']): Step[] {
  return ANCHORS.map(({ key, selector }) => ({
    ...(selector ? { selector } : {}),
    title: m[key].title,
    body: m[key].body,
  }));
}

/** The steps in the language selected right now, for a caller that is not a React component. */
export function tourSteps(): Step[] {
  return buildSteps(messages().onboarding);
}

const listeners = new Set<() => void>();
let active = false;
let index = 0;

function emit(): void {
  for (const l of listeners) l();
}

export function startTour(): void {
  active = true;
  index = 0;
  emit();
}

function endTour(): void {
  active = false;
  try {
    localStorage.setItem(DONE_KEY, '1');
  } catch {
    // ignore
  }
  emit();
}

const snap = () => (active ? `1:${index}` : '0');
const subscribe = (cb: () => void): (() => void) => {
  listeners.add(cb);
  return () => listeners.delete(cb);
};

export function Onboarding(): JSX.Element | null {
  const t = useMessages();
  useSyncExternalStore(subscribe, snap, snap);
  const [rect, setRect] = useState<DOMRect | null>(null);
  // `t` is the dependency that matters: it is what makes a locale switch re-word an open tour rather than leaving
  // it in the language the reader just turned off.
  const steps = useMemo(() => buildSteps(t.onboarding), [t]);

  // Auto-run once on first visit.
  useEffect(() => {
    let done = false;
    try {
      done = localStorage.getItem(DONE_KEY) === '1';
    } catch {
      done = true;
    }
    if (!done) {
      const timer = setTimeout(startTour, 600);
      return () => clearTimeout(timer);
    }
  }, []);

  const step = active ? steps[index] : undefined;

  // Track the spotlighted element's position (and follow scroll/resize). `step` changes with the index, so it's
  // the only dependency needed.
  useEffect(() => {
    if (!step) return;
    const measure = () => {
      const el = step.selector ? document.querySelector(step.selector) : null;
      if (el) {
        el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        setRect(el.getBoundingClientRect());
      } else {
        setRect(null);
      }
    };
    measure();
    window.addEventListener('resize', measure);
    window.addEventListener('scroll', measure, true);
    return () => {
      window.removeEventListener('resize', measure);
      window.removeEventListener('scroll', measure, true);
    };
  }, [step]);

  if (!step) return null;

  const pad = 6;
  const spotlight = rect
    ? { top: rect.top - pad, left: rect.left - pad, width: rect.width + pad * 2, height: rect.height + pad * 2 }
    : null;

  // Place the card below the target if there's room, else above; centered when there's no target.
  const cardStyle: CSSProperties = spotlight
    ? spotlight.top + spotlight.height + 200 < window.innerHeight
      ? {
          top: spotlight.top + spotlight.height + 12,
          left: Math.min(Math.max(spotlight.left, 16), window.innerWidth - 340),
        }
      : {
          top: Math.max(spotlight.top - 190, 16),
          left: Math.min(Math.max(spotlight.left, 16), window.innerWidth - 340),
        }
    : { top: '50%', left: '50%', transform: 'translate(-50%, -50%)' };

  const last = index === steps.length - 1;

  return (
    <div
      style={{ position: 'fixed', inset: 0, zIndex: 300 }}
      // biome-ignore lint/a11y/useSemanticElements: a custom tour overlay; a native <dialog> would need showModal() + imperative focus handling.
      role="dialog"
      aria-modal="true"
      aria-label={t.onboarding.ariaLabel}
    >
      {/* Dim + spotlight (a box-shadow cutout). Clicking the dim area does nothing; controls are on the card. */}
      {spotlight ? (
        <div
          style={{
            position: 'fixed',
            top: spotlight.top,
            left: spotlight.left,
            width: spotlight.width,
            height: spotlight.height,
            borderRadius: 10,
            boxShadow: '0 0 0 9999px var(--scrim)',
            outline: '2px solid var(--accent)',
            pointerEvents: 'none',
            transition: 'all 0.2s ease',
          }}
        />
      ) : (
        <div style={{ position: 'fixed', inset: 0, background: 'var(--scrim)' }} />
      )}

      <div className="dialog" style={{ position: 'fixed', width: 320, padding: 18, ...cardStyle }}>
        <div className="eyebrow" style={{ marginBottom: 6 }}>
          {t.onboarding.progress(index + 1, steps.length)}
        </div>
        <div className="dialog-title" style={{ fontSize: 15 }}>
          {step.title}
        </div>
        <p style={{ margin: '0 0 16px', fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.5 }}>{step.body}</p>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button type="button" className="btn btn-sm btn-ghost" onClick={endTour}>
            {t.onboarding.skip}
          </button>
          <div style={{ flex: 1 }} />
          {index > 0 && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                index -= 1;
                emit();
              }}
            >
              {t.onboarding.back}
            </button>
          )}
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => {
              if (last) endTour();
              else {
                index += 1;
                emit();
              }
            }}
          >
            {last ? t.onboarding.done : t.onboarding.next}
          </button>
        </div>
      </div>
    </div>
  );
}
