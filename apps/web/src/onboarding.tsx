/**
 * Guided tour — an optional, resettable onboarding that spotlights real interface elements (by data-tour
 * attribute) rather than a wall of text. It auto-runs once on first visit, never again unless the user starts
 * it from the header (?) or Settings. A module store drives a single <Onboarding/> mounted in the shell.
 */
import { type CSSProperties, useEffect, useState, useSyncExternalStore } from 'react';

const DONE_KEY = 'firmlab.tour.done';

interface Step {
  selector?: string;
  title: string;
  body: string;
}

const STEPS: Step[] = [
  {
    title: 'Welcome to FirmLab',
    body: 'A local, private firmware workbench. Everything is analyzed on this machine — nothing is uploaded. Here is a 20-second tour; you can skip it any time.',
  },
  {
    selector: '[data-tour="sidebar"]',
    title: 'Navigate here',
    body: 'The sidebar holds your workspace (Dashboard, Corpus, Capabilities) and, once a firmware image is open, its analysis sections grouped by purpose.',
  },
  {
    selector: '[data-tour="health"]',
    title: 'Security posture, always visible',
    body: 'This tells you whether the API is bound to loopback (local-only) or reachable over the network. FirmLab is meant to stay local.',
  },
  {
    selector: '[data-tour="appearance"]',
    title: 'Make it yours',
    body: 'Switch between light, dark, and system themes, and toggle comfortable/compact density for long analysis sessions. Full controls live in Settings.',
  },
  {
    selector: '[data-tour="upload"]',
    title: 'Start an analysis',
    body: 'Drop a firmware image (or browse) to analyze it instantly with the deterministic engine — no toolchain required. External tools add depth when present.',
  },
  {
    title: 'That’s it',
    body: 'Restart this tour any time from the ? button in the header or from Settings → Help. Happy hunting.',
  },
];

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
  useSyncExternalStore(subscribe, snap, snap);
  const [rect, setRect] = useState<DOMRect | null>(null);

  // Auto-run once on first visit.
  useEffect(() => {
    let done = false;
    try {
      done = localStorage.getItem(DONE_KEY) === '1';
    } catch {
      done = true;
    }
    if (!done) {
      const t = setTimeout(startTour, 600);
      return () => clearTimeout(t);
    }
  }, []);

  const step = active ? STEPS[index] : undefined;

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

  const last = index === STEPS.length - 1;

  return (
    // biome-ignore lint/a11y/useSemanticElements: a custom tour overlay; a native <dialog> would need showModal() + imperative focus handling.
    <div style={{ position: 'fixed', inset: 0, zIndex: 300 }} role="dialog" aria-modal="true" aria-label="Product tour">
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
          Step {index + 1} / {STEPS.length}
        </div>
        <div className="dialog-title" style={{ fontSize: 15 }}>
          {step.title}
        </div>
        <p style={{ margin: '0 0 16px', fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.5 }}>{step.body}</p>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button type="button" className="btn btn-sm btn-ghost" onClick={endTour}>
            Skip
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
              Back
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
            {last ? 'Done' : 'Next'}
          </button>
        </div>
      </div>
    </div>
  );
}
