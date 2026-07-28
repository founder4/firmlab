/**
 * The guided tour — the first prose a new operator reads, and therefore the one screen whose wording decides how
 * every screen after it is read.
 *
 * Two properties are pinned here, and they are different claims:
 *
 *   1. **The tour opens in the language selected NOW.** The steps used to be a module-level array of English
 *      literals, built once when the bundle loaded; a tour like that opens in whatever language was active at
 *      import time, and it is the only screen a reader cannot re-open to check. So the text is asserted after a
 *      locale change made BEFORE the tour is started, and again after one made while the card is already open.
 *   2. **The proof-state step keeps its meaning.** It is where the discipline is taught, before the reader has seen
 *      a finding. `blocked_by_platform` means the question WAS asked and could not be answered here — a Spanish
 *      rendering that read like "sin problemas" would teach the opposite of the workbench's central invariant on
 *      page one — and `needs_runtime_reproduction` is a lead and nothing more. The codes render verbatim in both
 *      languages, because they are identifiers the API and SQLite share.
 *
 * The tour is started explicitly rather than by its first-visit timer: `firmlab.tour.done` is set in `beforeEach`
 * so the 600 ms auto-run cannot fire into a later test, and `startTour()` before the render means the store emits
 * with nothing mounted, so no state update escapes act(…).
 */
import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { setLocale } from './i18n';
import { Onboarding, startTour, tourSteps } from './onboarding';

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and produces act(…) warnings.
  setLocale('en');
  // The first-visit flag, so the 600 ms auto-run cannot open a card into a later test. Written through an optional
  // call because this suite has no working `localStorage`: Node's own unavailable global wins over jsdom's, which is
  // also why the tour's own `getItem` throws, is caught, and is read as "already seen". Setting it makes the guard
  // hold whichever store is in place rather than depending on that accident.
  globalThis.localStorage?.setItem('firmlab.tour.done', '1');
});

/** Walk from the first card to the step with the given 1-based number, clicking the primary button. */
function advanceTo(step: number, next: string): void {
  for (let i = 1; i < step; i += 1) fireEvent.click(screen.getByRole('button', { name: next }));
}

describe('tourSteps — the catalogue is read when it is asked for, not when the module loaded', () => {
  it('answers in the language selected right now, for a caller outside React', () => {
    expect(tourSteps()[0]?.title).toBe('Welcome to FirmLab');
    setLocale('es');
    expect(tourSteps()[0]?.title).toBe('Bienvenido a FirmLab');
  });

  it('gives every step in the shape a title and a body, so a missing translation cannot render as a blank card', () => {
    setLocale('es');
    const steps = tourSteps();
    expect(steps).toHaveLength(7);
    for (const s of steps) {
      expect(s.title.trim().length).toBeGreaterThan(0);
      expect(s.body.trim().length).toBeGreaterThan(0);
    }
  });
});

describe('Onboarding', () => {
  it('opens in English with its progress and its controls', () => {
    startTour();
    render(<Onboarding />);

    expect(screen.getByText('Welcome to FirmLab')).toBeTruthy();
    expect(screen.getByText('Step 1 / 7')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Skip' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Next' })).toBeTruthy();
    expect(screen.getByRole('dialog', { name: 'Product tour' })).toBeTruthy();
  });

  it('opens in Spanish when Spanish is the selected language', () => {
    setLocale('es');
    startTour();
    render(<Onboarding />);

    expect(screen.getByText('Bienvenido a FirmLab')).toBeTruthy();
    expect(screen.getByText('Paso 1 / 7')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Saltar' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Siguiente' })).toBeTruthy();
    expect(screen.getByRole('dialog', { name: 'Recorrido guiado' })).toBeTruthy();
  });

  it('re-words an open card when the language changes under it', () => {
    startTour();
    render(<Onboarding />);
    expect(screen.getByText('Welcome to FirmLab')).toBeTruthy();

    // The switch happens with the tour mounted, so it is wrapped: the locale store notifies live subscribers.
    act(() => setLocale('es'));

    expect(screen.getByText('Bienvenido a FirmLab')).toBeTruthy();
    expect(screen.queryByText('Welcome to FirmLab')).toBeNull();
  });

  it('reaches the last step and labels the primary control as the end of the tour', () => {
    setLocale('es');
    startTour();
    render(<Onboarding />);

    advanceTo(7, 'Siguiente');
    expect(screen.getByText('Paso 7 / 7')).toBeTruthy();
    expect(screen.getByText('Ya está')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Listo' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Siguiente' })).toBeNull();
  });
});

/**
 * The step the tour exists for. Every assertion below is a sentence that inverts if it is softened, which is why
 * they are checked against the wording and not merely against "the card is in Spanish".
 */
describe('Onboarding — the proof-state step in Spanish', () => {
  it('teaches blocked as an unanswered question and a lead as a lead, with the codes untranslated', () => {
    setLocale('es');
    startTour();
    render(<Onboarding />);

    advanceTo(6, 'Siguiente');
    expect(screen.getByText('Paso 6 / 7')).toBeTruthy();
    expect(screen.getByText('Lee primero el estado de prueba')).toBeTruthy();

    const body = screen.getByText(/estado de prueba\./).textContent ?? '';

    // The codes cross the API and land in SQLite. They are identifiers, and they render as stored in any language.
    expect(body).toContain('static_confirmed');
    expect(body).toContain('needs_runtime_reproduction');
    expect(body).toContain('blocked_by_platform');

    // A lead is a lead: a precondition was observed and nothing was proven.
    expect(body).toContain('es una pista y nada más');

    // The claim that must never soften into "sin problemas": the question WAS asked and could not be answered here.
    expect(body).toContain('la pregunta se hizo y aquí no se pudo responder');
    expect(body).toContain('nunca que la imagen esté limpia');
    expect(body).not.toMatch(/sin problemas/i);

    // …and the other half of the same discipline: an empty findings list is not a clean image either.
    expect(body).toContain('Una lista vacía tampoco significa limpia');
  });
});
