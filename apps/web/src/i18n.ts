/**
 * Locale store — English and Spanish, persisted to localStorage and applied to <html lang>. Deliberately the same
 * module-level-store shape as `theme.ts` (and the toaster): any component reads it without a context provider, and
 * a change applies instantly with no reload.
 *
 * **Why the catalogue is typed rather than keyed by string.** This workbench's on-screen prose is not decoration —
 * the sentence that says a blocked stage is NOT a negative, or that an operator assertion counts towards no stage,
 * is the product. A conventional `t('some.key')` lookup fails at RUNTIME and falls back to the key or to English,
 * which means a half-translated build looks finished and degrades silently in exactly the places that matter. So
 * every Spanish namespace declares itself as `Messages['<ns>']`: a missing key, a renamed key or a changed
 * parameter list is a COMPILE error in the file that owns it, and `pnpm check` is the guard.
 *
 * **Why entries are functions when they interpolate.** Spanish agrees in gender and number where English does not,
 * and a placeholder-substitution scheme forces both languages through English's grammar. A function per message
 * lets each language build its own sentence — `${n} etapa${n === 1 ? '' : 's'}` on one side, `${n} stage${n === 1 ?
 * '' : 's'}` on the other — instead of pretending the two share a shape.
 *
 * **What is NOT translated, ever.** Proof states (`static_confirmed`, `blocked_by_platform`), finding kinds, source
 * strings and job kinds are IDENTIFIERS that cross the API and land in SQLite. Translating them would change data,
 * not presentation. They render verbatim; only their human-readable gloss is localised.
 *
 * **Why a catalogue is loaded, not imported.** Each language is its own chunk (see `locales/index.ts`). The active
 * one is fetched before React mounts (`initLocale`), and `locale` only ever names a catalogue that is already here,
 * so every read stays synchronous. A switch to a loaded language is instant; the first switch to the other one
 * keeps the current language on screen until its chunk arrives, rather than painting a half-empty frame.
 */
import { useSyncExternalStore } from 'react';
import { type Messages, catalogueLoaders } from './locales';

export type { Messages };

export type Locale = 'en' | 'es';

const LOCALE_KEY = 'firmlab.locale';

export const LOCALES: { value: Locale; label: string }[] = [
  { value: 'en', label: 'English' },
  { value: 'es', label: 'Español' },
];

const listeners = new Set<() => void>();
const loaded: Partial<Record<Locale, Messages>> = {};
let locale: Locale = load();
// The latest switch asked for. A slow load that resolves after a newer switch must not undo it.
let requested: Locale = locale;

function load(): Locale {
  try {
    const stored = localStorage.getItem(LOCALE_KEY);
    if (stored === 'en' || stored === 'es') return stored;
    // No stored preference: follow the browser once, so a Spanish-configured machine does not open in English and
    // stay there. It is only a starting point — the moment the operator picks one, that choice is what persists.
    const nav = typeof navigator !== 'undefined' ? navigator.language : '';
    if (nav.toLowerCase().startsWith('es')) return 'es';
  } catch {
    // localStorage unavailable (private mode / SSR) — fall back to the default below.
  }
  return 'en';
}

/** Write the current locale to the DOM. `lang` is what a screen reader and the browser's own UI read. */
export function applyLocale(): void {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('lang', locale);
}

function emit(): void {
  applyLocale();
  for (const l of listeners) l();
}

/** Fetch a catalogue once; later calls resolve from the cache. */
export async function loadLocale(l: Locale): Promise<Messages> {
  const t = loaded[l] ?? (await catalogueLoaders[l]());
  loaded[l] = t;
  return t;
}

function commit(next: Locale): void {
  locale = next;
  try {
    localStorage.setItem(LOCALE_KEY, next);
  } catch {
    // ignore persistence failure — the in-memory switch still works for this session
  }
  emit();
}

/** Switch language. Synchronous when the catalogue is loaded; otherwise applies once it arrives. */
export function setLocale(next: Locale): void {
  requested = next;
  if (loaded[next]) {
    commit(next);
    return;
  }
  void loadLocale(next).then(() => {
    if (requested === next) commit(next);
  });
}

/** Bootstrap: await before React mounts, so the first paint is already in the right language. */
export async function initLocale(): Promise<void> {
  applyLocale();
  await loadLocale(locale);
}

function catalogue(l: Locale): Messages {
  const t = loaded[l];
  if (!t) throw new Error(`locale '${l}' read before its catalogue loaded — await initLocale() first`);
  return t;
}

const subscribe = (cb: () => void): (() => void) => {
  listeners.add(cb);
  return () => listeners.delete(cb);
};

/** The active locale code. Use when a value must be formatted (dates, numbers) rather than looked up. */
export function useLocale(): Locale {
  return useSyncExternalStore(
    subscribe,
    () => locale,
    () => locale,
  );
}

/**
 * The active catalogue. `const t = useMessages()` then `t.nav.dashboard` — a typo is a compile error, not a
 * missing string at runtime.
 */
export function useMessages(): Messages {
  return catalogue(useLocale());
}

/** The catalogue outside React (event handlers, non-component helpers — not module scope, which runs pre-load). */
export function messages(): Messages {
  return catalogue(locale);
}

/** The active locale outside React — for `toLocaleDateString` and friends. */
export function currentLocale(): Locale {
  return locale;
}

/** BCP-47 tag for `Intl` APIs. Kept beside the store so a new locale cannot forget to add one. */
export function intlTag(l: Locale = locale): string {
  return l === 'es' ? 'es-ES' : 'en-GB';
}
