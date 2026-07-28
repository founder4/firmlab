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
 */
import { useSyncExternalStore } from 'react';
import { type Messages, catalogues } from './locales';

export type { Messages };

export type Locale = 'en' | 'es';

const LOCALE_KEY = 'firmlab.locale';

export const LOCALES: { value: Locale; label: string }[] = [
  { value: 'en', label: 'English' },
  { value: 'es', label: 'Español' },
];

const listeners = new Set<() => void>();
let locale: Locale = load();

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

export function setLocale(next: Locale): void {
  locale = next;
  try {
    localStorage.setItem(LOCALE_KEY, next);
  } catch {
    // ignore persistence failure — the in-memory switch still works for this session
  }
  emit();
}

/** Bootstrap: apply immediately, before React mounts, so the first paint is already in the right language. */
export function initLocale(): void {
  applyLocale();
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
  return catalogues[useLocale()];
}

/** The catalogue outside React (module scope, event handlers, non-component helpers). */
export function messages(): Messages {
  return catalogues[locale];
}

/** The active locale outside React — for `toLocaleDateString` and friends. */
export function currentLocale(): Locale {
  return locale;
}

/** BCP-47 tag for `Intl` APIs. Kept beside the store so a new locale cannot forget to add one. */
export function intlTag(l: Locale = locale): string {
  return l === 'es' ? 'es-ES' : 'en-GB';
}
