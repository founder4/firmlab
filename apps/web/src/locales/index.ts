/**
 * Catalogue registry. `i18n.ts` loads from this by the active locale; nothing else should import a catalogue
 * directly, so there is exactly one place a new language has to be registered.
 *
 * Each catalogue is its own chunk, fetched on first use. A reader sees one language at a time, and the pair was
 * 418 of the entry chunk's 540 kB (measured 2026-11-03), so every first paint carried a language nobody was reading.
 */
import type { Messages } from './en';

export type { Messages };

export const catalogueLoaders: Record<'en' | 'es', () => Promise<Messages>> = {
  en: () => import('./en').then((m) => m.en),
  es: () => import('./es').then((m) => m.es),
};
