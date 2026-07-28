/**
 * Catalogue registry. `i18n.ts` indexes this by the active locale; nothing else should import a catalogue
 * directly, so there is exactly one place a new language has to be registered.
 */
import { type Messages, en } from './en';
import { es } from './es';

export type { Messages };

export const catalogues: Record<'en' | 'es', Messages> = { en, es };
