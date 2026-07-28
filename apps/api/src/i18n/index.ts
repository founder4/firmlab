/**
 * Locale registry for the generated documents, and the one place a `?lang` value is turned into a locale.
 *
 * The workbench shell resolves its own locale in the browser (`apps/web/src/i18n.ts`). The report and the
 * disclosure draft are composed on the server, so their locale has to arrive as a request parameter — and there is
 * deliberately no module-level "current locale" here: two requests for two languages can be in flight at once, and
 * a generator that read a global would answer whichever one wrote last. Every generator takes the locale.
 *
 * `resolveLocale` never throws and never half-resolves. Anything absent, unknown, repeated (`?lang=es&lang=en`
 * arrives as an array) or malformed yields `en`, because a document rendered half in one language is worse than one
 * rendered wholly in the wrong one — and English is what every caller before this feature got.
 */
import { type Messages, en } from './en.js';
import { es } from './es.js';

export type { Messages, RevisionText } from './en.js';
export { escapeHtml } from './escape.js';

export type Locale = 'en' | 'es';

export const catalogues: Record<Locale, Messages> = { en, es };

/** The catalogue for a locale. Total: every `Locale` has one, so this cannot miss. */
export function messages(locale: Locale): Messages {
  return catalogues[locale];
}

/**
 * Pure: a query value into a locale. Accepts `es`, `ES`, `es-ES` and the same for English; everything else — a
 * missing parameter, `fr`, an array, an object, a number — is English. Never throws.
 */
export function resolveLocale(raw: unknown): Locale {
  if (typeof raw !== 'string') return 'en';
  const primary = raw.trim().toLowerCase().split('-')[0];
  return primary === 'es' ? 'es' : 'en';
}

/** The value for `<html lang>`. Kept beside the store so a new locale cannot forget one. */
export function htmlLang(locale: Locale): string {
  return locale;
}

/** BCP-47 tag for `Intl`. */
export function intlTag(locale: Locale): string {
  return locale === 'es' ? 'es-ES' : 'en-GB';
}

/**
 * Pure: an ISO timestamp as a reader of that locale writes a date.
 *
 * Fixed to UTC and stamped as such. A report is archived and read elsewhere, so a wall-clock time with no zone is
 * a time nobody can check against a log; the machine-readable ISO string is kept alongside it by both callers (the
 * HTML puts it in `<time datetime>`, the Markdown prints it in parentheses) rather than replaced by this.
 *
 * An unparseable input is returned untouched. A stored timestamp is data written by an older build, and printing
 * it verbatim is more honest than printing `Invalid Date`.
 */
export function formatTimestamp(iso: string, locale: Locale): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(intlTag(locale), {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZone: 'UTC',
    timeZoneName: 'short',
  }).format(d);
}
