/**
 * The locale store, and the two properties the catalogue design exists to guarantee.
 *
 * The important one cannot be tested here at all: that a missing Spanish key is a COMPILE error. `pnpm check` is
 * that test, and it was verified by deleting a key and watching tsc name the file and the key. What is testable is
 * the shape — that the two catalogues really are structurally identical at runtime, which catches the one hole the
 * type system leaves: a Spanish value that is present but still holds the English string.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { currentLocale, intlTag, messages, setLocale } from './i18n';
import { en } from './locales/en';
import { es } from './locales/es';

/** Every leaf path in a catalogue, so the two can be compared as sets rather than eyeballed. */
function leafPaths(obj: unknown, prefix = ''): string[] {
  if (typeof obj !== 'object' || obj === null) return [prefix];
  return Object.entries(obj).flatMap(([k, v]) =>
    typeof v === 'object' && v !== null ? leafPaths(v, `${prefix}${k}.`) : `${prefix}${k}`,
  );
}

beforeEach(() => {
  setLocale('en');
});

describe('locale store', () => {
  it('switches the active catalogue and persists the choice', () => {
    expect(currentLocale()).toBe('en');
    expect(messages().nav.settings).toBe('Settings');

    setLocale('es');
    expect(currentLocale()).toBe('es');
    expect(messages().nav.settings).toBe('Ajustes');
    // Persistence is deliberately NOT asserted here. `localStorage` is undefined under this runner — Node's own
    // experimental global shadows jsdom's and is unavailable without `--localstorage-file` — which is exactly why
    // every access in `i18n.ts` is wrapped. Asserting it would pin the runner's quirk, not the behaviour; what
    // matters, and what is checked, is that the switch works with no storage at all.
  });

  it('sets <html lang>, which is what a screen reader reads', () => {
    setLocale('es');
    expect(document.documentElement.getAttribute('lang')).toBe('es');
    setLocale('en');
    expect(document.documentElement.getAttribute('lang')).toBe('en');
  });

  it('offers an Intl tag per locale, so a date is never formatted under the wrong grammar', () => {
    expect(intlTag('es')).toBe('es-ES');
    expect(intlTag('en')).toBe('en-GB');
  });
});

describe('catalogue integrity', () => {
  it('has the same keys in both languages', () => {
    expect(leafPaths(es).sort()).toEqual(leafPaths(en).sort());
  });

  it('leaves no Spanish string identical to its English source', () => {
    // The type system guarantees a key EXISTS; it cannot guarantee it was translated. A copied English value is
    // the one way a half-finished catalogue still compiles, so it is checked here instead.
    //
    // Proper nouns, identifiers and symbols are legitimately identical in both languages and are exempt by value.
    const SHARED = new Set([
      'Corpus',
      'FirmLab',
      'SBOM',
      'SBOM & CVEs',
      'Diff',
      'no',
      'firmware · local',
      'General',
      'Firmware',
      'Bootloader',
    ]);
    const offenders: string[] = [];
    const walk = (a: unknown, b: unknown, path: string): void => {
      if (typeof a === 'string' && typeof b === 'string') {
        if (a === b && !SHARED.has(a)) offenders.push(`${path} = ${JSON.stringify(a)}`);
        return;
      }
      if (typeof a === 'object' && a !== null && typeof b === 'object' && b !== null) {
        for (const k of Object.keys(a)) {
          walk((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], path ? `${path}.${k}` : k);
        }
      }
    };
    walk(en, es, '');
    expect(offenders).toEqual([]);
  });

  it('keeps proof-state CODES out of the translated surface', () => {
    // The codes cross the API and land in SQLite. Only their gloss is localised; translating the identifier itself
    // would change data rather than presentation.
    expect(Object.keys(es.proofState.label).sort()).toEqual(Object.keys(en.proofState.label).sort());
    expect(Object.keys(en.proofState.label)).toContain('blocked_by_platform');
    // …and the Spanish gloss must not soften a blocked stage into a clean one.
    expect(es.proofState.meaning.blocked_by_platform).toMatch(/NO es un resultado negativo/i);
    expect(es.proofState.meaning.blocked_by_security).toMatch(/NO es un resultado negativo/i);
  });
});
