import { describe, expect, it } from 'vitest';
import { en } from './en.js';
import { es } from './es.js';
import { formatTimestamp, htmlLang, intlTag, messages, resolveLocale } from './index.js';

/**
 * The catalogue's own guarantees. The compiler already enforces most of this — `es` is declared as `Messages`, so a
 * missing or renamed key does not build — but the properties below are the ones a future `as unknown as Messages`,
 * a copy-paste that left an English sentence in the Spanish file, or a well-meaning "translation" of an identifier
 * would slip past. They are cheap, and each of them has a failure mode that would ship looking finished.
 */

type Leaf = { path: string; type: string };

function leaves(value: unknown, prefix = ''): Leaf[] {
  if (typeof value === 'function') return [{ path: prefix, type: 'function' }];
  if (value !== null && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .flatMap((k) => leaves((value as Record<string, unknown>)[k], prefix ? `${prefix}.${k}` : k));
  }
  return [{ path: prefix, type: typeof value }];
}

function stringLeaves(value: unknown, prefix = ''): Map<string, string> {
  const out = new Map<string, string>();
  if (typeof value === 'string') {
    out.set(prefix, value);
    return out;
  }
  if (value !== null && typeof value === 'object' && typeof value !== 'function') {
    for (const k of Object.keys(value)) {
      for (const [p, v] of stringLeaves((value as Record<string, unknown>)[k], prefix ? `${prefix}.${k}` : k)) {
        out.set(p, v);
      }
    }
  }
  return out;
}

/**
 * Leaves that are legitimately the same word in both languages. Every entry is an acronym or a standard identifier
 * that Spanish writes exactly as English does; the list is short on purpose, because "it happens to be the same"
 * is also what an untranslated string looks like.
 */
const SHARED_BY_NATURE = new Set(['report.sbomColumns.cve', 'disclosure.shaLabel']);

describe('the two catalogues describe the same document', () => {
  it('has an identical key set, leaf for leaf, with the same shape at each leaf', () => {
    expect(leaves(es)).toEqual(leaves(en));
  });

  it('translates every string leaf — an English sentence left in the Spanish file is a defect, not a default', () => {
    const enStrings = stringLeaves(en);
    const esStrings = stringLeaves(es);
    const untranslated = [...enStrings]
      .filter(([path, value]) => esStrings.get(path) === value && !SHARED_BY_NATURE.has(path))
      .map(([path]) => path);
    expect(untranslated).toEqual([]);
  });

  it('keeps every message reachable from both locales through the registry', () => {
    expect(messages('en')).toBe(en);
    expect(messages('es')).toBe(es);
  });
});

describe('identifiers are not translated, in either direction', () => {
  it('keys the proof-state gloss by the codes the API and SQLite use, in both languages', () => {
    const codes = [
      'confirmed_full_system',
      'confirmed_in_emulation',
      'static_confirmed',
      'needs_runtime_reproduction',
      'blocked_by_platform',
      'blocked_by_security',
      'false_positive',
      'operator_assertion',
    ];
    expect(Object.keys(en.proofState.meaning).sort()).toEqual([...codes].sort());
    expect(Object.keys(es.proofState.meaning).sort()).toEqual([...codes].sort());
  });

  it('keys the claim gloss by the operator claims, in both languages', () => {
    const claims = [
      'asserted_unverified',
      'asserted_from_device',
      'asserted_from_external_evidence',
      'disputes_finding',
    ];
    expect(Object.keys(en.ledger.claimMeaning).sort()).toEqual([...claims].sort());
    expect(Object.keys(es.ledger.claimMeaning).sort()).toEqual([...claims].sort());
  });

  it('never invents a Spanish spelling of a code, anywhere in the catalogue', () => {
    const prose = [...stringLeaves(es).values()].join('\n');
    for (const invented of [
      'confirmado_estatico',
      'confirmado_estático',
      'bloqueado_por_plataforma',
      'bloqueado_por_seguridad',
      'falso_positivo',
      'afirmacion_de_operador',
      'necesita_reproduccion',
    ]) {
      expect(prose).not.toContain(invented);
    }
  });

  it('names the ladder rung it refuses to claim by its real code, in Spanish too', () => {
    // `asserted_from_device` explains itself by pointing at the rung FirmLab stops at. Translating that token
    // would make the sentence unverifiable against the ledger it is talking about.
    expect(es.ledger.claimMeaning.asserted_from_device).toContain('confirmed_full_system');
    expect(en.ledger.claimMeaning.asserted_from_device).toContain('confirmed_full_system');
  });
});

describe('the load-bearing caveats survive translation', () => {
  it('says a blocked state is NOT a negative result, in both languages', () => {
    expect(en.proofState.meaning.blocked_by_platform).toContain('NOT a negative result');
    expect(en.proofState.meaning.blocked_by_security).toContain('NOT a negative result');
    expect(es.proofState.meaning.blocked_by_platform).toContain('NO es un resultado negativo');
    expect(es.proofState.meaning.blocked_by_security).toContain('NO es un resultado negativo');
  });

  it('never lets a blocked state read like "no problems found"', () => {
    for (const s of [es.proofState.meaning.blocked_by_platform, es.proofState.meaning.blocked_by_security]) {
      expect(s).not.toMatch(/sin problemas|no se encontr|todo correcto|limpio/i);
    }
  });

  it('says an empty measured ledger is not a clean image, in both languages', () => {
    expect(en.ledger.measuredEmpty).toContain('not evidence that the image is clean');
    expect(es.ledger.measuredEmpty).toContain('no es evidencia de que la imagen esté limpia');
  });

  it('says an emulated reproduction proves the sandbox and never the device, in both languages', () => {
    expect(en.proofState.meaning.confirmed_in_emulation).toContain('never the physical device');
    expect(es.proofState.meaning.confirmed_in_emulation).toContain('nunca el dispositivo físico');
    expect(en.disclosure.confirmedIntro).toContain('not the deployed device');
    expect(es.disclosure.confirmedIntro).toContain('no el dispositivo desplegado');
  });

  it('says a lead is not a verdict, in both languages', () => {
    expect(en.proofState.meaning.needs_runtime_reproduction).toContain('never report it as a bug');
    expect(es.proofState.meaning.needs_runtime_reproduction).toContain('nunca lo presentes como un fallo');
    expect(en.disclosure.leadsNotice).toContain('not confirmed');
    expect(es.disclosure.leadsNotice).toContain('no está confirmado');
  });

  it('says an operator assertion carries no proof state and counts towards no stage, in both languages', () => {
    expect(en.ledger.notAMeasurement).toContain('it counts towards no analysis stage');
    expect(es.ledger.notAMeasurement).toContain('no cuenta para ninguna etapa del análisis');
    expect(en.ledger.operatorIntro).toContain('none of it carries a proof state');
    expect(es.ledger.operatorIntro).toContain('nada de esto lleva estado de prueba');
  });

  it('says a dispute does not move the proof state, in both languages', () => {
    expect(en.ledger.claimMeaning.disputes_finding).toContain('does NOT change');
    expect(es.ledger.claimMeaning.disputes_finding).toContain('NO cambia el estado de prueba');
  });

  it('keeps the draft a draft nobody sends, in both languages', () => {
    expect(en.disclosure.draftNotice).toContain('DRAFT');
    expect(en.disclosure.draftNotice).toContain('FirmLab does not contact anyone');
    expect(es.disclosure.draftNotice).toContain('BORRADOR');
    expect(es.disclosure.draftNotice).toContain('FirmLab no contacta con nadie');
  });
});

describe('resolveLocale is total — an unknown value is English, never a throw and never half a document', () => {
  it('resolves what it recognises, case- and region-insensitively', () => {
    expect(resolveLocale('en')).toBe('en');
    expect(resolveLocale('es')).toBe('es');
    expect(resolveLocale('ES')).toBe('es');
    expect(resolveLocale('es-ES')).toBe('es');
    expect(resolveLocale('es-419')).toBe('es');
    expect(resolveLocale(' es ')).toBe('es');
    expect(resolveLocale('en-GB')).toBe('en');
  });

  it('falls back to English for everything else, without throwing', () => {
    for (const bad of [undefined, null, '', '  ', 'fr', 'de-DE', 'esperanto-ish', 'ES,EN', 42, true, {}, [], ['es']]) {
      expect(resolveLocale(bad)).toBe('en');
    }
    // A repeated query parameter arrives as an array; Fastify does not collapse it, and neither do we.
    expect(resolveLocale(['es', 'en'])).toBe('en');
  });

  it('gives every locale a document language and an Intl tag', () => {
    expect(htmlLang('en')).toBe('en');
    expect(htmlLang('es')).toBe('es');
    expect(intlTag('en')).toBe('en-GB');
    expect(intlTag('es')).toBe('es-ES');
  });
});

describe('formatTimestamp', () => {
  const iso = '2026-07-21T09:05:00.000Z';

  it('writes the date the way the locale writes it, pinned to UTC', () => {
    const inEnglish = formatTimestamp(iso, 'en');
    const inSpanish = formatTimestamp(iso, 'es');
    expect(inEnglish).not.toBe(inSpanish);
    expect(inEnglish).toContain('2026');
    expect(inSpanish).toContain('2026');
    expect(inSpanish).toMatch(/julio/i);
    // Pinned to UTC so an archived report means the same thing wherever it is opened.
    expect(inEnglish).toContain('09:05:00');
    expect(inSpanish).toContain('09:05:00');
  });

  it('returns an unparseable stamp untouched rather than printing "Invalid Date"', () => {
    expect(formatTimestamp('not a date', 'es')).toBe('not a date');
    expect(formatTimestamp('', 'en')).toBe('');
  });
});
