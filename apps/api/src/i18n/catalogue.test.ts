import { describe, expect, it } from 'vitest';
import { TOGGLEABLE_FLAGS } from '../flags.js';
import { TOOL_IDS } from '../tools.js';
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

/**
 * The three surfaces that are composed on the server and printed verbatim by the client. Each of them is keyed by
 * an identifier the rest of the system also uses, so the real risk is not a bad sentence — it is a MISSING one:
 * a tool or a lane added to its table and never glossed, which would render as `undefined` in both languages.
 * The compiler catches that for `es` (it is typed against `en`); these check `en` itself against the tables.
 */
describe('every runtime surface is glossed for every id it can be asked about', () => {
  it('glosses every tool this build probes, and invents no tool it does not', () => {
    expect(Object.keys(en.tools.unlocks).sort()).toEqual([...TOOL_IDS].sort());
    expect(Object.keys(es.tools.unlocks).sort()).toEqual([...TOOL_IDS].sort());
  });

  it('describes every toggleable lane, and invents no lane the allow-list does not offer', () => {
    const names = TOGGLEABLE_FLAGS.map((f) => f.name).sort();
    expect(Object.keys(en.flags).sort()).toEqual(names);
    expect(Object.keys(es.flags).sort()).toEqual(names);
  });

  it('keys the tool table by the shell identifiers, never by a translated name', () => {
    for (const id of ['qemu-system-mips', 'analyzeHeadless', 'mkfs.ext2', 'gdb-multiarch'] as const) {
      expect(es.tools.unlocks[id]).toBeTruthy();
    }
    // `binwalk`, `Ghidra`, `SquashFS`, `SBOM` and the CVE/KEV acronyms are names, not words — they survive intact.
    expect(es.tools.unlocks.binwalk).toContain('firmas');
    expect(es.tools.unlocks.syft).toContain('SBOM');
    expect(es.tools.unlocks.grype).toContain('CVE');
    expect(es.tools.unlocks.fwhunt).toContain('FwHunt');
  });

  it('keys the lane table by the environment variables an operator sets in compose', () => {
    expect(es.flags.FIRMLAB_RESEARCH.label).toBeTruthy();
    expect(es.flags.FIRMLAB_CAPTURE_GATEWAY.egress).toBeTruthy();
    // No Spanish spelling of a variable name is ever invented, in the prose or anywhere else.
    const prose = [...stringLeaves(es).values()].join('\n');
    for (const invented of ['FIRMLAB_INVESTIGACION', 'FIRMLAB_CAPTURA', 'FIRMLAB_AGENTE']) {
      expect(prose).not.toContain(invented);
    }
  });
});

/**
 * The coverage verdict, translated. Its branches exist because "nothing has run" and "everything ran and found
 * nothing" produce the identical empty findings list and are opposite conclusions — so the property to protect is
 * that no two of them collapse into the same sentence, and that none of them reads like a verdict about the
 * firmware. `providers/coverage.test.ts` checks the composed output; this checks the vocabulary it is built from.
 */
describe('the coverage verdict keeps its distinctions in Spanish', () => {
  it('says an unexamined image is UNEXAMINED, and not that it came back clean', () => {
    expect(en.coverage.verdict.unexamined(4)).toContain('UNEXAMINED, not clean');
    expect(es.coverage.verdict.unexamined(4)).toContain('SIN EXAMINAR, no limpia');
    expect(es.coverage.verdict.unexamined(4)).toContain('4 etapa(s)');
  });

  it('never lets "ran and found nothing" and "never ran" become the same sentence', () => {
    const ranEmpty = es.coverage.verdict.allRanEmpty(3);
    const nothingRan = es.coverage.verdict.unexamined(3);
    const partial = es.coverage.verdict.partialEmpty({ executed: 1, applicable: 3, missing: 2 });
    expect(new Set([ranEmpty, nothingRan, partial]).size).toBe(3);
    // The real negative is allowed to be a negative — but never proof of security.
    expect(en.coverage.verdict.allRanEmpty(3)).toContain('not proof the firmware is secure');
    expect(ranEmpty).toContain('no es prueba de que el firmware sea seguro');
    // And a partial run says outright that a zero covers only what ran.
    expect(partial).toContain('sólo cubre las etapas que se ejecutaron');
  });

  it('keeps UNKNOWN coverage unknown rather than letting individually-run findings stand in for a scan', () => {
    const s = es.coverage.verdict.unknownWithFindings({ applicable: 12, findingCount: 28 });
    expect(s).toContain('DESCONOCIDA');
    expect(s).toContain('28 hallazgo(s)');
    expect(s).not.toContain('SIN EXAMINAR');
  });

  it('keeps a degraded stage visibly degraded, so the headline cannot absorb its own caveat', () => {
    expect(en.coverage.degraded({ count: 1, workers: ['UEFI · FwHunt'], more: 0 })).toContain('DEGRADED');
    expect(es.coverage.degraded({ count: 1, workers: ['UEFI · FwHunt'], more: 0 })).toContain('DEGRADADAS');
  });

  it('says an operator assertion is a statement and covers no stage, in both languages', () => {
    expect(en.coverage.assertions(2)).toContain('not measurements');
    expect(en.coverage.assertions(2)).toContain('cover no stage');
    expect(es.coverage.assertions(2)).toContain('no mediciones');
    expect(es.coverage.assertions(2)).toContain('no cubren ninguna etapa');
  });

  it('prints worker ids verbatim in both languages — the reader compares them against the table below', () => {
    const workers = ['W3 · Credentials', 'Cross-check · Kernel command line'];
    for (const catalogue of [en, es]) {
      const s = catalogue.coverage.notCovered({ workers, more: 2 });
      for (const w of workers) expect(s).toContain(w);
      expect(s).toContain('+2');
    }
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
