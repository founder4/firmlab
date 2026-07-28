import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { es } from '../locales/es';
import { TechniqueCoverage } from './TechniqueCoverage';

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
});

describe('TechniqueCoverage', () => {
  it('renders the methodology areas and a status summary', () => {
    render(<TechniqueCoverage />);
    expect(screen.getByText(en.techniques.title)).toBeInTheDocument();
    expect(screen.getByText(/Static analysis \(FSTM 3–5\)/)).toBeInTheDocument();
    expect(screen.getByText(/UEFI \/ BIOS deep analysis/)).toBeInTheDocument();
    // The summary badges count each status at least once.
    expect(screen.getByText(/\d+ done/)).toBeInTheDocument();
    expect(screen.getByText(/\d+ planned/)).toBeInTheDocument();
  });

  it('marks shipped capabilities done and known gaps planned, honestly', () => {
    render(<TechniqueCoverage />);
    // A shipped technique. Read from the catalogue rather than restated here, so the assertion cannot drift from
    // the wording a reader actually sees.
    expect(screen.getByText(en.techniques.items.chipsec.name)).toBeInTheDocument();
    // A still-open gap.
    expect(screen.getByText(en.techniques.items.symreach.name)).toBeInTheDocument();
    // Weaponization is explicitly out of scope, not claimed.
    expect(screen.getByText(en.techniques.items.weaponization.name)).toBeInTheDocument();
  });

  it('names the methodologies exactly as they are published', () => {
    const { container } = render(<TechniqueCoverage />);
    const text = container.textContent ?? '';
    expect(text).toContain('OWASP FSTM');
    expect(text).toContain('ISTG');
    // The stage numbers belong to OWASP too, and a heading without them cannot be lined up against the standard.
    expect(text).toContain('FSTM 1–2');
    expect(text).toContain('FSTM 7–8');
  });
});

/**
 * The Spanish reading of this screen is where an overstatement would do the most damage: it is the workbench's own
 * account of what it does, so a `partial` that renders as finished or a `planned` that renders as available is the
 * tool lying about itself. The four status words are therefore asserted DISTINCT and each is pinned to the meaning
 * it has to keep — and `out-of-scope`, the deliberate boundary this screen exists partly to state, is checked
 * against both wrong readings: it may not sound done, and it may not sound like a gap nobody got round to.
 */
describe('TechniqueCoverage — Spanish', () => {
  it('keeps the four statuses distinct, and none of them stronger than it is', () => {
    setLocale('es');
    const { container } = render(<TechniqueCoverage />);
    const text = container.textContent ?? '';

    expect(screen.getByText(es.techniques.title)).toBeInTheDocument();

    // Four labels, four different words — the row badges.
    const labels = [
      es.techniques.status.done,
      es.techniques.status.partial,
      es.techniques.status.planned,
      es.techniques.status['out-of-scope'],
    ];
    expect(new Set(labels).size).toBe(4);
    expect(labels).toEqual(['hecha', 'parcial', 'prevista', 'no aplica']);
    for (const label of labels) expect(screen.getAllByText(new RegExp(label)).length).toBeGreaterThan(0);

    // …and the summary above them, which is where the long form of the boundary is spelled out.
    expect(text).toMatch(/\d+ hechas/);
    expect(text).toMatch(/\d+ parciales/);
    expect(text).toMatch(/\d+ previstas/);
    expect(text).toMatch(/\d+ fuera de alcance/);
    // "parcial" must not be readable as done, and "prevista" must not be readable as available.
    expect(es.techniques.status.partial).not.toBe(es.techniques.status.done);
    expect(text).not.toMatch(/disponible ya|ya funciona|completad/i);
  });

  it('renders the methodology identifiers verbatim in both languages', () => {
    setLocale('es');
    const { container } = render(<TechniqueCoverage />);
    const text = container.textContent ?? '';
    // The whole point of the screen: it can be laid beside the published methodology and lined up row for row.
    expect(text).toContain('OWASP FSTM');
    expect(text).toContain('ISTG');
    expect(text).toContain('FSTM 1–2');
    expect(text).toContain('FSTM 7–8');
    // Never localised: it is the name of a standard, not a description of one.
    expect(text).not.toMatch(/MPSF|Metodología OWASP de Pruebas/i);
    // Tool and provider names are pointers, not sentences.
    expect(text).toContain('providers/webprobe');
    expect(text).toContain('AFL++');
    expect(text).toContain('angr');
    expect(text).toContain('docs/METHODOLOGY-GAPS.md');
  });

  it('states an out-of-scope row as a boundary, not as done and not as a gap', () => {
    setLocale('es');
    const { container } = render(<TechniqueCoverage />);
    const text = container.textContent ?? '';

    // Weaponised exploitation is refused by design; the row says so and the note says why.
    expect(screen.getByText(es.techniques.items.weaponization.name)).toBeInTheDocument();
    expect(text).toContain('Explotación armada');
    expect(text).toContain('defensivo por diseño');
    // Chip-off and radio work are the same kind of boundary — hardware, not a to-do list.
    expect(text).toContain('laboratorio de hardware');
    expect(text).toContain('dongle de la fase 6');

    // The boundary is neither claimed as delivered…
    expect(es.techniques.status['out-of-scope']).not.toBe(es.techniques.status.done);
    expect(es.techniques.status['out-of-scope']).not.toMatch(/hech|list[oa]|cubiert/i);
    // …nor reported as something missing, unbuilt or pending, which is what `prevista` means and is a different
    // answer entirely.
    expect(es.techniques.status['out-of-scope']).not.toBe(es.techniques.status.planned);
    expect(es.techniques.status['out-of-scope']).not.toMatch(/falta|ausente|pendiente|sin (hacer|cubrir|implementar)/i);
    expect(es.techniques.summary.outOfScope(4)).toBe('4 fuera de alcance');
  });

  it('translates the prose of a note while leaving the pointer inside it alone', () => {
    setLocale('es');
    const { container } = render(<TechniqueCoverage />);
    const text = container.textContent ?? '';
    // A note that is a pure pointer into this repository never enters the catalogue and renders verbatim…
    expect(text).toContain('providers/report');
    expect(text).toContain('core/mcu + renode');
    // …while a note that is prose around one is translated, and the identifier inside it is not.
    expect(es.techniques.notes.secureBoot).toBe('providers/chipsec (sobre la imagen)');
    expect(text).toContain('providers/chipsec (sobre la imagen)');
    expect(text).toContain('integrar fwhunt-scan');
    expect(text).toContain('CC2531/ConBee');
    // The English note it came from is still the English note — the two are not the same string.
    expect(es.techniques.notes.weaponization).not.toBe(en.techniques.notes.weaponization);
  });
});
