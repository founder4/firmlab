/**
 * The four hand-rolled visuals, held to the one contract they share: the PICTURE is localised, the MEASUREMENT is
 * not, and the sentence saying what the picture refuses to claim survives translation intact.
 *
 * One file rather than four because that contract is one thing, and it is the thing a second language breaks. Each
 * of these visuals draws a measurement in a warning colour — a shaded entropy band, a hot SBOM node, a carved
 * ribbon that fills the width — and colour reads as a verdict. What stops it reading that way is a single sentence
 * per picture, so each test asserts that sentence in Spanish beside a value that must NOT have moved: an entropy
 * mean, a `0x…` offset, a CVE id, a package version, a signature category.
 *
 * The two that would invert if softened, and are asserted word for word:
 *   • entropy above 7.2 bits/byte is a HYPOTHESIS — compression, packing, encryption and a JPEG all look alike from
 *     here — never "this region is encrypted";
 *   • a grey SBOM node is a component nothing MATCHED, which is not a component that was checked and cleared.
 */
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type EntropyProfile, type Finding, type SbomResult, type StructureSegment, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { EntropyChart } from './EntropyChart';
import { SbomGraph } from './SbomGraph';
import { SignalCanvas } from './SignalCanvas';
import { StructureMap } from './StructureMap';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

/**
 * jsdom ships no `ResizeObserver`, and both `SignalCanvas` and `SbomGraph` measure their wrapper with one. Without
 * this the component throws during commit and its whole subtree renders BLANK — indistinguishable from a panel that
 * has no data, which is the failure mode this codebase has already shipped once. Same stub as `ImageDetail.test`.
 */
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub);

const SIZE = 12_288;

/** A profile with a real high-entropy band in it: 0x1000…0x3000 sits above the 7.2 line. */
const entropy: EntropyProfile = {
  windowSize: 4096,
  step: 4096,
  samples: [
    { offset: 0, entropy: 3.41 },
    { offset: 4096, entropy: 7.94 },
    { offset: 8192, entropy: 7.91 },
  ],
  mean: 6.42,
  max: 7.94,
  min: 0.18,
  highEntropyRegions: [{ start: 4096, end: 12_288, meanEntropy: 7.92 }],
  likelyEncrypted: false,
  likelyCompressed: true,
};

const segments: StructureSegment[] = [
  { start: 0, end: 4096, label: 'uImage header', category: 'bootloader', confidence: 'high' },
  { start: 4096, end: SIZE, label: 'squashfs', category: 'filesystem', confidence: 'high' },
];

/** One vulnerable component and one nothing matched — the grey node the caveat is about. */
const sbom: SbomResult = {
  available: true,
  target: 'squashfs-root',
  packageCount: 2,
  packages: [
    { name: 'busybox', version: '1.20.2', type: 'binary' },
    { name: 'openssl', version: '1.0.2n', type: 'binary' },
  ],
  grypeAvailable: true,
  vulnerabilities: [
    { id: 'CVE-2018-0737', severity: 'High', packageName: 'openssl', packageVersion: '1.0.2n', fixedIn: '1.0.2o' },
  ],
  counts: { Critical: 0, High: 1, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
};

const finding = (id: string, offset: number): Finding => ({
  id,
  imageId: 'img1',
  source: 'binvuln',
  kind: 'weak_credential',
  title: 'Hardcoded root password in /etc/shadow',
  severity: 'high',
  proofState: 'static_confirmed',
  evidence: { offset },
  createdAt: 1_700_000_000_000,
});

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
  mockApi.entropy.mockResolvedValue({ size: SIZE, entropy });
  mockApi.structure.mockResolvedValue({ size: SIZE, structure: segments, signatures: [] });
});

describe('EntropyChart — the band is a hypothesis in both languages', () => {
  it('states in English that high entropy is a lead, not a verdict', () => {
    render(<EntropyChart entropy={entropy} size={SIZE} />);

    expect(screen.getByText(/hypothesis to check against the structure map, never a verdict/i)).toBeTruthy();
    expect(screen.getByText(/so do an embedded JPEG and a certificate blob/i)).toBeTruthy();
  });

  it('translates the caveat and leaves the entropy values and the offset axis exactly as measured', () => {
    setLocale('es');
    const { container } = render(<EntropyChart entropy={entropy} size={SIZE} />);

    // The claim the picture must never make on its own.
    expect(screen.getByText(/hipótesis que contrastar con el mapa de estructura, nunca un veredicto/i)).toBeTruthy();
    expect(screen.getByText(/La compresión, el empaquetado y el cifrado se leen igual/i)).toBeTruthy();

    // The measurement did not move: two decimals, a dot, and the unit and threshold written as the code holds them.
    const summary = screen.getByText(/Media 6\.42 · Máx 7\.94/);
    expect(summary.textContent).toContain('7.2 bits/byte');

    // …and the axis is still hexadecimal byte offsets, which are notation and not prose.
    const text = container.textContent ?? '';
    expect(text).toContain('0x3000');
    expect(text).toContain('0x1800');

    expect(container.querySelector('svg')?.getAttribute('aria-label')).toBe(
      'Entropía a lo largo del desplazamiento de la imagen',
    );
  });
});

describe('StructureMap — a band is a signature match, not a verdict', () => {
  it('translates the prompt and the caveat while the carve itself renders as recorded', () => {
    setLocale('es');
    const { container } = render(<StructureMap segments={segments} size={SIZE} />);

    expect(screen.getByText('Pasa el cursor por un segmento para inspeccionarlo.')).toBeTruthy();
    expect(screen.getByText(/El tramo entre dos coincidencias está sin reclamar, no vacío/i)).toBeTruthy();

    // Categories are identifiers the signature engine decided; the ruler is notation. Neither is translated.
    expect(screen.getByText('filesystem')).toBeTruthy();
    expect(screen.getByText('bootloader')).toBeTruthy();
    expect(container.textContent).toContain('0x3000');
  });
});

describe('SbomGraph — no known CVE is not a cleared component', () => {
  it('says so in English, beside the legend that gives grey its name', () => {
    render(<SbomGraph sbom={sbom} />);

    expect(
      screen.getByText(/absence of a CVE here is absence of a match, not evidence that none exists/i),
    ).toBeTruthy();
    expect(screen.getByText('no CVE')).toBeTruthy();
  });

  it('keeps the caveat in Spanish while the package, its version and the CVE id stay verbatim', () => {
    setLocale('es');
    const { container } = render(<SbomGraph sbom={sbom} />);

    expect(screen.getByText(/no es lo mismo que un componente seguro/i)).toBeTruthy();
    expect(screen.getByText(/ausencia de coincidencia, no prueba de que no exista ninguno/i)).toBeTruthy();
    expect(screen.getByText('sin CVE')).toBeTruthy();
    expect(screen.getByText('1 de 2 componentes afectados · el tamaño del nodo = número de CVE')).toBeTruthy();

    // grype's severity vocabulary travels with the data and renders as grype wrote it, in either language.
    expect(screen.getByText('critical')).toBeTruthy();
    expect(screen.getByText('high')).toBeTruthy();

    // The hovered node's evidence: name, version and CVE id are the tool's output, never chrome. The vulnerable
    // component sorts first inside its ecosystem, so it is the first node circle drawn.
    const circles = container.querySelectorAll('circle');
    const first = circles[0];
    expect(first).toBeTruthy();
    if (first) fireEvent.mouseEnter(first);
    expect(screen.getByText('openssl')).toBeTruthy();
    expect(screen.getByText('1.0.2n')).toBeTruthy();
    expect(screen.getByText('CVE-2018-0737')).toBeTruthy();
  });

  it('names an unmatched component "sin CVE conocidos" rather than reporting it as clean', () => {
    setLocale('es');
    const { container } = render(<SbomGraph sbom={sbom} />);

    // busybox is the component nothing matched, so it sorts after openssl in the same ecosystem.
    const circles = container.querySelectorAll('circle');
    const second = circles[1];
    expect(second).toBeTruthy();
    if (second) fireEvent.mouseEnter(second);
    expect(screen.getByText('busybox')).toBeTruthy();
    expect(screen.getByText('sin CVE conocidos')).toBeTruthy();
  });
});

describe('SignalCanvas — the tape says what it does not show', () => {
  it('translates both refusals and agrees in gender and number with the marker count', async () => {
    setLocale('es');
    const { container } = render(
      <SignalCanvas imageId="img1" size={SIZE} findings={[finding('f1', 4096), finding('f2', 8192)]} />,
    );

    // Two markers: Spanish agrees twice in one clause, which is why the message is a function and not a template.
    expect(await screen.findByText('▲ 2 hallazgos anclados a su desplazamiento')).toBeTruthy();
    expect(screen.getByText(/es una pista que contrastar con la banda de estructura de debajo/i)).toBeTruthy();
    // The second refusal: a finding with no offset is not on the tape at all, so a clean stretch is not a cleared one.
    expect(screen.getByText(/un hallazgo sin desplazamiento no aparece en la cinta/i)).toBeTruthy();

    // The threshold and the axis are notation, and the accessible name is prose.
    const text = container.textContent ?? '';
    expect(text).toContain('7.2 bits/byte');
    expect(text).toContain('0x3000');
    expect(container.querySelector('svg')?.getAttribute('aria-label')).toBe('Cinta de señal del firmware');
  });

  it('agrees in the singular too, where English only drops an s', async () => {
    setLocale('es');
    render(<SignalCanvas imageId="img1" size={SIZE} findings={[finding('f1', 4096)]} />);

    expect(await screen.findByText('▲ 1 hallazgo anclado a su desplazamiento')).toBeTruthy();
  });
});
