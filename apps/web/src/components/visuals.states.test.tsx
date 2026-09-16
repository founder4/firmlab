/**
 * The four hand-rolled visuals under the states a fixture-shaped test never reaches: nothing to draw, HALF of
 * something to draw, and a hand on the mouse.
 *
 * `visuals.test.tsx` next door holds these same four to their translation contract — the sentence each picture
 * refuses to drop. This file is the other half of the same worry, and it is the half a green suite hides. A picture
 * is drawn from data, so what it does with data it does not have is a rendering decision nobody makes on purpose,
 * and three of the cases below were wrong:
 *
 *   • `SignalCanvas` kept its marker tally INSIDE the category-legend guard, so an image whose carve produced no
 *     categories drew its markers and then refused to count them — the count disappeared for exactly the image with
 *     least else to read;
 *   • the same tally counted only what it drew. Most findings on a real rootfs carry no byte offset, so «▲ 3
 *     findings pinned» is three out of forty, printed as if it were the ledger;
 *   • `SbomGraph` keyed CVEs by package name against a listing the provider caps at 500, so a Critical whose
 *     component fell outside the cut reached no node, no tooltip and no count, and «0 of 2 affected» was printed
 *     with that Critical in hand.
 *
 * The rule the three share, and what the assertions here are actually pinning: **a picture drawn from a subset must
 * say what the subset is measured against.** A count with no denominator is the same error as an empty findings list
 * read as «clean», one layer up in the stack.
 */
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type EntropyProfile, type Finding, type SbomResult, type SbomVuln, type StructureSegment, api } from '../api';
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

/** jsdom ships no `ResizeObserver`; without it the two measuring visuals throw and render BLANK. See `visuals.test`. */
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub);

const SIZE = 12_288;

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
  { start: 0, end: 4096, label: 'uImage header', category: 'bootloader', confidence: 'high', meta: { size: 4096 } },
  { start: 4096, end: SIZE, label: 'squashfs', category: 'filesystem', confidence: 'high' },
];

/** `offset: null` means the finding recorded no byte at all — the case the tape cannot draw. */
const finding = (id: string, offset: number | null): Finding => ({
  id,
  imageId: 'img1',
  source: 'binvuln',
  kind: 'weak_credential',
  title: `finding ${id}`,
  severity: 'high',
  proofState: 'static_confirmed',
  ...(offset === null ? {} : { evidence: { offset } }),
  createdAt: 1_700_000_000_000,
});

/**
 * jsdom gives every element a zero-size box, and both scrub handlers divide by that width — the readout is
 * `NaN`/`Infinity` without this, which is why neither had ever been exercised. 900 px is the width both components
 * assume when `ResizeObserver` never fires, so pixel and offset arithmetic below is the real arithmetic.
 */
function pinWidth(el: Element, width: number): void {
  el.getBoundingClientRect = () =>
    ({ left: 0, top: 0, right: width, bottom: 220, width, height: 220, x: 0, y: 0, toJSON: () => ({}) }) as DOMRect;
}

const sbomOf = (over: Partial<SbomResult>): SbomResult => ({
  available: true,
  target: 'squashfs-root',
  packageCount: 2,
  packages: [
    { name: 'busybox', version: '1.20.2', type: 'binary' },
    { name: 'zlib', version: '1.2.3', type: 'binary' },
  ],
  grypeAvailable: true,
  vulnerabilities: [],
  counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
  ...over,
});

beforeEach(() => {
  setLocale('en');
  mockApi.entropy.mockResolvedValue({ size: SIZE, entropy });
  mockApi.structure.mockResolvedValue({ size: SIZE, structure: segments, signatures: [] });
});

describe('EntropyChart — nothing measured, and a hand on the chart', () => {
  it('draws no trace and shades no band for a profile with no samples, and still carries the caveat', () => {
    const empty: EntropyProfile = { ...entropy, samples: [], highEntropyRegions: [], mean: 0, max: 0, min: 0 };
    const { container } = render(<EntropyChart entropy={empty} size={SIZE} />);

    // A zero-sample profile used to be the one input that could put a `M,` / `LNaN` path into the DOM.
    expect(container.querySelectorAll('path')).toHaveLength(0);
    expect(container.querySelectorAll('rect')).toHaveLength(0);
    // The grid, the 7.2 threshold and the offset ruler are chrome and survive an empty measurement.
    expect(container.querySelectorAll('line').length).toBeGreaterThan(0);
    expect(screen.getByText(/dashed line at 7.2 bits\/byte/)).toBeTruthy();
    expect(screen.getByText(/never a verdict/i)).toBeTruthy();
  });

  it('shades one band per recorded high-entropy region, measured against the image and not the samples', () => {
    const { container } = render(<EntropyChart entropy={entropy} size={SIZE} />);

    const shades = container.querySelectorAll('rect');
    expect(shades).toHaveLength(1);
    // 0x1000…0x3000 of a 0x3000 image: two thirds of the plot, offset by the left pad. The denominator is `size`.
    const plotW = 900 - 34 - 12;
    expect(Number(shades[0]?.getAttribute('x'))).toBeCloseTo(34 + (4096 / SIZE) * plotW, 3);
    expect(Number(shades[0]?.getAttribute('width'))).toBeCloseTo((1 - 4096 / SIZE) * plotW, 3);
  });

  it('replaces the summary with the nearest sample while scrubbing, and restores it outside the plot', () => {
    const { container } = render(<EntropyChart entropy={entropy} size={SIZE} />);
    const svg = container.querySelector('svg');
    expect(svg).toBeTruthy();
    if (!svg) return;
    pinWidth(svg, 900);

    fireEvent.mouseMove(svg, { clientX: 450 });
    expect(screen.getByText('offset 0x1000 · H = 7.94 bits/byte')).toBeTruthy();
    expect(screen.queryByText(/^Mean /)).toBeNull();

    // Left of the y-axis pad there is no plot, so there is nothing to report — the readout must not snap to sample 0.
    fireEvent.mouseMove(svg, { clientX: 10 });
    expect(screen.getByText(/^Mean 6\.42 · Max 7\.94/)).toBeTruthy();

    fireEvent.mouseMove(svg, { clientX: 450 });
    fireEvent.mouseLeave(svg);
    expect(screen.getByText(/^Mean 6\.42 · Max 7\.94/)).toBeTruthy();
  });

  it('scrubs from a touch as well as a pointer, which is the only input a phone has', () => {
    const { container } = render(<EntropyChart entropy={entropy} size={SIZE} />);
    const svg = container.querySelector('svg');
    expect(svg).toBeTruthy();
    if (!svg) return;
    pinWidth(svg, 900);

    fireEvent.touchStart(svg, { touches: [{ clientX: 880 }] });
    expect(screen.getByText('offset 0x2000 · H = 7.91 bits/byte')).toBeTruthy();
    fireEvent.touchMove(svg, { touches: [{ clientX: 450 }] });
    expect(screen.getByText('offset 0x1000 · H = 7.94 bits/byte')).toBeTruthy();
    fireEvent.touchEnd(svg);
    expect(screen.getByText(/^Mean 6\.42/)).toBeTruthy();
  });
});

describe('StructureMap — an empty carve, and what a band is a proportion OF', () => {
  it('renders the ruler, the prompt and the caveat with nothing carved, and draws no band', () => {
    const { container } = render(<StructureMap segments={[]} size={SIZE} />);

    expect(container.querySelectorAll('div[title]')).toHaveLength(0);
    expect(screen.getByText('Hover a segment to inspect it.')).toBeTruthy();
    expect(screen.getByText(/unclaimed, not empty/i)).toBeTruthy();
    // The ruler is the image, not the carve, so it still reads end to end with nothing on it.
    expect(screen.getByText('0x3000')).toBeTruthy();
  });

  it('sizes each band against the IMAGE, so a partial carve leaves the rest of the ribbon blank', () => {
    // Two segments covering 0x0…0x2000 of a 0x3000 image. Were the widths normalised over the drawn set instead,
    // they would come out 50/50 and the ribbon would claim a carve that reached the end of the image.
    const partial: StructureSegment[] = [
      { start: 0, end: 4096, label: 'uImage header', category: 'bootloader', confidence: 'high' },
      { start: 4096, end: 8192, label: 'squashfs', category: 'filesystem', confidence: 'high' },
    ];
    const { container } = render(<StructureMap segments={partial} size={SIZE} />);

    const widths = [...container.querySelectorAll('div[title]')].map((b) =>
      Number.parseFloat((b as HTMLElement).style.width),
    );
    expect(widths).toHaveLength(2);
    expect(widths[0]).toBeCloseTo(33.33, 1);
    expect(widths[1]).toBeCloseTo(33.33, 1);
    expect((widths[0] ?? 0) + (widths[1] ?? 0)).toBeLessThan(100);
  });

  it('swaps the prompt for the hovered segment and puts it back on the way out', () => {
    const { container } = render(<StructureMap segments={segments} size={SIZE} />);
    const bands = container.querySelectorAll('div[title]');
    expect(bands).toHaveLength(2);
    const header = bands[0];
    expect(header).toBeTruthy();
    if (!header) return;

    fireEvent.mouseEnter(header);
    expect(screen.getByText('uImage header')).toBeTruthy();
    expect(screen.getByText('0x0 – 0x1000 · 4.0 KB')).toBeTruthy();
    // The decoded header fields are what the carve read out of the bytes, and they render as recorded.
    expect(screen.getByText('size=')).toBeTruthy();
    expect(screen.getByText('4096')).toBeTruthy();
    expect(screen.queryByText('Hover a segment to inspect it.')).toBeNull();

    fireEvent.mouseLeave(header);
    expect(screen.getByText('Hover a segment to inspect it.')).toBeTruthy();
  });
});

describe('SignalCanvas — the marker tally and its denominator', () => {
  it('counts the markers it drew even when the carve produced no categories at all', async () => {
    // The legend only exists once the carve found a category, and the tally used to live inside it. An image with
    // no segments is the one that leans hardest on the markers, and it was the one that lost the count.
    mockApi.structure.mockResolvedValue({ size: SIZE, structure: [], signatures: [] });
    const { container } = render(
      <SignalCanvas imageId="img1" size={SIZE} findings={[finding('a', 4096), finding('b', 8192)]} />,
    );

    expect(await screen.findByText('▲ 2 findings pinned to offsets')).toBeTruthy();
    expect(container.querySelectorAll('polygon')).toHaveLength(2);
  });

  it('states how many findings carry no offset, because those are the ones it cannot draw', async () => {
    render(
      <SignalCanvas
        imageId="img1"
        size={SIZE}
        findings={[finding('a', 4096), finding('b', null), finding('c', null)]}
      />,
    );

    expect(await screen.findByText('▲ 1 finding pinned to offsets')).toBeTruthy();
    expect(screen.getByText('2 more carry no offset and are not drawn')).toBeTruthy();
  });

  it('prints a zero rather than nothing when not one finding could be placed', async () => {
    render(<SignalCanvas imageId="img1" size={SIZE} findings={[finding('a', null), finding('b', null)]} />);

    // An empty gutter with no sentence beside it reads as "no findings". It is "no findings WITH AN OFFSET".
    expect(await screen.findByText('▲ 0 findings pinned to offsets')).toBeTruthy();
    expect(screen.getByText('2 more carry no offset and are not drawn')).toBeTruthy();
  });

  it('agrees in the singular, where one dropped finding is not "1 more carry"', async () => {
    setLocale('es');
    render(<SignalCanvas imageId="img1" size={SIZE} findings={[finding('a', 4096), finding('b', null)]} />);

    expect(await screen.findByText('▲ 1 hallazgo anclado a su desplazamiento')).toBeTruthy();
    expect(screen.getByText('1 más sin desplazamiento, que no se dibuja en la cinta')).toBeTruthy();
  });

  it('says nothing about markers when there are no findings to have an opinion about', async () => {
    render(<SignalCanvas imageId="img1" size={SIZE} findings={[]} />);

    await screen.findByText(/a finding with no offset is not on the tape at all/i);
    expect(screen.queryByText(/pinned to offsets/)).toBeNull();
    expect(screen.queryByText(/carry no offset/)).toBeNull();
  });

  it('reads out the offset, the local entropy, the segment and the finding under the cursor', async () => {
    const onScrub = vi.fn();
    const { container } = render(
      <SignalCanvas imageId="img1" size={SIZE} findings={[finding('a', 4096)]} onScrub={onScrub} />,
    );
    await screen.findByText('▲ 1 finding pinned to offsets');

    const wrap = container.querySelector('svg')?.parentElement;
    expect(wrap).toBeTruthy();
    if (!wrap) return;
    pinWidth(wrap, 900);

    // 0x1000 of a 0x3000 image lands a third of the way across a 900 px tape.
    fireEvent.mouseMove(wrap, { clientX: 300 });
    expect(screen.getByText('0x1000')).toBeTruthy();
    expect(screen.getByText('H 7.94 bits')).toBeTruthy();
    expect(screen.getByText('squashfs')).toBeTruthy();
    expect(screen.getByText('● finding a')).toBeTruthy();
    // The scrubbed offset is lifted to the parent as BYTES, not pixels — the lenses above read it as an offset.
    expect(onScrub).toHaveBeenLastCalledWith(4096);

    fireEvent.mouseLeave(wrap);
    expect(onScrub).toHaveBeenLastCalledWith(null);
    expect(screen.queryByText('H 7.94 bits')).toBeNull();
  });

  it('still draws the markers and the caveat when both analysis fetches fail', async () => {
    // Both calls are caught and flattened to null, so a dead endpoint and a featureless image render identically —
    // what must not also disappear is the part that does not come from the API at all.
    mockApi.entropy.mockRejectedValue(new Error('entropy 500'));
    mockApi.structure.mockRejectedValue(new Error('structure 500'));
    const { container } = render(<SignalCanvas imageId="img1" size={SIZE} findings={[finding('a', 4096)]} />);

    expect(await screen.findByText('▲ 1 finding pinned to offsets')).toBeTruthy();
    expect(container.querySelectorAll('polygon')).toHaveLength(1);
    expect(container.querySelectorAll('path')).toHaveLength(0);
    expect(screen.getByText(/a finding with no offset is not on the tape at all/i)).toBeTruthy();
  });
});

describe('SbomGraph — the components a CVE can miss, and the matcher that never ran', () => {
  it('names the CVEs whose component is not in the listing instead of dropping them', () => {
    // `packages` is capped at 500 and the inventory and the matcher need not agree on a name, so a match can land
    // on nothing this ring draws. Silently, a Critical then exists in the result and nowhere in the picture.
    const sbom = sbomOf({
      vulnerabilities: [
        { id: 'CVE-2999-0001', severity: 'Critical', packageName: 'openssl', packageVersion: '1.0.2n', fixedIn: null },
        { id: 'CVE-2999-0002', severity: 'High', packageName: 'openssl', packageVersion: '1.0.2n', fixedIn: null },
      ],
      counts: { Critical: 1, High: 1, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
    });
    render(<SbomGraph sbom={sbom} />);

    expect(screen.getByText('2 CVEs match 1 component not in this listing — off the graph')).toBeTruthy();
    // …and the ring is still honest about the components it DOES draw, which none of those CVEs touched.
    expect(screen.getByText('0 of 2 components affected · node size = CVE count')).toBeTruthy();
  });

  it('keeps quiet when every CVE found its component', () => {
    const sbom = sbomOf({
      vulnerabilities: [
        { id: 'CVE-2999-0003', severity: 'High', packageName: 'busybox', packageVersion: '1.20.2', fixedIn: null },
      ],
      counts: { Critical: 0, High: 1, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
    });
    render(<SbomGraph sbom={sbom} />);

    expect(screen.queryByText(/off the graph/)).toBeNull();
    expect(screen.getByText('1 of 2 components affected · node size = CVE count')).toBeTruthy();
  });

  it('refuses to report "0 of 2 affected" when this deployment has no CVE matcher', () => {
    // Absence of the tool is not absence of a problem. A grey ring under a count of zero is the exact shape of the
    // claim the workbench exists to refuse, and the count is a measurement that never happened.
    render(<SbomGraph sbom={sbomOf({ grypeAvailable: false })} />);

    expect(screen.queryByText(/components affected/)).toBeNull();
    expect(screen.getByText('2 components inventoried · no CVE matcher: this is not a count of zero')).toBeTruthy();
  });

  it('translates that refusal rather than falling back to the affected count', () => {
    setLocale('es');
    render(<SbomGraph sbom={sbomOf({ grypeAvailable: false })} />);

    expect(
      screen.getByText('2 componentes inventariados · sin motor de CVE: esto no es un recuento de cero'),
    ).toBeTruthy();
    expect(screen.queryByText(/componentes afectados/)).toBeNull();
  });

  it('bounds the tooltip CVE list and says by how much, rather than ending at six', () => {
    const many: SbomVuln[] = Array.from({ length: 9 }, (_, i) => ({
      id: `CVE-2999-10${i}`,
      severity: 'High',
      packageName: 'busybox',
      packageVersion: '1.20.2',
      fixedIn: null,
    }));
    const { container } = render(
      <SbomGraph
        sbom={sbomOf({
          vulnerabilities: many,
          counts: { Critical: 0, High: 9, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
        })}
      />,
    );

    const first = container.querySelectorAll('circle')[0];
    expect(first).toBeTruthy();
    if (!first) return;
    fireEvent.mouseEnter(first);

    expect(
      screen.getByText(/CVE-2999-100, CVE-2999-101, CVE-2999-102, CVE-2999-103, CVE-2999-104, CVE-2999-105 \+3/),
    ).toBeTruthy();
  });

  it('counts a component whose severity word is outside the legend, instead of under-reporting it', () => {
    // grype also emits `Negligible` and `Unknown`, and neither has a legend swatch. A node the legend cannot
    // colour is still a node something matched, and dropping it from the tally would make the stricter reading the
    // smaller number.
    const sbom = sbomOf({
      vulnerabilities: [
        { id: 'CVE-2999-0004', severity: 'Negligible', packageName: 'zlib', packageVersion: '1.2.3', fixedIn: null },
      ],
      counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 1, Unknown: 0 },
    });
    render(<SbomGraph sbom={sbom} />);

    expect(screen.getByText('1 of 2 components affected · node size = CVE count')).toBeTruthy();
  });
});

describe('every visual carries an accessible name, which is all a screen reader gets from an SVG', () => {
  it('names the entropy chart, the signal tape and the SBOM graph', async () => {
    const { unmount } = render(<EntropyChart entropy={entropy} size={SIZE} />);
    expect(screen.getByRole('img', { name: 'Entropy across the image offset' })).toBeTruthy();
    unmount();

    const tape = render(<SignalCanvas imageId="img1" size={SIZE} findings={[]} />);
    // `<title>` is the accessible name an SVG gets without `role="img"`; both visuals ship one.
    expect(await screen.findByTitle('Firmware signal tape')).toBeTruthy();
    tape.unmount();

    render(<SbomGraph sbom={sbomOf({})} />);
    expect(screen.getByTitle('SBOM component graph')).toBeTruthy();
  });
});
