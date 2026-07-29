/**
 * ImageDetail — the localisation contract of the workbench's densest screen.
 *
 * Three things are asserted, and each of them is a rule that has to hold in both languages at once:
 *
 *   1. **The section title comes from the shared catalogue.** The screen used to carry a `SECTION_TITLES` map beside
 *      the `sections` namespace, which is the same list written twice; the test pins the heading to the catalogue so
 *      a second copy cannot come back unnoticed.
 *   2. **Chrome translates, evidence does not.** A finding's title is what a provider recorded and it renders as
 *      recorded, in Spanish too. A test that only checked "the page is in Spanish" would pass just as happily on a
 *      build that had helpfully translated the evidence.
 *   3. **A proof state prints its CODE and a localised gloss.** `confirmed_in_emulation` is an identifier that
 *      crosses the API and lands in SQLite, so it renders verbatim; the sentence beside it is the load-bearing part
 *      and it must still say, in Spanish, that emulation proves the sandbox and NEVER the physical device.
 *
 * What this does not claim: it exercises a slice, not the whole screen. The property that a missing Spanish key is
 * a COMPILE error lives in the type system, and `i18n.test.ts` covers the catalogues' structural equality.
 */
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type Finding, type ImageSummary, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { ImageDetail } from './ImageDetail';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

/**
 * jsdom ships no `ResizeObserver`, and the dossier's `SignalCanvas` measures its wrapper with one. Without this the
 * whole subtree throws during commit and renders BLANK — the failure mode that looks exactly like "this panel has
 * no data", so it is stubbed rather than tolerated.
 */
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub);

const image: ImageSummary = {
  id: 'img1',
  filename: 'router-fw.bin',
  size: 8 * 1024 * 1024,
  sha256: 'a'.repeat(64),
  uploadedAt: 1_700_000_000_000,
  status: 'ready',
  identity: {
    firmwareClass: 'embedded-linux',
    arch: 'mips',
    endianness: 'big',
    filesystems: ['squashfs'],
  },
  tags: [],
};

/** A stored finding: its title and rationale are evidence a provider wrote, not chrome. */
const finding: Finding = {
  id: 'f1',
  imageId: 'img1',
  source: 'binvuln',
  kind: 'weak_credential',
  title: 'Hardcoded root password in /etc/shadow',
  severity: 'high',
  proofState: 'static_confirmed',
  rationale: 'The hash is present in the extracted rootfs.',
  createdAt: 1_700_000_000_000,
};

function renderSection(section: string): ReturnType<typeof render> {
  return render(
    <MemoryRouter initialEntries={[`/image/img1/${section}`]}>
      <Routes>
        <Route path="/image/:id/:section" element={<ImageDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  // Before the render, never in an afterEach: the locale store notifies live subscribers, so switching a mounted
  // tree back to English at teardown re-renders it outside act() and fills the suite with warnings.
  setLocale('en');

  mockApi.getImage.mockResolvedValue(image);
  mockApi.analysis.mockResolvedValue({
    size: image.size,
    identity: image.identity,
    entropy: { windowSize: 4096, step: 4096, samples: [], mean: 6.1, max: 7.9, min: 0.2, highEntropyRegions: [] },
    signatures: [],
    structure: [
      { start: 0, end: 1024, label: 'uImage header', category: 'header', confidence: 'high' },
      { start: 1024, end: image.size, label: 'squashfs', category: 'filesystem', confidence: 'high' },
    ],
    secrets: [],
  });

  // StepTimeline + the dossier both read these; every one is stubbed so nothing reaches the network.
  mockApi.jobs.mockResolvedValue([]);
  mockApi.findings.mockResolvedValue([finding]);
  mockApi.emulation.mockResolvedValue({
    identity: image.identity,
    rootfsReady: true,
    suggestedBinary: null,
    recipes: [],
    capabilities: {
      arch: 'mips',
      firmwareClass: 'embedded-linux',
      hasRootfs: true,
      userEmulator: 'qemu-mips',
      systemEmulator: null,
      strategy: 'qemu-user',
      proofCeiling: 'confirmed_in_emulation',
      reason: 'qemu-mips is present, so a binary can be run under user-mode emulation.',
    },
  });
  mockApi.agentStatus.mockResolvedValue({ enabled: false });
  mockApi.copilotResult.mockResolvedValue(null);
  mockApi.binaries.mockResolvedValue([]);
  mockApi.corpusRefs.mockResolvedValue({ credentials: [], components: [], artifacts: [] });
  mockApi.researchStatus.mockResolvedValue({ enabled: false });
  mockApi.researchResult.mockResolvedValue(null);
  mockApi.entropy.mockResolvedValue({ size: image.size, entropy: { samples: [] } });
  mockApi.structure.mockResolvedValue({ size: image.size, structure: [] });
});

describe('ImageDetail section heading', () => {
  it('names the section from the shared catalogue rather than a second map of its own', async () => {
    renderSection('structure');
    expect(await screen.findByRole('heading', { level: 1, name: 'Structure' })).toBeTruthy();
    // The panel needs the analysis bundle; awaiting it settles the second load inside the test.
    expect(await screen.findByText(/2 segments/)).toBeTruthy();
  });

  it('reads the same section id out of the Spanish catalogue, leaving the route segment alone', async () => {
    setLocale('es');
    renderSection('structure');
    expect(await screen.findByRole('heading', { level: 1, name: 'Estructura' })).toBeTruthy();
    expect(await screen.findByText(/2 segmentos/)).toBeTruthy();
  });

  it('falls back to the dossier for a section id it does not serve, instead of a blank title', async () => {
    renderSection('not-a-section');
    expect(await screen.findByRole('heading', { level: 1, name: 'General' })).toBeTruthy();
    await waitFor(() => expect(screen.getByText('Coverage')).toBeTruthy());
  });
});

describe('ImageDetail export links', () => {
  it('asks the API for the report in the language the workbench is being read in', async () => {
    setLocale('es');
    renderSection('structure');

    const report = await screen.findByRole('link', { name: /Informe/ });
    const disclosure = await screen.findByRole('link', { name: /Divulgación/ });
    expect(report.getAttribute('href')).toBe('/api/images/img1/report?lang=es');
    expect(disclosure.getAttribute('href')).toBe('/api/images/img1/disclosure-report?lang=es');

    // No filename is asserted here: the server's content-disposition carries the locale suffix, and a hardcoded
    // `download="…"` would override it and let two languages of one report overwrite each other.
    expect(report.getAttribute('download')).toBe('');
    expect(await screen.findByText(/2 segmentos/)).toBeTruthy();
  });
});

describe('ImageDetail in Spanish', () => {
  it('translates the chrome and leaves a stored finding title exactly as the provider recorded it', async () => {
    setLocale('es');
    renderSection('dossier');

    // Chrome: panel titles and stat labels are ours to translate.
    expect(await screen.findByText('Cinta de señal')).toBeTruthy();
    expect(await screen.findByText('Cobertura')).toBeTruthy();
    expect(screen.getByText('Hallazgos')).toBeTruthy();

    // Evidence: the API wrote this title, and it renders as recorded — in either language.
    expect(await screen.findByText(finding.title)).toBeTruthy();
  });

  it('prints the proof-state CODE verbatim and glosses it in Spanish, sandbox caveat intact', async () => {
    setLocale('es');
    renderSection('dossier');

    // The code is an identifier: it crosses the API and lands in SQLite, so it is never translated.
    const code = await screen.findByText('confirmed_in_emulation');
    expect(code.className).toContain('mono');

    // …and the gloss beside it comes from the shared proofState namespace, not from a second copy here.
    expect(screen.getByText('confirmado (emulado)')).toBeTruthy();
    expect(screen.getByText(/Techo de prueba/)).toBeTruthy();

    // The claim the gloss must never soften: emulation proves the sandbox, never the physical device.
    const chip = screen.getByTitle(/nunca el dispositivo físico/);
    expect(chip.textContent).toContain('confirmed_in_emulation');
  });
});

/**
 * Both LLM lanes on this screen hand back Markdown, and both used to show it as its source. The assertion is not
 * "it looks nicer" — it is that no `##`/`**` reaches the reader and that a citation is a link they can follow.
 */
describe('ImageDetail — the prose the LLM lanes return', () => {
  it('renders the copilot interpretation as structure, not as its Markdown source', async () => {
    mockApi.agentStatus.mockResolvedValue({ enabled: true, provider: 'deepseek', model: 'deepseek-v4-flash' });
    mockApi.copilotResult.mockResolvedValue({
      text: '## Reading\n\nThe **root** account has `no password` — see [NVD](https://nvd.nist.gov/x).',
      model: 'deepseek-v4-flash',
      provider: 'deepseek',
    });
    const { container } = renderSection('dossier');

    await waitFor(() => expect(container.querySelector('.md.copilot-output')).toBeTruthy());
    const md = container.querySelector('.md.copilot-output');
    expect(md?.querySelector('h3')?.textContent).toBe('Reading');
    expect(md?.querySelector('strong')?.textContent).toBe('root');
    expect(md?.querySelector('code')?.textContent).toBe('no password');
    expect(md?.querySelector('a')?.getAttribute('href')).toBe('https://nvd.nist.gov/x');
    expect(md?.textContent).not.toContain('**');
    expect(md?.textContent).not.toContain('##');
  });

  it('renders the research brief the same way, and refuses its `#` citation as a link', async () => {
    mockApi.researchStatus.mockResolvedValue({ enabled: true });
    // The research panel carries a RunHistory, which is the only thing on this screen that asks for the ledger.
    mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
    mockApi.researchResult.mockResolvedValue({
      enabled: true,
      provenance: {
        identity: { firmwareClass: 'embedded-linux', arch: 'mips', bootloader: null },
        vendors: [],
        models: [],
        versions: [],
        urls: [],
        domains: [],
        certCNs: [],
        banners: [],
      },
      egress: { destinations: [], neverSent: [] },
      osv: { queried: 0, skipped: 0, withAdvisories: 0, totalAdvisories: 0, components: [] },
      nvd: { queried: 0, notQueried: 0, withAdvisories: 0, totalAdvisories: 0, components: [] },
      kev: { checked: false, catalogSize: 0, matches: [] },
      keyMaterial: [],
      securityContacts: [],
      hashLookup: { enabled: false, reason: '', attempted: 0, resolved: 0, notQueried: 0, entries: [] },
      synthesis: {
        text: '### Priority\n\n- `CVE-2022-48174` — busybox [[OSV](#)] [[NVD](https://nvd.nist.gov/y)]',
        model: 'deepseek-v4-flash',
        provider: 'deepseek',
      },
    });
    const { container } = renderSection('dossier');

    await waitFor(() => expect(container.querySelector('.md')).toBeTruthy());
    const md = container.querySelector('.md');
    expect(md?.querySelector('h4')?.textContent).toBe('Priority');
    expect(md?.querySelector('li code')?.textContent).toBe('CVE-2022-48174');
    // Exactly one anchor: `#` is a route change under HashRouter, so it stays inert label text.
    const links = md?.querySelectorAll('a') ?? [];
    expect(links).toHaveLength(1);
    expect(links[0]?.getAttribute('href')).toBe('https://nvd.nist.gov/y');
    expect(md?.textContent).toContain('[OSV]');
  });
});
