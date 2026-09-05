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
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
  mockApi.coverage.mockResolvedValue({
    firmwareClass: 'embedded-linux',
    applicable: 12,
    executed: 10,
    findingCount: 1,
    stages: [],
    verdict: '1 finding across 10 of 12 stages',
    ambiguous: true,
  });
  mockApi.sbom.mockResolvedValue(null);
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

describe('ImageDetail agent session', () => {
  const session = {
    id: 'session-1',
    imageId: 'img1',
    status: 'done' as const,
    goal: null,
    budget: { maxSteps: 8, maxTokens: 250000, maxUsd: 1, maxWallMs: 900000 },
    consumed: { steps: 4, inputTokens: 12000, outputTokens: 8000, usd: 0.01, elapsedMs: 90000 },
    haltReason: null,
    createdAt: 1,
    updatedAt: 2,
  };

  beforeEach(() => {
    mockApi.agentConfig.mockResolvedValue({
      enabled: true,
      provider: 'deepseek',
      model: 'deepseek-v4-pro',
      approval: {
        key: 'FIRMLAB_AGENT_PREAPPROVE',
        preapproveAll: false,
        source: 'default',
        environmentValue: false,
      },
    });
  });

  it('renders the closing synthesis as Markdown and names 4/8 as an LLM-turn budget', async () => {
    mockApi.agentSession.mockResolvedValue({
      session,
      steps: [
        {
          seq: 1,
          node: 'synthesis',
          status: 'ok',
          input: null,
          output: { provider: 'deepseek', model: 'deepseek-v4-pro' },
          rationale:
            '## Risk summary\n\nReadable result.\n\n| Priority | Finding |\n|---|---|\n| 1 | `popen` reachable |',
          model: 'deepseek-v4-pro',
          inputTokens: 100,
          outputTokens: 200,
          reasoningTokens: 50,
          fallbackUsed: false,
          createdAt: 2,
        },
      ],
    });
    const { container } = renderSection('agent');

    expect(await screen.findByRole('heading', { name: 'Risk summary' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Priority' })).toBeInTheDocument();
    expect(screen.getByText('LLM turns')).toBeInTheDocument();
    expect(screen.getByText('4 / 8').parentElement?.title).toMatch(/budget, not a checklist/i);
    expect(container.querySelector('.md.agent-synthesis')).toBeTruthy();
    expect(container.textContent).not.toContain('## Risk summary');
  });

  it('offers one action that authorises every proposed emulation target', async () => {
    const awaiting = { ...session, status: 'awaiting_approval' as const };
    const steps = [
      {
        seq: 1,
        node: 'target-selection',
        status: 'ok',
        input: null,
        output: {
          emulationPlan: [
            { binary: 'bin/busybox', rung: 'qemu-user' },
            { binary: 'usr/bin/hostapd', rung: 'full-system' },
          ],
        },
        rationale: null,
        model: 'deepseek-v4-pro',
        inputTokens: 10,
        outputTokens: 10,
        reasoningTokens: 0,
        fallbackUsed: false,
        createdAt: 1,
      },
    ];
    mockApi.agentSession.mockResolvedValue({ session: awaiting, steps });
    mockApi.approveEmulation.mockResolvedValue({ session, steps });
    renderSection('agent');

    fireEvent.click(await screen.findByRole('button', { name: 'Approve all proposed runs' }));
    await waitFor(() => expect(mockApi.approveEmulation).toHaveBeenCalledWith('session-1', undefined, true));
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

describe('ImageDetail findings workflow', () => {
  it('shows the findings ledger before the secondary report builder', async () => {
    const { container } = renderSection('findings');
    expect((await screen.findAllByText(finding.title)).length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: 'Critical + high' })).toBeInTheDocument();
    expect(screen.getByText('Build an exportable report')).toBeInTheDocument();

    const ledger = container.querySelector('.findings-table');
    const report = container.querySelector('.report-disclosure');
    expect(ledger).toBeTruthy();
    expect(report).toBeTruthy();
    if (!ledger || !report) throw new Error('findings ledger and report disclosure must both render');
    expect(ledger.compareDocumentPosition(report) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect((report as HTMLDetailsElement).open).toBe(false);
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

/**
 * The online hash lookup. It was typed, produced, and read by nobody — so a hash that was never sent rendered
 * exactly like one that was checked and came back clean, on the highest-stakes finding class in the workbench.
 */
describe('ImageDetail — the password-hash lookup says what it refused to ask', () => {
  const research = (hashLookup: Record<string, unknown>) => ({
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
    hashLookup,
  });

  const entry = (o: Record<string, unknown>) => ({
    account: 'root',
    source: 'etc/shadow',
    scheme: 'md5crypt',
    ...o,
  });

  beforeEach(() => {
    mockApi.researchStatus.mockResolvedValue({ enabled: true });
    mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
  });

  it('does not let a hash that was NEVER SENT read like one that came back clean', async () => {
    mockApi.researchResult.mockResolvedValue(
      research({
        enabled: true,
        reason: 'Online hash lookup: 1 unsalted hash(es) queried, 0 recovered.',
        attempted: 1,
        resolved: 0,
        notQueried: 1,
        entries: [
          entry({ account: 'root', outcome: 'skipped_salted' }),
          entry({ account: 'admin', outcome: 'miss', manualLookupUrl: 'https://crackstation.net/' }),
        ],
      }),
    );
    const { container } = renderSection('dossier');

    // Two different labels for two different facts — the distinction the whole block exists for.
    expect(await screen.findByText('not sent (salted)')).toBeInTheDocument();
    expect(screen.getByText('no match')).toBeInTheDocument();
    // …and the sentence a pair of labels cannot carry alone.
    expect(container.textContent).toMatch(/refusal to ask, not an answer/i);
    // A miss must never be dressed as reassurance.
    expect(screen.getByTitle(/not evidence the password is strong/i)).toBeInTheDocument();
  });

  it('says the lane was off rather than rendering an empty list', async () => {
    // With FIRMLAB_HASH_LOOKUP unset nothing is asked at all, and an empty block would read as "nothing found".
    mockApi.researchResult.mockResolvedValue(
      research({ enabled: false, reason: '', attempted: 0, resolved: 0, notQueried: 0, entries: [] }),
    );
    const { container } = renderSection('dossier');
    await waitFor(() => expect(container.textContent).toMatch(/Password-hash lookup/));
    expect(container.textContent).toMatch(/the question was never put/i);
  });

  it('marks a recovered-and-verified password as the credential it is', async () => {
    mockApi.researchResult.mockResolvedValue(
      research({
        enabled: true,
        reason: 'r',
        attempted: 1,
        resolved: 1,
        notQueried: 0,
        entries: [entry({ outcome: 'resolved', passwordMasked: 'ad****' })],
      }),
    );
    renderSection('dossier');
    expect(await screen.findByText('recovered')).toBeInTheDocument();
    // The provider masks it; this screen never widens that.
    expect(screen.getByText('ad****')).toBeInTheDocument();
  });
});

/**
 * The denominators of the research lane, and its egress ledger.
 *
 * Both lanes count what they never asked about — `osv.skipped`, `nvd.notQueried` — and neither number reached
 * the screen, so "0 advisories" read as "there are none" when it meant "none among the ones we asked". The
 * egress ledger has the same shape of defect: `research/egress.ts` composes the privacy claim that justifies the
 * only internet-touching flag in the product, and nothing rendered it.
 */
describe('ImageDetail — what the research lane did not ask, and what it sent', () => {
  const base = (o: Record<string, unknown>) => ({
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
    osv: { queried: 3, skipped: 0, withAdvisories: 0, totalAdvisories: 0, components: [] },
    nvd: { queried: 0, notQueried: 0, withAdvisories: 0, totalAdvisories: 0, components: [] },
    kev: { checked: false, catalogSize: 0, matches: [] },
    keyMaterial: [],
    securityContacts: [],
    hashLookup: { enabled: false, reason: '', attempted: 0, resolved: 0, notQueried: 0, entries: [] },
    ...o,
  });

  const show = async (result: Record<string, unknown>) => {
    mockApi.researchStatus.mockResolvedValue({ enabled: true });
    mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
    mockApi.researchResult.mockResolvedValue(result as never);
    const rendered = renderSection('dossier');
    await screen.findByText(/OSV \d+ queried/);
    return rendered;
  };

  it('says how many components were never asked about at all', async () => {
    await show(base({ osv: { queried: 3, skipped: 5, withAdvisories: 0, totalAdvisories: 0, components: [] } }));
    expect(screen.getByText(/5 SBOM components could not be mapped to an OSV ecosystem/)).toBeInTheDocument();
    expect(screen.getByText(/does not cover them/)).toBeInTheDocument();
  });

  it('says the same for the NVD candidates a cap left unasked', async () => {
    await show(base({ nvd: { queried: 2, notQueried: 7, withAdvisories: 0, totalAdvisories: 0, components: [] } }));
    expect(screen.getByText(/7 candidates went unasked at NVD/)).toBeInTheDocument();
  });

  it('stays silent when nothing was skipped, rather than printing a zero', async () => {
    // A 0 here is a real measurement — everything was asked — and a line saying so is noise that dilutes the
    // lines that matter.
    await show(base({}));
    expect(screen.queryByText(/never asked about/)).not.toBeInTheDocument();
    expect(screen.queryByText(/went unasked at NVD/)).not.toBeInTheDocument();
  });

  it('renders the egress ledger: each destination, what goes there, and the ceiling', async () => {
    await show(
      base({
        egress: {
          destinations: [
            { host: 'api.osv.dev', sends: 'SBOM component names + versions (no bytes)', count: 12 },
            { host: 'www.cisa.gov', sends: 'nothing about your firmware — downloads the public KEV catalog', count: 0 },
          ],
          neverSent: ['raw firmware bytes / the image file', 'secret values, private keys'],
        },
      }),
    );
    expect(screen.getByText('api.osv.dev')).toBeInTheDocument();
    expect(screen.getByText('at most 12')).toBeInTheDocument();
    // A count of 0 is a DIRECTION, not a bound: the catalog comes in, nothing goes out.
    expect(screen.getByText('nothing about your firmware')).toBeInTheDocument();
    expect(screen.queryByText('at most 0')).not.toBeInTheDocument();
    expect(screen.getByText('raw firmware bytes / the image file')).toBeInTheDocument();
  });

  it('shows no egress block for a result stored before the ledger existed', async () => {
    await show(base({ egress: { destinations: [], neverSent: [] } }));
    expect(screen.queryByText('What this lookup sent, and where')).not.toBeInTheDocument();
  });
});

/**
 * The secrets panel, and the zero that used to read as a clean bill.
 *
 * The string walk runs from offset 0 upward and stops at its cap, so it truncates by FILE OFFSET — arrival order,
 * the one axis a bound in this codebase may not cut on silently. Measured on the deployed corpus before this
 * existed: the 106 MB GL.iNet image stopped at 11.0% of the file and the 34.5 MB Framework BIOS capsule at 92.5%,
 * and both rendered as "No secret-like strings detected in the raw image".
 */
describe('ImageDetail — a secrets result says what it covered, not that it is clean', () => {
  // The secrets section also mounts the deep scan; unstubbed it reaches the network and the subtree throws, which
  // renders BLANK — the failure mode that looks exactly like "this panel found nothing".
  beforeEach(() => {
    mockApi.gitleaks.mockResolvedValue(null);
  });

  const withScan = (scan: { matched: number; scannedBytes: number; totalBytes: number }, secrets: [] = []): void => {
    mockApi.analysis.mockResolvedValue({
      size: image.size,
      identity: image.identity,
      entropy: { windowSize: 4096, step: 4096, samples: [], mean: 6.1, max: 7.9, min: 0.2, highEntropyRegions: [] },
      signatures: [],
      structure: [],
      secrets,
      secretScan: scan,
    });
  };

  it('names the percentage it stopped at, and refuses the rest of the image outright', async () => {
    withScan({ matched: 0, scannedBytes: 11_000_000, totalBytes: 100_000_000 });
    renderSection('secrets');
    expect(await screen.findByText(/stopped at 11\.0% of the image/)).toBeTruthy();
    expect(screen.getByText(/says nothing whatever about the rest/)).toBeTruthy();
  });

  it('says an empty result is bounded by what the heuristic can see at all', async () => {
    withScan({ matched: 0, scannedBytes: 8 * 1024 * 1024, totalBytes: 8 * 1024 * 1024 });
    renderSection('secrets');
    // The zero has to carry the reason a compressed filesystem is invisible to this stage.
    expect(await screen.findByText(/cannot be found by this stage at all/)).toBeTruthy();
    // A complete walk must NOT print the partial banner — the branch where nothing is wrong.
    expect(screen.queryByText(/stopped at/)).toBeNull();
  });

  it('separates the listing cap, which examined what it dropped, from the walk, which did not', async () => {
    const many = Array.from({ length: 500 }, (_, i) => ({
      offset: i,
      value: `-----BEGIN RSA PRIVATE KEY----- ${i}`,
      secretKind: 'private-key',
      severity: 'critical' as const,
    }));
    mockApi.analysis.mockResolvedValue({
      size: image.size,
      identity: image.identity,
      entropy: { windowSize: 4096, step: 4096, samples: [], mean: 6.1, max: 7.9, min: 0.2, highEntropyRegions: [] },
      signatures: [],
      structure: [],
      secrets: many,
      secretScan: { matched: 900, scannedBytes: image.size, totalBytes: image.size },
    });
    renderSection('secrets');
    expect(await screen.findByText(/Showing the 500 highest-severity of 900 matches/)).toBeTruthy();
    expect(screen.getByText(/every one of the 900 was examined/)).toBeTruthy();
  });

  it('claims nothing at all when the coverage was never recorded', async () => {
    // An analysis persisted before `secretScan` existed. Absent is not "complete".
    renderSection('secrets');
    expect(await screen.findByText(/cannot be found by this stage at all/)).toBeTruthy();
    expect(screen.queryByText(/stopped at/)).toBeNull();
    expect(screen.queryByText(/highest-severity of/)).toBeNull();
  });

  it('states the bound in Spanish without letting it become a clean bill', async () => {
    setLocale('es');
    withScan({ matched: 0, scannedBytes: 11_000_000, totalBytes: 100_000_000 });
    renderSection('secrets');
    expect(await screen.findByText(/se detuvo en el 11\.0 % de la imagen/)).toBeTruthy();
    expect(screen.getByText(/no dice absolutamente nada del resto/)).toBeTruthy();
    // No switch back here: the global beforeEach sets English before the next render, and restoring it while this
    // tree is still mounted re-renders it outside act() — the very thing this file's header warns about.
  });
});

/**
 * The structure map draws from a BOUNDED signature list, and used to say nothing about it.
 *
 * Measured before the bound was reshaped: the 61.7 MB Obsbot image listed 5 000 of 32 372 matches and drew 4 325
 * of 29 408 segments. The list is still bounded now — what changed is that it can no longer lose a rule TYPE, so
 * the class and the filesystems are exact while the drawing stays a sample. Saying which is which matters in the
 * direction people get wrong: distrusting the class because the map is capped discards the one part that is sound.
 */
describe('ImageDetail — the structure map says it is a bounded sample', () => {
  const withSignatureScan = (scan: { matched: number; distinctIds: number } | undefined): void => {
    mockApi.analysis.mockResolvedValue({
      size: image.size,
      identity: image.identity,
      entropy: { windowSize: 4096, step: 4096, samples: [], mean: 6.1, max: 7.9, min: 0.2, highEntropyRegions: [] },
      signatures: [],
      structure: [{ start: 0, end: image.size, label: 'squashfs', category: 'filesystem', confidence: 'high' }],
      secrets: [],
      ...(scan ? { signatureScan: { hits: [], ...scan } } : {}),
    });
  };

  it('names how many of the matches it drew, and clears the identity of the same doubt', async () => {
    withSignatureScan({ matched: 32_372, distinctIds: 17 });
    renderSection('structure');
    expect(await screen.findByText(/Drawn from 0 of 32372 signature matches/)).toBeTruthy();
    expect(screen.getByText(/device class and the filesystems above are unaffected/)).toBeTruthy();
  });

  it('says nothing when the list was not bounded — the branch where the guard finds nothing wrong', async () => {
    mockApi.analysis.mockResolvedValue({
      size: image.size,
      identity: image.identity,
      entropy: { windowSize: 4096, step: 4096, samples: [], mean: 6.1, max: 7.9, min: 0.2, highEntropyRegions: [] },
      signatures: [],
      structure: [{ start: 0, end: image.size, label: 'squashfs', category: 'filesystem', confidence: 'high' }],
      secrets: [],
      signatureScan: { hits: [], matched: 0, distinctIds: 0 },
    });
    renderSection('structure');
    expect(await screen.findByText(/Structure map/)).toBeTruthy();
    expect(screen.queryByText(/bounded sample/)).toBeNull();
  });

  it('claims nothing when the count was never recorded', async () => {
    withSignatureScan(undefined);
    renderSection('structure');
    expect(await screen.findByText(/Structure map/)).toBeTruthy();
    expect(screen.queryByText(/bounded sample/)).toBeNull();
  });
});
