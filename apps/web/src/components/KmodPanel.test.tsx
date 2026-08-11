/**
 * The panel's job is to keep three silences legible, and each test below pins one of them. All three are real
 * states of the deployed corpus, not invented shapes: the WDR3600 has no `intree` tag on any of its 84 modules,
 * 73 of its 254 sink references are addresses the compiler parked rather than call sites, and its ledger carries
 * both a `static_confirmed` surface row and a `needs_runtime_reproduction` lead at once.
 */
import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type KmodResult, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { KmodPanel } from './KmodPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const result = (o: Partial<KmodResult> = {}): KmodResult => ({
  available: true,
  reason: '84 kernel module(s) read. NOT ONE module on this image carries an `intree` tag.',
  modulesFound: 84,
  notRelocatable: 0,
  symbolTableUnreadable: 0,
  provenance: { intreeTagInUse: false, licenceDeclared: true, note: 'tag unused' },
  callSitePass: { available: true, modulesExamined: 8, modulesDropped: [], sitesDropped: 0, sitesHoisted: 73 },
  modules: [
    {
      file: 'lib/modules/2.6.31/nas/NetUSB.ko',
      size: 250401,
      identity: {
        license: 'Proprietary',
        author: 'KCodes',
        versionCandidate: { value: '1.02.66', from: '1.02.66 TL-WDR3600' },
      },
      api: { socket: ['sock_create'], alloc: ['__kmalloc'] },
      keys: { nonGpl: true, socket: true, score: 14 },
      sites: [{ sink: '__kmalloc', addr: 0x8011968, fn: 'SoftwareBus_dispatchNormalEPMsgOut', evidence: null }],
    },
  ],
  findings: [
    {
      id: 'f1',
      kind: 'kernel-module-network-surface',
      title: 'Kernel module answers the network: NetUSB.ko 1.02.66',
      severity: 'high',
      proofState: 'static_confirmed',
      rationale: 'imports sock_create and allocates with __kmalloc.',
    },
    {
      id: 'f2',
      kind: 'kernel-module-wire-length-alloc',
      title: 'Byte-swapped length reaches __kmalloc unchecked in view: NetUSB.ko',
      severity: 'high',
      proofState: 'needs_runtime_reproduction',
      rationale: 'a value passes through a byte-order reversal.',
    },
  ] as KmodResult['findings'],
  ...o,
});

beforeEach(() => {
  setLocale('en');
});

describe('KmodPanel', () => {
  it('bounds every call-site row to the window it was read in, above the table', async () => {
    mockApi.kmod.mockResolvedValue(result());
    render(<KmodPanel imageId="img1" />);
    await waitFor(() =>
      expect(screen.getByText(/No comparison appears.*means none appears in the window/s)).toBeTruthy(),
    );
  });

  it('says the intree tag decides nothing when the image does not carry it', async () => {
    // Ranking silently by an absent signal is the defect this string exists to prevent. Matched on the clause
    // only the catalogue carries: the provider's own `reason` repeats the first half verbatim, so a looser
    // pattern matches twice and asserts nothing about which of the two is on screen.
    mockApi.kmod.mockResolvedValue(result());
    render(<KmodPanel imageId="img1" />);
    await waitFor(() =>
      expect(screen.getByText(/its absence is not evidence that a module is out-of-tree/)).toBeTruthy(),
    );
  });

  it('reports the parked-address references rather than letting them read as examined', async () => {
    mockApi.kmod.mockResolvedValue(result());
    render(<KmodPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/73 sink references were the place/)).toBeTruthy());
  });

  it('names the modules the budget did not reach instead of counting them', async () => {
    mockApi.kmod.mockResolvedValue(
      result({
        callSitePass: {
          available: true,
          modulesExamined: 8,
          modulesDropped: ['lib/modules/5.4.213/qca-mcs.ko'],
          sitesDropped: 0,
          sitesHoisted: 0,
        },
      }),
    );
    render(<KmodPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText('lib/modules/5.4.213/qca-mcs.ko')).toBeTruthy());
  });

  it('reports a missing disassembler as a gap, not as a clean sweep', async () => {
    mockApi.kmod.mockResolvedValue(
      result({
        callSitePass: {
          available: false,
          reason: 'radare2 (rabin2) is not installed in this deployment.',
          modulesExamined: 0,
          modulesDropped: [],
          sitesDropped: 0,
          sitesHoisted: 0,
        },
        findings: [],
      }),
    );
    render(<KmodPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/its absence is a gap rather than a clean result/)).toBeTruthy());
  });

  it('does not read a rootfs with no modules as a rootfs with nothing wrong', async () => {
    mockApi.kmod.mockResolvedValue(result({ modulesFound: 0, modules: [], findings: [] }));
    render(<KmodPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/A monolithic kernel with everything compiled in/)).toBeTruthy());
  });

  it('reads a failed request as "has not run", never as a clean result', async () => {
    mockApi.kmod.mockRejectedValue(new Error('boom'));
    render(<KmodPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/has not been run for this image/)).toBeTruthy());
  });
});
