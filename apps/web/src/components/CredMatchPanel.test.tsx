/**
 * The panel exists to keep four run states and three per-hash outcomes legible, and each test below pins one. The
 * shapes are the provider's real ones: a recovered root password is `static_confirmed` and carries its plaintext, a
 * miss is a bounded negative that must never read as a clean bill, a scheme this build cannot compute is blocked,
 * and a rootfs-gate refusal is a prerequisite rather than a result about the firmware.
 */
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CredMatchResult, type CredMatchTarget, api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { mockedApi } from '../test-api-mock';
import { CredMatchPanel } from './CredMatchPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const summary = {
  root: '/data/extract/img1/rootfs',
  filesFound: 812,
  filesRead: 640,
  filesTooLarge: 0,
  filesUnreadable: 0,
  dirsUnreadable: 0,
  deepDirsSkipped: 0,
  bytesRead: 1_200_000,
  stringsHarvested: 9001,
  candidatesDistinct: 4200,
  candidatesTested: 4200,
  candidatesDropped: 0,
  cap: 200_000,
  capRule: 'no cap',
  minStringLength: 3,
  maxCandidateLength: 128,
};

const scanned = (targets: CredMatchTarget[], over: Partial<CredMatchResult> = {}): CredMatchResult => ({
  available: true,
  state: 'scanned',
  reason: '1 password recovered from 2 stored hashes.',
  candidates: summary,
  targets,
  openssl: { available: true, verifiedFlags: ['-1', '-6'], failures: [] },
  ...over,
});

beforeEach(() => {
  setLocale('en');
  // RunHistory reads the same ledger; keep it inert so it never counts as an unmocked call.
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
});

describe('CredMatchPanel', () => {
  it('reads no prior run as "has not run", never as a clean result', async () => {
    mockApi.credmatchResult.mockResolvedValue(null);
    render(<CredMatchPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(en.credmatch.notRun)).toBeTruthy());
  });

  it('shows a recovered root password as static_confirmed and never as a live login', async () => {
    mockApi.credmatchResult.mockResolvedValue(
      scanned([
        {
          account: 'root',
          uid: 0,
          file: 'etc/shadow',
          scheme: 'md5crypt',
          schemeLabel: 'md5crypt ($1$)',
          hashRedacted: '$1$……',
          locked: false,
          result: {
            outcome: 'recovered',
            password: 'admin1234',
            candidate: {
              value: 'admin1234',
              derivation: 'assignment-value',
              key: 'PASSWD',
              file: 'etc/init.d/rcS',
              offset: 0x1f4,
            },
            tested: 4200,
          },
        },
      ]),
    );
    render(<CredMatchPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText('admin1234')).toBeTruthy());
    // The proof-state code renders verbatim and the ceiling that keeps a hit below a live login is on screen.
    expect(screen.getAllByText('static_confirmed').length).toBeGreaterThan(0);
    expect(screen.getByText(new RegExp(en.credmatch.recoveredCeiling.slice(0, 40)))).toBeTruthy();
  });

  it('keeps a miss reading as a bounded negative, not a clean bill', async () => {
    mockApi.credmatchResult.mockResolvedValue(
      scanned([
        {
          account: 'admin',
          uid: 1000,
          file: 'etc/shadow',
          scheme: 'sha512crypt',
          schemeLabel: 'sha512crypt ($6$)',
          hashRedacted: '$6$……',
          locked: false,
          result: { outcome: 'not-recovered', tested: 4200, collapsed: 4200 },
        },
      ]),
    );
    render(<CredMatchPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/4200 candidates .* did not reproduce this hash/)).toBeTruthy());
    expect(screen.getByText(new RegExp(en.credmatch.emptyNotClean.slice(0, 40)))).toBeTruthy();
  });

  it('records an uncomputable scheme as blocked_by_platform, not as a hash that held', async () => {
    mockApi.credmatchResult.mockResolvedValue(
      scanned(
        [
          {
            account: 'svc',
            uid: 500,
            file: 'etc/shadow',
            scheme: 'yescrypt',
            schemeLabel: 'yescrypt ($y$)',
            hashRedacted: '$y$……',
            locked: false,
            result: { outcome: 'blocked', reason: 'this build’s `openssl passwd` does not support yescrypt' },
          },
        ],
        { openssl: { available: true, verifiedFlags: ['-1'], failures: [] } },
      ),
    );
    render(<CredMatchPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/does not support yescrypt/)).toBeTruthy());
    expect(screen.getAllByText('blocked_by_platform').length).toBeGreaterThan(0);
  });

  it('says openssl is missing rather than reporting non-DES hashes as clean', async () => {
    mockApi.credmatchResult.mockResolvedValue(
      scanned([], { openssl: { available: false, verifiedFlags: [], failures: [] } }),
    );
    render(<CredMatchPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(new RegExp(en.credmatch.opensslMissing.slice(0, 40)))).toBeTruthy());
  });

  it('renders a run blocked before hashing as a question asked and not answered', async () => {
    mockApi.credmatchResult.mockResolvedValue({
      available: false,
      state: 'no_hashes',
      reason: 'etc/shadow and etc/passwd were read and hold no testable password hash',
      candidates: null,
      targets: [],
      openssl: { available: false, verifiedFlags: [], failures: [] },
    });
    render(<CredMatchPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(en.credmatch.blockedHeading)).toBeTruthy());
    expect(screen.getByText(/hold no testable password hash/)).toBeTruthy();
    expect(screen.getByText(new RegExp(en.credmatch.blockedCaveat.slice(0, 30)))).toBeTruthy();
  });

  it('surfaces a rootfs-gate refusal as a prerequisite, not a transport error', async () => {
    mockApi.credmatchResult.mockResolvedValue(null);
    // The gate's sentence is the whole answer; `post` throws it as an Error.
    const gate =
      'Extraction ran, completed, and found no Linux rootfs in this image, so the credential cross-reference has nothing to read.';
    mockApi.runCredmatch.mockRejectedValue(new Error(gate));
    render(<CredMatchPanel imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: en.credmatch.run }));
    await waitFor(() => expect(screen.getByText(en.credmatch.prereqHeading)).toBeTruthy());
    expect(screen.getByText(gate)).toBeTruthy();
    // A prerequisite is not a bench fault: the run-failed heading must not appear for a gate refusal.
    expect(screen.queryByText(en.credmatch.runFailedHeading)).toBeNull();
  });

  it('labels a job that started and errored as a bench fault, not a prerequisite', async () => {
    mockApi.credmatchResult.mockResolvedValue(null);
    mockApi.runCredmatch.mockResolvedValue({ jobId: 'job1' });
    mockApi.job.mockResolvedValue({
      id: 'job1',
      imageId: 'img1',
      kind: 'credmatch',
      status: 'error',
      createdAt: 0,
      updatedAt: 0,
      params: {},
      log: 'credmatch: openssl probe crashed',
      result: null,
      error: 'openssl exited 139 (segfault)',
    });
    render(<CredMatchPanel imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: en.credmatch.run }));
    await waitFor(() => expect(screen.getByText(en.credmatch.runFailedHeading)).toBeTruthy());
    expect(screen.getByText(/openssl exited 139/)).toBeTruthy();
    expect(screen.queryByText(en.credmatch.prereqHeading)).toBeNull();
  });

  it('renders the Spanish copy without leaking English', async () => {
    setLocale('es');
    mockApi.credmatchResult.mockResolvedValue(null);
    render(<CredMatchPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/no se ha ejecutado ningún cotejo/i)).toBeTruthy());
    setLocale('en');
  });
});
