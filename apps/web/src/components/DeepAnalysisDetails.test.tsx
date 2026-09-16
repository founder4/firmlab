/**
 * DeepAnalysisDetails, on a DOM.
 *
 * This component is the one place where EVERY provider's persisted result is re-read by a build that may not be the
 * one that wrote it, so its whole contract is defensive: a field that is missing renders as `—` or "not recorded",
 * never as a zero or a blank, and a payload whose shape predates the renderer must not throw. The cases below are
 * chosen for the readings that would be wrong rather than merely ugly — a device-tree run that completed and found
 * nothing versus one that never ran, a command line only a branch assembles, a verifier reached through a shell
 * command, and a bound stated as a fraction of what was opened.
 */
import { render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { setLocale } from '../i18n';
import { DeepAnalysisDetails } from './DeepAnalysisDetails';

beforeEach(() => setLocale('en'));

describe('DeepAnalysisDetails', () => {
  it('renders sparse persisted kernel results without inventing missing measurements', () => {
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="kernel"
        value={{
          version: '5.10.0',
          answers: [{ id: 'aslr', option: 'CONFIG_RANDOMIZE_BASE', question: 'Kernel ASLR?', verdict: 'unknown' }],
        }}
      />,
    );

    expect(screen.getByText('5.10.0')).toBeInTheDocument();
    expect(screen.getByText('CONFIG_RANDOMIZE_BASE')).toBeInTheDocument();
    expect(screen.getByText('unknown')).toHaveClass('run-blocked');
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
  });

  it('keeps finding proof codes and provider titles verbatim', () => {
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="services"
        value={{
          services: [],
          findings: [
            {
              kind: 'network-service',
              title: 'telnetd listens on the LAN',
              severity: 'high',
              proofState: 'needs_runtime_reproduction',
            },
          ],
        }}
      />,
    );

    const card = screen.getByText('telnetd listens on the LAN').closest('.deep-data-card');
    expect(card).not.toBeNull();
    expect(within(card as HTMLElement).getByText('high')).toBeInTheDocument();
    expect(within(card as HTMLElement).getByText('needs_runtime_reproduction')).toHaveClass('mono');
  });

  it('reports component-list bounds and links to the dedicated graph', () => {
    const orphanBinaries = Array.from({ length: 23 }, (_, index) => `bin/orphan-${index}`);
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="compmap"
        value={{
          binaryCount: 30,
          elfCount: 40,
          symlinkCount: 2,
          orphanBinaries,
          graph: { edges: [{ from: 'a', to: 'b' }], unresolved: ['libmissing.so'] },
        }}
      />,
    );

    expect(screen.getByText('libmissing.so')).toBeInTheDocument();
    expect(screen.getByText(/20 of 23/)).toBeInTheDocument();
    expect(screen.queryByText('bin/orphan-22')).toBeNull();
    expect(screen.getByRole('link', { name: /Open the full component map/ })).toHaveAttribute(
      'href',
      '#/image/img1/compmap',
    );
  });

  it('refuses non-http FCC links while preserving valid evidence links', () => {
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="fcc"
        value={{
          links: [
            { id: 'SAFE', fccReport: 'https://fcc.example/report', fccid: 'javascript:alert(1)' },
            { id: 'NO-LINK', fccReport: '/relative/report' },
          ],
        }}
      />,
    );

    expect(screen.getByRole('link', { name: 'FCC filing' })).toHaveAttribute('href', 'https://fcc.example/report');
    expect(screen.getAllByRole('link')).toHaveLength(1);
    expect(screen.getByText('NO-LINK')).toBeInTheDocument();
  });

  it('says where a device-tree run looked even when it found nothing', () => {
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="devicetree"
        value={{
          searched: ['boot/dtb', 'squashfs-root/boot'],
          blobs: [],
          rejected: [{ origin: 'boot/dtb', reason: 'magic ok, totalsize past end of file' }],
        }}
      />,
    );

    // The codebase's central conflation, one level down: a run that completed and found nothing is not a run that
    // never happened, and the list of places it looked is what keeps the two apart.
    expect(screen.getByText('Places searched')).toBeInTheDocument();
    expect(screen.getByText('boot/dtb')).toBeInTheDocument();
    expect(screen.queryByText('Device trees')).toBeNull();
    // A candidate that was read and thrown out carries the rule that threw it out.
    expect(screen.getByText(/magic ok, totalsize past end of file/)).toBeInTheDocument();
  });

  it('sorts a u-boot environment and keeps a conditional command line marked as conditional', () => {
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="uboot"
        value={{
          found: true,
          varCount: 2,
          vars: { bootcmd: 'bootm 0x9f050000', baudrate: '115200' },
          bootScript: {
            roots: ['bootcmd'],
            variants: [{ value: 'console=ttyS0,115200 root=31:02', via: ['bootcmd', 'bootargs'], conditional: true }],
          },
        }}
      />,
    );

    // Sorted by name, so the same environment reads the same way twice — never in the order the parser emitted it.
    const names = Array.from(document.querySelectorAll('.deep-data-table tbody th')).map((n) => n.textContent);
    expect(names).toEqual(['baudrate', 'bootcmd']);
    expect(screen.getByText('bootcmd → bootargs')).toBeInTheDocument();
    // A command line only some branch assembles is not the command line this device boots with.
    expect(screen.getByText('conditional branch')).toBeInTheDocument();
  });

  it('counts a verify command as a signature check and leaves an unrecorded rollback state unknown', () => {
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="updatepath"
        value={{
          imageIntegrity: { container: 'trx', items: [{ kind: 'crc32', detail: 'header CRC over the payload' }] },
          filesWalked: 1200,
          elfsExamined: 40,
          rollback: { evidence: 'no version floor was found in any updater' },
          updaters: [
            {
              path: 'sbin/sysupgrade',
              why: 'writes to mtd',
              digestFns: ['md5sum'],
              signatureFns: [],
              verifyCommands: ['fwtool -q -t -i /dev/null'],
            },
          ],
        }}
      />,
    );

    // A shell that shells OUT to a verifier is verifying; counting only `signatureFns` would report this updater
    // as unchecked.
    expect(screen.getByText('fwtool -q -t -i /dev/null')).toBeInTheDocument();
    expect(screen.getByText('md5sum')).toBeInTheDocument();
    // `state` was never written, and an absent state is not "no rollback protection".
    expect(screen.getByText('unknown')).toBeInTheDocument();
    expect(screen.getByText(/no version floor was found/)).toBeInTheDocument();
  });

  it('prints RTOS addresses as fixed-width hex and an absent one as a dash', () => {
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="rtos"
        value={{
          isCortexM: true,
          vectorTable: { initialSP: 0x20005000, resetHandler: 0x8000201 },
          memoryMap: { flashBase: 0x8000000 },
        }}
      />,
    );

    expect(screen.getByText('0x20005000')).toBeInTheDocument();
    // Padded, so two addresses line up in a column instead of reading as different magnitudes.
    expect(screen.getByText('0x08000201')).toBeInTheDocument();
    expect(screen.getByText('—')).toBeInTheDocument();
    // An RTOS kernel nobody identified says so rather than showing a blank cell.
    expect(screen.getByText('Not recorded by this run.')).toBeInTheDocument();
  });

  it('bounds a certificate sweep by what it actually read', () => {
    render(
      <DeepAnalysisDetails
        imageId="img1"
        kind="certs"
        value={{
          scan: { filesScanned: 118, filesConsidered: 1204, bytesScanned: 9437184 },
          certs: [
            {
              subject: 'CN=Acme Router',
              issuer: 'CN=Acme Router',
              validFrom: '2012-01-01',
              validTo: '2022-01-01',
              keyType: 'RSA',
              keyBits: 1024,
              selfSigned: true,
            },
          ],
        }}
      />,
    );

    // 118 of 1204 is the sweep's own bound: "one certificate" is a statement about what was opened, not the image.
    expect(screen.getByText('118 / 1,204')).toBeInTheDocument();
    expect(screen.getByText('9,437,184')).toBeInTheDocument();
    expect(screen.getByText('RSA 1024 bit')).toBeInTheDocument();
    expect(screen.getByText('yes')).toBeInTheDocument();
  });

  it('renders nothing for legacy non-object payloads instead of throwing', () => {
    const { container } = render(<DeepAnalysisDetails imageId="img1" kind="kernel" value={['legacy']} />);
    expect(container).toBeEmptyDOMElement();
  });
});
