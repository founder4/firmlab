/**
 * The browser-composed report had the defect its server-side counterpart was built to make impossible: the ledger
 * route serves measured rows and operator assertions in ONE array, separated only by the `operator_assertion`
 * sentinel, and this component sorted the whole array into the findings table. A person's claim therefore appeared
 * in the measured population, under a "Proof state" column, printing the raw sentinel — `PROOF_LABEL` has no entry
 * for it — and was counted in the executive summary's finding total.
 *
 * It survived because nothing here was tested. These assertions are written against the DOM preview rather than the
 * export string, because the preview is the thing a person reads before deciding the report is right.
 */
import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type Finding, type ImageSummary, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { ReportBuilder } from './ReportBuilder';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const image: ImageSummary = {
  id: 'img1',
  filename: 'router-v1.bin',
  size: 4 * 1024 * 1024,
  sha256: 'deadbeef',
  uploadedAt: 1,
  status: 'ready',
  identity: { firmwareClass: 'embedded-linux', arch: 'mips', endianness: 'big', filesystems: ['squashfs'] },
  tags: [],
};

const measured = (over: Partial<Finding> = {}): Finding => ({
  id: 'f-measured',
  imageId: 'img1',
  source: 'binvuln',
  kind: 'stack-overflow-candidate',
  title: 'unbounded strcpy in sbin/httpd',
  severity: 'medium',
  proofState: 'static_confirmed',
  createdAt: 1_700_000_000_000,
  ...over,
});

/** An assertion as the ledger actually serves it: same array, same shape, one sentinel on `proofState`. */
const assertion = (over: Partial<Finding> = {}): Finding => ({
  id: 'f-asserted',
  imageId: 'img1',
  source: 'operator',
  kind: 'operator-assertion',
  title: 'the update endpoint is behind a VPN on this fleet',
  severity: 'high',
  proofState: 'operator_assertion',
  assertion: {
    claim: 'disputes_finding',
    assertedBy: 'aaron',
    authorKind: 'human',
    assertedAt: 1_700_000_000_000,
    rationale: 'the fleet reaches this endpoint only over a VPN',
    status: 'active',
  },
  createdAt: 1_700_000_000_000,
  ...over,
});

beforeEach(() => {
  mockApi.jobs.mockResolvedValue([]);
  mockApi.sbom.mockResolvedValue(null);
});

// The locale store is module-level, so a test that switches it would leak into the next file's worth of assertions.
// `cleanup()` runs BEFORE the switch back on purpose: the store notifies its subscribers, and notifying a still
// mounted tree from outside `act` is an unwrapped update — the warning would be real, not noise.
afterEach(() => {
  cleanup();
  setLocale('en');
});

const findingsTable = (): HTMLElement => {
  const header = screen.getByText('Proof state');
  const table = header.closest('table');
  if (!table) throw new Error('the measured findings table is not rendered');
  return table;
};

describe('ReportBuilder — assertions are never measured findings', () => {
  it('keeps an operator assertion out of the measured findings table', async () => {
    mockApi.findings.mockResolvedValue([measured(), assertion()]);
    render(<ReportBuilder imageId="img1" image={image} analysis={null} />);

    await screen.findByText('unbounded strcpy in sbin/httpd');
    const table = findingsTable();
    expect(within(table).getByText('unbounded strcpy in sbin/httpd')).toBeInTheDocument();
    // The claim is in the report — just not in this population.
    expect(within(table).queryByText(/behind a VPN/i)).not.toBeInTheDocument();
    expect(screen.getByText(/behind a VPN/i)).toBeInTheDocument();
  });

  it('never prints the raw `operator_assertion` sentinel as though it were a proof state', async () => {
    mockApi.findings.mockResolvedValue([measured(), assertion()]);
    render(<ReportBuilder imageId="img1" image={image} analysis={null} />);

    await screen.findByText('unbounded strcpy in sbin/httpd');
    expect(screen.queryByText('operator_assertion')).not.toBeInTheDocument();
  });

  it('excludes assertions from the finding count and says where they went', async () => {
    mockApi.findings.mockResolvedValue([measured(), assertion(), assertion({ id: 'f-2' })]);
    render(<ReportBuilder imageId="img1" image={image} analysis={null} />);

    // One measured finding, not three rows.
    expect(await screen.findByText(/1 finding was recorded/i)).toBeInTheDocument();
    expect(screen.getByText(/2 operator assertions are listed separately/i)).toBeInTheDocument();
    expect(screen.getByText(/counted in neither that total nor any stage/i)).toBeInTheDocument();
  });

  it('does not let a high-severity assertion inflate the critical/high note', async () => {
    // The assertion is `high`. If it leaked into sevCount the summary would advertise a high severity the
    // workbench never measured — the worst version of this defect, because it reads as a result.
    mockApi.findings.mockResolvedValue([measured(), assertion()]);
    render(<ReportBuilder imageId="img1" image={image} analysis={null} />);

    await screen.findByText('unbounded strcpy in sbin/httpd');
    expect(screen.queryByText(/1 high/)).not.toBeInTheDocument();
  });

  it('renders the assertion block with provenance and no proof-state column', async () => {
    mockApi.findings.mockResolvedValue([measured(), assertion()]);
    render(<ReportBuilder imageId="img1" image={image} analysis={null} />);

    await screen.findByText(/behind a VPN/i);
    expect(screen.getByText(/Operator assertions \(1\) — asserted, not measured/i)).toBeInTheDocument();
    expect(screen.getByText('aaron')).toBeInTheDocument();
    // One "Proof state" header in the document: the measured table's. The assertion table has none.
    expect(screen.getAllByText('Proof state')).toHaveLength(1);
  });

  it('says zero findings is not clean, and does not invent an assertion block when there are none', async () => {
    mockApi.findings.mockResolvedValue([]);
    render(<ReportBuilder imageId="img1" image={image} analysis={null} />);

    expect(await screen.findByText(/zero findings is not the same as clean/i)).toBeInTheDocument();
    expect(screen.queryByText(/Operator assertions/i)).not.toBeInTheDocument();
  });
});

/**
 * The report is exported and handed on, so its scaffolding has to translate — and the evidence inside it must not.
 * Those are opposite requirements landing in the same paragraph, which is why they are asserted together: a
 * catalogue that swallowed the finding titles would pass every English test in this file.
 */
describe('ReportBuilder — Spanish translates the frame, never the record', () => {
  it('translates the assertion partition while the stored finding title stays as recorded', async () => {
    setLocale('es');
    mockApi.findings.mockResolvedValue([measured(), assertion()]);
    render(<ReportBuilder imageId="img1" image={image} analysis={null} />);

    // The honesty sentences, in Spanish. Losing any of these ships a document making a claim nobody measured.
    expect(await screen.findByText(/Cada hallazgo lleva un estado de prueba explícito/i)).toBeInTheDocument();
    expect(screen.getByText(/se declara como tal en lugar de darse por limpia/i)).toBeInTheDocument();
    expect(screen.getByText(/no cuenta ni para ese total ni para ninguna etapa/i)).toBeInTheDocument();
    expect(screen.getByText(/Afirmaciones del operador \(1\) — afirmadas, no medidas/i)).toBeInTheDocument();
    // The English is gone, not merely joined by the Spanish.
    expect(screen.queryByText(/counted in neither that total nor any stage/i)).not.toBeInTheDocument();

    // The frame is translated…
    const header = screen.getByText('Estado de prueba');
    const table = header.closest('table');
    if (!table) throw new Error('the measured findings table is not rendered');
    expect(within(table).getByText('confirmado en los bytes')).toBeInTheDocument();

    // …and the record is not. The title is the sentence the analysis wrote, the source is an identifier that
    // crosses the API, and neither is this screen's to reword.
    expect(within(table).getByText('unbounded strcpy in sbin/httpd')).toBeInTheDocument();
    expect(within(table).getByText('binvuln')).toBeInTheDocument();
    expect(screen.getByText(/the update endpoint is behind a VPN on this fleet/i)).toBeInTheDocument();
  });

  it('keeps the assertion out of the measured population in Spanish too', async () => {
    setLocale('es');
    mockApi.findings.mockResolvedValue([measured(), assertion()]);
    render(<ReportBuilder imageId="img1" image={image} analysis={null} />);

    // `proofState.label` HAS a Spanish gloss for `operator_assertion`; the partition, not the missing label, is
    // what keeps a person's claim out of the measured table.
    await screen.findByText('unbounded strcpy in sbin/httpd');
    const table = screen.getByText('Estado de prueba').closest('table');
    if (!table) throw new Error('the measured findings table is not rendered');
    expect(within(table).queryByText(/behind a VPN/i)).not.toBeInTheDocument();
    expect(within(table).queryByText('afirmado · no medido')).not.toBeInTheDocument();
    expect(screen.getAllByText('Estado de prueba')).toHaveLength(1);
    // One measured finding, counted in Spanish and not inflated by the assertion.
    expect(screen.getByText(/Se registró 1 hallazgo/i)).toBeInTheDocument();
  });
});
