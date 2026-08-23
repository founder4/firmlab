import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type Job, type RunSummary, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { AnalysisActionsPanel } from './AnalysisActionsPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const job = (overrides: Partial<Job> = {}): Job => ({
  id: 'job-uboot',
  imageId: 'image-1',
  kind: 'uboot',
  status: 'done',
  createdAt: Date.now() - 60_000,
  updatedAt: Date.now() - 50_000,
  params: {},
  log: '',
  result: { findings: [], reason: 'U-Boot environment was not present in the extracted input.' },
  error: null,
  ...overrides,
});

const run = (overrides: Partial<RunSummary> = {}): RunSummary => ({
  jobId: 'job-uboot',
  kind: 'uboot',
  status: 'done',
  startedAt: Date.now() - 60_000,
  finishedAt: Date.now() - 50_000,
  target: null,
  question: null,
  headline: 'U-Boot environment was not present in the extracted input.',
  outcome: 'blocked',
  bound: 'rootfs and carved regions',
  ...overrides,
});

beforeEach(() => {
  vi.clearAllMocks();
  setLocale('es');
  mockApi.jobs.mockResolvedValue([]);
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
});

describe('AnalysisActionsPanel', () => {
  it('hydrates every provider from persisted jobs instead of resetting the UI on reload', async () => {
    mockApi.jobs.mockResolvedValue([job()]);
    mockApi.runs.mockResolvedValue({ runs: [run()], byTarget: [] });

    const { unmount } = render(<AnalysisActionsPanel imageId="image-1" />);
    const row = (await screen.findByText('U-Boot environment was not present in the extracted input.')).closest(
      'article',
    );
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText('bloqueada')).toBeTruthy();
    expect(within(row as HTMLElement).getByText('0 hallazgos')).toBeTruthy();
    expect(within(row as HTMLElement).getByText('Repetir')).toBeTruthy();
    expect(screen.getByText('1 de 10 con respuesta guardada')).toBeTruthy();
    unmount();

    // A fresh mount reads exactly the same persisted answer. The old component returned to ten idle cards here.
    render(<AnalysisActionsPanel imageId="image-1" />);
    expect(await screen.findByText('U-Boot environment was not present in the extracted input.')).toBeTruthy();
    expect(screen.getByText('1 de 10 con respuesta guardada')).toBeTruthy();
  });

  it('keeps a blocked answer distinct from an empty or successful one', async () => {
    mockApi.jobs.mockResolvedValue([job()]);
    mockApi.runs.mockResolvedValue({ runs: [run()], byTarget: [] });
    render(<AnalysisActionsPanel imageId="image-1" />);

    const badge = await screen.findByText('bloqueada');
    expect(badge.className).toContain('run-blocked');
    expect(badge.className).not.toContain('run-proven');
    expect(badge.closest('[title]')?.getAttribute('title')).toContain('NO es un resultado negativo');
  });

  it('puts an explicit no-run answer beside providers that have no stored execution', async () => {
    render(<AnalysisActionsPanel imageId="image-1" />);
    await waitFor(() => expect(mockApi.jobs).toHaveBeenCalledWith('image-1'));

    expect(screen.getByText('0 de 10 con respuesta guardada')).toBeTruthy();
    expect(screen.getAllByText('Sin ejecutar')).toHaveLength(10);
    expect(screen.getAllByText('Todavía no hay una respuesta guardada para esta pregunta.')).toHaveLength(10);
  });

  it('shows progress in the provider row as soon as Run is pressed', async () => {
    mockApi.runAnalysis.mockReturnValue(new Promise(() => undefined));
    render(<AnalysisActionsPanel imageId="image-1" />);
    await screen.findByText('0 de 10 con respuesta guardada');

    const uboot = screen.getByText('U-Boot / gestor de arranque').closest('article');
    expect(uboot).not.toBeNull();
    fireEvent.click(within(uboot as HTMLElement).getByRole('button', { name: 'Ejecutar U-Boot / gestor de arranque' }));

    expect(await within(uboot as HTMLElement).findByText('en curso')).toBeTruthy();
    expect(
      within(uboot as HTMLElement).getByText('El resultado aparecerá aquí cuando termine el proveedor.'),
    ).toBeTruthy();
    expect(within(uboot as HTMLElement).getByRole('button')).toBeDisabled();
  });

  it('keeps a launch failure visible beside the action that failed', async () => {
    mockApi.runAnalysis.mockRejectedValue(new Error('provider route unavailable'));
    render(<AnalysisActionsPanel imageId="image-1" />);
    await screen.findByText('0 de 10 con respuesta guardada');

    const uboot = screen.getByText('U-Boot / gestor de arranque').closest('article');
    fireEvent.click(within(uboot as HTMLElement).getByRole('button', { name: 'Ejecutar U-Boot / gestor de arranque' }));

    expect(await within(uboot as HTMLElement).findByText('provider route unavailable')).toBeTruthy();
    expect(within(uboot as HTMLElement).getByText('falló')).toBeTruthy();
  });

  it('shows every parsed U-Boot variable and its value in the collected-data disclosure', async () => {
    mockApi.jobs.mockResolvedValue([
      job({
        result: {
          available: true,
          found: true,
          varCount: 3,
          vars: {
            bootcmd: 'run boot_normal',
            bootdelay: '3',
            ipaddr: '192.168.0.1',
          },
          findings: [],
          reason: 'Parsed 3 U-Boot environment variables from the image.',
        },
      }),
    ]);
    mockApi.runs.mockResolvedValue({
      runs: [run({ outcome: 'empty', headline: 'Parsed 3 U-Boot environment variables from the image.' })],
      byTarget: [],
    });
    render(<AnalysisActionsPanel imageId="image-1" />);

    const uboot = (await screen.findByText('Parsed 3 U-Boot environment variables from the image.')).closest('article');
    fireEvent.click(within(uboot as HTMLElement).getByText('Datos obtenidos'));

    expect(within(uboot as HTMLElement).getByText('bootcmd')).toBeTruthy();
    expect(within(uboot as HTMLElement).getByText('run boot_normal')).toBeTruthy();
    expect(within(uboot as HTMLElement).getByText('bootdelay')).toBeTruthy();
    expect(within(uboot as HTMLElement).getAllByText('3').length).toBeGreaterThanOrEqual(1);
    expect(within(uboot as HTMLElement).getByText('ipaddr')).toBeTruthy();
    expect(within(uboot as HTMLElement).getByText('192.168.0.1')).toBeTruthy();
  });

  it('renders provider-specific structured data for non-U-Boot results too', async () => {
    mockApi.jobs.mockResolvedValue([
      job({
        id: 'job-services',
        kind: 'services',
        result: {
          available: true,
          services: [
            {
              name: 'httpd',
              binary: '/usr/bin/httpd',
              source: 'etc/rc.d/rcS',
              network: true,
              autostart: true,
              port: 80,
            },
          ],
          findings: [],
          reason: 'Service map: 1 configured service.',
        },
      }),
    ]);
    mockApi.runs.mockResolvedValue({
      runs: [run({ jobId: 'job-services', kind: 'services', headline: 'Service map: 1 configured service.' })],
      byTarget: [],
    });
    render(<AnalysisActionsPanel imageId="image-1" />);

    const services = (await screen.findByText('Service map: 1 configured service.')).closest('article');
    fireEvent.click(within(services as HTMLElement).getByText('Datos obtenidos'));

    expect(within(services as HTMLElement).getByText('/usr/bin/httpd')).toBeTruthy();
    expect(within(services as HTMLElement).getByText('etc/rc.d/rcS')).toBeTruthy();
    expect(within(services as HTMLElement).getByText('80')).toBeTruthy();
  });

  it('keeps the summary and detail payload on the same run when an older job finishes later', async () => {
    const older = job({
      id: 'older-job',
      createdAt: 100,
      updatedAt: 500,
      result: { found: true, varCount: 1, vars: { source: 'older' }, findings: [], reason: 'Older answer.' },
    });
    const newer = job({
      id: 'newer-job',
      createdAt: 200,
      updatedAt: 300,
      result: { found: true, varCount: 1, vars: { source: 'newer' }, findings: [], reason: 'Newer answer.' },
    });
    mockApi.jobs.mockResolvedValue([older, newer]);
    mockApi.runs.mockResolvedValue({
      runs: [run({ jobId: 'newer-job', startedAt: 200, finishedAt: 300, headline: 'Newer answer.' })],
      byTarget: [],
    });
    render(<AnalysisActionsPanel imageId="image-1" />);

    const uboot = (await screen.findByText('Newer answer.')).closest('article');
    fireEvent.click(within(uboot as HTMLElement).getByText('Datos obtenidos'));

    expect(within(uboot as HTMLElement).getByText('newer')).toBeTruthy();
    expect(within(uboot as HTMLElement).queryByText('older')).toBeNull();
  });
});
