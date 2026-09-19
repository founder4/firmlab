import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { Capabilities } from './Capabilities';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

beforeEach(() => {
  vi.clearAllMocks();
  setLocale('es');
});

describe('Capabilities', () => {
  it('keeps a missing tool distinct from a capability the deployment actually has', async () => {
    mockApi.tools.mockResolvedValue({
      tools: [
        {
          id: 'binwalk',
          bin: 'binwalk',
          available: true,
          version: 'Binwalk v3',
          unlocks: 'Extrae sistemas de ficheros.',
          group: 'extract',
        },
        {
          id: 'ghidra',
          bin: 'analyzeHeadless',
          available: false,
          unlocks: 'Descompila binarios.',
          group: 'analyze',
        },
      ],
      groups: {},
    });

    render(<Capabilities />);

    expect(await screen.findByText('1 de 2 disponibles en este despliegue')).toBeInTheDocument();
    expect(screen.getByText('Binwalk v3')).toBeInTheDocument();
    expect(screen.getByText('no encontrada')).toBeInTheDocument();
    expect(screen.getByText(/RESPUESTA ausente/)).toBeInTheDocument();
    expect(mockApi.tools).toHaveBeenCalledWith('es');
  });

  it('does not let a tool that timed out read as one this deployment lacks', async () => {
    // The row the fix exists for: installed, and the probe budget ran out. `available: false` is the same on both
    // rows below, so if the page renders them alike an operator reads a capability it HAS as one it never had —
    // and every provider needing it reports blocked_by_platform, which is not a negative.
    mockApi.tools.mockResolvedValue({
      tools: [
        {
          id: 'ghidra',
          bin: 'analyzeHeadless',
          available: false,
          unlocks: 'Descompila binarios.',
          group: 'analyze',
          outcome: 'missing',
          outcomeReason: 'no está instalada en este despliegue — el binario no está en el PATH',
        },
        {
          id: 'angr',
          bin: 'python3',
          available: false,
          unlocks: 'Alcanzabilidad simbólica.',
          group: 'analyze',
          outcome: 'timeout',
          outcomeReason: 'está instalada, pero no respondió dentro de su presupuesto de sondeo.',
        },
      ],
      groups: {},
    });

    render(<Capabilities />);

    // The count cannot tell them apart — `available` is false for both — so the page says it in its own sentence.
    expect(await screen.findByText('0 de 2 disponibles en este despliegue')).toBeInTheDocument();
    expect(screen.getByText(/1 de las filas de abajo está instalada y no respondió/)).toBeInTheDocument();
    // Two different labels, and the API's sentence on screen rather than a flat "not found".
    expect(screen.getByText('no encontrada')).toBeInTheDocument();
    expect(screen.getByText('sin respuesta a tiempo')).toBeInTheDocument();
    expect(screen.getByText(/no respondió dentro de su presupuesto de sondeo/)).toBeInTheDocument();
    // The absent one gets no explanatory row: its short label already says the whole fact.
    expect(screen.queryByText(/el binario no está en el PATH/)).not.toBeInTheDocument();
  });

  it('says nothing extra when every probe answered', async () => {
    // The branch nobody runs. An AVAILABLE tool carries no outcome, so the sentence about unanswered probes must
    // not appear at all — a guard that fires on a clean deployment is worse than no guard.
    mockApi.tools.mockResolvedValue({
      tools: [
        {
          id: 'binwalk',
          bin: 'binwalk',
          available: true,
          version: 'Binwalk v3',
          unlocks: 'Extrae sistemas de ficheros.',
          group: 'extract',
        },
      ],
      groups: {},
    });

    render(<Capabilities />);
    expect(await screen.findByText('1 de 1 disponibles en este despliegue')).toBeInTheDocument();
    expect(screen.queryByText(/no respondieron a su sondeo/)).not.toBeInTheDocument();
    expect(screen.queryByText(/está instalada y no respondió/)).not.toBeInTheDocument();
  });

  it('does not let grype without a database read as a deployment that can match CVEs', async () => {
    // The row this state exists for, measured live on 2026-09-19: grype answers `version`, so the probe says
    // available — and `grype db status` says the database does not exist. Rendered as a plain available row, the
    // page promises "CVE matching (N-day)" for a lane that is going to refuse it.
    mockApi.tools.mockResolvedValue({
      tools: [
        {
          id: 'syft',
          bin: 'syft',
          available: true,
          version: 'syft 1.50.0',
          unlocks: 'Generación del SBOM',
          group: 'sbom',
        },
        {
          id: 'grype',
          bin: 'grype',
          available: true,
          version: 'grype 0.106.1',
          unlocks: 'Correlación de CVE (N-day)',
          group: 'sbom',
          dataset: { ready: false, detail: 'Instalada, pero sin base de vulnerabilidades en /data/grype-db.' },
        },
      ],
      groups: {},
    });

    render(<Capabilities />);

    // The binary IS here, and the count must keep saying so — a dataset is not a tool.
    expect(await screen.findByText('2 de 2 disponibles en este despliegue')).toBeInTheDocument();
    // But the page says out loud that one of them cannot answer, and why.
    expect(screen.getByText(/1 de las filas de abajo está instalada pero no tiene base de datos/)).toBeInTheDocument();
    expect(screen.getByText('sin base de datos')).toBeInTheDocument();
    expect(screen.getByText(/sin base de vulnerabilidades en \/data\/grype-db/)).toBeInTheDocument();
    // The row that IS ready keeps its version and gains no warning of its own.
    expect(screen.getByText('syft 1.50.0')).toBeInTheDocument();
    // The version of the unready tool is displaced by the label, not shown as though nothing were wrong.
    expect(screen.queryByText('grype 0.106.1')).not.toBeInTheDocument();
  });

  it('reports a provisioned dataset without warning about it — the success path', async () => {
    // The branch nobody runs. A ready dataset must produce its sentence and NO warning line, or the page cries
    // wolf on every healthy deployment and the warning stops meaning anything.
    mockApi.tools.mockResolvedValue({
      tools: [
        {
          id: 'grype',
          bin: 'grype',
          available: true,
          version: 'grype 0.106.1',
          unlocks: 'Correlación de CVE (N-day)',
          group: 'sbom',
          dataset: { ready: true, detail: 'Base de vulnerabilidades compilada el 2026-09-15 (4 día(s)).' },
        },
      ],
      groups: {},
    });

    render(<Capabilities />);

    expect(await screen.findByText('1 de 1 disponibles en este despliegue')).toBeInTheDocument();
    expect(screen.getByText('grype 0.106.1')).toBeInTheDocument();
    // The date travels to the reader: "grype found 0" is only as current as this.
    expect(screen.getByText(/compilada el 2026-09-15/)).toBeInTheDocument();
    expect(screen.queryByText(/no tiene base de datos/)).not.toBeInTheDocument();
    expect(screen.queryByText('sin base de datos')).not.toBeInTheDocument();
  });

  it('reads a tool with no dataset field as needing none, never as one whose dataset is missing', async () => {
    // `dataset` absent covers every tool that has no data dependency AND every response from an API build older
    // than the field. Either way it must not raise the warning — that would flag 26 healthy rows.
    mockApi.tools.mockResolvedValue({
      tools: [
        {
          id: 'binwalk',
          bin: 'binwalk',
          available: true,
          version: 'Binwalk v3',
          unlocks: 'Extrae sistemas de ficheros.',
          group: 'extract',
        },
      ],
      groups: {},
    });

    render(<Capabilities />);
    expect(await screen.findByText('1 de 1 disponibles en este despliegue')).toBeInTheDocument();
    expect(screen.queryByText(/no tiene base de datos/)).not.toBeInTheDocument();
    expect(screen.queryByText('sin base de datos')).not.toBeInTheDocument();
  });

  it('renders a new backend group by its identifier instead of dropping it', async () => {
    mockApi.tools.mockResolvedValue({
      tools: [
        {
          id: 'future-tool',
          bin: 'future-tool',
          available: true,
          version: '1.0',
          unlocks: 'Future analysis.',
          group: 'analyze',
        },
      ],
      groups: {},
    });

    render(<Capabilities />);
    expect(await screen.findByText('Análisis de binarios')).toBeInTheDocument();
    expect(screen.getByText('future-tool')).toBeInTheDocument();
  });
});
