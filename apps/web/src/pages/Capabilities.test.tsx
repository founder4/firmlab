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
