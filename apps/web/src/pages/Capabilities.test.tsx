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
