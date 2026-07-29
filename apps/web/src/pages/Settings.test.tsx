/**
 * Settings, in Spanish — the screen where a half-translated build is hardest to notice.
 *
 * Its seven tabs render one at a time, so an untranslated panel is invisible from every other tab: the appearance
 * tab (the one an operator opens first, and the one the language switch lives on) was fully translated while the
 * analysis, agent, storage and help panels underneath it were still English prose. A snapshot of the default view
 * would have passed throughout.
 *
 * So each converted tab is opened and read. What is asserted is BOTH halves: that the prose moved, and that the
 * things beside it did not. Environment variable names (`FIRMLAB_MAX_UPLOAD`, `FIRMLAB_AGENT_MAX_STEPS`), the
 * provider and model ids, and the bind address are what an operator types into a compose file or greps a log for —
 * a translation that bent one of them would be a translation of an identifier.
 *
 * The lane switches are deliberately NOT re-tested here: their prose is composed by the API and arrives in the
 * locale this page asked for, which `api.test.ts` pins at the request level.
 */
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { Settings } from './Settings';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const usage = {
  imageCount: 3,
  imagesBytes: 2048,
  extractsBytes: 1024,
  totalBytes: 3072,
  quotaBytes: 0,
  maxAgeDays: 0,
};

const renderSettings = (): void => {
  render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Settings />
    </MemoryRouter>,
  );
};

/** Open one of the tabs by its localised label. */
const openTab = (label: string): void => {
  fireEvent.click(screen.getByRole('button', { name: label }));
};

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a component that is still mounted and the suite fills with act(…) warnings.
  setLocale('en');
  mockApi.health.mockResolvedValue({ status: 'ok', exposedToNetwork: false, host: '127.0.0.1', port: 8799 });
  mockApi.agentConfig.mockResolvedValue({ enabled: false });
  mockApi.storage.mockResolvedValue(usage);
  mockApi.flags.mockResolvedValue({ flags: [], appliesImmediately: true });
});

describe('Settings — the tab bodies follow the locale', () => {
  it('renders the analysis tab in English by default, variable names beside the prose', async () => {
    renderSettings();
    openTab('Analysis');
    expect(await screen.findByText(/The deterministic engine runs on every upload/)).toBeInTheDocument();
    expect(screen.getByText('Upload limit')).toBeInTheDocument();
    expect(screen.getByText('FIRMLAB_MAX_UPLOAD')).toBeInTheDocument();
  });

  it('translates the analysis tab and leaves the environment variables verbatim', async () => {
    setLocale('es');
    renderSettings();
    openTab('Análisis');
    expect(await screen.findByText(/El motor determinista se ejecuta en cada subida/)).toBeInTheDocument();
    expect(screen.getByText('Límite de subida')).toBeInTheDocument();
    expect(screen.getByText('Concurrencia de trabajos')).toBeInTheDocument();
    expect(screen.getByText('Ver las herramientas detectadas')).toBeInTheDocument();
    // Typed by the operator, not read by them.
    expect(screen.getByText('FIRMLAB_MAX_UPLOAD')).toBeInTheDocument();
    expect(screen.getByText('FIRMLAB_MAX_CONCURRENT_JOBS')).toBeInTheDocument();
  });

  it('translates the agent tab, keeping every budget variable and its value untouched', async () => {
    mockApi.agentConfig.mockResolvedValue({
      enabled: true,
      provider: 'deepseek',
      model: 'deepseek-chat',
      budget: { maxSteps: 12, maxTokens: 100000, maxUsd: 0, maxWallMs: 600000 },
    });
    setLocale('es');
    renderSettings();
    openTab('IA y agente');

    expect(await screen.findByText('Proveedor de IA')).toBeInTheDocument();
    expect(screen.getByText('Gobernador del agente')).toBeInTheDocument();
    expect(screen.getByText('Presupuesto de pasos')).toBeInTheDocument();
    expect(screen.getByText('Techo de coste')).toBeInTheDocument();
    expect(screen.getByText('Activado')).toBeInTheDocument();
    // No ceiling is configured. It must read as "nothing is stopping this", not as a blank.
    expect(screen.getByText('sin acotar')).toBeInTheDocument();
    // The governor's variables and the provider/model ids are identifiers.
    expect(screen.getByText('FIRMLAB_AGENT_MAX_STEPS')).toBeInTheDocument();
    expect(screen.getByText('FIRMLAB_AGENT_MAX_USD')).toBeInTheDocument();
    expect(screen.getAllByText(/deepseek · deepseek-chat/).length).toBeGreaterThan(0);
  });

  it('translates the storage tab, and says outright when a limit is not set', async () => {
    setLocale('es');
    renderSettings();
    openTab('Almacenamiento');

    expect(await screen.findByText('En disco')).toBeInTheDocument();
    expect(screen.getByText('Retención')).toBeInTheDocument();
    // An unset limit is a stated fact here, never an empty cell: both halves say so.
    expect(screen.getByText('Sin límite de antigüedad. Sin cuota de tamaño.')).toBeInTheDocument();
    expect(screen.getByText('FIRMLAB_MAX_IMAGE_AGE_DAYS')).toBeInTheDocument();
    expect(screen.getByText('FIRMLAB_MAX_DATA_BYTES')).toBeInTheDocument();
  });

  it('translates the help tab', async () => {
    setLocale('es');
    renderSettings();
    openTab('Ayuda');
    expect(await screen.findByText('Recorrido del producto')).toBeInTheDocument();
    expect(screen.getByText('Repetir el recorrido')).toBeInTheDocument();
    expect(screen.getByText('Teclado')).toBeInTheDocument();
    expect(screen.getByText('Acerca de')).toBeInTheDocument();
  });
});

/**
 * The privacy tab's posture badge is a verdict about where the API is bound, recomputed from `/health` on every
 * load. `Sólo local` claims that firmware never leaves this machine; the other three claim the opposite or claim
 * nothing at all, and an unreachable API is its own state precisely so the panel cannot guess in the reassuring
 * direction. Every one of the four is checked, because they are one `? :` chain away from each other.
 */
describe('Settings — the network posture keeps its four distinct answers in Spanish', () => {
  const openPrivacy = async (): Promise<void> => {
    setLocale('es');
    renderSettings();
    openTab('Privacidad');
    await screen.findByText('Postura de red');
  };

  it('reads loopback as local-only, and says the firmware does not leave', async () => {
    await openPrivacy();
    expect(screen.getByText('Sólo local')).toBeInTheDocument();
    expect(screen.getByText(/el firmware no sale de esta máquina/)).toBeInTheDocument();
    expect(screen.getByText('127.0.0.1:8799')).toBeInTheDocument();
  });

  it('reads a network bind as exposed rather than as anything softer', async () => {
    mockApi.health.mockResolvedValue({ status: 'ok', exposedToNetwork: true, host: '0.0.0.0', port: 8799 });
    await openPrivacy();
    expect(screen.getByText('Expuesto a la red')).toBeInTheDocument();
    expect(screen.getByText(/Conviene restringirla/)).toBeInTheDocument();
  });

  it('names an authenticating proxy as its own answer, not as local-only', async () => {
    mockApi.health.mockResolvedValue({
      status: 'ok',
      exposedToNetwork: true,
      trustedProxy: true,
      host: '0.0.0.0',
      port: 8799,
    });
    await openPrivacy();
    expect(screen.getByText('Proxy con autenticación')).toBeInTheDocument();
    expect(screen.queryByText('Sólo local')).not.toBeInTheDocument();
  });

  it('reads an unreachable API as UNKNOWN — never as a deployment that happens to be safe', async () => {
    mockApi.health.mockRejectedValue(new Error('offline'));
    await openPrivacy();
    expect(screen.getByText('Desconocida')).toBeInTheDocument();
    expect(screen.getByText('La API no responde.')).toBeInTheDocument();
    expect(screen.queryByText('Sólo local')).not.toBeInTheDocument();
  });

  it('says the copilot is off, and where the engine can and cannot reach', async () => {
    await openPrivacy();
    expect(screen.getByText('Desactivado')).toBeInTheDocument();
    expect(screen.getByText(/No se envía nada fuera de la máquina/)).toBeInTheDocument();
    expect(screen.getByText('FIRMLAB_AGENT=1')).toBeInTheDocument();
    expect(screen.getByText(/El motor \(@firmlab\/core\) es determinista/)).toBeInTheDocument();
  });
});

/**
 * The residue check. Each assertion above names a sentence that moved; this one names the sentences that would
 * still be there if a panel had been missed — the failure mode a per-string test cannot see, because it only ever
 * looks where somebody remembered to look.
 */
describe('Settings — no English residue in the converted tabs', () => {
  const ENGLISH_LEFTOVERS = [
    /The deterministic engine runs on every upload/,
    /Max image size is set with/,
    /Heavy tools are throttled with/,
    /These are deployment settings rather than per-session preferences/,
    /FirmLab is designed to run locally/,
    /Bound to loopback/,
    /No external model is configured/,
    /The engine \(@firmlab\/core\) is deterministic/,
    /An LLM powers the copilot/,
    /The agent reasons within a deterministic skeleton/,
    /Uploaded images and carved rootfs live under the data directory/,
    /No age limit set/,
    /Manage or bulk-delete images from/,
    /Navigate with Tab and Shift\+Tab/,
    /local-only firmware analysis workbench/,
  ];

  const TABS_EN = ['Analysis', 'Privacy', 'AI & Agent', 'Storage', 'Help'];
  const TABS_ES = ['Análisis', 'Privacidad', 'IA y agente', 'Almacenamiento', 'Ayuda'];

  /** Every leftover found at least once while walking the tabs, so the two runs below can be compared. */
  const sweep = (tabs: string[]): Set<RegExp> => {
    const found = new Set<RegExp>();
    for (const tab of tabs) {
      openTab(tab);
      for (const leftover of ENGLISH_LEFTOVERS) {
        if (screen.queryAllByText(leftover).length > 0) found.add(leftover);
      }
    }
    return found;
  };

  /**
   * The guard's SUCCESS path — the one nobody runs, and the one this project has shipped broken four times. A list
   * of sentences that are absent from a Spanish render is also what a list of TYPOS looks like: every regex here
   * would "pass" against a fully English page if it simply matched nothing. So the same sweep is run in English
   * first, and every entry must be found.
   */
  it('finds every one of those sentences in the English render — otherwise the check below proves nothing', async () => {
    renderSettings();
    await screen.findByRole('heading', { name: 'Settings' });
    const found = sweep(TABS_EN);
    expect(ENGLISH_LEFTOVERS.filter((r) => !found.has(r)).map(String)).toEqual([]);
  });

  it('shows none of the English sentences on any converted tab', async () => {
    setLocale('es');
    renderSettings();
    await screen.findByRole('heading', { name: 'Ajustes' });
    expect([...sweep(TABS_ES)].map(String)).toEqual([]);
  });
});
