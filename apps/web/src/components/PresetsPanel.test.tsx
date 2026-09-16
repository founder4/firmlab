/**
 * PresetsPanel, on a DOM.
 *
 * The panel is a thin store over one thing that is not thin: `dispatchPreset` maps a stored MODE onto four different
 * endpoints with four different argument shapes, and a preset is persisted — the row on screen is data written by an
 * older build. Two claims follow and both are pinned here:
 *
 *  - **every mode reaches its own endpoint with its own arguments.** `system-qemu` is `emulateSystem(id,
 *    'full-system')` with no binary; `chroot-qemu` is the same call with `'chroot-service'` and one. A mode wired to
 *    the neighbouring rung would start the wrong emulator and report a boot it never performed.
 *  - **a mode this build does not gloss shows its CODE.** The identifier is the truth about the row, and a blank pill
 *    would lose the only thing that says what the preset would run.
 */
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type EmulationPreset, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { PresetsPanel } from './PresetsPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

beforeEach(() => setLocale('en'));

const preset = (o: Partial<EmulationPreset> = {}): EmulationPreset => ({
  id: 'p1',
  name: 'httpd bring-up',
  mode: 'user-qemu',
  binary: 'bin/httpd',
  args: [],
  createdAt: 0,
  ...o,
});

describe('PresetsPanel', () => {
  it('asks for a binary only for the modes that take one', async () => {
    mockApi.listPresets.mockResolvedValue([]);
    render(<PresetsPanel imageId="img1" />);

    expect(await screen.findByPlaceholderText('bin/httpd (optional)')).toBeInTheDocument();
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'system-qemu' } });
    // Full-system QEMU boots the image; a target binary would be a field the dispatch throws away.
    expect(screen.queryByPlaceholderText('bin/httpd (optional)')).toBeNull();
  });

  it('refuses an unnamed preset and trims the name it does save', async () => {
    mockApi.listPresets.mockResolvedValue([]);
    mockApi.savePreset.mockResolvedValue(preset());
    render(<PresetsPanel imageId="img1" />);

    const save = await screen.findByRole('button', { name: 'Save preset' });
    expect(save).toBeDisabled();

    const name = screen.getByPlaceholderText('preset name');
    fireEvent.change(name, { target: { value: '  httpd bring-up  ' } });
    fireEvent.change(screen.getByPlaceholderText('bin/httpd (optional)'), { target: { value: ' bin/httpd ' } });
    mockApi.listPresets.mockClear();
    fireEvent.click(save);

    await waitFor(() =>
      expect(mockApi.savePreset).toHaveBeenCalledWith('img1', {
        name: 'httpd bring-up',
        mode: 'user-qemu',
        binary: 'bin/httpd',
      }),
    );
    // Saved presets are re-read rather than pushed onto local state, so a rejected write cannot show as stored.
    await waitFor(() => expect(mockApi.listPresets).toHaveBeenCalledWith('img1'));
    expect(name).toHaveValue('');
  });

  it('never attaches a binary to a mode that does not take one, even after one was typed', async () => {
    mockApi.listPresets.mockResolvedValue([]);
    mockApi.savePreset.mockResolvedValue(preset({ mode: 'renode', binary: null }));
    render(<PresetsPanel imageId="img1" />);

    fireEvent.change(await screen.findByPlaceholderText('bin/httpd (optional)'), { target: { value: 'bin/httpd' } });
    fireEvent.change(screen.getByPlaceholderText('preset name'), { target: { value: 'rtos' } });
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'renode' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save preset' }));

    await waitFor(() => expect(mockApi.savePreset).toHaveBeenCalledWith('img1', { name: 'rtos', mode: 'renode' }));
  });

  it('surfaces a save that failed instead of clearing the form as though it had worked', async () => {
    mockApi.listPresets.mockResolvedValue([]);
    mockApi.savePreset.mockRejectedValue(new Error('a preset named "httpd bring-up" already exists'));
    render(<PresetsPanel imageId="img1" />);

    const name = await screen.findByPlaceholderText('preset name');
    fireEvent.change(name, { target: { value: 'httpd bring-up' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save preset' }));

    expect(await screen.findByText(/already exists/)).toBeInTheDocument();
    expect(name).toHaveValue('httpd bring-up');
  });

  it.each([
    ['user-qemu', 'emulate', ['img1', 'bin/httpd']],
    ['chroot-qemu', 'emulateSystem', ['img1', 'chroot-service', 'bin/httpd']],
    ['system-qemu', 'emulateSystem', ['img1', 'full-system']],
    ['renode', 'runRenode', ['img1']],
    ['uefi-chipsec', 'runChipsec', ['img1']],
  ] as const)('runs a %s preset through %s', async (mode, method, args) => {
    mockApi.listPresets.mockResolvedValue([preset({ mode })]);
    mockApi[method].mockResolvedValue({ jobId: 'job-9' });
    render(<PresetsPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run' }));
    await waitFor(() => expect(mockApi[method]).toHaveBeenCalledWith(...args));
    // The job id is the only handle the operator has on what the click started.
    expect(await screen.findByText(/Started "httpd bring-up" \(job job-9\)/)).toBeInTheDocument();
  });

  it('reports a dispatch that failed rather than a job that never started', async () => {
    mockApi.listPresets.mockResolvedValue([preset()]);
    mockApi.emulate.mockRejectedValue(new Error('qemu-mipsel is not installed'));
    render(<PresetsPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run' }));
    expect(await screen.findByText(/qemu-mipsel is not installed/)).toBeInTheDocument();
    expect(screen.queryByText(/Started/)).toBeNull();
  });

  it('shows the raw mode of a preset this build does not gloss', async () => {
    mockApi.listPresets.mockResolvedValue([
      preset({ mode: 'bhyve-arm' as EmulationPreset['mode'], name: 'written by a newer build' }),
    ]);
    render(<PresetsPanel imageId="img1" />);

    // The identifier is the truth about the row; an empty pill would lose what the preset would run.
    expect(await screen.findByText('bhyve-arm')).toBeInTheDocument();
  });

  it('re-reads the list after a delete', async () => {
    mockApi.listPresets.mockResolvedValueOnce([preset()]).mockResolvedValue([]);
    mockApi.deletePreset.mockResolvedValue({ deleted: 'p1' });
    render(<PresetsPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Delete this preset' }));
    await waitFor(() => expect(mockApi.deletePreset).toHaveBeenCalledWith('p1'));
    await waitFor(() => expect(screen.queryByText('httpd bring-up')).toBeNull());
  });

  it('reads a list that could not be fetched as no presets, never as a broken panel', async () => {
    mockApi.listPresets.mockRejectedValue(new Error('502'));
    render(<PresetsPanel imageId="img1" />);

    expect(await screen.findByText('Saved presets')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Run' })).toBeNull();
  });
});
