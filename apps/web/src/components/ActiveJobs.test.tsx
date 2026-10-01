import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { type Job, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { ActiveJobs } from './ActiveJobs';
vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});
const mockApi = mockedApi(api);
const job = (id: string, status: Job['status']): Job => ({
  id,
  status,
  imageId: 'img',
  kind: 'extract',
  createdAt: 1,
  updatedAt: 1,
  params: {},
  log: '',
  result: null,
  error: null,
});
beforeEach(() => setLocale('en'));
it('offers image-wide cancellation only for queued/running jobs and shows pending teardown', async () => {
  mockApi.jobs.mockResolvedValue([
    job('queued', 'queued'),
    job('running', 'running'),
    job('pending', 'cancelling'),
    job('done', 'done'),
    job('error', 'error'),
  ]);
  mockApi.cancelJob.mockResolvedValue(job('queued', 'cancelled'));
  render(<ActiveJobs imageId="img" />);
  expect(await screen.findByRole('region', { name: 'Active jobs' })).toBeTruthy();
  expect(screen.getAllByRole('button', { name: 'Cancel' })).toHaveLength(2);
  expect(screen.getByText('Cancelling…')).toBeTruthy();
  expect(screen.queryByText('done')).toBeNull();
  expect(screen.queryByText('error')).toBeNull();
  const [cancel] = screen.getAllByRole('button', { name: 'Cancel' });
  if (!cancel) throw new Error('missing cancel control');
  fireEvent.click(cancel);
  await waitFor(() => expect(mockApi.cancelJob).toHaveBeenCalledWith('queued'));
  expect(await screen.findByText('cancelled')).toBeTruthy();
  expect(screen.getAllByRole('button', { name: 'Cancel' })).toHaveLength(1);
});
it('is silent for completed histories', async () => {
  mockApi.jobs.mockResolvedValue([job('done', 'done'), job('cancelled', 'cancelled')]);
  const { container } = render(<ActiveJobs imageId="img" />);
  await waitFor(() => expect(mockApi.jobs).toHaveBeenCalled());
  expect(container.textContent).toBe('');
});

it('surfaces failed process cleanup and retained capacity even after a reload', async () => {
  mockApi.jobs.mockResolvedValue([
    {
      ...job('failed-cleanup', 'cancelled'),
      error: 'Process cleanup failed; scheduler capacity retained until API restart',
    },
  ]);
  render(<ActiveJobs imageId="img" />);
  expect(await screen.findByRole('alert')).toHaveTextContent('scheduler capacity retained');
  expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull();
});

it('does not apply an old cancellation response after the image changes', async () => {
  let finish: ((value: Job) => void) | undefined;
  mockApi.jobs.mockImplementation(async (image) => [job(image, 'running')]);
  mockApi.cancelJob.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const view = render(<ActiveJobs imageId="old" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }));
  view.rerender(<ActiveJobs imageId="new" />);
  expect(await screen.findByText('new')).toBeInTheDocument();
  if (!finish) throw new Error('cancel request missing');
  finish(job('old', 'cancelled'));
  await waitFor(() => expect(screen.getByText('new')).toBeInTheDocument());
  expect(screen.queryByText('old')).toBeNull();
  expect(screen.queryByText('cancelled')).toBeNull();
});
