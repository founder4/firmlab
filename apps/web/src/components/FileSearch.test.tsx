import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type FilesSearch, api } from '../api';
import { mockedApi } from '../test-api-mock';
import { FileSearch, isCompleteSearch } from './FileSearch';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});
const mockApi = mockedApi(api);

const clean: FilesSearch = {
  query: 'nope',
  hits: [],
  coverage: {
    filesExamined: 6279,
    entriesWalked: 7340,
    skipped: { tooLarge: 0, unreadable: 0, budgetExhausted: 0 },
    walkTruncated: false,
    hitCapReached: false,
  },
  verdict:
    'Searched 6279 file(s) of 7340 walked; 0 match(es). Every file in the extraction was opened, so this list is complete for this term.',
};

const partial: FilesSearch = {
  query: 'nope',
  hits: [],
  coverage: {
    filesExamined: 6200,
    entriesWalked: 7340,
    skipped: { tooLarge: 2, unreadable: 0, budgetExhausted: 0 },
    walkTruncated: false,
    hitCapReached: false,
  },
  verdict:
    'Searched 6200 file(s) of 7340 walked; 0 match(es). NOT searched: 2 file(s) larger than 8 MB — a term present only in those would not appear above.',
};

describe('isCompleteSearch', () => {
  it('is false whenever anything was skipped or capped, and false for a result with no coverage', () => {
    expect(isCompleteSearch(clean)).toBe(true);
    expect(isCompleteSearch(partial)).toBe(false);
    expect(isCompleteSearch({ hits: [], verdict: 'stored by an older build' })).toBe(false);
    expect(isCompleteSearch(null)).toBe(false);
  });
});

describe('FileSearch', () => {
  // The submit handler is async, so the state it sets lands a microtask AFTER fireEvent returns. Clicking
  // inside act() lets that update settle within the render cycle React accounts for, instead of arriving
  // unattached and being reported as an unwrapped update.
  const search = async (result: FilesSearch) => {
    mockApi.searchFiles.mockResolvedValue(result);
    render(<FileSearch imageId="447719f7" />);
    fireEvent.change(screen.getByLabelText('Search term'), { target: { value: 'nope' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Search/i }));
    });
  };

  it('an empty COMPLETE search is allowed to be a negative, and says so plainly', async () => {
    await search(clean);
    expect(await screen.findByText('complete search')).toBeTruthy();
    expect(screen.getByText(/No file in this extraction contains that term/i)).toBeTruthy();
  });

  it('an empty PARTIAL search refuses to be a negative', async () => {
    await search(partial);
    expect(await screen.findByText('partial search')).toBeTruthy();
    expect(screen.getByText(/not the same as absent from this firmware/i)).toBeTruthy();
    // The reason has to be on screen, not merely encoded in a flag.
    expect(screen.getByText(/would not appear above/i)).toBeTruthy();
  });

  it('renders the verdict even when there ARE hits — it is not a failure-only caveat', async () => {
    await search({
      ...clean,
      hits: [
        { path: 'squashfs-root/etc/config', offset: 5, line: 1, excerpt: 'host=updates', binary: false },
        { path: 'squashfs-root/bin/httpd', offset: 4660, excerpt: '..GET updates', binary: true },
      ],
    });
    await waitFor(() => expect(screen.getByText('squashfs-root/bin/httpd')).toBeTruthy());
    expect(screen.getByText(/Every file in the extraction was opened/)).toBeTruthy();
    // A binary hit is labelled and dated by byte offset, never by a line number it does not have.
    expect(screen.getByText('binary')).toBeTruthy();
    expect(screen.getByText('0x1234')).toBeTruthy();
    expect(screen.getByText(':1')).toBeTruthy();
  });
});
