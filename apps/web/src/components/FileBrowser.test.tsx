import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type FilesListing, type FilesRead, api } from '../api';
import { FileBrowser } from './FileBrowser';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return { ...actual, api: { ...actual.api, files: vi.fn(), readFile: vi.fn() } };
});

const mockApi = api as unknown as { files: ReturnType<typeof vi.fn>; readFile: ReturnType<typeof vi.fn> };

const listing = (o: Partial<FilesListing> = {}): FilesListing => ({
  claim: 'These bytes are what the extractor wrote to disk for this image.',
  extraction: {
    state: 'rootfs',
    browsable: true,
    verdict: "Extraction recovered a rootfs at 'squashfs-root'. You are browsing the WHOLE carve.",
    rootfsRel: 'squashfs-root',
  },
  listing: {
    path: '',
    entries: [
      { name: 'squashfs-root', path: 'squashfs-root', type: 'dir', size: 0, mode: 0o755, modeString: 'drwxr-xr-x' },
      {
        name: 'busybox',
        path: 'busybox',
        type: 'file',
        size: 512000,
        mode: 0o4755,
        modeString: '-rwsr-xr-x',
        setuid: true,
      },
      {
        name: 'passwd',
        path: 'passwd',
        type: 'symlink',
        size: 0,
        mode: 0o777,
        modeString: 'lrwxrwxrwx',
        symlinkTarget: '/dev/null',
        symlinkEscapes: true,
      },
    ],
    totalEntries: 3,
    fileCount: 1,
    dirCount: 1,
    symlinkCount: 1,
    truncated: false,
  },
  ...o,
});

const CLAIM = 'These bytes are what the extractor wrote to disk for this image.';

const fileRead = (o: Partial<NonNullable<FilesRead['read']>> = {}): FilesRead => ({
  claim: CLAIM,
  extraction: listing().extraction,
  read: {
    claim: CLAIM,
    path: 'jffs2-root/private_key.pem',
    size: 451,
    offset: 0,
    bytesRead: 451,
    truncated: false,
    unreadBefore: 0,
    unreadAfter: 0,
    classification: {
      kind: 'text',
      reason: 'Text: no NUL bytes.',
      sampled: 451,
      nulBytes: 0,
      nonPrintable: 0,
      utf8: true,
    },
    view: 'text',
    viewReason: 'Text: no NUL bytes. Decided from the bytes; the file’s name played no part.',
    text: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B\n-----END PUBLIC KEY-----\n',
    adjustments: [],
    ...o,
  },
});

describe('FileBrowser', () => {
  it('renders the extraction verdict above the tree, never a bare empty list', async () => {
    mockApi.files.mockResolvedValue(
      listing({
        extraction: {
          state: 'never-run',
          browsable: false,
          verdict: 'No extraction has run for this image, so there is nothing on disk to browse.',
        },
        listing: null,
      }),
    );
    render(<FileBrowser imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/No extraction has run for this image/)).toBeTruthy());
    expect(screen.getByText('Extraction · never extracted')).toBeTruthy();
    // The distinction the whole feature turns on.
    expect(screen.getByText(/This is not an empty filesystem/)).toBeTruthy();
  });

  it('keeps a carve with no rootfs browsable and quotes the diagnosis', async () => {
    mockApi.files.mockResolvedValue(
      listing({
        extraction: {
          state: 'volumes-only',
          browsable: true,
          verdict: '27 volume(s) were extracted holding 666 file(s), and none is a Linux rootfs.',
        },
      }),
    );
    render(<FileBrowser imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/none is a Linux rootfs/)).toBeTruthy());
    expect(screen.getByText('Extraction · carve only — no rootfs')).toBeTruthy();
    expect(screen.queryByText(/This is not an empty filesystem/)).toBeNull();
  });

  it('shows the mode string, badges setuid and reports a symlink that leaves the extraction', async () => {
    mockApi.files.mockResolvedValue(listing());
    render(<FileBrowser imageId="img1" />);
    await waitFor(() => expect(screen.getByText('-rwsr-xr-x')).toBeTruthy());
    expect(screen.getByText('setuid')).toBeTruthy();
    // The link is REPORTED, not hidden — that the firmware ships it is the fact worth seeing.
    expect(screen.getByText('leaves extraction')).toBeTruthy();
    expect(screen.getByText(/\/dev\/null/)).toBeTruthy();
  });

  it('walks into a directory and back out through the breadcrumb', async () => {
    mockApi.files.mockResolvedValue(listing());
    render(<FileBrowser imageId="img1" />);
    await waitFor(() => expect(screen.getByText('squashfs-root')).toBeTruthy());

    fireEvent.click(screen.getByText('squashfs-root'));
    await waitFor(() => expect(mockApi.files).toHaveBeenCalledWith('img1', 'squashfs-root'));

    fireEvent.click(screen.getByRole('button', { name: 'extract' }));
    await waitFor(() => expect(mockApi.files).toHaveBeenLastCalledWith('img1', undefined));
  });

  it('opens a file and shows the bytes — the case the withdrawn backlog entry needed', async () => {
    mockApi.files.mockResolvedValue(listing());
    mockApi.readFile.mockResolvedValue(fileRead());
    render(<FileBrowser imageId="img1" />);
    await waitFor(() => expect(screen.getByText('busybox')).toBeTruthy());

    fireEvent.click(screen.getByText('busybox'));
    await waitFor(() => expect(screen.getByText(/BEGIN PUBLIC KEY/)).toBeTruthy());
    expect(screen.getByText('Whole file — all 451 bytes.')).toBeTruthy();
    expect(screen.getByText(/the file’s name played no part/)).toBeTruthy();
  });

  it('never lets a window read as the whole file', async () => {
    mockApi.files.mockResolvedValue(listing());
    mockApi.readFile.mockResolvedValue(
      fileRead({
        size: 512000,
        bytesRead: 65536,
        truncated: true,
        unreadAfter: 446464,
        truncationRule: 'This is a 65536-byte window of a 512000-byte file, bytes 0–65536.',
      }),
    );
    render(<FileBrowser imageId="img1" />);
    await waitFor(() => expect(screen.getByText('busybox')).toBeTruthy());

    fireEvent.click(screen.getByText('busybox'));
    await waitFor(() => expect(screen.getByText('Showing bytes 0–65536 of 512000.')).toBeTruthy());
    expect(screen.getByText(/65536-byte window of a 512000-byte file/)).toBeTruthy();
    // The bound is navigable, not a dead end.
    expect(screen.getByRole('button', { name: 'Next' }).hasAttribute('disabled')).toBe(false);
    expect(screen.getByRole('button', { name: 'Previous' }).hasAttribute('disabled')).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() =>
      expect(mockApi.readFile).toHaveBeenLastCalledWith('img1', 'busybox', { offset: 65536, view: 'text' }),
    );
  });

  it('renders a refused read as its rule, not as an empty viewer', async () => {
    mockApi.files.mockResolvedValue(listing());
    mockApi.readFile.mockResolvedValue({
      extraction: listing().extraction,
      read: null,
      claim: '',
      refusal: {
        rule: 'symlink-escapes-root',
        error: "Refused by the symlink rule: 'passwd' resolves through a symlink to '/dev/null'.",
        symlinkTarget: '/dev/null',
      },
    } as FilesRead);
    render(<FileBrowser imageId="img1" />);
    await waitFor(() => expect(screen.getByText('passwd')).toBeTruthy());

    fireEvent.click(screen.getByText('passwd'));
    await waitFor(() => expect(screen.getByText('Refused · symlink-escapes-root')).toBeTruthy());
    expect(screen.getByText(/Refused by the symlink rule/)).toBeTruthy();
  });

  it('shows the listing cap as a stated bound rather than dropping entries quietly', async () => {
    const l = listing();
    mockApi.files.mockResolvedValue({
      ...l,
      listing: {
        ...(l.listing as NonNullable<FilesListing['listing']>),
        totalEntries: 6497,
        truncated: true,
        truncationRule: '6497 entries are present and 2000 are shown. The cap is 2000; entries are sorted first.',
      },
    });
    render(<FileBrowser imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/6497 entries are present and 2000 are shown/)).toBeTruthy());
  });
});
