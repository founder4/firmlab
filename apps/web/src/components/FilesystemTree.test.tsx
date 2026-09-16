/**
 * FilesystemTree, on a DOM.
 *
 * Two things this tree must not do: hide the audit-relevant metadata behind a click (setuid, setgid and a symlink's
 * target are badged on the row, at every depth, so a rootfs is scanned rather than clicked through), and present its
 * expand control as something only a mouse can reach. `aria-expanded` is asserted per-row because it is the only
 * signal that says whether what a directory hides is currently shown.
 */
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { FsNode } from '../api';
import { FilesystemTree } from './FilesystemTree';

const tree: FsNode = {
  name: 'rootfs',
  path: '',
  type: 'dir',
  size: 0,
  children: [
    {
      name: 'usr',
      path: 'usr',
      type: 'dir',
      size: 0,
      children: [
        {
          name: 'bin',
          path: 'usr/bin',
          type: 'dir',
          size: 0,
          children: [{ name: 'helper', path: 'usr/bin/helper', type: 'file', size: 1536, setgid: true }],
        },
      ],
    },
    { name: 'busybox', path: 'bin/busybox', type: 'file', size: 512000, setuid: true },
    { name: 'passwd', path: 'etc/passwd', type: 'symlink', size: 0, symlinkTarget: '/dev/null' },
  ],
};

describe('FilesystemTree', () => {
  it('renders audit-relevant metadata without requiring expansion', () => {
    render(<FilesystemTree root={tree} />);

    expect(screen.getByText('setuid')).toBeInTheDocument();
    expect(screen.getByText('500.0 KB')).toBeInTheDocument();
    expect(screen.getByText('→ /dev/null')).toBeInTheDocument();
  });

  it('starts one level open and expands deeper directories on demand', () => {
    render(<FilesystemTree root={tree} />);

    const bin = screen.getByRole('button', { name: /bin/ });
    expect(bin).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByText(/helper/)).toBeNull();

    fireEvent.click(bin);
    expect(bin).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText(/helper/)).toBeInTheDocument();
    expect(screen.getByText('setgid')).toBeInTheDocument();

    fireEvent.click(bin);
    expect(screen.queryByText(/helper/)).toBeNull();
  });

  it('does not announce collapsed content for a directory that holds none', () => {
    render(<FilesystemTree root={{ ...tree, children: [{ name: 'var', path: 'var', type: 'dir', size: 0 }] }} />);

    // An empty directory is a fact about the carve. A toggle on it would claim there is something behind it.
    expect(screen.getByRole('button', { name: /var/ })).not.toHaveAttribute('aria-expanded');
  });

  it('exposes expandable rows as keyboard-operable controls', () => {
    render(<FilesystemTree root={tree} />);
    const bin = screen.getByRole('button', { name: /bin/ });

    bin.focus();
    expect(bin).toHaveFocus();
    expect(bin.tagName).toBe('BUTTON');
    expect(bin.tabIndex).toBe(0);
  });
});
