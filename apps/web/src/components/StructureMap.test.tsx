import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { StructureSegment } from '../api';
import { setLocale } from '../i18n';
import { StructureMap } from './StructureMap';

const segments: [StructureSegment, StructureSegment] = [
  {
    start: 0,
    end: 4096,
    label: 'MediaTek BootROM synthetic envelope',
    category: 'container',
    confidence: 'high',
    meta: { digest: 'not_verified', payloadSize: 257 },
  },
  {
    start: 8192,
    end: 8193,
    label: 'Narrow embedded boundary',
    category: 'bootloader',
    confidence: 'medium',
    meta: { digest: 'mismatch', coveredStart: 9728 },
  },
];

beforeEach(() => setLocale('en'));

describe('StructureMap segment inspection', () => {
  it('exposes every listed segment through a labelled native selector, including a one-byte band', () => {
    render(<StructureMap segments={segments} size={16384} />);
    const select = screen.getByRole('combobox', { name: 'Inspect a segment' });
    expect(select.tagName).toBe('SELECT');
    expect(within(select).getAllByRole('option')).toHaveLength(3);
    expect(within(select).getByRole('option', { name: '0x2000–0x2001 · Narrow embedded boundary' })).toBeVisible();
    expect(select).toHaveValue('');
    fireEvent.change(select, { target: { value: '1' } });
    const details = screen.getByRole('region', { name: 'Segment details' });
    expect(within(details).getByText('Narrow embedded boundary')).toBeVisible();
    expect(within(details).getByText('mismatch')).toBeVisible();
    expect(within(details).getByText('9728')).toBeVisible();
    expect(select).toHaveAttribute('aria-controls', details.id);
  });

  it('keeps an explicit selection after focus leaves and restores it after a pointer preview', () => {
    const { container } = render(<StructureMap segments={segments} size={16384} />);
    const select = screen.getByRole('combobox', { name: 'Inspect a segment' });
    fireEvent.change(select, { target: { value: '0' } });
    fireEvent.blur(select);
    const details = screen.getByRole('region', { name: 'Segment details' });
    expect(within(details).getByText('not_verified')).toBeVisible();
    const narrow = container.querySelectorAll('div[title]')[1];
    if (!narrow) throw new Error('Missing visual band');
    fireEvent.mouseEnter(narrow);
    expect(within(details).getByText('mismatch')).toBeVisible();
    expect(select).toHaveValue('0');
    fireEvent.mouseLeave(narrow);
    expect(within(details).getByText('not_verified')).toBeVisible();
    expect(within(details).queryByText('mismatch')).toBeNull();
  });

  it('gives keyboard focus and selection precedence over a stale pointer preview', () => {
    const { container } = render(<StructureMap segments={segments} size={16384} />);
    const band = container.querySelector('div[title]');
    if (!band) throw new Error('Missing visual band');
    fireEvent.mouseEnter(band);
    const select = screen.getByRole('combobox', { name: 'Inspect a segment' });
    fireEvent.focus(select);
    fireEvent.change(select, { target: { value: '1' } });
    const details = screen.getByRole('region', { name: 'Segment details' });
    expect(within(details).getByText('mismatch')).toBeVisible();
    expect(within(details).queryByText('not_verified')).toBeNull();
  });

  it('can clear a selection and resets it when the supplied analysis changes', () => {
    const { rerender } = render(<StructureMap segments={segments} size={16384} />);
    const select = screen.getByRole('combobox', { name: 'Inspect a segment' });
    fireEvent.change(select, { target: { value: '0' } });
    fireEvent.change(select, { target: { value: '' } });
    expect(screen.getByText('Choose a segment or point to the map to inspect its details.')).toBeVisible();
    fireEvent.change(select, { target: { value: '1' } });
    rerender(<StructureMap segments={[{ ...segments[0], label: 'Replacement analysis' }]} size={4096} />);
    expect(select).toHaveValue('');
    expect(screen.queryByText('mismatch')).toBeNull();
    expect(within(select).getAllByRole('option')).toHaveLength(2);
  });

  it('does not offer a selection or invent metadata for an empty listing', () => {
    render(<StructureMap segments={[]} size={16384} />);
    expect(screen.queryByRole('combobox')).toBeNull();
    expect(screen.getByText('No segment details are listed.')).toBeVisible();
    expect(screen.getByText(/unclaimed, not empty/)).toBeVisible();
  });

  it('localises the controls while preserving provider labels, ranges and optional legacy metadata', () => {
    setLocale('es');
    const legacy: StructureSegment = {
      start: 0,
      end: 4096,
      label: segments[0].label,
      category: 'container',
      confidence: 'high',
    };
    render(<StructureMap segments={[legacy]} size={16384} />);
    const select = screen.getByRole('combobox', { name: 'Inspeccionar un segmento' });
    fireEvent.change(select, { target: { value: '0' } });
    const details = screen.getByRole('region', { name: 'Detalles del segmento' });
    expect(within(details).getByText('MediaTek BootROM synthetic envelope')).toBeVisible();
    expect(within(details).getByText('0x0 – 0x1000 · 4.0 KB')).toBeVisible();
    expect(details.textContent).not.toMatch(/undefined|verified|NaN/);
  });
});
