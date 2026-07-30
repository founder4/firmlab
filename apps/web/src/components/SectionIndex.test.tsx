import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';
import { setLocale } from '../i18n';
import { SectionIndex } from './SectionIndex';

const SECTIONS = [
  'dossier',
  'overview',
  'structure',
  'entropy',
  'filesystem',
  'files',
  'secrets',
  'hardware',
  'bootloader',
  'sbom',
  'compmap',
  'deepscans',
  'binaries',
  'testbench',
  'findings',
  'operator',
  'diff',
  'simulate',
  'opacidad',
  'agent',
];

const row = (s: string): HTMLElement => {
  const el = document.querySelector(`[data-section="${s}"]`);
  if (!el) throw new Error(`no row for ${s}`);
  return el as HTMLElement;
};

const draw = (extraction: { ran: boolean; rootfs: boolean }) =>
  render(
    <MemoryRouter>
      <SectionIndex imageId="abc" sections={SECTIONS} extraction={extraction} />
    </MemoryRouter>,
  );

beforeEach(() => setLocale('en'));

describe('SectionIndex — every section reachable, and nothing hidden on a guess', () => {
  it('links every section, including the ten that had no link anywhere in the app', () => {
    draw({ ran: true, rootfs: true });
    for (const s of [
      'structure',
      'files',
      'secrets',
      'hardware',
      'compmap',
      'deepscans',
      'testbench',
      'diff',
      'opacidad',
      'agent',
    ]) {
      const link = row(s).querySelector('a');
      expect(link?.getAttribute('href')).toBe(`/image/abc/${s}`);
    }
  });

  it('omits `overview`, a dead id that resolveSection remaps to dossier', () => {
    draw({ ran: true, rootfs: true });
    // Listing both would offer two links to one page and imply a section that does not exist.
    expect(document.querySelector('[data-section="overview"]')).toBeNull();
    expect(row('dossier')).toBeTruthy();
  });

  it('marks which sections the timeline already reached and which were URL-only', () => {
    draw({ ran: true, rootfs: true });
    expect(row('sbom').textContent).toMatch(/In the step timeline above/);
    expect(row('files').textContent).toMatch(/was reachable only by URL/);
  });

  /**
   * The pair: a rootfs-reading section is empty for two different reasons, and telling an operator to run an
   * extraction that already ran is the cost of collapsing them.
   */
  it('says an unrun extraction is about the workbench, and no-rootfs is about the image', () => {
    draw({ ran: false, rootfs: false });
    expect(row('files').dataset.readiness).toBe('extraction-not-run');
    expect(row('files').textContent).toMatch(/statement about this workbench, not about the firmware/);

    draw({ ran: true, rootfs: false });
    const noRootfs = document.querySelectorAll('[data-section="files"]')[1] as HTMLElement;
    expect(noRootfs.dataset.readiness).toBe('extraction-found-no-rootfs');
    expect(noRootfs.textContent).toMatch(/extraction RAN and produced no rootfs/);
    expect(noRootfs.textContent).toMatch(/not a stage nobody started/);
  });

  it('still LINKS a section whose rootfs is missing — reachability is the defect, not a lock', () => {
    draw({ ran: false, rootfs: false });
    expect(row('files').querySelector('a')?.getAttribute('href')).toBe('/image/abc/files');
  });

  it('says nothing about extraction for sections that do not read the rootfs', () => {
    draw({ ran: false, rootfs: false });
    expect(row('entropy').dataset.readiness).toBe('ready');
    expect(row('entropy').textContent).not.toMatch(/extraction/i);
  });

  it('states that class routing is deliberately not duplicated here', () => {
    draw({ ran: true, rootfs: true });
    expect(screen.getByTestId('section-index').textContent).toMatch(/routing lives in the API/);
  });

  it('renders in Spanish too', () => {
    setLocale('es');
    draw({ ran: true, rootfs: false });
    expect(row('files').textContent).toMatch(/la extracción SÍ corrió y no produjo rootfs/);
  });
});
