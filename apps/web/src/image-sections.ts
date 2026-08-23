import type { Messages } from './i18n';

/**
 * Stable route segments served by the image workbench. Kept outside the page module so the shell can build its
 * navigation without eagerly loading the entire (and deliberately feature-rich) ImageDetail bundle.
 */
export const SECTION_IDS = [
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
  'binvuln',
  'kernel',
  'kmod',
  'binaries',
  'testbench',
  'findings',
  'operator',
  'diff',
  'simulate',
  'egress',
  'opacidad',
  'agent',
] as const satisfies readonly (keyof Messages['sections'])[];

export type ImageSectionId = (typeof SECTION_IDS)[number];
