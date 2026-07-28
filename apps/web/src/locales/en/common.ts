/**
 * common — words and sentences that appear on more than one screen. English source of truth.
 *
 * Adding a key here makes `locales/es/common.ts` fail to compile until it is translated.
 *
 * A note on what belongs here: only strings whose meaning does not shift with context. "Run" as a button label is
 * shared; "Run" as a column heading in the test bench is not, because Spanish renders the two differently
 * (`Ejecutar` vs `Ejecución`). When in doubt put it in the screen's own namespace — a wrongly shared string is far
 * harder to find later than a duplicated one.
 */
export const common = {
  run: 'Run',
  cancel: 'Cancel',
  close: 'Close',
  save: 'Save',
  delete: 'Delete',
  retry: 'Retry',
  showAll: 'Show all',
  showLess: 'Show less',
  loading: 'Loading…',
  copy: 'Copy',
  copied: 'Copied',
  download: 'Download',
  search: 'Search',
  filter: 'Filter',
  none: 'none',
  unknown: 'unknown',
  yes: 'yes',
  no: 'no',
  /** Appended wherever a list shows a bounded head and states the remainder. */
  andMore: (n: number) => `+${n} more`,
};
