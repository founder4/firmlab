/**
 * dashboard — the Local analysis screen: the corpus listing and the upload surface. English source of truth.
 *
 * The coverage wording is the load-bearing part and has to survive translation intact. A listing that shows only
 * filename, class and size renders an image nothing has ever analyzed and a fully-scanned one identically, so
 * `unexamined` is a word this screen must be able to say in every language — never a neutral dash, never a zero.
 *
 * What is deliberately absent: filenames, architectures, firmware-class ids and job statuses. Those are data the
 * API produced, and the table renders them verbatim.
 */
export const dashboard = {
  eyebrow: 'Workspace',
  title: 'Local analysis',
  desc: 'Upload an image to analyze it locally, then read it as signal, deepen with tool-backed jobs, and compare across your corpus.',

  coverage: {
    /** Never dressed as a neutral zero: nothing ran, which is a different thing from a clean result. */
    unexamined: 'unexamined',
    stages: (executed: number, applicable: number) => `${executed}/${applicable} stages`,
    /** The corpus-scale reading of the same number — "0 findings" over an unscanned corpus is not a quiet one. */
    unexaminedCount: (n: number, total: number) => `${n} of ${total} unexamined`,
    unexaminedTitle: 'Run the autonomous scan on these to actually examine them',
  },

  upload: {
    analyzing: 'Analyzing…',
    dropTitle: 'Drop a firmware image to begin',
    dropBody:
      'Get an instant identity, structure map, entropy profile, and secret scan — analyzed entirely on this machine, no toolchain required.',
    another: 'Analyze another image',
    anotherHint: 'drop a file, or select — nothing leaves this machine',
    dropOrSelect: 'Drop or select',
  },

  list: {
    title: 'Images',
    filterPlaceholder: 'Filter by filename, arch, class, or tag…',
    noMatches: 'No matches',
    noMatchesBody: (query: string, total: number) =>
      `No image matches “${query}”. Clear the filter to see all ${total}.`,
    clearFilter: 'Clear filter',
    colFilename: 'Filename',
    colClass: 'Class',
    colArch: 'Arch',
    colTags: 'Tags',
    colSize: 'Size',
    colFindings: 'Findings',
    colCoverage: 'Coverage',
    colStatus: 'Status',
    findingsLabel: (n: number): string => (n === 1 ? 'finding' : 'findings'),
    statusReady: 'Ready',
    statusAnalyzing: 'Analyzing',
    statusError: 'Error',
    select: (filename: string) => `Select ${filename}`,
    addTag: 'Add tag',
    removeTag: 'Remove tag',
    tagPlaceholder: 'tag…',
    deleteImage: (filename: string) => `Delete ${filename}`,
  },

  del: {
    confirm: 'Confirm',
    selected: (n: number) => `Delete selected (${n})`,
    manyTitle: (n: number) => `Delete ${n} image${n === 1 ? '' : 's'}?`,
    manyBody: 'This removes each image and any carved rootfs. This cannot be undone.',
    oneTitle: (filename: string) => `Delete ${filename}?`,
    oneBody: 'This removes the image and any carved rootfs.',
    done: (n: number) => `Deleted ${n} image${n === 1 ? '' : 's'}`,
  },
};
