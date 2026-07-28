/**
 * files — the extraction browser and the content search. English source of truth.
 *
 * Three sentences are the reason both panels are shaped the way they are, and a loose translation undoes them:
 *
 *  - `browser.nothingBody` — an empty tree is never an empty firmware. "Nothing extracted", "the carve is
 *    truncated" and "54 volumes came out and none is a rootfs" look identical on screen and need opposite moves.
 *  - `viewer.window` — a 64 KB window of a 7 MB binary looks exactly like a whole file, so the viewer states which
 *    it is holding before a reader quotes it as the file.
 *  - `search.nonePartial` — "no match in what was searched" is NOT "absent from this firmware". The complete case
 *    (`search.noneComplete`) is the only one allowed to be a plain negative.
 *
 * Never translated: file paths, mode strings, symlink targets, the `extract` root crumb (a real directory name),
 * refusal rule ids, and the verdict / truncation-rule / view-reason sentences the API composed — those are the
 * record of what the extractor did, not this screen's prose.
 */
export const files = {
  browser: {
    title: 'Extracted files',
    sub: 'Open what the extractor wrote to disk and read the bytes a finding cites. Reading a file establishes that the content is present in this extraction — it is not evidence about the running device.',
    extractionEyebrow: (state: string) => `Extraction · ${state}`,
    refusedEyebrow: (rule: string) => `Refused · ${rule}`,
    nothingTitle: 'Nothing on disk to browse',
    /** Load-bearing: the verdict above says which of several different reasons applies. */
    nothingBody:
      'This is not an empty filesystem. Read the verdict above — it says which of the several different reasons applies, and what would change it.',
    pathLabel: 'Extraction path',
    counts: (dirs: number, entries: number, links: number) => `${dirs} dir · ${entries} file · ${links} link`,
    // The `setuid` badge names the POSIX bit and is written in the component, not translated here.
    symlinkEscapes: 'leaves extraction',
  },

  /** How each extraction state is allowed to read. Only a real rootfs is neutral; nothing here reads as "fine". */
  state: {
    'never-run': 'never extracted',
    'in-progress': 'extracting',
    failed: 'extraction failed',
    'no-output': 'nothing on disk',
    'volumes-only': 'carve only — no rootfs',
    rootfs: 'rootfs recovered',
  },

  viewer: {
    heading: 'Viewer',
    viewLabel: 'View',
    // `Hex` is the radix, not a word; the component labels that half of the toggle.
    text: 'Text',
    pickTitle: 'Pick a file',
    /** Split around the `.pem` extension, which is rendered mono and never translated. */
    pickBodyBefore:
      'Text and binary are decided from the bytes, not from the extension — the mistake this panel exists to prevent was a',
    pickBodyAfter: 'that turned out to hold a public key.',
    empty: 'Empty file — 0 bytes on disk.',
    /** Load-bearing: a window must never read as the whole file. */
    window: (from: number, to: number, size: number) => `Showing bytes ${from}–${to} of ${size}.`,
    whole: (size: number) => `Whole file — all ${size} bytes.`,
    previous: 'Previous',
    next: 'Next',
  },

  search: {
    title: 'Search the extraction',
    sub: 'Which file says this — a certificate CN, a hostname, a symbol, an NVRAM key. Binaries are searched too; their hits carry a byte offset rather than a line number.',
    termLabel: 'Search term',
    // `regex` is the term of art in both languages and is written in the component.
    deep: 'deep (open large files)',
    complete: 'complete search',
    partial: 'partial search',
    noVerdict: 'This result carries no coverage verdict, so how much of the extraction it covered is unknown.',
    /** The only empty result allowed to be a plain negative: every file was opened and nothing was capped. */
    noneComplete: 'No file in this extraction contains that term.',
    /** Load-bearing: a partial search is not a negative. */
    nonePartial: 'No match in what was searched — which is not the same as absent from this firmware. See above.',
    file: 'File',
    at: 'At',
    match: 'Match',
    binary: 'binary',
  },
};
