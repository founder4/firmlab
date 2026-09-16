/**
 * corpus — the CROSS-IMAGE corpus, FirmLab's knowledge base. English source of truth.
 *
 * The screen names which corpus it is, because three unrelated things in this repository are called one: this
 * knowledge base, the validation corpus (the locked sample set `pnpm corpus:matrix` measures) and the YARA rule
 * corpus (`pnpm yara-corpus:sync`). A sidebar entry reading just "Corpus" left the operator to guess, and the
 * page said nothing at all — it opened straight into three stat tiles. See "The three corpora" in
 * docs/ARCHITECTURE.md; the title and the lead below are where that distinction reaches a reader.
 *
 * Everything this screen says is a PRIOR: it reports where a credential, a component version or an identity recurs
 * across images, and never that any of them is vulnerable. The per-image findings stay the source of truth, so the
 * prose must keep saying "worth checking" and never slide into a verdict when it is translated.
 *
 * Component names, versions, family keys and hashes are values the corpus stored; they render verbatim.
 */
export const corpus = {
  eyebrow: 'Workspace',
  title: 'Cross-image corpus',
  desc: 'What recurs across every image on this bench — a shared credential, a component version, a device family. Priors to check against the per-image findings, never verdicts. Not the validation corpus that the coverage matrix is measured over, and not the YARA rule corpus the scanner applies.',

  loading: 'Loading the cross-image corpus…',

  stats: {
    images: 'Images',
    reusedCredentials: 'Reused credentials',
    watchlistRules: 'Watchlist rules',
  },

  reuse: {
    title: 'Credential reuse',
    sub: 'Secrets that appear in more than one image — a prior worth checking, not a verdict. Promote a recurring one to the known-bad watchlist to auto-flag it on future uploads.',
    empty: 'No credential appears in more than one image yet.',
    colKind: 'Kind',
    colHash: 'Hash',
    colImages: 'Images',
    colWatchlist: 'Watchlist',
    promote: '+ watchlist',
    /** `window.prompt` label and the default it offers, so a hurried operator still stores a meaningful label. */
    promptLabel: 'Label for this known-bad credential:',
    promptDefault: 'known-bad credential',
    promoted: 'Promoted to the watchlist',
  },

  /**
   * The footnote a truncated table owes its reader. Both corpus-wide tables are a ranked prefix, and without this
   * line a full page of rows and the whole set look identical — which is how a cap becomes a claim.
   */
  listNote: (shown: number, total: number, rule: string) => `Showing ${shown} of ${total}. ${rule}`,

  prevalence: {
    title: 'Component prevalence',
    sub: 'Which component versions span the most images, and how many CVEs grype matched.',
    /** Why the table is empty: no SBOM at all, or SBOMs exist but no version yet recurs across two of them. */
    empty: (withSbom: number, total: number) =>
      withSbom === 0
        ? 'No SBOM data yet — run SBOM on some images.'
        : `No component version spans more than one image yet (${withSbom} of ${total} image(s) have an SBOM).`,
    colComponent: 'Component',
    colVersion: 'Version',
    colImages: 'Images',
    colCves: 'CVEs',
  },

  families: {
    title: 'Device families',
    sub: 'Images share a family only when vendor is evidenced; an unknown vendor stays scoped to one image. A proven family with several versions is the basis for cross-version diff.',
  },

  rules: {
    title: (n: number) => `Watchlist rules (${n})`,
    colType: 'Type',
    colLabel: 'Label',
    colKey: 'Key',
    remove: 'remove',
  },
};
