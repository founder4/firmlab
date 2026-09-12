/**
 * corpus — the cross-image knowledge base. English source of truth.
 *
 * Everything this screen says is a PRIOR: it reports where a credential, a component version or an identity recurs
 * across images, and never that any of them is vulnerable. The per-image findings stay the source of truth, so the
 * prose must keep saying "worth checking" and never slide into a verdict when it is translated.
 *
 * Component names, versions, family keys and hashes are values the corpus stored; they render verbatim.
 */
export const corpus = {
  loading: 'Loading corpus…',

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
