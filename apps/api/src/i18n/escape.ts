/**
 * HTML escaping, shared by the catalogues and by the ledger renderer that consumes them.
 *
 * It lives here rather than in `providers/report-assertions.ts` for one reason: the catalogue entries that build
 * HTML fragments have to escape what they interpolate themselves. An author's name, a claim's title and a stored
 * proof state all reach a sentence whose word order differs per language, so the escaping cannot be done by the
 * caller and handed over as "already safe" — that convention survives exactly until the first entry someone adds
 * without reading the comment. Putting the function under `i18n/` lets `en.ts` and `es.ts` import it without the
 * catalogue and the renderer importing each other in a cycle. `report-assertions.ts` re-exports it, so its own
 * consumers (the report generator) are unaffected.
 */
export function escapeHtml(s: unknown): string {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] ?? c);
}
