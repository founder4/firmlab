/**
 * The capture-proxy flow manifest (Phase 6.1) — pure parsing, kept in its own store-free module so the parser can
 * be unit-tested without pulling in the SQLite layer. The mitmproxy addon appends one JSON object per response to
 * `<capdir>/flows.jsonl`; this turns that into typed records, tolerating blank/malformed lines.
 */
import type { TlsPosture } from '../providers/flowscore.js';

export interface RawFlow {
  id: string;
  host: string | null;
  url: string;
  method: string;
  status: number | null;
  contentType: string | null;
  contentLength: number;
  tls: TlsPosture;
  /** Relative path (under the capdir) to the saved body, or null when only metadata was recorded. */
  body: string | null;
}

/** Pure: parse the addon's JSONL manifest into typed flows, skipping blank/malformed and id/url-less lines. */
export function parseFlowManifest(text: string): RawFlow[] {
  const out: RawFlow[] = [];
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(t) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (typeof o.id !== 'string' || typeof o.url !== 'string') continue;
    const tls = o.tls === 'plaintext' || o.tls === 'tls-unpinned' || o.tls === 'tls-pinned' ? o.tls : null;
    out.push({
      id: o.id,
      host: typeof o.host === 'string' ? o.host : null,
      url: o.url,
      method: typeof o.method === 'string' ? o.method : 'GET',
      status: typeof o.status === 'number' ? o.status : null,
      contentType: typeof o.contentType === 'string' ? o.contentType : null,
      contentLength: typeof o.contentLength === 'number' ? o.contentLength : 0,
      tls,
      body: typeof o.body === 'string' ? o.body : null,
    });
  }
  return out;
}
