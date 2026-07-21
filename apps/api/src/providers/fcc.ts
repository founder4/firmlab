/**
 * FCC-ID recon provider (Phase 5, deterministic, no network) — extracts candidate FCC IDs from the firmware
 * bytes and builds authoritative lookup links. The public FCC equipment-authorization filing for a device is a
 * recon goldmine: external/internal photos, user + test manuals, RF/EMC test reports, and block diagrams are all
 * published. This provider does NOT hit the network — it honestly extracts the ID that is literally present in
 * the image and hands back the two canonical URLs where an analyst can pull those filings.
 *
 * Everything here is PURE and unit-tested: ID extraction, the strict shape check, the link builder, and the
 * finding mapper. The runner only gathers strings (from the cached static analysis + a bounded raw-image strings
 * pass) and composes them. A finding is `info` / `static_confirmed`: a factual lead (the ID is in the bytes), a
 * pointer to public filings — never a device or vulnerability claim.
 */
import fs from 'node:fs';
import type { FindingSeverity, ProofState, SignatureHit, StaticAnalysis, StringHit } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';

/** An extracted FCC ID paired with its authoritative lookup links. */
export interface FccLink {
  id: string;
  /** fccid.io — the community mirror that hosts the published photos/manuals/test reports. */
  fccid: string;
  /** The FCC OET equipment-authorization (grantee/EA) search for the ID. */
  fccReport: string;
}

export interface FccResult {
  available: boolean;
  ids: string[];
  links: FccLink[];
  findings: FindingDraft[];
  reason: string;
}

/** Cap on the number of distinct IDs surfaced (keeps a noisy blob from flooding the ledger). */
const FCC_ID_CAP = 20;
/** Bounded prefix of the raw image scanned as latin1 in the lightweight strings pass. */
const RAW_IMAGE_PREFIX = 16 * 1024 * 1024;
/** Minimum run length kept from the raw strings pass. */
const MIN_STRING_LEN = 4;

// The labeled form — `FCC ID: <id>`, `FCCID:<id>`, `FCC-ID <id>` — case-insensitive. This is the high-confidence
// path: an explicit label precedes the token, so we accept whatever printable ID-shaped value follows and let
// `isPlausibleFccId` reject anything that isn't a real FCC ID shape.
const LABELED_RE = /FCC[-\s]?ID[:\s]+([A-Za-z0-9][A-Za-z0-9-]{2,19})/gi;
// The standalone form — a strict, UPPER-CASE FCC-ID-shaped token directly adjacent to a bare `FCC`. Deliberately
// case-sensitive (real FCC IDs are upper-case) so prose like `FCC part 15` never matches.
const ADJACENT_RE = /\bFCC\s+([A-Z0-9][A-Z0-9-]{2,19})\b/g;

/**
 * Pure: the strict FCC-ID shape check. An FCC ID is a grantee code (3 upper-case alphanumerics, or 5 for the
 * newer format) followed by a product code (1–14 of A–Z / 0–9 / `-`). Rejects obvious non-IDs: an all-digit
 * token (a serial/part number, never a valid grantee) and anything too short or too long.
 */
export function isPlausibleFccId(s: string): boolean {
  const id = s.toUpperCase();
  if (id.length > 20) return false;
  // A real FCC ID always carries at least one letter (the grantee code is never all digits) — this rejects
  // pure numerics like `1234567`.
  if (!/[A-Z]/.test(id)) return false;
  // grantee (3 or 5 alphanumerics) + product (1–14 of A–Z / 0–9 / `-`).
  return /^(?:[A-Z0-9]{3}|[A-Z0-9]{5})[A-Z0-9-]{1,14}$/.test(id);
}

/**
 * Pure: extract candidate FCC IDs from a bag of strings. Matches the labeled `FCC ID: <id>` form primarily (to
 * avoid false positives) plus a strict upper-case token adjacent to a bare `FCC`. Every candidate is upper-cased
 * and validated with `isPlausibleFccId`; results are deduped, kept in insertion order, and capped.
 */
export function extractFccIds(strings: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (raw: string | undefined): void => {
    if (!raw || out.length >= FCC_ID_CAP) return;
    const id = raw.toUpperCase();
    if (!isPlausibleFccId(id) || seen.has(id)) return;
    seen.add(id);
    out.push(id);
  };
  for (const s of strings) {
    if (!s) continue;
    for (const m of s.matchAll(LABELED_RE)) add(m[1]);
    for (const m of s.matchAll(ADJACENT_RE)) add(m[1]);
    if (out.length >= FCC_ID_CAP) break;
  }
  return out;
}

/**
 * Pure: the two authoritative lookup links for an FCC ID. `fccid` is the fccid.io community mirror (photos,
 * manuals, internal photos, test reports); `fccReport` is the FCC OET equipment-authorization search endpoint.
 */
export function buildFccLinks(id: string): { fccid: string; fccReport: string } {
  const enc = encodeURIComponent(id);
  return {
    fccid: `https://fccid.io/${enc}`,
    fccReport: `https://www.fcc.gov/oet/ea/fccid?fccid=${enc}`,
  };
}

/**
 * Pure: one honest recon finding per FCC ID. `info` / `static_confirmed` — the ID is literally present in the
 * image bytes, and its public FCC filing (photos, manuals, internal photos, RF/EMC test reports) is a documented
 * lead for hardware recon. A pointer to public intelligence, never a device or vulnerability claim.
 */
export function fccFindings(ids: string[]): FindingDraft[] {
  return ids.map((id) => {
    const links = buildFccLinks(id);
    return {
      kind: 'fcc-id',
      title: `FCC ID ${id} — public device filings`,
      severity: 'info' as FindingSeverity,
      proofState: 'static_confirmed' as ProofState,
      evidence: { id, links },
      rationale: `FCC ID "${id}" is present in the firmware bytes. Its public FCC equipment-authorization filing exposes external/internal photos, user + test manuals, and RF/EMC test reports — a goldmine for hardware recon (board layout, chipsets, radios). A factual lead to public intelligence, not a device or vulnerability claim.`,
    };
  });
}

/** Pull candidate strings out of the cached static analysis: the extracted secrets + the signature descriptions. */
function parseAnalysisStrings(analysisJson: string | null): string[] {
  if (!analysisJson) return [];
  try {
    const a = JSON.parse(analysisJson) as Partial<StaticAnalysis>;
    const out: string[] = [];
    if (Array.isArray(a.secrets)) {
      for (const s of a.secrets as StringHit[]) if (s && typeof s.value === 'string') out.push(s.value);
    }
    if (Array.isArray(a.signatures)) {
      for (const sig of a.signatures as SignatureHit[])
        if (sig && typeof sig.description === 'string') out.push(sig.description);
    }
    return out;
  } catch {
    return [];
  }
}

/** A lightweight strings pass over a bounded latin1 prefix of the raw image (splits on non-printable runs). */
function rawImageStrings(imagePath: string): string[] {
  let text = '';
  try {
    const fd = fs.openSync(imagePath, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, RAW_IMAGE_PREFIX);
      const buf = Buffer.allocUnsafe(size);
      if (size > 0) fs.readSync(fd, buf, 0, size, 0);
      text = buf.toString('latin1');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return [];
  }
  return text.split(/[^\x20-\x7e]+/).filter((t) => t.length >= MIN_STRING_LEN);
}

/**
 * Extract candidate FCC IDs from a firmware image and build the authoritative lookup links — deterministic and
 * honest, no network. Gathers strings from the cached static analysis (secrets + signature descriptions) and a
 * bounded raw-image strings pass, then extracts + links + composes findings. Always `available`; no FCC ID found
 * is an explicit, non-fabricated result.
 */
export function runFccLookup(imagePath: string, analysisJson: string | null): FccResult {
  const strings = [...parseAnalysisStrings(analysisJson), ...rawImageStrings(imagePath)];
  const ids = extractFccIds(strings);
  if (ids.length === 0) {
    return { available: true, ids: [], links: [], findings: [], reason: 'No FCC ID found in the firmware.' };
  }
  const links: FccLink[] = ids.map((id) => ({ id, ...buildFccLinks(id) }));
  const findings = fccFindings(ids);
  return {
    available: true,
    ids,
    links,
    findings,
    reason: `Extracted ${ids.length} candidate FCC ID${ids.length === 1 ? '' : 's'} from the image bytes and built the public FCC filing links (fccid.io + the FCC OET equipment-authorization search). A recon lead — the ID is present in the firmware — not a device or vulnerability claim.`,
  };
}
