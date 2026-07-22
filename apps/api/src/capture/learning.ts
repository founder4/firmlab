/**
 * The capture learning surface (Phase 6.6, design §11) — what makes FirmLab more than a capture tool. Captured
 * versions accumulate in the corpus; this PURE aggregation turns the `capture_provenance` history (enriched with
 * the image + device it links to) into: a per-device-family OTA timeline, per-vendor "how this vendor ships" priors
 * (plaintext vs TLS, which CDN), and a CDN→families graph. It records what was observed across captures — never a
 * conclusion. Cross-version diff reuses the existing `diff` provider between any two captures of the same family.
 *
 * Pure + unit-tested; the route enriches provenance rows with `getImage`/`getDevice` and hands them here.
 */

export interface EnrichedProvenance {
  imageId: string;
  capturedAt: number;
  endpoint: string | null;
  transport: string | null;
  tlsPosture: string | null;
  /** Vendor from the linked device's OUI, or null. */
  vendor: string | null;
  filename: string;
  size: number;
  firmwareClass: string | null;
}

export interface OtaVersion {
  imageId: string;
  filename: string;
  capturedAt: number;
  endpoint: string | null;
  transport: string | null;
  tlsPosture: string | null;
  size: number;
  firmwareClass: string | null;
}

export interface DeviceFamily {
  key: string;
  vendor: string | null;
  captures: OtaVersion[];
  transports: string[];
  endpoints: string[];
}

export interface VendorPrior {
  vendor: string;
  /** How this vendor was observed to ship OTA. */
  ships: 'plaintext-http' | 'https' | 'mixed' | 'ble-gatt' | 'unknown';
  cdns: string[];
  captureCount: number;
}

export interface CdnEdge {
  host: string;
  families: string[];
}

export interface LearningSurface {
  families: DeviceFamily[];
  vendorPriors: VendorPrior[];
  cdnGraph: CdnEdge[];
}

/** Pure: the host of a URL/endpoint, or null when it isn't parseable (e.g. a bare string). */
export function hostOf(endpoint: string | null): string | null {
  if (!endpoint) return null;
  try {
    return new URL(endpoint).hostname || null;
  } catch {
    return null;
  }
}

/** Pure: the family key for a capture — its vendor when known, else the endpoint host, else 'unknown'. */
export function familyKey(row: EnrichedProvenance): string {
  return row.vendor ?? hostOf(row.endpoint) ?? 'unknown';
}

function uniq(xs: (string | null)[]): string[] {
  return [...new Set(xs.filter((x): x is string => x !== null && x !== ''))];
}

/** Pure: aggregate the enriched provenance history into families, per-vendor priors, and a CDN graph. */
export function buildLearningSurface(rows: EnrichedProvenance[]): LearningSurface {
  // Families — one per family key, captures ordered oldest→newest.
  const byFamily = new Map<string, EnrichedProvenance[]>();
  for (const r of rows) {
    const k = familyKey(r);
    const list = byFamily.get(k) ?? [];
    list.push(r);
    byFamily.set(k, list);
  }
  const families: DeviceFamily[] = [...byFamily.entries()].map(([key, list]) => {
    const sorted = [...list].sort((a, b) => a.capturedAt - b.capturedAt);
    return {
      key,
      vendor: sorted.find((r) => r.vendor)?.vendor ?? null,
      captures: sorted.map((r) => ({
        imageId: r.imageId,
        filename: r.filename,
        capturedAt: r.capturedAt,
        endpoint: r.endpoint,
        transport: r.transport,
        tlsPosture: r.tlsPosture,
        size: r.size,
        firmwareClass: r.firmwareClass,
      })),
      transports: uniq(list.map((r) => r.transport)),
      endpoints: uniq(list.map((r) => r.endpoint)),
    };
  });
  families.sort((a, b) => b.captures.length - a.captures.length);

  // Per-vendor priors — how each vendor was observed to ship.
  const byVendor = new Map<string, EnrichedProvenance[]>();
  for (const r of rows) {
    if (!r.vendor) continue;
    const list = byVendor.get(r.vendor) ?? [];
    list.push(r);
    byVendor.set(r.vendor, list);
  }
  const vendorPriors: VendorPrior[] = [...byVendor.entries()].map(([vendor, list]) => {
    const transports = uniq(list.map((r) => r.transport));
    let ships: VendorPrior['ships'] = 'unknown';
    if (transports.length === 1) {
      const t = transports[0];
      ships = t === 'http' ? 'plaintext-http' : t === 'https' ? 'https' : t === 'ble-gatt' ? 'ble-gatt' : 'unknown';
    } else if (transports.length > 1) {
      ships = 'mixed';
    }
    return { vendor, ships, cdns: uniq(list.map((r) => hostOf(r.endpoint))), captureCount: list.length };
  });
  vendorPriors.sort((a, b) => b.captureCount - a.captureCount);

  // CDN graph — which endpoint host serves which families.
  const byHost = new Map<string, Set<string>>();
  for (const r of rows) {
    const h = hostOf(r.endpoint);
    if (!h) continue;
    const set = byHost.get(h) ?? new Set<string>();
    set.add(familyKey(r));
    byHost.set(h, set);
  }
  const cdnGraph: CdnEdge[] = [...byHost.entries()].map(([host, fams]) => ({ host, families: [...fams] }));

  return { families, vendorPriors, cdnGraph };
}
