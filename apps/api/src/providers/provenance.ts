/**
 * Provenance fingerprint (Phase 5, deterministic, no network) — the byte-derived signals that hint at who made a
 * firmware and what product it is: vendor/brand markers, model numbers, version strings, update URLs and their
 * domains, certificate CNs, and bootloader/OS banners. Pure extraction from strings + identity; it invents
 * nothing. The external-intelligence node reasons over this to resolve manufacturer/product, always citing.
 */
import type { ImageIdentity } from '@firmlab/core';

export interface ProvenanceFingerprint {
  identity: { firmwareClass: string; arch: string; bootloader: string | null };
  vendors: string[];
  models: string[];
  versions: string[];
  urls: string[];
  domains: string[];
  certCNs: string[];
  banners: string[];
}

const RE_URL = /\bhttps?:\/\/[^\s"'<>）)]+/gi;
const RE_VERSION = /\bv?\d+\.\d+(?:\.\d+){0,2}\b/g;
const RE_CN = /\bCN\s*=\s*([^,/\n]{2,60})/gi;
const RE_MODEL = /\b[A-Z]{2,6}[- ]?\d{2,5}[A-Z0-9-]{0,6}\b/g;
const RE_COPYRIGHT = /copyright[^A-Za-z0-9]*(?:\(c\)|©)?\s*(?:\d{4}[-,\s]*)*([A-Z][\w&.\- ]{2,34}?)(?:\.|,|\s{2}|$)/i;
const BANNER_HINT = /(U-Boot|Linux version|Barebox|RedBoot|CFE|BusyBox v|OpenWrt|DD-WRT|VxWorks)/i;

const uniqCap = (xs: string[], n: number): string[] =>
  [...new Set(xs.map((x) => x.trim()).filter(Boolean))].slice(0, n);

/** Pure: derive the provenance fingerprint from a bag of strings plus the inferred identity. */
export function buildProvenanceFingerprint(strings: string[], identity: ImageIdentity): ProvenanceFingerprint {
  const urls: string[] = [];
  const versions: string[] = [];
  const vendors: string[] = [];
  const models: string[] = [];
  const certCNs: string[] = [];
  const banners: string[] = [];

  for (const s of strings) {
    if (!s) continue;
    const u = s.match(RE_URL);
    if (u) urls.push(...u);
    const v = s.match(RE_VERSION);
    if (v) versions.push(...v);
    const cn = [...s.matchAll(RE_CN)].map((m) => m[1] as string);
    if (cn.length) certCNs.push(...cn);
    const cr = s.match(RE_COPYRIGHT);
    if (cr?.[1]) vendors.push(cr[1]);
    if (BANNER_HINT.test(s)) banners.push(s.slice(0, 120));
    const m = s.match(RE_MODEL);
    if (m) models.push(...m);
  }

  const domains = uniqCap(
    urls
      .map((u) => {
        try {
          return new URL(u).hostname;
        } catch {
          return '';
        }
      })
      .filter(Boolean),
    20,
  );
  // A second-level domain is a strong vendor hint (netgear.com → netgear).
  for (const d of domains) {
    const parts = d.split('.');
    if (parts.length >= 2) vendors.push(parts[parts.length - 2] as string);
  }

  return {
    identity: {
      firmwareClass: identity.firmwareClass,
      arch: identity.arch,
      bootloader: identity.bootloader ?? null,
    },
    vendors: uniqCap(vendors, 12),
    models: uniqCap(models, 12),
    versions: uniqCap(versions, 12),
    urls: uniqCap(urls, 20),
    domains,
    certCNs: uniqCap(certCNs, 10),
    banners: uniqCap(banners, 8),
  };
}
