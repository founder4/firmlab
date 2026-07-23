/**
 * The external-intelligence run (Phase 5) — orchestrates the deterministic providers and the optional synthesis:
 * provenance fingerprint (local) → egress ledger (what will leave) → OSV correlation (allowlisted, names+versions
 * only) → cited intelligence brief (if the LLM layer is on). Refuses to run unless FIRMLAB_RESEARCH is set, so the
 * default posture stays local-only.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { StaticAnalysis } from '@firmlab/core';
import { type IntelContext, runIntelSynthesis } from '../agent/intel.js';
import { credentialOtherImages, deviceFamilyKey, hashSecret, listReachabilityPriors } from '../corpus.js';
import { syncFindings } from '../findings.js';
import { loadLlmConfig } from '../llm.js';
import { parseShadow } from '../providers/fsaudit.js';
import {
  type HashCandidate,
  type HashLookupResult,
  classifyHash,
  normalizeHashLookup,
  runHashLookup,
} from '../providers/hashlookup.js';
import type { JobHandle } from '../providers/jobs.js';
import { type KevResult, collectCveIds, fetchAndMatchKev } from '../providers/kev.js';
import { type KeyMaterial, summarizeKeyMaterial } from '../providers/keys.js';
import { type NvdBatchResult, queryNvdBatch } from '../providers/nvd.js';
import { type OsvBatchResult, osvEcosystem, queryOsvBatch } from '../providers/osv.js';
import { type ProvenanceFingerprint, buildProvenanceFingerprint } from '../providers/provenance.js';
import type { SbomResult } from '../providers/sbom.js';
import { type SecurityTxt, fetchSecurityTxt } from '../providers/securitytxt.js';
import { getImage, listJobs } from '../store.js';
import { loadResearchConfig } from './config.js';
import { type EgressLedger, buildEgressLedger } from './egress.js';

export interface ResearchResult {
  enabled: true;
  provenance: ProvenanceFingerprint;
  egress: EgressLedger;
  osv: OsvBatchResult;
  nvd: NvdBatchResult;
  kev: KevResult;
  keyMaterial: KeyMaterial[];
  securityContacts: SecurityTxt[];
  hashLookup: HashLookupResult;
  synthesis?: { text: string; model: string; provider: string };
}

/** Well-known rootfs files that carry vendor/product/version banners. Read locally to enrich provenance. */
const PROVENANCE_FILES = [
  'etc/issue',
  'etc/os-release',
  'usr/lib/os-release',
  'etc/banner',
  'etc/openwrt_release',
  'etc/version',
  'etc/motd',
  'etc/hostname',
];

function latestRootfs(imageId: string): string | null {
  const extractJob = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return extractJob?.resultJson
    ? ((JSON.parse(extractJob.resultJson) as { rootfsPath?: string }).rootfsPath ?? null)
    : null;
}

/**
 * Collect the password-hash candidates for the online lookup from the extracted rootfs's /etc/shadow (parsed with
 * the same pure parser fsaudit uses). Bounded read; missing/oversized shadow → no candidates. The lookup provider
 * itself decides which are resolvable — this only gathers account+hash pairs.
 */
function collectShadowCandidates(imageId: string): HashCandidate[] {
  const rootfs = latestRootfs(imageId);
  if (!rootfs) return [];
  const shadowPath = path.join(rootfs, 'etc/shadow');
  try {
    if (!fs.existsSync(shadowPath) || !fs.statSync(shadowPath).isFile() || fs.statSync(shadowPath).size > 65536) {
      return [];
    }
    return parseShadow(fs.readFileSync(shadowPath, 'utf8')).map((s) => ({
      account: s.name,
      hash: s.hash,
      source: '/etc/shadow',
    }));
  } catch {
    return [];
  }
}

/** Key material lives inside the (compressed) filesystem, so it's only visible after extraction — scan the rootfs. */
const KEY_MARKERS: { re: RegExp; kind: string }[] = [
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, kind: 'private-key' },
  { re: /-----BEGIN CERTIFICATE-----/, kind: 'certificate' },
];

/** Bounded rootfs walk that finds embedded key material (private keys are effectively public — extractable). */
function scanRootfsKeys(imageId: string): KeyMaterial[] {
  const rootfs = latestRootfs(imageId);
  if (!rootfs) return [];
  const out: KeyMaterial[] = [];
  const stack = [rootfs];
  let visited = 0;
  while (stack.length > 0 && visited < 4000 && out.length < 20) {
    const cur = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      visited++;
      const abs = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(abs);
      else if (e.isFile()) {
        try {
          if (fs.statSync(abs).size >= 32768) continue;
          const txt = fs.readFileSync(abs, 'utf8');
          for (const { re, kind } of KEY_MARKERS) {
            const m = txt.match(re);
            if (m) {
              out.push({ kind, redacted: `${e.name}: ${m[0]}…`, effectivelyPublic: kind === 'private-key' });
              break;
            }
          }
        } catch {
          // unreadable / binary — skip
        }
      }
    }
  }
  return out;
}

/** Deterministic, local: pull banner strings from the extracted rootfs (bounded), for the provenance fingerprint. */
function rootfsProvenanceStrings(imageId: string): string[] {
  const rootfs = latestRootfs(imageId);
  if (!rootfs) return [];
  const out: string[] = [];
  for (const rel of PROVENANCE_FILES) {
    try {
      const p = path.join(rootfs, rel);
      if (fs.existsSync(p) && fs.statSync(p).isFile() && fs.statSync(p).size < 16384) {
        out.push(...fs.readFileSync(p, 'utf8').split('\n'));
      }
    } catch {
      // unreadable / vanished — skip
    }
  }
  return out;
}

export async function runResearch(imageId: string, handle: JobHandle): Promise<ResearchResult> {
  const cfg = loadResearchConfig();
  if (!cfg) throw new Error('External research disabled — set FIRMLAB_RESEARCH=1');
  const row = getImage(imageId);
  if (!row?.analysisJson || !row.identityJson) throw new Error('No analysis for this image');

  const analysis = JSON.parse(row.analysisJson) as StaticAnalysis;
  const identity = JSON.parse(row.identityJson);
  const strings = [
    ...analysis.secrets.map((s) => s.value),
    ...analysis.signatures.map((s) => s.description),
    ...rootfsProvenanceStrings(imageId),
    identity.bootloader ?? '',
  ];
  const provenance = buildProvenanceFingerprint(strings, identity);

  const sbomJob = listJobs(imageId).find((j) => j.kind === 'sbom' && j.status === 'done' && j.resultJson);
  const packages = sbomJob?.resultJson ? (JSON.parse(sbomJob.resultJson) as SbomResult).packages : [];
  // NVD covers exactly OSV's gap: the components OSV can't map to an ecosystem. Compute that set up front so the
  // egress ledger can declare precisely how many names go to NVD before anything leaves.
  const nvdCandidates = packages.filter((p) => !osvEcosystem(p.type));
  // Hash-lookup candidates (from /etc/shadow) — gathered up front so the egress ledger can declare exactly how many
  // UNSALTED hashes would leave before anything does. Salted hashes are counted out here and never sent.
  const hashCandidates = cfg.hashLookup ? collectShadowCandidates(imageId) : [];
  const unsaltedCount = hashCandidates.filter((c) => classifyHash(c.hash).resolvable).length;
  const egress = buildEgressLedger(packages, provenance, {
    nvdCandidates: nvdCandidates.length,
    hashLookup: { enabled: cfg.hashLookup, unsaltedCount },
  });

  handle.log(`Egress: ${packages.length} component names+versions → api.osv.dev (no firmware bytes leave).`);
  const osv = await queryOsvBatch(packages, cfg);
  handle.log(
    `OSV: ${osv.queried} queried, ${osv.skipped} unmapped, ${osv.withAdvisories} with advisories (${osv.totalAdvisories} total).`,
  );

  // Source #2 — NVD by keyword for the OSV-unmapped components (rate-limit capped; honest about what it skipped).
  const nvd = await queryNvdBatch(nvdCandidates, cfg);
  handle.log(
    `NVD: ${nvd.queried} queried${nvd.notQueried > 0 ? ` (${nvd.notQueried} more skipped — rate-limit cap)` : ''}, ${nvd.withAdvisories} with advisories (${nvd.totalAdvisories} total).`,
  );

  // Source #3 — CISA KEV: which of the discovered CVEs are known-exploited in the wild. Downloads the public
  // catalog and cross-references locally, so nothing about the firmware leaves for this step.
  const cveIds = collectCveIds(osv.components, nvd.components);
  const kev = await fetchAndMatchKev(cveIds, cfg);
  handle.log(
    kev.checked
      ? `KEV: ${cveIds.length} discovered CVEs cross-referenced → ${kev.matches.length} known-exploited (catalog: ${kev.catalogSize}).`
      : `KEV: not checked (${kev.reason}).`,
  );

  // 5.2 — embedded key material from the image (corpus-cross-referenced) + a scan of the extracted rootfs, where
  // key files actually live (compressed out of the image-level view). An embedded private key is effectively public.
  const imageKeys = summarizeKeyMaterial(analysis.secrets).map((k) => {
    const src = analysis.secrets.find((s) => s.offset === k.offset);
    const shared = src ? credentialOtherImages(hashSecret(src.value), imageId).length : 0;
    return { ...k, sharedInImages: shared };
  });
  const rootfsKeys = scanRootfsKeys(imageId);
  const seenKeys = new Set(imageKeys.map((k) => k.redacted));
  const keyMaterial = [...imageKeys, ...rootfsKeys.filter((k) => !seenKeys.has(k.redacted))];

  // 5.3 — vendor security contacts from security.txt, but only for domains the operator allowlisted.
  const securityContacts: SecurityTxt[] = [];
  for (const domain of provenance.domains.slice(0, 5)) {
    securityContacts.push(await fetchSecurityTxt(domain, cfg));
  }
  const checked = securityContacts.filter((c) => c.checked).length;
  handle.log(
    `Keys: ${keyMaterial.length} embedded. Disclosure: ${checked}/${securityContacts.length} domains checked.`,
  );

  // Source #5 — online password-hash lookup (opt-in on top of the track, FIRMLAB_HASH_LOOKUP). Sends only unsalted
  // digests to public reverse-hash DBs, verifies any recovery locally, and never cracks. A verified recovery is a
  // durable, critical finding; misses/salted-skips are reported but are not findings.
  if (cfg.hashLookup && hashCandidates.length > 0) {
    handle.log(`Hash lookup: ${unsaltedCount} unsalted hash(es) → nitrxgen/weakpass (salted hashes are not sent).`);
  }
  const hashLookup = await runHashLookup(hashCandidates, cfg);
  syncFindings(imageId, 'hashlookup', normalizeHashLookup(hashLookup));
  if (hashLookup.enabled) handle.log(hashLookup.reason);

  let synthesis: ResearchResult['synthesis'];
  const llm = loadLlmConfig();
  if (llm) {
    const reachablePriors = listReachabilityPriors(deviceFamilyKey(identity))
      .filter((p) => p.proofState === 'confirmed_in_emulation' || p.proofState === 'confirmed_full_system')
      .slice(0, 10)
      .map((p) => ({ subject: p.subject, proofState: p.proofState }));
    const ctx: IntelContext = { provenance, osv, nvd, kev, reachablePriors, keyMaterial, securityContacts };
    handle.log(`Synthesizing cited intelligence brief via ${llm.provider} (${llm.model})…`);
    const r = await runIntelSynthesis(ctx, llm);
    synthesis = { text: r.text, model: r.model, provider: r.provider };
  }

  return {
    enabled: true,
    provenance,
    egress,
    osv,
    nvd,
    kev,
    keyMaterial,
    securityContacts,
    hashLookup,
    ...(synthesis ? { synthesis } : {}),
  };
}
