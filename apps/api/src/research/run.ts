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
import { deviceFamilyKey, listReachabilityPriors } from '../corpus.js';
import { loadLlmConfig } from '../llm.js';
import type { JobHandle } from '../providers/jobs.js';
import { type OsvBatchResult, queryOsvBatch } from '../providers/osv.js';
import { type ProvenanceFingerprint, buildProvenanceFingerprint } from '../providers/provenance.js';
import type { SbomResult } from '../providers/sbom.js';
import { getImage, listJobs } from '../store.js';
import { loadResearchConfig } from './config.js';
import { type EgressLedger, buildEgressLedger } from './egress.js';

export interface ResearchResult {
  enabled: true;
  provenance: ProvenanceFingerprint;
  egress: EgressLedger;
  osv: OsvBatchResult;
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

/** Deterministic, local: pull banner strings from the extracted rootfs (bounded), for the provenance fingerprint. */
function rootfsProvenanceStrings(imageId: string): string[] {
  const extractJob = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  const rootfs = extractJob?.resultJson
    ? (JSON.parse(extractJob.resultJson) as { rootfsPath?: string }).rootfsPath
    : null;
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
  const egress = buildEgressLedger(packages, provenance);

  handle.log(`Egress: ${packages.length} component names+versions → api.osv.dev (no firmware bytes leave).`);
  const osv = await queryOsvBatch(packages, cfg);
  handle.log(
    `OSV: ${osv.queried} queried, ${osv.skipped} unmapped, ${osv.withAdvisories} with advisories (${osv.totalAdvisories} total).`,
  );

  let synthesis: ResearchResult['synthesis'];
  const llm = loadLlmConfig();
  if (llm) {
    const reachablePriors = listReachabilityPriors(deviceFamilyKey(identity))
      .filter((p) => p.proofState === 'confirmed_in_emulation' || p.proofState === 'confirmed_full_system')
      .slice(0, 10)
      .map((p) => ({ subject: p.subject, proofState: p.proofState }));
    const ctx: IntelContext = { provenance, osv, reachablePriors };
    handle.log(`Synthesizing cited intelligence brief via ${llm.provider} (${llm.model})…`);
    const r = await runIntelSynthesis(ctx, llm);
    synthesis = { text: r.text, model: r.model, provider: r.provider };
  }

  return { enabled: true, provenance, egress, osv, ...(synthesis ? { synthesis } : {}) };
}
