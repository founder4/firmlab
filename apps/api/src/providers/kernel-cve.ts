/**
 * Kernel CVE correlation glue.
 *
 * The posture provider establishes which kernel version is physically present. The research lane can then ask
 * NVD a narrower question: the Linux-kernel CPE at that upstream version, restricted to advisories issued by the
 * Linux kernel CNA. A broad Linux CPE query is deliberately forbidden here because it also matches applications
 * whose vulnerable configuration merely includes Linux.
 *
 * A version-range match is still only a lead. Firmware vendors backport fixes without changing the banner, and a
 * CVE may depend on a subsystem that was not built. Every resulting row therefore stays
 * `needs_runtime_reproduction`; the static fact is the version, not exploitability.
 */
import type { EvidenceChannel, FindingSeverity, ProofState } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';
import type { KernelPostureResult } from './kernelposture.js';
import { LINUX_KERNEL_CNA_SOURCE, type NvdCandidate, type NvdComponentResult } from './nvd.js';

export interface KernelCveSelection {
  candidate: NvdCandidate | null;
  detectedVersion: string | null;
  queryVersion: string | null;
  versionSource: KernelPostureResult['versionSource'];
  reason: string;
}

/**
 * Reduce a vendor-suffixed banner (`2.6.31--LSDK-…`) to the upstream release token NVD indexes. Refuse a
 * conflicting posture result rather than silently picking one of two incompatible version claims.
 */
export function selectKernelCveCandidate(posture: KernelPostureResult): KernelCveSelection {
  const base = {
    detectedVersion: posture.version,
    versionSource: posture.versionSource,
  };
  if (!posture.located || !posture.version) {
    return { ...base, candidate: null, queryVersion: null, reason: 'No kernel version was established.' };
  }
  if (posture.versionConflicts.length > 0) {
    return {
      ...base,
      candidate: null,
      queryVersion: null,
      reason: `${posture.versionConflicts.length} kernel version source conflict(s) remain unresolved.`,
    };
  }
  const token = /^(\d+\.\d+(?:\.\d+)?)/.exec(posture.version.trim())?.[1] ?? null;
  if (!token) {
    return { ...base, candidate: null, queryVersion: null, reason: 'The detected version has no upstream token.' };
  }
  return {
    ...base,
    candidate: { name: 'linux-kernel', version: token },
    queryVersion: token,
    reason: `Linux ${posture.version} is queryable as upstream ${token} (source: ${posture.versionSource}).`,
  };
}

function advisorySeverity(raw: string | null): FindingSeverity {
  switch (raw?.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'info';
  }
}

/** Turn the shown prefix of a successful kernel-CNA answer into durable, explicitly provisional ledger rows. */
export function normalizeKernelCves(selection: KernelCveSelection, component: NvdComponentResult): FindingDraft[] {
  if (!selection.candidate || component.name !== 'linux-kernel') return [];
  const shown = component.advisories.length;
  const total = component.totalMatching;
  const prefix = total !== null && total > shown;
  return component.advisories.map((advisory) => ({
    kind: 'kernel-cve-candidate',
    title: `${advisory.id} — Linux kernel ${selection.detectedVersion ?? component.version}`,
    severity: advisorySeverity(advisory.severity),
    proofState: 'needs_runtime_reproduction' as ProofState,
    evidenceChannel: 'external_advisory' as EvidenceChannel,
    evidence: {
      id: advisory.id,
      detectedVersion: selection.detectedVersion,
      queryVersion: selection.queryVersion,
      versionSource: selection.versionSource,
      matchedBy: component.matchedBy,
      cnaSourceIdentifier: LINUX_KERNEL_CNA_SOURCE,
      score: advisory.score,
      summary: advisory.summary,
      references: advisory.references,
      shown,
      totalMatching: total,
      truncated: prefix,
      freshness: component.freshness,
    },
    rationale: `NVD places upstream Linux ${selection.queryVersion} inside this advisory's affected CPE range, and the query is restricted to the Linux kernel CNA. The firmware's version was read from ${selection.versionSource}. This is a candidate, not a confirmed device vulnerability: vendor backports may keep the same banner, the affected subsystem may be absent or disabled, and reachability has not been reproduced.${
      prefix
        ? ` NVD reports ${total} matching kernel advisories; this run retained the first ${shown}, so the rows are a prefix rather than the complete set.`
        : ''
    }`,
  }));
}
