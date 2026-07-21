/**
 * External-intelligence synthesis (Phase 5) — the interpretation layer over the deterministic research providers
 * (provenance fingerprint + OSV advisories) plus the corpus's reachability priors. Like the copilot it produces a
 * cited brief and invents nothing: a published advisory for a present component is a LEAD, never a confirmed
 * vulnerability of THIS image — reachability is decided per-image. It also drafts responsible-disclosure next
 * steps (find the vendor security contact; the human sends anything). Defensive only.
 *
 * The prompt builders are pure; runIntelSynthesis is the thin LLM call.
 */
import type { LlmConfig, LlmResult } from '../llm.js';
import { complete } from '../llm.js';
import type { KevResult } from '../providers/kev.js';
import type { KeyMaterial } from '../providers/keys.js';
import type { NvdBatchResult } from '../providers/nvd.js';
import type { OsvBatchResult } from '../providers/osv.js';
import type { ProvenanceFingerprint } from '../providers/provenance.js';
import type { SecurityTxt } from '../providers/securitytxt.js';

export interface IntelContext {
  provenance: ProvenanceFingerprint;
  osv: OsvBatchResult;
  /** NVD advisories (by keyword) for the components OSV could not map to an ecosystem — same lead discipline. */
  nvd: NvdBatchResult;
  /** CISA KEV cross-reference: which discovered CVEs are known-exploited in the wild (priority, not reachability). */
  kev: KevResult;
  /** Components/subjects the corpus has actually seen reachable in this device family — priors, not verdicts. */
  reachablePriors: { subject: string; proofState: string }[];
  /** Phase 5.2: embedded key material (redacted). Private keys in firmware are effectively public. */
  keyMaterial: KeyMaterial[];
  /** Phase 5.3: vendor security contacts discovered from security.txt (allowlisted domains only). */
  securityContacts: SecurityTxt[];
}

export const INTEL_SYSTEM_PROMPT = `You are FirmLab's external-intelligence analyst. You are given deterministic
signals gathered locally (a provenance fingerprint) and from allowlisted public sources — OSV and NVD published
advisories for the firmware's SBOM components, and the CISA KEV catalog (CVEs known-exploited in the wild) — plus
the corpus's reachability priors. Produce a concise, CITED intelligence brief.

Rules, non-negotiable:
1. Cite every external claim to its source (OSV advisory ID / NVD CVE ID / CVE alias / URL). Never invent an
   advisory, a CVE, a vendor, or a product. OSV and NVD may report the same CVE — dedupe by CVE ID when you can.
2. A published advisory for a component that is merely PRESENT is a lead, NOT a confirmed vulnerability of this
   image. Say "reachability unverified" unless a corpus prior or prior reproduction supports it. Do not upgrade.
3. KEV membership means the CVE is KNOWN-EXPLOITED in the wild globally — it raises PRIORITY, but it does NOT
   confirm reachability here. Surface KEV-listed CVEs first and label them "known-exploited (KEV) · reachability
   unverified". Note \`knownRansomware: Known\` when present.
4. Provenance (vendor/product/model) is your best inference from the fingerprint — hedge it honestly and say what
   evidence supports it.
5. Key material: an embedded PRIVATE key is extractable from any device and is therefore effectively public /
   shared across the product line — call that out plainly. \`sharedInImages\` > 0 is direct proof of cross-device
   reuse. Never print key values; they are redacted.
6. Defensive only. If findings look serious, DRAFT a responsible-disclosure report and give concrete next steps. Use
   the discovered security contact (security.txt) when present; if a domain wasn't checked, say to add it to the
   allowlist. Draft — NEVER send. No exploitation, no publication.

Structure the brief as: Provenance (vendor/product/firmware family, with confidence) · Priority: known-exploited
(KEV) CVEs first, each cited and marked reachability-unverified · Known advisories (grouped by component, most
severe first, each cited via OSV/NVD, each marked reachability-unverified unless a prior supports it) · Key
material (embedded/shared keys, effectively public) · Responsible disclosure (security contact + a short report
draft). Output concise GitHub-flavored markdown.`;

export function buildIntelUserPrompt(ctx: IntelContext): string {
  return [
    'Write the intelligence brief from these deterministic + public-source results:',
    '',
    '```json',
    JSON.stringify(ctx, null, 2),
    '```',
  ].join('\n');
}

export async function runIntelSynthesis(ctx: IntelContext, cfg: LlmConfig): Promise<LlmResult> {
  return complete(INTEL_SYSTEM_PROMPT, buildIntelUserPrompt(ctx), cfg);
}
