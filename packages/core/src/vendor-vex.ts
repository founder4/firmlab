/**
 * Pure, bounded parser and resolver for vendor vulnerability-exploitability (VEX) documents.
 *
 * Firmware images frequently ship vendor-authored advisory or exploitability assertions embedded
 * directly in root filesystems (e.g. OpenVEX JSON or CSAF 2.0 VEX profile JSON). This module parses
 * those assertions and correlates them against candidate findings by exact CVE identifier and accepted
 * component product identifiers.
 *
 * What this module refuses to claim:
 *
 *   - A vendor document is a claim found in the bytes, NOT a code fact or proof state. It never sets,
 *     changes, or elevates a finding's ProofState (e.g. it cannot turn a finding into static_confirmed
 *     or false_positive). Code and execution evidence alone decide proof state.
 *   - A vendor assertion NEVER suppresses or deletes a finding row. It only attaches a descriptive
 *     verdict indicating the vendor's asserted posture.
 *   - Silence is not agreement or cleanliness: an unmentioned CVE or missing document is explicitly
 *     reported as `unmentioned`, and stated as NOT evidence of absence or cleanliness.
 *   - No fuzzy matching: product matching requires exact CVE identifier match and explicit acceptance
 *     by the caller's component matcher. We never guess that "linux" matches an arbitrary product string.
 *   - Disagreeing statements are marked `conflicting`, never resolved by document order or precedence.
 *   - Resource limits are strictly enforced: oversized documents, statement caps, and product caps
 *     report exact counts dropped and the rule applied (document order). Malformed or non-VEX inputs
 *     return structured refusals without throwing.
 */

export const DEFAULT_MAX_VEX_DOCUMENT_BYTES = 4 * 1024 * 1024; // 4 MiB
export const DEFAULT_MAX_VEX_STATEMENTS = 2000;
export const DEFAULT_MAX_VEX_PRODUCTS = 2000;
export const VEX_BOUNDS_RULE =
  'document_order: statements and products beyond configured limits are dropped in document order';

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

export type VendorVexFormat = 'openvex' | 'csaf_vex';

export type VendorVexStatus = 'not_affected' | 'fixed' | 'affected' | 'under_investigation';

export type VendorVexVerdictKind =
  | 'vendor_states_fixed'
  | 'vendor_states_not_affected'
  | 'vendor_states_affected'
  | 'vendor_under_investigation'
  | 'conflicting'
  | 'unmentioned';

export interface VendorVexStatement {
  readonly statementIndex: number;
  readonly vulnerabilityId: string;
  readonly status: VendorVexStatus;
  readonly products: readonly string[];
  readonly justification?: string | undefined;
  readonly impactStatement?: string | undefined;
  readonly actionStatement?: string | undefined;
  readonly statusNotes?: string | undefined;
}

export interface VendorVexLimits {
  readonly maxDocumentBytes?: number | undefined;
  readonly maxStatements?: number | undefined;
  readonly maxProducts?: number | undefined;
}

export interface VendorVexDocument {
  readonly ok: true;
  readonly format: VendorVexFormat;
  readonly sourcePath: string;
  readonly author: string | null;
  readonly timestamp: string | null;
  readonly statements: readonly VendorVexStatement[];
  readonly droppedStatementsCount: number;
  readonly droppedProductsCount: number;
  readonly ignoredNonCveCount: number;
  readonly boundsRule: string;
}

export type VendorVexRefusalReason = 'malformed_json' | 'non_vex_json' | 'oversized_document';

export interface VendorVexRefusal {
  readonly ok: false;
  readonly reason: VendorVexRefusalReason;
  readonly message: string;
  readonly sourcePath: string;
  readonly bytesExamined: number;
  readonly maxBytes: number;
}

export type VendorVexParseResult = VendorVexDocument | VendorVexRefusal;

export interface VendorVexVerdict {
  readonly verdict: VendorVexVerdictKind;
  readonly sourcePath: string | null;
  readonly statementIndex: number | null;
  readonly justification: string | null;
  readonly author: string | null;
  readonly timestamp: string | null;
  readonly documentAuthor: string | null;
  readonly documentTimestamp: string | null;
  readonly rationale: string;
  readonly impactStatement?: string | null | undefined;
  readonly actionStatement?: string | null | undefined;
  readonly conflictingStatements?: readonly VendorVexStatement[] | undefined;
  readonly matchedStatements?: readonly VendorVexStatement[] | undefined;
}

export type ProductMatcherPredicate = (productId: string) => boolean;

export type ProductMatcher = ProductMatcherPredicate | readonly string[] | ReadonlySet<string> | string;

export function isVendorVexDocument(result: unknown): result is VendorVexDocument {
  return (
    result !== null &&
    typeof result === 'object' &&
    (result as { ok?: unknown }).ok === true &&
    Array.isArray((result as { statements?: unknown }).statements)
  );
}

function getUtf8ByteLength(text: string): number {
  if (typeof Buffer !== 'undefined') {
    return Buffer.byteLength(text, 'utf8');
  }
  return new TextEncoder().encode(text).length;
}

function normalizeCveId(rawId: string): string | null {
  const trimmed = rawId.trim();
  if (CVE_ID_PATTERN.test(trimmed)) {
    return trimmed.toUpperCase();
  }
  return null;
}

function extractOpenVexVulnerabilityId(vuln: unknown): string | null {
  if (typeof vuln === 'string') {
    const trimmed = vuln.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  if (vuln !== null && typeof vuln === 'object') {
    const obj = vuln as Record<string, unknown>;
    if (typeof obj.name === 'string' && obj.name.trim().length > 0) {
      return obj.name.trim();
    }
    if (typeof obj.id === 'string' && obj.id.trim().length > 0) {
      return obj.id.trim();
    }
    if (typeof obj['@id'] === 'string' && obj['@id'].trim().length > 0) {
      return obj['@id'].trim();
    }
  }
  return null;
}

function parseVexStatus(status: unknown): VendorVexStatus | null {
  if (typeof status !== 'string') return null;
  const normalized = status.toLowerCase().trim().replace(/-/g, '_');
  if (
    normalized === 'not_affected' ||
    normalized === 'fixed' ||
    normalized === 'affected' ||
    normalized === 'under_investigation'
  ) {
    return normalized;
  }
  return null;
}

function extractOpenVexProducts(productsRaw: unknown, subcomponentsRaw: unknown): string[] {
  const result: string[] = [];
  const collect = (arr: unknown) => {
    if (!Array.isArray(arr)) return;
    for (const item of arr) {
      if (typeof item === 'string') {
        const trimmed = item.trim();
        if (trimmed.length > 0) result.push(trimmed);
      } else if (item !== null && typeof item === 'object') {
        const obj = item as Record<string, unknown>;
        const id = typeof obj['@id'] === 'string' ? obj['@id'] : typeof obj.id === 'string' ? obj.id : null;
        if (id && id.trim().length > 0) {
          result.push(id.trim());
        }
      }
    }
  };
  collect(productsRaw);
  collect(subcomponentsRaw);
  return result;
}

interface RawStatementCandidate {
  vulnerabilityId: string;
  status: VendorVexStatus;
  products: string[];
  justification?: string | undefined;
  impactStatement?: string | undefined;
  actionStatement?: string | undefined;
  statusNotes?: string | undefined;
}

function buildCsafProductTreeMap(productTreeRaw: unknown): Map<string, string[]> {
  const map = new Map<string, string[]>();
  if (productTreeRaw === null || typeof productTreeRaw !== 'object') return map;
  const tree = productTreeRaw as Record<string, unknown>;

  if (Array.isArray(tree.full_product_names)) {
    for (const item of tree.full_product_names) {
      if (item !== null && typeof item === 'object') {
        const obj = item as Record<string, unknown>;
        const pid = typeof obj.product_id === 'string' ? obj.product_id.trim() : null;
        if (!pid) continue;
        const aliases: string[] = [];
        if (typeof obj.name === 'string' && obj.name.trim().length > 0) {
          aliases.push(obj.name.trim());
        }
        if (obj.product_identification_helper !== null && typeof obj.product_identification_helper === 'object') {
          const helper = obj.product_identification_helper as Record<string, unknown>;
          if (typeof helper.purl === 'string' && helper.purl.trim().length > 0) {
            aliases.push(helper.purl.trim());
          }
          if (typeof helper.cpe === 'string' && helper.cpe.trim().length > 0) {
            aliases.push(helper.cpe.trim());
          }
        }
        if (aliases.length > 0) {
          map.set(pid, aliases);
        }
      }
    }
  }

  return map;
}

function applyBounds(
  candidates: readonly RawStatementCandidate[],
  maxStatements: number,
  maxProducts: number,
): {
  statements: VendorVexStatement[];
  droppedStatementsCount: number;
  droppedProductsCount: number;
} {
  const totalStatements = candidates.length;
  const retainedCandidates = candidates.slice(0, maxStatements);
  const droppedStatementsCount = Math.max(0, totalStatements - maxStatements);

  let totalProductsExamined = 0;
  let droppedProductsCount = 0;
  const statements: VendorVexStatement[] = [];

  for (let i = 0; i < retainedCandidates.length; i++) {
    const candidate = retainedCandidates[i];
    if (!candidate) continue;

    const acceptedProducts: string[] = [];
    for (const prod of candidate.products) {
      if (totalProductsExamined < maxProducts) {
        acceptedProducts.push(prod);
        totalProductsExamined++;
      } else {
        droppedProductsCount++;
      }
    }

    statements.push({
      statementIndex: i,
      vulnerabilityId: candidate.vulnerabilityId,
      status: candidate.status,
      products: acceptedProducts,
      ...(candidate.justification ? { justification: candidate.justification } : {}),
      ...(candidate.impactStatement ? { impactStatement: candidate.impactStatement } : {}),
      ...(candidate.actionStatement ? { actionStatement: candidate.actionStatement } : {}),
      ...(candidate.statusNotes ? { statusNotes: candidate.statusNotes } : {}),
    });
  }

  return {
    statements,
    droppedStatementsCount,
    droppedProductsCount,
  };
}

/**
 * Pure, bounded parser for OpenVEX JSON and CSAF 2.0 VEX profile JSON documents.
 * Never throws on malformed, non-VEX, or oversized input; returns a structured refusal instead.
 */
export function parseVendorVex(rawText: string, sourcePath: string, limits?: VendorVexLimits): VendorVexParseResult {
  const maxBytes = limits?.maxDocumentBytes ?? DEFAULT_MAX_VEX_DOCUMENT_BYTES;
  const maxStatements = limits?.maxStatements ?? DEFAULT_MAX_VEX_STATEMENTS;
  const maxProducts = limits?.maxProducts ?? DEFAULT_MAX_VEX_PRODUCTS;

  const byteLength = getUtf8ByteLength(rawText);
  if (byteLength > maxBytes) {
    return {
      ok: false,
      reason: 'oversized_document',
      message: `Document size of ${byteLength} bytes exceeds limit of ${maxBytes} bytes; parsing refused to bound resource consumption.`,
      sourcePath,
      bytesExamined: byteLength,
      maxBytes,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    return {
      ok: false,
      reason: 'malformed_json',
      message: `Malformed JSON: ${err instanceof Error ? err.message : String(err)}`,
      sourcePath,
      bytesExamined: byteLength,
      maxBytes,
    };
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      ok: false,
      reason: 'non_vex_json',
      message: 'JSON document must be an object representing an OpenVEX or CSAF 2.0 VEX document.',
      sourcePath,
      bytesExamined: byteLength,
      maxBytes,
    };
  }

  const root = parsed as Record<string, unknown>;

  // Check OpenVEX format
  const hasOpenVexContext =
    (typeof root['@context'] === 'string' && root['@context'].includes('openvex')) ||
    (Array.isArray(root['@context']) &&
      root['@context'].some((c: unknown) => typeof c === 'string' && c.includes('openvex')));

  const isOpenVex =
    (hasOpenVexContext && Array.isArray(root.statements)) ||
    (Array.isArray(root.statements) &&
      root.statements.length > 0 &&
      typeof (root.statements[0] as Record<string, unknown> | undefined)?.status === 'string' &&
      typeof (root.statements[0] as Record<string, unknown> | undefined)?.vulnerability !== 'undefined');

  // Check CSAF 2.0 VEX profile format
  const documentObj =
    root.document !== null && typeof root.document === 'object' ? (root.document as Record<string, unknown>) : null;
  const csafCategory = typeof documentObj?.category === 'string' ? documentObj.category.toLowerCase().trim() : null;
  const isCsaf = csafCategory === 'csaf_vex' && Array.isArray(root.vulnerabilities);

  if (!isOpenVex && !isCsaf) {
    return {
      ok: false,
      reason: 'non_vex_json',
      message:
        'Document JSON does not match OpenVEX (@context/statements) or CSAF 2.0 VEX profile (document.category "csaf_vex" with vulnerabilities).',
      sourcePath,
      bytesExamined: byteLength,
      maxBytes,
    };
  }

  let ignoredNonCveCount = 0;
  const rawCandidates: RawStatementCandidate[] = [];

  if (isOpenVex) {
    const author =
      typeof root.author === 'string' && root.author.trim().length > 0
        ? root.author.trim()
        : root.author !== null &&
            typeof root.author === 'object' &&
            typeof (root.author as Record<string, unknown>).name === 'string'
          ? ((root.author as Record<string, unknown>).name as string).trim()
          : typeof root.vendor === 'string' && root.vendor.trim().length > 0
            ? root.vendor.trim()
            : null;

    const timestamp =
      typeof root.timestamp === 'string' && root.timestamp.trim().length > 0
        ? root.timestamp.trim()
        : typeof root.last_updated === 'string' && root.last_updated.trim().length > 0
          ? root.last_updated.trim()
          : null;

    const statementsArray = Array.isArray(root.statements) ? root.statements : [];

    for (const stmtItem of statementsArray) {
      if (stmtItem === null || typeof stmtItem !== 'object') continue;
      const stmt = stmtItem as Record<string, unknown>;

      const rawVulnId = extractOpenVexVulnerabilityId(stmt.vulnerability);
      if (!rawVulnId) {
        ignoredNonCveCount++;
        continue;
      }

      const normalizedCve = normalizeCveId(rawVulnId);
      if (!normalizedCve) {
        ignoredNonCveCount++;
        continue;
      }

      const status = parseVexStatus(stmt.status);
      if (!status) continue;

      const products = extractOpenVexProducts(stmt.products, stmt.subcomponents);
      const justification =
        typeof stmt.justification === 'string' && stmt.justification.trim().length > 0
          ? stmt.justification.trim()
          : undefined;
      const impactStatement =
        typeof stmt.impact_statement === 'string' && stmt.impact_statement.trim().length > 0
          ? stmt.impact_statement.trim()
          : undefined;
      const actionStatement =
        typeof stmt.action_statement === 'string' && stmt.action_statement.trim().length > 0
          ? stmt.action_statement.trim()
          : undefined;
      const statusNotes =
        typeof stmt.status_notes === 'string' && stmt.status_notes.trim().length > 0
          ? stmt.status_notes.trim()
          : undefined;

      rawCandidates.push({
        vulnerabilityId: normalizedCve,
        status,
        products,
        ...(justification ? { justification } : {}),
        ...(impactStatement ? { impactStatement } : {}),
        ...(actionStatement ? { actionStatement } : {}),
        ...(statusNotes ? { statusNotes } : {}),
      });
    }

    const { statements, droppedStatementsCount, droppedProductsCount } = applyBounds(
      rawCandidates,
      maxStatements,
      maxProducts,
    );

    return {
      ok: true,
      format: 'openvex',
      sourcePath,
      author,
      timestamp,
      statements,
      droppedStatementsCount,
      droppedProductsCount,
      ignoredNonCveCount,
      boundsRule: VEX_BOUNDS_RULE,
    };
  }

  // CSAF 2.0 VEX profile
  const publisherObj =
    documentObj?.publisher !== null && typeof documentObj?.publisher === 'object'
      ? (documentObj?.publisher as Record<string, unknown>)
      : null;
  const author =
    typeof publisherObj?.name === 'string' && publisherObj.name.trim().length > 0
      ? publisherObj.name.trim()
      : typeof documentObj?.publisher === 'string' && documentObj.publisher.trim().length > 0
        ? documentObj.publisher.trim()
        : null;

  const trackingObj =
    documentObj?.tracking !== null && typeof documentObj?.tracking === 'object'
      ? (documentObj?.tracking as Record<string, unknown>)
      : null;
  const timestamp =
    typeof trackingObj?.current_release_date === 'string' && trackingObj.current_release_date.trim().length > 0
      ? trackingObj.current_release_date.trim()
      : typeof trackingObj?.initial_release_date === 'string' && trackingObj.initial_release_date.trim().length > 0
        ? trackingObj.initial_release_date.trim()
        : null;

  const productTreeMap = buildCsafProductTreeMap(root.product_tree);
  const vulnerabilitiesArray = Array.isArray(root.vulnerabilities) ? root.vulnerabilities : [];

  for (const vulnItem of vulnerabilitiesArray) {
    if (vulnItem === null || typeof vulnItem !== 'object') continue;
    const vuln = vulnItem as Record<string, unknown>;

    let candidateCve: string | null = null;
    if (typeof vuln.cve === 'string' && vuln.cve.trim().length > 0) {
      candidateCve = vuln.cve.trim();
    } else if (Array.isArray(vuln.ids)) {
      for (const idEntry of vuln.ids) {
        if (idEntry !== null && typeof idEntry === 'object') {
          const entry = idEntry as Record<string, unknown>;
          if (typeof entry.text === 'string' && CVE_ID_PATTERN.test(entry.text.trim())) {
            candidateCve = entry.text.trim();
            break;
          }
        }
      }
      if (!candidateCve && vuln.ids.length > 0) {
        const first = vuln.ids[0];
        if (
          first !== null &&
          typeof first === 'object' &&
          typeof (first as Record<string, unknown>).text === 'string'
        ) {
          candidateCve = ((first as Record<string, unknown>).text as string).trim();
        }
      }
    }

    if (!candidateCve) {
      ignoredNonCveCount++;
      continue;
    }

    const normalizedCve = normalizeCveId(candidateCve);
    if (!normalizedCve) {
      ignoredNonCveCount++;
      continue;
    }

    const productStatus =
      vuln.product_status !== null && typeof vuln.product_status === 'object'
        ? (vuln.product_status as Record<string, unknown>)
        : null;

    if (!productStatus) continue;

    // CSAF VEX profile product_status mappings
    const statusGroups: Array<{ key: string; status: VendorVexStatus }> = [
      { key: 'known_not_affected', status: 'not_affected' },
      { key: 'fixed', status: 'fixed' },
      { key: 'known_affected', status: 'affected' },
      { key: 'under_investigation', status: 'under_investigation' },
    ];

    for (const group of statusGroups) {
      const pidsRaw = productStatus[group.key];
      if (!Array.isArray(pidsRaw) || pidsRaw.length === 0) continue;

      const productSet = new Set<string>();
      for (const pidItem of pidsRaw) {
        if (typeof pidItem === 'string') {
          const pid = pidItem.trim();
          if (pid.length > 0) {
            productSet.add(pid);
            const aliases = productTreeMap.get(pid);
            if (aliases) {
              for (const alias of aliases) {
                productSet.add(alias);
              }
            }
          }
        }
      }

      if (productSet.size === 0) continue;
      const products = Array.from(productSet);

      // Extract justification from flags (CSAF 2.0 VEX justification enum)
      let justification: string | undefined;
      if (Array.isArray(vuln.flags)) {
        for (const flagItem of vuln.flags) {
          if (flagItem !== null && typeof flagItem === 'object') {
            const flag = flagItem as Record<string, unknown>;
            if (typeof flag.label === 'string' && flag.label.trim().length > 0) {
              const flagProducts = Array.isArray(flag.product_ids) ? flag.product_ids : null;
              if (
                !flagProducts ||
                flagProducts.some((fp: unknown) => typeof fp === 'string' && productSet.has(fp.trim()))
              ) {
                justification = flag.label.trim();
                break;
              }
            }
          }
        }
      }

      // Extract impact statement from threats
      let impactStatement: string | undefined;
      if (Array.isArray(vuln.threats)) {
        for (const threatItem of vuln.threats) {
          if (threatItem !== null && typeof threatItem === 'object') {
            const threat = threatItem as Record<string, unknown>;
            if (typeof threat.details === 'string' && threat.details.trim().length > 0) {
              const threatProducts = Array.isArray(threat.product_ids) ? threat.product_ids : null;
              if (
                !threatProducts ||
                threatProducts.some((tp: unknown) => typeof tp === 'string' && productSet.has(tp.trim()))
              ) {
                impactStatement = threat.details.trim();
                break;
              }
            }
          }
        }
      }

      // Extract action statement from remediations
      let actionStatement: string | undefined;
      if (Array.isArray(vuln.remediations)) {
        for (const remItem of vuln.remediations) {
          if (remItem !== null && typeof remItem === 'object') {
            const rem = remItem as Record<string, unknown>;
            if (typeof rem.details === 'string' && rem.details.trim().length > 0) {
              const remProducts = Array.isArray(rem.product_ids) ? rem.product_ids : null;
              if (
                !remProducts ||
                remProducts.some((rp: unknown) => typeof rp === 'string' && productSet.has(rp.trim()))
              ) {
                actionStatement = rem.details.trim();
                break;
              }
            }
          }
        }
      }

      rawCandidates.push({
        vulnerabilityId: normalizedCve,
        status: group.status,
        products,
        ...(justification ? { justification } : {}),
        ...(impactStatement ? { impactStatement } : {}),
        ...(actionStatement ? { actionStatement } : {}),
      });
    }
  }

  const { statements, droppedStatementsCount, droppedProductsCount } = applyBounds(
    rawCandidates,
    maxStatements,
    maxProducts,
  );

  return {
    ok: true,
    format: 'csaf_vex',
    sourcePath,
    author,
    timestamp,
    statements,
    droppedStatementsCount,
    droppedProductsCount,
    ignoredNonCveCount,
    boundsRule: VEX_BOUNDS_RULE,
  };
}

function normalizeMatcher(matcher: ProductMatcher): (productId: string) => boolean {
  if (typeof matcher === 'function') {
    return matcher;
  }
  if (typeof matcher === 'string') {
    const target = matcher.trim();
    return (pid: string) => pid.trim() === target;
  }
  if (Array.isArray(matcher)) {
    const set = new Set(matcher.map((s) => s.trim()));
    return (pid: string) => set.has(pid.trim());
  }
  if (matcher instanceof Set) {
    return (pid: string) => matcher.has(pid.trim());
  }
  return () => false;
}

/**
 * Pure resolution function: for a candidate CVE id and component matcher, returns the vendor's
 * statement as a structured verdict to attach to an existing candidate row.
 *
 * Invariants strictly preserved:
 *   - NEVER changes or assigns a proof state.
 *   - NEVER suppresses or drops a finding.
 *   - Matches ONLY explicit statements naming the exact CVE id and an accepted product string.
 *   - Several disagreeing statements evaluate to 'conflicting' (never resolved by order).
 *   - Absence / non-mention evaluates to 'unmentioned', explicitly stated as NOT evidence of absence.
 */
export function resolveVendorVex(
  document: VendorVexDocument | VendorVexParseResult | null | undefined,
  cveId: string,
  componentOrMatcher: string | ProductMatcher,
  matcherOrOptions?: ProductMatcher | { componentName?: string; sourcePath?: string },
  options?: { componentName?: string; sourcePath?: string },
): VendorVexVerdict {
  let componentName: string | undefined;
  let matcher: ProductMatcher;
  let explicitSourcePath: string | undefined;

  if (typeof componentOrMatcher === 'string') {
    if (
      typeof matcherOrOptions === 'function' ||
      Array.isArray(matcherOrOptions) ||
      matcherOrOptions instanceof Set ||
      typeof matcherOrOptions === 'string'
    ) {
      componentName = componentOrMatcher;
      matcher = matcherOrOptions;
      explicitSourcePath = options?.sourcePath;
      if (options?.componentName) {
        componentName = options.componentName;
      }
    } else {
      componentName = componentOrMatcher;
      matcher = componentOrMatcher;
      const opts = matcherOrOptions as { componentName?: string; sourcePath?: string } | undefined;
      explicitSourcePath = opts?.sourcePath;
      if (opts?.componentName) {
        componentName = opts.componentName;
      }
    }
  } else {
    matcher = componentOrMatcher;
    if (
      matcherOrOptions &&
      typeof matcherOrOptions === 'object' &&
      !Array.isArray(matcherOrOptions) &&
      !(matcherOrOptions instanceof Set)
    ) {
      const opts = matcherOrOptions as { componentName?: string; sourcePath?: string };
      componentName = opts.componentName;
      explicitSourcePath = opts.sourcePath;
    }
  }

  const effectiveSourcePath = explicitSourcePath ?? (document && 'sourcePath' in document ? document.sourcePath : null);

  if (document === null || document === undefined) {
    return {
      verdict: 'unmentioned',
      sourcePath: null,
      statementIndex: null,
      justification: null,
      author: null,
      timestamp: null,
      documentAuthor: null,
      documentTimestamp: null,
      rationale: `No vendor VEX document was provided for ${cveId}${componentName ? ` in ${componentName}` : ''}; absence of a vendor statement is not evidence of absence or cleanliness.`,
    };
  }

  if (!document.ok) {
    return {
      verdict: 'unmentioned',
      sourcePath: document.sourcePath,
      statementIndex: null,
      justification: null,
      author: null,
      timestamp: null,
      documentAuthor: null,
      documentTimestamp: null,
      rationale: `Vendor VEX document at ${document.sourcePath} was refused (${document.reason}: ${document.message}); a refused document is not evidence of absence or cleanliness.`,
    };
  }

  const normalizedTargetCve = normalizeCveId(cveId);
  if (!normalizedTargetCve) {
    return {
      verdict: 'unmentioned',
      sourcePath: document.sourcePath,
      statementIndex: null,
      justification: null,
      author: document.author,
      timestamp: document.timestamp,
      documentAuthor: document.author,
      documentTimestamp: document.timestamp,
      rationale: `Target identifier "${cveId}" is not a valid CVE ID; cannot resolve vendor VEX statement.`,
    };
  }

  const predicate = normalizeMatcher(matcher);
  const matchingStatements: VendorVexStatement[] = [];

  for (const stmt of document.statements) {
    if (stmt.vulnerabilityId !== normalizedTargetCve) {
      continue;
    }
    const hasMatchingProduct = stmt.products.some((prod) => predicate(prod));
    if (hasMatchingProduct) {
      matchingStatements.push(stmt);
    }
  }

  if (matchingStatements.length === 0) {
    return {
      verdict: 'unmentioned',
      sourcePath: document.sourcePath,
      statementIndex: null,
      justification: null,
      author: document.author,
      timestamp: document.timestamp,
      documentAuthor: document.author,
      documentTimestamp: document.timestamp,
      rationale: `Vendor VEX document at ${document.sourcePath} makes no statement regarding ${normalizedTargetCve}${componentName ? ` for component ${componentName}` : ''}; silence in vendor documentation is not evidence of absence or cleanliness.`,
    };
  }

  const uniqueStatuses = Array.from(new Set(matchingStatements.map((s) => s.status)));

  if (uniqueStatuses.length > 1) {
    const conflictSummary = matchingStatements
      .map((s) => `statement #${s.statementIndex} asserts ${s.status}`)
      .join(', ');
    return {
      verdict: 'conflicting',
      sourcePath: document.sourcePath,
      statementIndex: null,
      justification: null,
      author: document.author,
      timestamp: document.timestamp,
      documentAuthor: document.author,
      documentTimestamp: document.timestamp,
      conflictingStatements: matchingStatements,
      matchedStatements: matchingStatements,
      rationale: `Vendor VEX document at ${document.sourcePath} contains conflicting statements for ${normalizedTargetCve} (${conflictSummary}); conflicting vendor claims cannot resolve exploitability and are not code facts.`,
    };
  }

  const primaryStatement = matchingStatements[0];
  if (!primaryStatement) {
    return {
      verdict: 'unmentioned',
      sourcePath: document.sourcePath,
      statementIndex: null,
      justification: null,
      author: document.author,
      timestamp: document.timestamp,
      documentAuthor: document.author,
      documentTimestamp: document.timestamp,
      rationale: `Vendor VEX document at ${document.sourcePath} makes no statement regarding ${normalizedTargetCve}${componentName ? ` for component ${componentName}` : ''}; silence in vendor documentation is not evidence of absence or cleanliness.`,
    };
  }
  const authorPrefix = document.author ? `${document.author} ` : '';
  const compDesc = componentName ? ` for component ${componentName}` : '';

  let verdictKind: VendorVexVerdictKind;
  let rationale: string;

  switch (primaryStatement.status) {
    case 'fixed':
      verdictKind = 'vendor_states_fixed';
      rationale = `Vendor asserts in ${authorPrefix}VEX document at ${document.sourcePath} (statement #${primaryStatement.statementIndex}) that ${normalizedTargetCve}${compDesc} is fixed; this is the vendor's assertion, not a verified code fact.`;
      break;
    case 'not_affected':
      verdictKind = 'vendor_states_not_affected';
      rationale = `Vendor asserts in ${authorPrefix}VEX document at ${document.sourcePath} (statement #${primaryStatement.statementIndex}) that ${componentName ?? 'component'} is not affected by ${normalizedTargetCve}${primaryStatement.justification ? ` (${primaryStatement.justification})` : ''}; this is the vendor's assertion, not a verified code fact.`;
      break;
    case 'affected':
      verdictKind = 'vendor_states_affected';
      rationale = `Vendor asserts in ${authorPrefix}VEX document at ${document.sourcePath} (statement #${primaryStatement.statementIndex}) that ${componentName ?? 'component'} is affected by ${normalizedTargetCve}; this is the vendor's assertion, not a verified code fact.`;
      break;
    case 'under_investigation':
      verdictKind = 'vendor_under_investigation';
      rationale = `Vendor asserts in ${authorPrefix}VEX document at ${document.sourcePath} (statement #${primaryStatement.statementIndex}) that ${normalizedTargetCve}${compDesc} is under investigation; this is the vendor's assertion, not a verified code fact.`;
      break;
  }

  return {
    verdict: verdictKind,
    sourcePath: document.sourcePath,
    statementIndex: primaryStatement.statementIndex,
    justification: primaryStatement.justification ?? null,
    author: document.author,
    timestamp: document.timestamp,
    documentAuthor: document.author,
    documentTimestamp: document.timestamp,
    rationale,
    ...(primaryStatement.impactStatement ? { impactStatement: primaryStatement.impactStatement } : {}),
    ...(primaryStatement.actionStatement ? { actionStatement: primaryStatement.actionStatement } : {}),
    matchedStatements: matchingStatements,
  };
}
