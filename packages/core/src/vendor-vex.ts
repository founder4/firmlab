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
 *     return structured refusals without throwing. A cap that dropped anything is restated on every
 *     verdict the document yields (`droppedByBounds`): a statement past the cap could be the half of a
 *     disagreement that never arrived, so a clean single verdict from a truncated document is not
 *     presented as a complete reading.
 *   - A statement whose status is not one of the four VEX statuses is counted
 *     (`unrecognisedStatusCount`, with bounded examples), never silently dropped: `known_affected`
 *     written into an OpenVEX file is a statement the vendor made, and losing it can hide a conflict.
 *     CSAF first_affected/last_affected/first_fixed groups are counted there too: their boundary semantics are
 *     unsupported, so they never become exact affected/fixed assertions or inferred version ranges.
 *   - A CSAF product keeps its identity together. When its `product_identification_helper` carries a
 *     VERSIONED purl or CPE, only those versioned identities stand for it — never its bare `name` or
 *     free-form `product_id`, which would let a statement scoped to busybox 1.30.1 attach to any
 *     busybox. A product with no versioned identity keeps its id, name and unversioned helpers.
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

/** One statement omitted because its status is unrecognised or unsupported — kept as an example, bounded. */
export interface VendorVexUnrecognisedStatus {
  readonly vulnerabilityId: string;
  readonly status: string;
}

/** How many examples of unrecognised statuses a document keeps; the count is always exact. */
export const MAX_UNRECOGNISED_STATUS_EXAMPLES = 10;

/**
 * A product structure the parser saw and deliberately did not interpret, for one CVE. No pinned primary CSAF/OpenVEX
 * specification text backs a reading of these shapes here, so instead of guessing what they mean they are counted:
 *
 *  - `csaf_unindexed_product` — a product_status reference to a product_id defined only under
 *    `product_tree.branches` or `product_tree.relationships`. It is NOT matched by its raw id: the definition it
 *    points at may carry a versioned helper, and matching the bare id would drop that version restriction.
 *  - `csaf_product_tree_truncated` — an unresolved reference while the bounded product-tree walk stopped early, so it
 *    cannot be told whether the id was defined in the part not walked. Also not matched by its raw id.
 *  - `openvex_product_identifiers` — a product object carrying `identifiers`; its `@id` is still read, the alternate
 *    identifiers are not (an object with no `@id` contributes nothing).
 *  - `openvex_nested_subcomponents` — subcomponents nested inside a product object; the statement-level
 *    `subcomponents` list is read, these are not.
 */
export type VendorVexUnreadStructureKind =
  | 'csaf_unindexed_product'
  | 'csaf_product_tree_truncated'
  | 'openvex_product_identifiers'
  | 'openvex_nested_subcomponents';

export interface VendorVexUnreadStructure {
  readonly vulnerabilityId: string;
  readonly kind: VendorVexUnreadStructureKind;
  /** The product id/reference involved, truncated to 128 characters; empty when the product had none. */
  readonly reference: string;
}

/** How many examples of unread structures a document keeps; the count is always exact. */
export const MAX_UNREAD_STRUCTURE_EXAMPLES = 10;
/** Bounds on the CSAF product-tree walk that only collects ids defined outside `full_product_names`. */
export const MAX_CSAF_TREE_DEPTH = 32;
export const MAX_CSAF_TREE_NODES = 10_000;

export const VEX_UNREAD_STRUCTURE_RULE = `CSAF product ids defined only under product_tree.branches/relationships, and OpenVEX product identifiers and nested subcomponents, are counted per CVE rather than interpreted; a reference to such an id is never matched by its raw id. The product-tree walk stops at depth ${MAX_CSAF_TREE_DEPTH} or ${MAX_CSAF_TREE_NODES} nodes; past that, unresolved references are counted, not matched. First ${MAX_UNREAD_STRUCTURE_EXAMPLES} examples kept in document order.`;

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
  /**
   * Statements naming a CVE whose status is unrecognised or unsupported, so they were not kept. Each nonempty CSAF
   * boundary-status array counts as one group, independent of product count. Optional because a document from an
   * older build never counted them; absent means "not counted", never zero.
   */
  readonly unrecognisedStatusCount?: number | undefined;
  /** The first `MAX_UNRECOGNISED_STATUS_EXAMPLES` of them, in document order. */
  readonly unrecognisedStatusExamples?: readonly VendorVexUnrecognisedStatus[] | undefined;
  /**
   * Product structures seen and not interpreted (see `VendorVexUnreadStructureKind`). Optional: a document from an
   * older build never counted them; absent means "not counted", never zero.
   */
  readonly unreadStructureCount?: number | undefined;
  /** The first `MAX_UNREAD_STRUCTURE_EXAMPLES` of them, in document order. */
  readonly unreadStructureExamples?: readonly VendorVexUnreadStructure[] | undefined;
  readonly unreadStructureRule?: string | undefined;
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
  /**
   * Present when the document's statement or product cap dropped anything: what was dropped may have named this CVE,
   * so the verdict is not a complete reading of the document.
   */
  readonly droppedByBounds?: { readonly statements: number; readonly products: number } | undefined;
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

function isNonEmptyStructure(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  return value !== null && typeof value === 'object' && Object.keys(value).length > 0;
}

function extractOpenVexProducts(
  productsRaw: unknown,
  subcomponentsRaw: unknown,
): { products: string[]; unread: { kind: VendorVexUnreadStructureKind; reference: string }[] } {
  const result: string[] = [];
  const unread: { kind: VendorVexUnreadStructureKind; reference: string }[] = [];
  const collect = (arr: unknown) => {
    if (!Array.isArray(arr)) return;
    for (const item of arr) {
      if (typeof item === 'string') {
        const trimmed = item.trim();
        if (trimmed.length > 0) result.push(trimmed);
      } else if (item !== null && typeof item === 'object') {
        const obj = item as Record<string, unknown>;
        const id = typeof obj['@id'] === 'string' ? obj['@id'] : typeof obj.id === 'string' ? obj.id : null;
        const reference = id?.trim().slice(0, 128) ?? '';
        if (id && id.trim().length > 0) {
          result.push(id.trim());
        }
        if (isNonEmptyStructure(obj.identifiers)) unread.push({ kind: 'openvex_product_identifiers', reference });
        if (Array.isArray(obj.subcomponents) && obj.subcomponents.length > 0) {
          unread.push({ kind: 'openvex_nested_subcomponents', reference });
        }
      }
    }
  };
  collect(productsRaw);
  collect(subcomponentsRaw);
  return { products: result, unread };
}

/**
 * Product ids defined outside `full_product_names` — under `branches` (any depth) or as a relationship's
 * `full_product_name` — which this parser does not interpret. Collected only so a reference to one is counted instead
 * of being matched by its raw id. Iterative and bounded, so no document can recurse the parser off the stack.
 */
function collectUnindexedCsafProductIds(productTreeRaw: unknown): { ids: Set<string>; truncated: boolean } {
  const ids = new Set<string>();
  if (productTreeRaw === null || typeof productTreeRaw !== 'object') return { ids, truncated: false };
  const tree = productTreeRaw as Record<string, unknown>;
  const addFrom = (product: unknown) => {
    if (product === null || typeof product !== 'object') return;
    const pid = (product as Record<string, unknown>).product_id;
    if (typeof pid === 'string' && pid.trim().length > 0) ids.add(pid.trim());
  };
  let nodes = 0;
  let truncated = false;
  const stack: { node: unknown; depth: number }[] = [];
  if (Array.isArray(tree.branches)) for (const b of tree.branches) stack.push({ node: b, depth: 1 });
  while (stack.length > 0) {
    const { node, depth } = stack.pop() as { node: unknown; depth: number };
    if (++nodes > MAX_CSAF_TREE_NODES || depth > MAX_CSAF_TREE_DEPTH) {
      truncated = true;
      break;
    }
    if (node === null || typeof node !== 'object') continue;
    const branch = node as Record<string, unknown>;
    addFrom(branch.product);
    if (Array.isArray(branch.branches)) for (const b of branch.branches) stack.push({ node: b, depth: depth + 1 });
  }
  if (Array.isArray(tree.relationships)) {
    for (const rel of tree.relationships) {
      if (++nodes > MAX_CSAF_TREE_NODES) {
        truncated = true;
        break;
      }
      if (rel !== null && typeof rel === 'object') addFrom((rel as Record<string, unknown>).full_product_name);
    }
  }
  return { ids, truncated };
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

function isWildcardVersion(v: string | undefined): boolean {
  return v === undefined || v === '' || v === '*' || v === '-';
}

/**
 * Whether a purl or CPE string names a concrete version. Reads the raw text only — nothing is percent-decoded here, so
 * no firmware-controlled string can throw.
 */
function isVersionedIdentity(raw: string): boolean {
  const id = raw.trim();
  const purl = /^pkg:[^/]+\/([^?#]+)/i.exec(id);
  if (purl) {
    const body = purl[1] as string;
    const at = body.lastIndexOf('@');
    return at >= 0 && body.slice(at + 1).length > 0;
  }
  if (/^cpe:2\.3:/i.test(id)) return !isWildcardVersion(id.split(':')[5]);
  if (/^cpe:\//i.test(id)) return !isWildcardVersion(id.slice(5).split(':')[3]);
  return false;
}

/** The identity strings one CSAF product stands for, and whether its free-form product_id may stand for it too. */
interface CsafProductIdentity {
  identities: string[];
  includeProductId: boolean;
}

function buildCsafProductTreeMap(productTreeRaw: unknown): Map<string, CsafProductIdentity> {
  const map = new Map<string, CsafProductIdentity>();
  if (productTreeRaw === null || typeof productTreeRaw !== 'object') return map;
  const tree = productTreeRaw as Record<string, unknown>;

  if (Array.isArray(tree.full_product_names)) {
    for (const item of tree.full_product_names) {
      if (item !== null && typeof item === 'object') {
        const obj = item as Record<string, unknown>;
        const pid = typeof obj.product_id === 'string' ? obj.product_id.trim() : null;
        if (!pid) continue;
        const helpers: string[] = [];
        if (obj.product_identification_helper !== null && typeof obj.product_identification_helper === 'object') {
          const helper = obj.product_identification_helper as Record<string, unknown>;
          if (typeof helper.purl === 'string' && helper.purl.trim().length > 0) {
            helpers.push(helper.purl.trim());
          }
          if (typeof helper.cpe === 'string' && helper.cpe.trim().length > 0) {
            helpers.push(helper.cpe.trim());
          }
        }
        // A versioned purl or CPE scopes the product: it alone stands for it, because the bare name or product_id
        // would match every version of the same software.
        const versioned = helpers.filter(isVersionedIdentity);
        if (versioned.length > 0) {
          map.set(pid, { identities: versioned, includeProductId: false });
          continue;
        }
        const aliases: string[] = [];
        if (typeof obj.name === 'string' && obj.name.trim().length > 0) {
          aliases.push(obj.name.trim());
        }
        aliases.push(...helpers);
        map.set(pid, { identities: aliases, includeProductId: true });
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
  let unrecognisedStatusCount = 0;
  const unrecognisedStatusExamples: VendorVexUnrecognisedStatus[] = [];
  let unreadStructureCount = 0;
  const unreadStructureExamples: VendorVexUnreadStructure[] = [];
  const noteUnread = (vulnerabilityId: string, kind: VendorVexUnreadStructureKind, reference: string) => {
    unreadStructureCount++;
    if (unreadStructureExamples.length < MAX_UNREAD_STRUCTURE_EXAMPLES) {
      unreadStructureExamples.push({ vulnerabilityId, kind, reference: reference.slice(0, 128) });
    }
  };
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
      if (!status) {
        unrecognisedStatusCount++;
        if (unrecognisedStatusExamples.length < MAX_UNRECOGNISED_STATUS_EXAMPLES) {
          const raw = typeof stmt.status === 'string' ? stmt.status : JSON.stringify(stmt.status ?? null);
          unrecognisedStatusExamples.push({ vulnerabilityId: normalizedCve, status: raw.slice(0, 64) });
        }
        continue;
      }

      const { products, unread } = extractOpenVexProducts(stmt.products, stmt.subcomponents);
      for (const u of unread) noteUnread(normalizedCve, u.kind, u.reference);
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
      unrecognisedStatusCount,
      unrecognisedStatusExamples,
      unreadStructureCount,
      unreadStructureExamples,
      unreadStructureRule: VEX_UNREAD_STRUCTURE_RULE,
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
  const unindexed = collectUnindexedCsafProductIds(root.product_tree);
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

    // Boundary groups describe endpoints, not exact affected/fixed assertions or a range we can infer. Count one
    // omitted group per CVE/status (as for supported groups), even when statement/product caps retain nothing.
    // Object.keys preserves their document order for bounded examples; never inspect or expand their products.
    for (const status of Object.keys(productStatus)) {
      if (status !== 'first_affected' && status !== 'last_affected' && status !== 'first_fixed') continue;
      const products = productStatus[status];
      if (!Array.isArray(products) || products.length === 0) continue;
      unrecognisedStatusCount++;
      if (unrecognisedStatusExamples.length < MAX_UNRECOGNISED_STATUS_EXAMPLES) {
        unrecognisedStatusExamples.push({ vulnerabilityId: normalizedCve, status });
      }
    }

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

      // `pidSet` is what flags, threats and remediations reference; `productSet` is what a matcher sees.
      const pidSet = new Set<string>();
      const productSet = new Set<string>();
      for (const pidItem of pidsRaw) {
        if (typeof pidItem === 'string') {
          const pid = pidItem.trim();
          if (pid.length > 0) {
            pidSet.add(pid);
            const identity = productTreeMap.get(pid);
            // A reference to a definition this parser does not read is counted, never matched by its raw id: that
            // definition may carry a versioned helper the bare id would silently drop.
            if (!identity && unindexed.ids.has(pid)) {
              noteUnread(normalizedCve, 'csaf_unindexed_product', pid);
              continue;
            }
            if (!identity && unindexed.truncated) {
              noteUnread(normalizedCve, 'csaf_product_tree_truncated', pid);
              continue;
            }
            if (!identity || identity.includeProductId) productSet.add(pid);
            for (const alias of identity?.identities ?? []) productSet.add(alias);
          }
        }
      }
      const refersToGroup = (id: unknown) =>
        typeof id === 'string' && (pidSet.has(id.trim()) || productSet.has(id.trim()));

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
              if (!flagProducts || flagProducts.some(refersToGroup)) {
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
              if (!threatProducts || threatProducts.some(refersToGroup)) {
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
              if (!remProducts || remProducts.some(refersToGroup)) {
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
    unrecognisedStatusCount,
    unrecognisedStatusExamples,
    unreadStructureCount,
    unreadStructureExamples,
    unreadStructureRule: VEX_UNREAD_STRUCTURE_RULE,
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
  const droppedByBounds =
    document.droppedStatementsCount > 0 || document.droppedProductsCount > 0
      ? { statements: document.droppedStatementsCount, products: document.droppedProductsCount }
      : undefined;
  const boundsSentence = droppedByBounds
    ? ` The document's caps dropped ${droppedByBounds.statements} statement(s) and ${droppedByBounds.products} product reference(s) (${document.boundsRule}); what was dropped may concern ${normalizedTargetCve}, so this is not a complete reading of the document.`
    : '';

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
      rationale: `Vendor VEX document at ${document.sourcePath} makes no statement regarding ${normalizedTargetCve}${componentName ? ` for component ${componentName}` : ''}; silence in vendor documentation is not evidence of absence or cleanliness.${boundsSentence}`,
      ...(droppedByBounds ? { droppedByBounds } : {}),
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
      rationale: `Vendor VEX document at ${document.sourcePath} contains conflicting statements for ${normalizedTargetCve} (${conflictSummary}); conflicting vendor claims cannot resolve exploitability and are not code facts.${boundsSentence}`,
      ...(droppedByBounds ? { droppedByBounds } : {}),
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
    rationale: `${rationale}${boundsSentence}`,
    ...(droppedByBounds ? { droppedByBounds } : {}),
    ...(primaryStatement.impactStatement ? { impactStatement: primaryStatement.impactStatement } : {}),
    ...(primaryStatement.actionStatement ? { actionStatement: primaryStatement.actionStatement } : {}),
    matchedStatements: matchingStatements,
  };
}
