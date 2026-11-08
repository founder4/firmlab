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
 *     busybox. Only valid top-level products without a versioned identity retain legacy id/name aliases. Branch
 *     products require a readable exact versioned helper. Unknown, ambiguous and truncated definitions stay unread.
 *   - Direct OpenVEX identifier maps provide only literal, concrete versioned aliases. A generic @id/id cannot
 *     bypass that version scope. Unread or conflicting maps refuse the entire product identity, and nested
 *     subcomponents remain omitted context rather than standalone package assertions.
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
  /** Lower test/operator budgets only; values above the hard 32/10,000 ceilings cannot widen the walk. */
  readonly maxCsafTreeDepth?: number | undefined;
  readonly maxCsafTreeNodes?: number | undefined;
}

/** One statement omitted because its status is unrecognised or unsupported — kept as an example, bounded. */
export interface VendorVexUnrecognisedStatus {
  readonly vulnerabilityId: string;
  readonly status: string;
}

/** How many examples of unrecognised statuses a document keeps; the count is always exact. */
export const MAX_UNRECOGNISED_STATUS_EXAMPLES = 10;

/**
 * A product structure the parser deliberately did not interpret, counted per CVE/status/reference:
 *
 *  - `csaf_ambiguous_product` — an id defined more than once, including collisions across tree locations.
 *  - `csaf_unread_product_identity` — a malformed top-level full product name/helper.
 *  - `csaf_unknown_product` — a reference token with no product definition; never a raw identity fallback.
 *  - `csaf_unindexed_product` — a branch without a readable full product name/versioned helper, or a relationship
 *    product; relationship semantics remain unsupported. Retains the existing kind for unread branch products.
 *  - `csaf_product_tree_truncated` — any reference when the walk stopped early; an unseen duplicate may invalidate
 *    even an already-read definition, so all references are refused.
 *  - `openvex_product_identifiers` — an unread direct product identity (malformed, unsupported, unversioned or
 *    conflicting identifiers/ID), or legacy statement-level identifiers, counted once per product node/group.
 *  - `openvex_nested_subcomponents` — contextual subcomponents inside a product, counted once per parent; never
 *    flattened into standalone claims. Statement-level subcomponents retain their existing legacy reading.
 */
export type VendorVexUnreadStructureKind =
  | 'csaf_ambiguous_product'
  | 'csaf_unread_product_identity'
  | 'csaf_unknown_product'
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
/** Bounds on the CSAF product-tree definition walk, including top-level names and relationships. */
export const MAX_CSAF_TREE_DEPTH = 32;
export const MAX_CSAF_TREE_NODES = 10_000;

export const VEX_UNREAD_STRUCTURE_RULE = `CSAF branch products require explicit full product names and readable versioned purl/CPE helpers. Unknown ids, duplicate definitions, unreadable helpers, relationships, unread OpenVEX product identities, and contextual nested subcomponents are counted per CVE rather than interpreted; a reference to such an id is never matched by its raw id. The product-tree walk stops at depth ${MAX_CSAF_TREE_DEPTH} or ${MAX_CSAF_TREE_NODES} nodes; if truncated, every reference is counted, not matched, because unseen definitions may conflict. Direct OpenVEX identifier maps require only readable concrete versioned purl/cpe22/cpe23 aliases, with no generic id fallback; unsupported or conflicting map entries refuse the entire identity. First ${MAX_UNREAD_STRUCTURE_EXAMPLES} examples kept in document order.`;

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

/**
 * Read one direct OpenVEX v0.2.0 product (Component Fields / Appendix B), not a nested subcomponent.
 * A map names literal aliases of this one component; no cross-scheme equivalence or version inference is needed.
 * Every supplied map entry must be a readable concrete versioned helper. Refuse the entire identity on an
 * unsupported entry: retaining a convenient subset could hide the other half of a disagreement.
 * An opaque @id/id is only a reference when a map is supplied, never an unversioned matching fallback. An explicit
 * helper-shaped ID must itself be readable/versioned and cannot disagree with the same scheme's map entry.
 * Without a map, keep the established @id/id-only reading. No name, version, hash or external JSON-LD lookup.
 */
export function readOpenVexProductIdentity(product: unknown): {
  products: string[];
  unread: boolean;
  reference: string;
} {
  const refused = (reference = '') => ({ products: [], unread: true, reference });
  if (typeof product === 'string') {
    const id = product.trim();
    return id ? { products: [id], unread: false, reference: id.slice(0, 128) } : refused();
  }
  if (product === null || typeof product !== 'object' || Array.isArray(product)) return refused();
  const obj = product as Record<string, unknown>;
  const rawId = typeof obj['@id'] === 'string' ? obj['@id'] : typeof obj.id === 'string' ? obj.id : '';
  const reference = rawId.trim().slice(0, 128);
  if (!Object.hasOwn(obj, 'identifiers')) {
    return rawId.trim() ? { products: [rawId.trim()], unread: false, reference } : refused(reference);
  }

  const map = obj.identifiers;
  if (map === null || typeof map !== 'object' || Array.isArray(map) || Object.keys(map).length === 0) {
    return refused(reference);
  }
  const identifiers = map as Record<string, unknown>;
  const readable = (kind: string, value: unknown): value is string => {
    if (typeof value !== 'string' || value !== value.trim()) return false;
    switch (kind) {
      case 'purl':
        if (!value.startsWith('pkg:')) return false;
        break;
      case 'cpe22':
        if (!value.startsWith('cpe:/')) return false;
        break;
      case 'cpe23':
        if (!value.startsWith('cpe:2.3:')) return false;
        break;
      default:
        return false;
    }
    return csafHelperVersion(value, kind === 'purl' ? 'purl' : 'cpe')?.versioned === true;
  };
  const products: string[] = [];
  for (const [kind, value] of Object.entries(identifiers)) {
    if (!readable(kind, value)) return refused(reference);
    products.push(value);
  }

  if (Object.hasOwn(obj, '@id') && Object.hasOwn(obj, 'id') && obj['@id'] !== obj.id) return refused(reference);
  for (const key of ['@id', 'id']) {
    if (!Object.hasOwn(obj, key)) continue;
    const id = obj[key];
    if (typeof id !== 'string' || id.length === 0 || id !== id.trim()) return refused(reference);
    const kind = id.startsWith('pkg:')
      ? 'purl'
      : id.startsWith('cpe:/')
        ? 'cpe22'
        : id.startsWith('cpe:2.3:')
          ? 'cpe23'
          : null;
    if (kind) {
      if (!readable(kind, id)) return refused(reference);
      // Exact disagreement within a scheme is refused, even if a richer parser could normalize the two strings.
      if (Object.hasOwn(identifiers, kind) && identifiers[kind] !== id) return refused(reference);
      products.push(id);
    } else if (/^(?:pkg|cpe):/i.test(id)) {
      return refused(reference);
    }
  }
  return { products: [...new Set(products)], unread: false, reference };
}

function extractOpenVexProducts(
  productsRaw: unknown,
  subcomponentsRaw: unknown,
): { products: string[]; unread: { kind: VendorVexUnreadStructureKind; reference: string }[] } {
  const result: string[] = [];
  const unread: { kind: VendorVexUnreadStructureKind; reference: string }[] = [];
  if (Array.isArray(productsRaw) && productsRaw.length > 0) {
    for (const product of productsRaw) {
      const identity = readOpenVexProductIdentity(product);
      result.push(...identity.products);
      if (identity.unread) unread.push({ kind: 'openvex_product_identifiers', reference: identity.reference });
      if (product !== null && typeof product === 'object' && !Array.isArray(product)) {
        const nested = (product as Record<string, unknown>).subcomponents;
        // Context belongs to this parent. Count the omitted group once; never walk or flatten its children.
        if (nested !== undefined && !(Array.isArray(nested) && nested.length === 0)) {
          unread.push({ kind: 'openvex_nested_subcomponents', reference: identity.reference });
        }
      }
    }
  } else if (productsRaw !== undefined || !Array.isArray(subcomponentsRaw) || subcomponentsRaw.length === 0) {
    unread.push({ kind: 'openvex_product_identifiers', reference: '' });
  }
  // Preserve the legacy, nonstandard statement-level path; do not extend identifier-map support to it.
  if (Array.isArray(subcomponentsRaw)) {
    for (const item of subcomponentsRaw) {
      if (typeof item === 'string') {
        if (item.trim()) result.push(item.trim());
      } else if (item !== null && typeof item === 'object') {
        const obj = item as Record<string, unknown>;
        const id = typeof obj['@id'] === 'string' ? obj['@id'] : typeof obj.id === 'string' ? obj.id : null;
        const reference = id?.trim().slice(0, 128) ?? '';
        if (id?.trim()) result.push(id.trim());
        if (isNonEmptyStructure(obj.identifiers)) unread.push({ kind: 'openvex_product_identifiers', reference });
        if (Array.isArray(obj.subcomponents) && obj.subcomponents.length > 0) {
          unread.push({ kind: 'openvex_nested_subcomponents', reference });
        }
      }
    }
  }
  return { products: result, unread };
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

/** The identity strings one CSAF product stands for, or why its reference must remain unread. */
interface CsafProductIdentity {
  identities: string[];
  includeProductId: boolean;
  unread?: VendorVexUnreadStructureKind;
}

/**
 * Conservative helper syntax reader, not an ecosystem matcher or a complete PURL/CPE conformance validator.
 * Decode only to validate component boundaries and concrete versions; return the original helper to the caller's
 * matcher. Unsupported escaping/CPE patterns are refused rather than repaired or turned into plain aliases.
 */
function csafHelperVersion(raw: string, kind: 'purl' | 'cpe'): { versioned: boolean } | null {
  const concrete = (value: string) => value.length > 0 && !/[*?]/.test(value) && value !== '-';
  const decode = (value: string): string | null => {
    try {
      const decoded = decodeURIComponent(value);
      return [...decoded].some((char) => char.charCodeAt(0) <= 32 || char.charCodeAt(0) === 127) ? null : decoded;
    } catch {
      return null;
    }
  };
  if (kind === 'purl') {
    const match = /^pkg:([a-z][a-z0-9.-]*)\/([^?#]+)(?:\?([^#]+))?(?:#(.+))?$/i.exec(raw);
    if (!match || !/^[A-Za-z0-9._~%:/@?=&#-]+$/.test(raw)) return null;
    let body = match[2] as string;
    let version: string | null = null;
    const at = body.indexOf('@');
    if (at >= 0) {
      if (body.indexOf('@', at + 1) >= 0) return null;
      version = decode(body.slice(at + 1));
      if (version === null || !concrete(version) || version.includes('/')) return null;
      body = body.slice(0, at);
    }
    const components = body.split('/').map(decode);
    if (components.some((part) => !part || /[/@]/.test(part.replace(/^@/, '')))) return null;
    const keys = new Set<string>();
    for (const pair of match[3]?.split('&') ?? []) {
      const eq = pair.indexOf('=');
      const key = pair.slice(0, eq);
      const value = decode(pair.slice(eq + 1));
      if (eq <= 0 || pair.indexOf('=', eq + 1) >= 0 || !/^[a-z][a-z0-9._-]*$/.test(key) || !value || keys.has(key)) {
        return null;
      }
      keys.add(key);
    }
    const subpath = match[4]?.split('/').map(decode) ?? [];
    if (subpath.some((part) => !part || part === '.' || part === '..' || part.includes('/'))) return null;
    return { versioned: version !== null };
  }
  if (raw.startsWith('cpe:2.3:')) {
    const parts = raw.split(':');
    // Escaped separators and wildcard patterns need a richer CPE reader than the row matcher currently has.
    if (parts.length !== 13 || !/^[aho]$/.test(parts[2] ?? '')) return null;
    if (parts.slice(3).some((part) => !/^(?:[A-Za-z0-9._~-]+|\*)$/.test(part))) return null;
    if (!concrete(parts[3] ?? '') || !concrete(parts[4] ?? '')) return null;
    const version = parts[5] as string;
    return { versioned: concrete(version) };
  }
  if (/^cpe:\/[aho]:/.test(raw)) {
    const parts = raw.slice(5).split(':');
    if (parts.length < 3 || parts.length > 7 || parts.some((part) => !/^[A-Za-z0-9._~%-]*$/.test(part))) return null;
    if (parts.some((part) => decode(part) === null)) return null;
    if (!concrete(parts[1] ?? '') || !concrete(parts[2] ?? '')) return null;
    // The legacy row matcher compares raw URI fields; percent-encoded identity fields cannot safely be read here.
    if (parts.slice(1, 4).some((part) => part.includes('%'))) return null;
    return { versioned: concrete(parts[3] ?? '') };
  }
  return null;
}

function csafProductIdentity(product: Record<string, unknown>, branch: boolean): CsafProductIdentity {
  const unread = (): CsafProductIdentity => ({
    identities: [],
    includeProductId: false,
    unread: branch ? 'csaf_unindexed_product' : 'csaf_unread_product_identity',
  });
  if (typeof product.name !== 'string' || product.name.trim().length === 0) return unread();
  const helperRaw = product.product_identification_helper;
  const helpers: { identity: string; versioned: boolean }[] = [];
  if (helperRaw !== undefined) {
    if (
      helperRaw === null ||
      typeof helperRaw !== 'object' ||
      Array.isArray(helperRaw) ||
      Object.keys(helperRaw).length === 0
    )
      return unread();
    const helper = helperRaw as Record<string, unknown>;
    for (const kind of ['purl', 'cpe'] as const) {
      if (!(kind in helper)) continue;
      const value = helper[kind];
      if (typeof value !== 'string') return unread();
      const identity = value.trim();
      const parsed = csafHelperVersion(identity, kind);
      if (!parsed) return unread();
      helpers.push({ identity, versioned: parsed.versioned });
    }
  }
  const versioned = helpers.filter((helper) => helper.versioned).map((helper) => helper.identity);
  if (versioned.length > 0) return { identities: versioned, includeProductId: false };
  if (branch) return unread();
  // Preserve the established top-level unversioned identity contract for valid full_product_names.
  return { identities: [product.name.trim(), ...helpers.map((helper) => helper.identity)], includeProductId: true };
}

/**
 * CSAF 2.0 §§3.1.2–3.1.3 and 6.1.1–6.1.2: branch.product is a full_product_name, and ids must have one definition.
 * Scan top-level names, then branches in depth-first document order, then relationship definitions (ids only).
 * Array cursor frames keep auxiliary traversal memory bounded by depth, even for very wide trees. All tree entries
 * consume the node budget. If any subtree is unseen, refuse every reference: an unseen duplicate could invalidate
 * even an already-read product. Neither an unknown id nor a relationship is an identity alias.
 */
function buildCsafProductTreeMap(
  productTreeRaw: unknown,
  maxDepth: number,
  maxNodes: number,
): {
  products: Map<string, CsafProductIdentity>;
  truncated: boolean;
} {
  const products = new Map<string, CsafProductIdentity>();
  if (productTreeRaw === null || typeof productTreeRaw !== 'object') return { products, truncated: false };
  const tree = productTreeRaw as Record<string, unknown>;
  type Kind = 'top' | 'branch' | 'relationship';
  const stack: { items: unknown[]; index: number; depth: number; kind: Kind }[] = [];
  for (const [key, kind] of [
    ['relationships', 'relationship'],
    ['branches', 'branch'],
    ['full_product_names', 'top'],
  ] as const) {
    if (Array.isArray(tree[key])) stack.push({ items: tree[key], index: 0, depth: 1, kind });
  }
  const add = (raw: unknown, kind: Kind) => {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return;
    const product = raw as Record<string, unknown>;
    const id = typeof product.product_id === 'string' ? product.product_id.trim() : '';
    if (!id) return;
    if (products.has(id)) {
      products.set(id, { identities: [], includeProductId: false, unread: 'csaf_ambiguous_product' });
    } else if (kind === 'relationship') {
      products.set(id, { identities: [], includeProductId: false, unread: 'csaf_unindexed_product' });
    } else {
      products.set(id, csafProductIdentity(product, kind === 'branch'));
    }
  };
  let nodes = 0;
  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    if (!frame) break;
    if (frame.index >= frame.items.length) {
      stack.pop();
      continue;
    }
    if (nodes >= maxNodes || frame.depth > maxDepth) return { products, truncated: true };
    const item = frame.items[frame.index++];
    nodes++;
    if (item === null || typeof item !== 'object' || Array.isArray(item)) continue;
    const obj = item as Record<string, unknown>;
    if (frame.kind === 'branch') {
      add(obj.product, 'branch');
      if (Array.isArray(obj.branches))
        stack.push({ items: obj.branches, index: 0, depth: frame.depth + 1, kind: 'branch' });
    } else {
      add(frame.kind === 'top' ? obj : obj.full_product_name, frame.kind);
    }
  }
  return { products, truncated: false };
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

  // Configured tree budgets may tighten the hard ceilings, never raise or disable them.
  const treeLimit = (value: number | undefined, ceiling: number) =>
    value !== undefined && Number.isFinite(value) ? Math.max(0, Math.min(ceiling, Math.floor(value))) : ceiling;
  const maxTreeDepth = treeLimit(limits?.maxCsafTreeDepth, MAX_CSAF_TREE_DEPTH);
  const maxTreeNodes = treeLimit(limits?.maxCsafTreeNodes, MAX_CSAF_TREE_NODES);
  const productTree = buildCsafProductTreeMap(root.product_tree, maxTreeDepth, maxTreeNodes);
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
            if (pidSet.has(pid)) continue;
            pidSet.add(pid);
            const identity = productTree.products.get(pid);
            // A cap may hide a duplicate of any id, including a top-level definition read before the cap.
            if (productTree.truncated) {
              noteUnread(normalizedCve, 'csaf_product_tree_truncated', pid);
              continue;
            }
            if (!identity || identity.unread) {
              noteUnread(normalizedCve, identity?.unread ?? 'csaf_unknown_product', pid);
              continue;
            }
            if (identity.includeProductId) productSet.add(pid);
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
    unreadStructureRule: `${VEX_UNREAD_STRUCTURE_RULE} Effective tree limits: depth ${maxTreeDepth}, ${maxTreeNodes} nodes.`,
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
