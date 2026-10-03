import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_VEX_DOCUMENT_BYTES,
  DEFAULT_MAX_VEX_PRODUCTS,
  DEFAULT_MAX_VEX_STATEMENTS,
  MAX_UNRECOGNISED_STATUS_EXAMPLES,
  VEX_BOUNDS_RULE,
  isVendorVexDocument,
  parseVendorVex,
  resolveVendorVex,
} from '../src/vendor-vex.js';

describe('vendor-vex parser and resolver', () => {
  describe('OpenVEX parsing and resolution', () => {
    it('parses OpenVEX fixed statement and resolves verdict with action statement', () => {
      const openVexDoc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        '@id': 'https://vendor.example.com/vex/openvex-2023-001',
        author: 'ACME Security Advisory Team',
        timestamp: '2023-02-01T10:00:00Z',
        version: 1,
        statements: [
          {
            vulnerability: { name: 'CVE-2022-30065' },
            products: ['pkg:apk/wolfi/busybox@1.35.0-r1', 'busybox'],
            status: 'fixed',
            action_statement: 'Upgrade busybox to 1.35.0-r2 or higher.',
          },
        ],
      });

      const parsed = parseVendorVex(openVexDoc, '/etc/vex/openvex.json');
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      expect(parsed.format).toBe('openvex');
      expect(parsed.author).toBe('ACME Security Advisory Team');
      expect(parsed.timestamp).toBe('2023-02-01T10:00:00Z');
      expect(parsed.statements).toHaveLength(1);
      expect(parsed.statements[0]?.vulnerabilityId).toBe('CVE-2022-30065');
      expect(parsed.statements[0]?.status).toBe('fixed');
      expect(parsed.statements[0]?.actionStatement).toBe('Upgrade busybox to 1.35.0-r2 or higher.');
      expect(parsed.droppedStatementsCount).toBe(0);
      expect(parsed.droppedProductsCount).toBe(0);
      expect(parsed.ignoredNonCveCount).toBe(0);

      // Resolve verdict
      const verdict = resolveVendorVex(parsed, 'CVE-2022-30065', 'busybox');
      expect(verdict.verdict).toBe('vendor_states_fixed');
      expect(verdict.statementIndex).toBe(0);
      expect(verdict.sourcePath).toBe('/etc/vex/openvex.json');
      expect(verdict.author).toBe('ACME Security Advisory Team');
      expect(verdict.timestamp).toBe('2023-02-01T10:00:00Z');
      expect(verdict.documentAuthor).toBe('ACME Security Advisory Team');
      expect(verdict.documentTimestamp).toBe('2023-02-01T10:00:00Z');
      expect(verdict.actionStatement).toBe('Upgrade busybox to 1.35.0-r2 or higher.');
      expect(verdict.rationale).toContain('Vendor asserts in ACME Security Advisory Team VEX document');
      expect(verdict.rationale).toContain("this is the vendor's assertion, not a verified code fact");
    });

    it('parses OpenVEX not_affected statement with justification and impact statement', () => {
      const openVexDoc = JSON.stringify({
        '@context': ['https://openvex.dev/ns'],
        author: { name: 'ACME Embedded Linux OS' },
        last_updated: '2023-03-15T12:00:00Z',
        statements: [
          {
            vulnerability: 'CVE-2021-44228',
            products: ['pkg:generic/busybox@1.35.0'],
            status: 'not_affected',
            justification: 'component_not_present',
            impact_statement: 'Log4j is a Java component not included in this BusyBox embedded build.',
          },
        ],
      });

      const parsed = parseVendorVex(openVexDoc, '/usr/share/vex/acme.openvex.json');
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      expect(parsed.author).toBe('ACME Embedded Linux OS');
      expect(parsed.timestamp).toBe('2023-03-15T12:00:00Z');
      expect(parsed.statements[0]?.justification).toBe('component_not_present');
      expect(parsed.statements[0]?.impactStatement).toBe(
        'Log4j is a Java component not included in this BusyBox embedded build.',
      );

      const verdict = resolveVendorVex(parsed, 'CVE-2021-44228', ['pkg:generic/busybox@1.35.0'], {
        componentName: 'busybox',
      });
      expect(verdict.verdict).toBe('vendor_states_not_affected');
      expect(verdict.statementIndex).toBe(0);
      expect(verdict.justification).toBe('component_not_present');
      expect(verdict.impactStatement).toBe('Log4j is a Java component not included in this BusyBox embedded build.');
      expect(verdict.rationale).toContain('not affected by CVE-2021-44228 (component_not_present)');
      expect(verdict.rationale).toContain("this is the vendor's assertion, not a verified code fact");
    });

    it('handles OpenVEX affected and under_investigation statements', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        author: 'RouterVendor',
        statements: [
          {
            vulnerability: { name: 'CVE-2023-1111' },
            products: ['dnsmasq'],
            status: 'affected',
          },
          {
            vulnerability: { name: 'CVE-2023-2222' },
            products: ['dnsmasq'],
            status: 'under_investigation',
          },
        ],
      });

      const parsed = parseVendorVex(doc, '/etc/openvex.json');
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      const verdictAffected = resolveVendorVex(parsed, 'CVE-2023-1111', 'dnsmasq');
      expect(verdictAffected.verdict).toBe('vendor_states_affected');
      expect(verdictAffected.rationale).toContain('is affected by CVE-2023-1111');
      expect(verdictAffected.rationale).toContain("this is the vendor's assertion, not a verified code fact");

      const verdictUnderInv = resolveVendorVex(parsed, 'CVE-2023-2222', 'dnsmasq');
      expect(verdictUnderInv.verdict).toBe('vendor_under_investigation');
      expect(verdictUnderInv.rationale).toContain('under investigation');
      expect(verdictUnderInv.rationale).toContain("this is the vendor's assertion, not a verified code fact");
    });
  });

  describe('CSAF 2.0 VEX profile parsing and resolution', () => {
    it('parses CSAF known_not_affected, fixed, and known_affected statuses', () => {
      const csafDoc = JSON.stringify({
        document: {
          category: 'csaf_vex',
          csaf_version: '2.0',
          title: 'ACME Security Advisory for Gateway Firmware',
          publisher: {
            name: 'ACME Product Security',
            category: 'vendor',
          },
          tracking: {
            id: 'CSAF-2023-GW-01',
            current_release_date: '2023-04-10T14:30:00Z',
          },
        },
        product_tree: {
          full_product_names: [
            {
              product_id: 'CSAFPID-0001',
              name: 'busybox 1.35.0',
              product_identification_helper: {
                purl: 'pkg:generic/busybox@1.35.0',
              },
            },
            {
              product_id: 'CSAFPID-0002',
              name: 'dropbear 2020.81',
            },
            {
              product_id: 'CSAFPID-0003',
              name: 'dnsmasq 2.85',
            },
          ],
        },
        vulnerabilities: [
          {
            cve: 'CVE-2022-22817',
            title: 'Buffer overflow in image parser',
            product_status: {
              known_not_affected: ['CSAFPID-0001'],
            },
            flags: [
              {
                label: 'inline_mitigations_already_exist',
                product_ids: ['CSAFPID-0001'],
              },
            ],
            threats: [
              {
                category: 'impact',
                details: 'Vulnerable code is guarded by compiler stack protection and ASLR.',
                product_ids: ['CSAFPID-0001'],
              },
            ],
          },
          {
            cve: 'CVE-2022-22818',
            title: 'Dropbear authentication bypass',
            product_status: {
              fixed: ['CSAFPID-0002'],
            },
            remediations: [
              {
                category: 'vendor_fix',
                details: 'Backported upstream commit 9a8b7c into vendor build tree.',
                product_ids: ['CSAFPID-0002'],
              },
            ],
          },
          {
            cve: 'CVE-2022-22819',
            title: 'Dnsmasq heap overflow',
            product_status: {
              known_affected: ['CSAFPID-0003'],
            },
            threats: [
              {
                category: 'impact',
                details: 'Remote denial of service reachable via DHCP requests.',
                product_ids: ['CSAFPID-0003'],
              },
            ],
          },
        ],
      });

      const parsed = parseVendorVex(csafDoc, '/etc/security/csaf-vex.json');
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      expect(parsed.format).toBe('csaf_vex');
      expect(parsed.author).toBe('ACME Product Security');
      expect(parsed.timestamp).toBe('2023-04-10T14:30:00Z');
      expect(parsed.statements).toHaveLength(3);

      // 1. known_not_affected -> vendor_states_not_affected
      const verdictNotAffected = resolveVendorVex(parsed, 'CVE-2022-22817', 'busybox', ['pkg:generic/busybox@1.35.0']);
      expect(verdictNotAffected.verdict).toBe('vendor_states_not_affected');
      expect(verdictNotAffected.statementIndex).toBe(0);
      expect(verdictNotAffected.justification).toBe('inline_mitigations_already_exist');
      expect(verdictNotAffected.impactStatement).toBe(
        'Vulnerable code is guarded by compiler stack protection and ASLR.',
      );
      expect(verdictNotAffected.rationale).toContain("this is the vendor's assertion, not a verified code fact");

      // 2. fixed -> vendor_states_fixed
      const verdictFixed = resolveVendorVex(parsed, 'CVE-2022-22818', 'dropbear', ['CSAFPID-0002']);
      expect(verdictFixed.verdict).toBe('vendor_states_fixed');
      expect(verdictFixed.statementIndex).toBe(1);
      expect(verdictFixed.actionStatement).toBe('Backported upstream commit 9a8b7c into vendor build tree.');
      expect(verdictFixed.rationale).toContain("this is the vendor's assertion, not a verified code fact");

      // 3. known_affected -> vendor_states_affected
      const verdictAffected = resolveVendorVex(parsed, 'CVE-2022-22819', 'dnsmasq', ['dnsmasq 2.85']);
      expect(verdictAffected.verdict).toBe('vendor_states_affected');
      expect(verdictAffected.statementIndex).toBe(2);
      expect(verdictAffected.impactStatement).toBe('Remote denial of service reachable via DHCP requests.');
    });
  });

  describe('resolution: unmentioned CVE and unmatched products', () => {
    it('returns unmentioned for CVEs not present in the document', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        author: 'Vendor',
        statements: [
          {
            vulnerability: 'CVE-2021-1111',
            products: ['busybox'],
            status: 'fixed',
          },
        ],
      });

      const parsed = parseVendorVex(doc, '/etc/vex.json');
      expect(parsed.ok).toBe(true);

      const verdict = resolveVendorVex(parsed, 'CVE-2024-99999', 'busybox');
      expect(verdict.verdict).toBe('unmentioned');
      expect(verdict.statementIndex).toBeNull();
      expect(verdict.justification).toBeNull();
      expect(verdict.rationale).toContain('makes no statement regarding CVE-2024-99999');
      expect(verdict.rationale).toContain('silence in vendor documentation is not evidence of absence or cleanliness');
    });

    it('returns unmentioned when document is null or undefined', () => {
      const verdictNull = resolveVendorVex(null, 'CVE-2021-44228', 'busybox');
      expect(verdictNull.verdict).toBe('unmentioned');
      expect(verdictNull.statementIndex).toBeNull();
      expect(verdictNull.rationale).toContain(
        'absence of a vendor statement is not evidence of absence or cleanliness',
      );

      const verdictUndefined = resolveVendorVex(undefined, 'CVE-2021-44228', 'busybox');
      expect(verdictUndefined.verdict).toBe('unmentioned');
    });

    it('returns unmentioned when CVE is present but product is not accepted by the matcher', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        author: 'Vendor',
        statements: [
          {
            vulnerability: 'CVE-2021-44228',
            products: ['pkg:generic/log4j@2.14.0', 'java-runtime'],
            status: 'not_affected',
            justification: 'component_not_present',
          },
        ],
      });

      const parsed = parseVendorVex(doc, '/etc/vex.json');
      expect(parsed.ok).toBe(true);

      // Caller matches only busybox products; log4j is not accepted
      const verdict = resolveVendorVex(parsed, 'CVE-2021-44228', 'busybox', ['pkg:generic/busybox@1.35.0']);
      expect(verdict.verdict).toBe('unmentioned');
      expect(verdict.statementIndex).toBeNull();
      expect(verdict.rationale).toContain('makes no statement regarding CVE-2021-44228');
    });
  });

  describe('conflicting statements', () => {
    it('returns conflicting when multiple matching statements disagree on status, never resolved by order', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        author: 'Vendor Security',
        statements: [
          {
            vulnerability: 'CVE-2021-44228',
            products: ['busybox'],
            status: 'not_affected',
            justification: 'component_not_present',
          },
          {
            vulnerability: 'CVE-2021-44228',
            products: ['busybox'],
            status: 'fixed',
            action_statement: 'Backported patch in v1.35.0-patch1',
          },
        ],
      });

      const parsed = parseVendorVex(doc, '/etc/vex.json');
      expect(parsed.ok).toBe(true);

      const verdict = resolveVendorVex(parsed, 'CVE-2021-44228', 'busybox');
      expect(verdict.verdict).toBe('conflicting');
      expect(verdict.statementIndex).toBeNull();
      expect(verdict.justification).toBeNull();
      expect(verdict.conflictingStatements).toHaveLength(2);
      expect(verdict.rationale).toContain('contains conflicting statements for CVE-2021-44228');
      expect(verdict.rationale).toContain('statement #0 asserts not_affected');
      expect(verdict.rationale).toContain('statement #1 asserts fixed');
      expect(verdict.rationale).toContain(
        'conflicting vendor claims cannot resolve exploitability and are not code facts',
      );
    });

    it('does not conflict if multiple matching statements agree on the same status', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        author: 'Vendor Security',
        statements: [
          {
            vulnerability: 'CVE-2021-44228',
            products: ['busybox-bin'],
            status: 'not_affected',
            justification: 'component_not_present',
          },
          {
            vulnerability: 'CVE-2021-44228',
            products: ['busybox-source'],
            status: 'not_affected',
            justification: 'vulnerable_code_not_present',
          },
        ],
      });

      const parsed = parseVendorVex(doc, '/etc/vex.json');
      expect(parsed.ok).toBe(true);

      const verdict = resolveVendorVex(parsed, 'CVE-2021-44228', (prod) => prod.startsWith('busybox'));
      expect(verdict.verdict).toBe('vendor_states_not_affected');
      expect(verdict.matchedStatements).toHaveLength(2);
      expect(verdict.conflictingStatements).toBeUndefined();
    });
  });

  describe('bounds and error resilience', () => {
    it('refuses malformed JSON without throwing', () => {
      const malformed = '{\n  "@context": "https://openvex.dev/ns/v0.2.0",\n  "statements": [ { unclosed';
      const parsed = parseVendorVex(malformed, '/etc/broken.json');
      expect(parsed.ok).toBe(false);
      if (parsed.ok) return;

      expect(parsed.reason).toBe('malformed_json');
      expect(parsed.message).toContain('Malformed JSON');
      expect(parsed.sourcePath).toBe('/etc/broken.json');
    });

    it('refuses non-VEX JSON without throwing', () => {
      const nonVex = JSON.stringify({
        name: '@firmlab/core',
        version: '0.1.0',
        dependencies: {},
      });
      const parsed = parseVendorVex(nonVex, '/package.json');
      expect(parsed.ok).toBe(false);
      if (parsed.ok) return;

      expect(parsed.reason).toBe('non_vex_json');
      expect(parsed.message).toContain('Document JSON does not match OpenVEX');
    });

    it('refuses oversized documents beyond maxDocumentBytes without throwing', () => {
      const largeDoc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        statements: [],
        padding: 'A'.repeat(500),
      });

      const parsed = parseVendorVex(largeDoc, '/etc/huge-vex.json', { maxDocumentBytes: 200 });
      expect(parsed.ok).toBe(false);
      if (parsed.ok) return;

      expect(parsed.reason).toBe('oversized_document');
      expect(parsed.bytesExamined).toBeGreaterThan(200);
      expect(parsed.maxBytes).toBe(200);
    });

    it('enforces maxStatements cap and reports dropped statements in document order', () => {
      const statements = [
        { vulnerability: 'CVE-2021-0001', products: ['prod-a'], status: 'fixed' },
        { vulnerability: 'CVE-2021-0002', products: ['prod-b'], status: 'fixed' },
        { vulnerability: 'CVE-2021-0003', products: ['prod-c'], status: 'fixed' },
        { vulnerability: 'CVE-2021-0004', products: ['prod-d'], status: 'fixed' },
        { vulnerability: 'CVE-2021-0005', products: ['prod-e'], status: 'fixed' },
      ];
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        statements,
      });

      const parsed = parseVendorVex(doc, '/etc/vex.json', { maxStatements: 2 });
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      expect(parsed.statements).toHaveLength(2);
      expect(parsed.statements[0]?.vulnerabilityId).toBe('CVE-2021-0001');
      expect(parsed.statements[1]?.vulnerabilityId).toBe('CVE-2021-0002');
      expect(parsed.droppedStatementsCount).toBe(3);
      expect(parsed.boundsRule).toBe(VEX_BOUNDS_RULE);
    });

    it('enforces maxProducts cap and reports dropped products in document order', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        statements: [
          {
            vulnerability: 'CVE-2021-0001',
            products: ['prod-1', 'prod-2', 'prod-3'],
            status: 'fixed',
          },
          {
            vulnerability: 'CVE-2021-0002',
            products: ['prod-4', 'prod-5', 'prod-6'],
            status: 'fixed',
          },
        ],
      });

      const parsed = parseVendorVex(doc, '/etc/vex.json', { maxProducts: 4 });
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      expect(parsed.statements).toHaveLength(2);
      expect(parsed.statements[0]?.products).toEqual(['prod-1', 'prod-2', 'prod-3']);
      expect(parsed.statements[1]?.products).toEqual(['prod-4']);
      expect(parsed.droppedProductsCount).toBe(2);
    });

    it('ignores non-CVE identifiers and increments ignoredNonCveCount', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        statements: [
          { vulnerability: 'GHSA-1234-5678', products: ['prod'], status: 'fixed' },
          { vulnerability: 'RHSA-2023:9999', products: ['prod'], status: 'fixed' },
          { vulnerability: 'ALAS-2022-001', products: ['prod'], status: 'fixed' },
          { vulnerability: 'cve-bad-format', products: ['prod'], status: 'fixed' },
          { vulnerability: 'CVE-2023-4567', products: ['prod'], status: 'fixed' },
        ],
      });

      const parsed = parseVendorVex(doc, '/etc/vex.json');
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      expect(parsed.ignoredNonCveCount).toBe(4);
      expect(parsed.statements).toHaveLength(1);
      expect(parsed.statements[0]?.vulnerabilityId).toBe('CVE-2023-4567');
    });

    it('ignores non-CVE identifiers in CSAF vulnerabilities', () => {
      const csafDoc = JSON.stringify({
        document: {
          category: 'csaf_vex',
          csaf_version: '2.0',
        },
        vulnerabilities: [
          {
            cve: 'GHSA-9876-5432',
            product_status: { fixed: ['prod-1'] },
          },
          {
            cve: 'CVE-2022-12345',
            product_status: { fixed: ['prod-2'] },
          },
        ],
      });

      const parsed = parseVendorVex(csafDoc, '/etc/csaf.json');
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      expect(parsed.ignoredNonCveCount).toBe(1);
      expect(parsed.statements).toHaveLength(1);
      expect(parsed.statements[0]?.vulnerabilityId).toBe('CVE-2022-12345');
    });

    it('type guard isVendorVexDocument accurately distinguishes documents from refusals', () => {
      const validDoc = parseVendorVex(
        JSON.stringify({ '@context': 'https://openvex.dev/ns', statements: [] }),
        '/doc.json',
      );
      const invalidDoc = parseVendorVex('{ not json', '/bad.json');

      expect(isVendorVexDocument(validDoc)).toBe(true);
      expect(isVendorVexDocument(invalidDoc)).toBe(false);
      expect(isVendorVexDocument(null)).toBe(false);
      expect(isVendorVexDocument(undefined)).toBe(false);
    });

    it('safely handles refused document passed directly into resolveVendorVex', () => {
      const refusal = parseVendorVex('{ broken json', '/bad.json');
      const verdict = resolveVendorVex(refusal, 'CVE-2021-44228', 'busybox');

      expect(verdict.verdict).toBe('unmentioned');
      expect(verdict.sourcePath).toBe('/bad.json');
      expect(verdict.statementIndex).toBeNull();
      expect(verdict.rationale).toContain('was refused (malformed_json');
      expect(verdict.rationale).toContain('is not evidence of absence or cleanliness');
    });
  });

  describe('proof-state and findings invariants', () => {
    it('never assigns or modifies proof states and states the claim is vendor assertion', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        author: 'Acme Hardware Corp',
        statements: [
          {
            vulnerability: 'CVE-2021-44228',
            products: ['busybox'],
            status: 'not_affected',
            justification: 'component_not_present',
          },
        ],
      });

      const parsed = parseVendorVex(doc, '/vex/openvex.json');
      expect(parsed.ok).toBe(true);

      const verdict = resolveVendorVex(parsed, 'CVE-2021-44228', 'busybox');

      // The returned object must not carry proofState field
      expect((verdict as Record<string, unknown>).proofState).toBeUndefined();

      // Must be marked vendor_states_not_affected, not static_confirmed or false_positive
      expect(verdict.verdict).toBe('vendor_states_not_affected');
      expect(verdict.rationale).toContain("this is the vendor's assertion, not a verified code fact");
    });
  });

  describe('CSAF product identity is kept together (version scope)', () => {
    const csaf = (products: unknown[], productStatus: Record<string, string[]>, flags?: unknown[]) =>
      JSON.stringify({
        document: { category: 'csaf_vex', publisher: { name: 'V' } },
        product_tree: { full_product_names: products },
        vulnerabilities: [{ cve: 'CVE-2022-48174', product_status: productStatus, ...(flags ? { flags } : {}) }],
      });

    it('a product with a versioned purl stands only for that purl, never its bare name or product_id', () => {
      const parsed = parseVendorVex(
        csaf(
          [
            {
              product_id: 'busybox',
              name: 'busybox',
              product_identification_helper: { purl: 'pkg:generic/busybox@1.30.1' },
            },
          ],
          { fixed: ['busybox'] },
          [{ label: 'vulnerable_code_not_present', product_ids: ['busybox'] }],
        ),
        '/etc/csaf.json',
      );
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      expect(parsed.statements[0]?.products).toEqual(['pkg:generic/busybox@1.30.1']);
      // Flags still reference the group by product_id even though the id no longer stands for the product.
      expect(parsed.statements[0]?.justification).toBe('vulnerable_code_not_present');
      expect(resolveVendorVex(parsed, 'CVE-2022-48174', 'busybox', ['busybox']).verdict).toBe('unmentioned');
      expect(resolveVendorVex(parsed, 'CVE-2022-48174', 'busybox', ['pkg:generic/busybox@1.30.1']).verdict).toBe(
        'vendor_states_fixed',
      );
    });

    it('a kernel product with a versioned CPE stands only for that CPE', () => {
      const cpe = 'cpe:2.3:o:linux:linux_kernel:4.4.0:*:*:*:*:*:*:*';
      const parsed = parseVendorVex(
        csaf([{ product_id: 'K', name: 'linux-kernel', product_identification_helper: { cpe } }], {
          known_not_affected: ['K'],
        }),
        '/etc/csaf.json',
      );
      if (!parsed.ok) throw new Error('fixture refused');
      expect(parsed.statements[0]?.products).toEqual([cpe]);
    });

    it('a product with only a name, or only unversioned helpers, keeps its id and name', () => {
      const parsed = parseVendorVex(
        csaf(
          [
            { product_id: 'P1', name: 'busybox' },
            { product_id: 'P2', name: 'dropbear', product_identification_helper: { purl: 'pkg:generic/dropbear' } },
          ],
          { fixed: ['P1', 'P2'] },
        ),
        '/etc/csaf.json',
      );
      if (!parsed.ok) throw new Error('fixture refused');
      expect(parsed.statements[0]?.products).toEqual(['P1', 'busybox', 'P2', 'dropbear', 'pkg:generic/dropbear']);
    });
  });

  describe('CSAF boundary statuses remain omissions, never assertions', () => {
    const cve = 'CVE-2022-48174';
    const boundaryStatuses = ['first_affected', 'last_affected', 'first_fixed'];
    const csaf = (vulnerabilities: unknown[]) =>
      JSON.stringify({ document: { category: 'csaf_vex' }, vulnerabilities });

    it.each(boundaryStatuses)('counts %s once per group without matching its products', (status) => {
      const parsed = parseVendorVex(
        csaf([{ cve: cve.toLowerCase(), product_status: { [status]: ['busybox', 'pkg:generic/busybox@1.30.1'] } }]),
        '/csaf.json',
      );
      if (!parsed.ok) throw new Error('fixture refused');
      expect(parsed.statements).toEqual([]);
      expect(parsed.unrecognisedStatusCount).toBe(1);
      expect(parsed.unrecognisedStatusExamples).toEqual([{ vulnerabilityId: cve, status }]);
      expect(resolveVendorVex(parsed, cve, () => true).verdict).toBe('unmentioned');
    });

    it('counts every omitted group beyond the example and statement/product caps in document order', () => {
      const vulnerabilities = Array.from({ length: 5 }, (_, i) => ({
        cve: `CVE-2022-${1000 + i}`,
        product_status: { last_affected: ['P', 'Q'], first_fixed: ['P'], first_affected: ['Q'], fixed: ['P'] },
      }));
      const parsed = parseVendorVex(csaf(vulnerabilities), '/csaf.json', { maxStatements: 0, maxProducts: 0 });
      if (!parsed.ok) throw new Error('fixture refused');
      expect(parsed.statements).toEqual([]);
      expect(parsed.droppedStatementsCount).toBe(5);
      expect(parsed.unrecognisedStatusCount).toBe(15);
      expect(parsed.unrecognisedStatusExamples).toEqual(
        vulnerabilities
          .flatMap((v) =>
            ['last_affected', 'first_fixed', 'first_affected'].map((status) => ({
              vulnerabilityId: v.cve,
              status,
            })),
          )
          .slice(0, MAX_UNRECOGNISED_STATUS_EXAMPLES),
      );
    });

    it('preserves supported conflicts alongside unsupported boundaries', () => {
      const parsed = parseVendorVex(
        csaf([
          {
            cve,
            product_status: {
              first_affected: ['busybox'],
              last_affected: ['busybox'],
              first_fixed: ['busybox'],
              fixed: ['busybox'],
              known_affected: ['busybox'],
            },
          },
        ]),
        '/csaf.json',
      );
      if (!parsed.ok) throw new Error('fixture refused');
      expect(parsed.unrecognisedStatusCount).toBe(3);
      const verdict = resolveVendorVex(parsed, cve, 'busybox');
      expect(verdict.verdict).toBe('conflicting');
      expect(verdict.matchedStatements?.map((s) => s.status)).toEqual(['fixed', 'affected']);
    });

    it.each([null, false, 42, 'P', {}, [], [null, {}, 42]])(
      'handles malformed or empty boundary product lists without throwing (%j)',
      (products) => {
        const text = csaf([null, { cve, product_status: null }, { cve, product_status: { first_fixed: products } }]);
        expect(() => parseVendorVex(text, '/csaf.json')).not.toThrow();
        const parsed = parseVendorVex(text, '/csaf.json');
        if (!parsed.ok) throw new Error('fixture refused');
        expect(parsed.statements).toEqual([]);
        expect(parsed.unrecognisedStatusCount).toBe(Array.isArray(products) && products.length > 0 ? 1 : 0);
      },
    );

    it('resolves a legacy persisted document without optional omission fields', () => {
      const parsed = parseVendorVex(csaf([{ cve, product_status: { fixed: ['busybox'] } }]), '/csaf.json');
      if (!parsed.ok) throw new Error('fixture refused');
      const { unrecognisedStatusCount: _count, unrecognisedStatusExamples: _examples, ...legacy } = parsed;
      expect(resolveVendorVex(JSON.parse(JSON.stringify(legacy)), cve, 'busybox').verdict).toBe('vendor_states_fixed');
    });
  });

  describe('a truncated or partly unreadable document says so', () => {
    it('a verdict from a document whose statement cap dropped anything carries droppedByBounds', () => {
      const doc = JSON.stringify({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        statements: [
          { vulnerability: 'CVE-2022-48174', products: ['busybox'], status: 'not_affected' },
          { vulnerability: 'CVE-2021-0001', products: ['x'], status: 'fixed' },
          { vulnerability: 'CVE-2022-48174', products: ['busybox'], status: 'affected' },
        ],
      });
      const parsed = parseVendorVex(doc, '/etc/vex.json', { maxStatements: 2 });
      if (!parsed.ok) throw new Error('fixture refused');
      const verdict = resolveVendorVex(parsed, 'CVE-2022-48174', 'busybox');
      // The conflicting half was dropped: the verdict is single, and must not read as complete.
      expect(verdict.verdict).toBe('vendor_states_not_affected');
      expect(verdict.droppedByBounds).toEqual({ statements: 1, products: 0 });
      expect(verdict.rationale).toMatch(/not a complete reading of the document/);

      const whole = parseVendorVex(doc, '/etc/vex.json');
      if (!whole.ok) throw new Error('fixture refused');
      const full = resolveVendorVex(whole, 'CVE-2022-48174', 'busybox');
      expect(full.verdict).toBe('conflicting');
      expect(full.droppedByBounds).toBeUndefined();
    });

    it('counts statements with an unrecognised status, with bounded examples, instead of dropping them silently', () => {
      const statements = [
        { vulnerability: 'CVE-2022-48174', products: ['busybox'], status: 'not_affected' },
        { vulnerability: 'CVE-2022-48174', products: ['busybox'], status: 'known_affected' },
        { vulnerability: 'CVE-2022-48174', products: ['busybox'], status: 'not affected' },
        { vulnerability: 'CVE-2022-48174', products: ['busybox'] },
        ...Array.from({ length: MAX_UNRECOGNISED_STATUS_EXAMPLES }, (_, i) => ({
          vulnerability: `CVE-2020-${1000 + i}`,
          products: ['x'],
          status: 'bogus',
        })),
      ];
      const parsed = parseVendorVex(
        JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', statements }),
        '/etc/vex.json',
      );
      if (!parsed.ok) throw new Error('fixture refused');
      expect(parsed.statements).toHaveLength(1);
      expect(parsed.unrecognisedStatusCount).toBe(3 + MAX_UNRECOGNISED_STATUS_EXAMPLES);
      expect(parsed.unrecognisedStatusExamples).toHaveLength(MAX_UNRECOGNISED_STATUS_EXAMPLES);
      expect(parsed.unrecognisedStatusExamples?.slice(0, 3)).toEqual([
        { vulnerabilityId: 'CVE-2022-48174', status: 'known_affected' },
        { vulnerabilityId: 'CVE-2022-48174', status: 'not affected' },
        { vulnerabilityId: 'CVE-2022-48174', status: 'null' },
      ]);
    });
  });
});
