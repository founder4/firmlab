import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  DEFERRED_SWITCH_MAPPINGS,
  NEAR_MISS_EXAMPLES,
  SWITCH_EVIDENCE_RULES,
  SWITCH_VENDOR_NAMES,
  detectSwitchFamily,
  matchTokenAt,
  nearMissAt,
} from '../src/switch-family.js';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

/** A buffer of non-printable filler with ASCII strings placed at given offsets, the way literals sit in an image. */
function image(size: number, strings: readonly [number, string][]): Uint8Array {
  const buf = new Uint8Array(size).fill(0xff);
  for (const [offset, s] of strings) {
    for (let k = 0; k < s.length; k++) buf[offset + k] = s.charCodeAt(k);
  }
  return buf;
}

function bytesOf(s: string): Uint8Array {
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

describe('rule table rationale', () => {
  it('backs every rule with text that is verbatim in the cited repository file', () => {
    // Independent of the module: read the cited file and look for the quote, so a rule cannot cite a source that
    // does not say what the rule claims, and a doc edit that drops the backing breaks this test.
    for (const rule of SWITCH_EVIDENCE_RULES) {
      const text = readFileSync(`${REPO_ROOT}${rule.backing.file}`, 'utf8');
      expect(text, rule.id).toContain(rule.backing.quote);
      expect(rule.backing.quote.toLowerCase(), rule.id).toContain(rule.prefix);
      expect(rule.rationale.length, rule.id).toBeGreaterThan(40);
    }
  });

  it('accepts as exact only a part the repository names exactly; templates stay templates', () => {
    const exact = SWITCH_EVIDENCE_RULES.filter((r) => r.tier === 'exact-literal');
    expect(exact.map((r) => r.id)).toEqual(['qca8337-literal']);
    for (const r of exact) expect(r.digits).toBe(0);
    for (const r of SWITCH_EVIDENCE_RULES.filter((x) => x.tier === 'family-template')) {
      // The doc writes the template with two `x` placeholders; the rule must not widen it.
      expect(r.backing.quote).toMatch(/xx$/);
      expect(r.digits).toBe(2);
    }
  });

  it('never lets a vendor name be a rule, and defers what no repository source maps', () => {
    const vendorPrefixes = new Set(SWITCH_VENDOR_NAMES.map((v) => v.prefix));
    for (const r of SWITCH_EVIDENCE_RULES) expect(vendorPrefixes.has(r.prefix)).toBe(false);
    const deferred = DEFERRED_SWITCH_MAPPINGS.map((d) => d.what).join(' | ');
    expect(deferred).toMatch(/compatible/);
    expect(deferred).toMatch(/driver/);
    expect(deferred).toMatch(/RTL83xx and BCM53xx/);
  });
});

describe('matchTokenAt', () => {
  it('requires a whole token, case-insensitively', () => {
    expect(matchTokenAt(bytesOf(' QCA8337 '), 1, 'qca8337', 0, false)).toEqual({ kind: 'match', length: 7 });
    expect(matchTokenAt(bytesOf(',qca8337_'), 1, 'qca8337', 0, false)).toEqual({ kind: 'match', length: 7 });
    expect(matchTokenAt(bytesOf('XQCA8337 '), 1, 'qca8337', 0, false).kind).toBe('none');
    expect(matchTokenAt(bytesOf(' QCA83370'), 1, 'qca8337', 0, false).kind).toBe('none');
    expect(matchTokenAt(bytesOf(' QCA8337N'), 1, 'qca8337', 0, false).kind).toBe('none');
  });

  it('requires exactly the template digit count', () => {
    expect(matchTokenAt(bytesOf(' RTL8367 '), 1, 'rtl83', 2, false)).toEqual({ kind: 'match', length: 7 });
    expect(matchTokenAt(bytesOf(' RTL836 '), 1, 'rtl83', 2, false).kind).toBe('none');
    expect(matchTokenAt(bytesOf(' RTL83670 '), 1, 'rtl83', 2, false).kind).toBe('none');
    expect(matchTokenAt(bytesOf(' RTL83xx '), 1, 'rtl83', 2, false).kind).toBe('none');
  });

  it('separates the end of the data from the end of a truncated read', () => {
    expect(matchTokenAt(bytesOf(' QCA8337'), 1, 'qca8337', 0, false)).toEqual({ kind: 'match', length: 7 });
    expect(matchTokenAt(bytesOf(' QCA8337'), 1, 'qca8337', 0, true).kind).toBe('edge');
    expect(matchTokenAt(bytesOf(' QCA83'), 1, 'qca8337', 0, false).kind).toBe('none');
    expect(matchTokenAt(bytesOf(' QCA83'), 1, 'qca8337', 0, true).kind).toBe('edge');
  });
});

describe('detectSwitchFamily', () => {
  it('positive: one exact literal yields a single-family lead with offset, rule, match and context', () => {
    const r = detectSwitchFamily(image(4096, [[1000, 'qca8337: switch probe failed']]));
    expect(r.verdict).toBe('single-family-lead');
    expect(r.candidates).toHaveLength(1);
    const c = r.candidates[0];
    expect(c?.family).toBe('qca8337');
    expect(c?.standing).toBe('exact-literal');
    expect(c?.distinctTokens).toEqual(['QCA8337']);
    expect(c?.evidence[0]).toMatchObject({
      ruleId: 'qca8337-literal',
      offset: 1000,
      length: 7,
      matchedText: 'qca8337',
      context: 'qca8337: switch probe failed',
      contextOffset: 1000,
    });
    expect(r.coverage.completed).toBe(true);
    expect(r.coverage.stoppedBy).toBe('end-of-input');
    expect(r.summary).toMatch(/dormant driver/);
    expect(r.summary).toMatch(/never describes the hardware on a live device/);
    expect(r.summary).toMatch(/Nothing here emulates a switch or shows that any network works/);
  });

  it('template: a template-fitting token alone does not single out a family', () => {
    const r = detectSwitchFamily(image(2048, [[200, 'rtl8367 init']]));
    expect(r.verdict).toBe('template-only');
    expect(r.candidates.map((c) => [c.family, c.standing])).toEqual([['rtl83xx', 'family-template']]);
    expect(r.summary).toMatch(/does not single out a family/);
  });

  it('ambiguous: literals from two families are reported together, in fixed family order', () => {
    const r = detectSwitchFamily(
      image(8192, [
        [100, 'QCA8337'],
        [5000, 'BCM5325 robo'],
      ]),
    );
    expect(r.verdict).toBe('ambiguous');
    expect(r.candidates.map((c) => [c.family, c.standing])).toEqual([
      ['bcm53xx', 'family-template'],
      ['qca8337', 'exact-literal'],
    ]);
    expect(r.summary).toMatch(/2 families/);
    expect(r.summary).toMatch(/rather than resolved by count or order/);
  });

  it('ambiguous wins over counts: many hits of one family do not outvote another', () => {
    const strings: [number, string][] = Array.from({ length: 30 }, (_, k) => [100 + k * 20, 'QCA8337']);
    strings.push([4000, 'RTL8370']);
    expect(detectSwitchFamily(image(8192, strings)).verdict).toBe('ambiguous');
  });

  it('vendor-only: vendor names never create a candidate', () => {
    const r = detectSwitchFamily(
      image(4096, [
        [10, 'Realtek Semiconductor Corp.'],
        [300, 'Broadcom Corporation'],
        [900, 'Atheros Communications'],
        [1500, 'Qualcomm'],
      ]),
    );
    expect(r.verdict).toBe('vendor-only');
    expect(r.candidates).toEqual([]);
    expect(r.vendorMentions.map((v) => [v.vendor, v.count, v.offsets])).toEqual([
      ['Realtek', 1, [10]],
      ['Broadcom', 1, [300]],
      ['Qualcomm', 1, [1500]],
      ['Atheros', 1, [900]],
    ]);
    expect(r.summary).toMatch(/never switch-family evidence/);
  });

  it('negative: near-miss tokens match nothing, and none-observed says it is not absence', () => {
    const r = detectSwitchFamily(
      image(4096, [
        [10, 'XQCA8337'],
        [100, 'QCA83370'],
        [200, 'RTL836 '],
        [300, 'BCM53115'],
        [400, 'RTL8367RB'],
        [500, 'RTL83xx'],
        [600, 'Realtekish'],
      ]),
    );
    expect(r.verdict).toBe('none-observed');
    expect(r.candidates).toEqual([]);
    expect(r.vendorMentions).toEqual([]);
    expect(r.summary).toMatch(/not evidence of no switch/);
    // Only the tokens rejected by the closing boundary are near-misses; a left-boundary miss, a short digit run
    // and the template placeholder are not family-shaped.
    expect(r.nearMisses).toEqual({
      count: 3,
      examples: [
        { ruleId: 'qca8337-literal', token: 'QCA83370', offset: 100 },
        { ruleId: 'bcm53xx-template', token: 'BCM53115', offset: 300 },
        { ruleId: 'rtl83xx-template', token: 'RTL8367RB', offset: 400 },
      ],
    });
    expect(r.summary).toMatch(/3 family-shaped token\(s\) \(e\.g\. QCA83370, BCM53115, RTL8367RB\) were seen/);
    expect(r.summary).toMatch(/deliberately not matched by the boundary rule/);
    expect(r.coverage.statement).toMatch(/3 family-shaped token\(s\)/);
    expect(r.coverage.statement).toMatch(/Compressed or encrypted regions are not decoded/);
    expect(r.coverage.statement).toMatch(/single-byte ASCII.*UTF-16.*not matched/);
    expect(r.coverage.rulesAttempted).toEqual([
      'qca8337-literal',
      'rtl83xx-template',
      'bcm53xx-template',
      'vendor:Realtek',
      'vendor:Broadcom',
      'vendor:Qualcomm',
      'vendor:Atheros',
    ]);
  });

  it('empty input: nothing scanned is not-scanned, never none-observed', () => {
    const r = detectSwitchFamily(new Uint8Array(0));
    expect(r.verdict).toBe('not-scanned');
    expect(r.summary).toMatch(/nothing was scanned/);
    expect(r.summary).not.toMatch(/not evidence of no switch/);
    expect(r.coverage).toMatchObject({ bytesScanned: 0, bytesTotal: 0, completed: true, edgeUnresolved: 0 });
  });

  it('near-misses: real switch markings rejected by the boundary are counted and named, never matched', () => {
    for (const marking of ['RTL8367RB', 'RTL8367S', 'rtl8366rb', 'RTL8370M', 'BCM53125', 'BCM5325E', 'qca8337n']) {
      const r = detectSwitchFamily(bytesOf(` ${marking} `));
      expect(r.verdict, marking).toBe('none-observed');
      expect(r.candidates, marking).toEqual([]);
      expect(r.nearMisses, marking).toEqual({ count: 1, examples: [expect.objectContaining({ token: marking })] });
      expect(r.summary, marking).toMatch(new RegExp(`1 family-shaped token\\(s\\) \\(e\\.g\\. ${marking}\\)`));
    }
    // Driver names are a deferred mapping, not a family-shaped part number.
    for (const name of ['qca8k', 'b53_mdio']) {
      expect(detectSwitchFamily(bytesOf(` ${name} `)).nearMisses?.count, name).toBe(0);
    }
    // A clean hit and a near-miss side by side: the verdict comes from the hit alone.
    const mixed = detectSwitchFamily(bytesOf(' QCA8337 RTL8367RB '));
    expect(mixed.verdict).toBe('single-family-lead');
    expect(mixed.candidates.map((c) => c.family)).toEqual(['qca8337']);
    expect(mixed.nearMisses?.count).toBe(1);
  });

  it('near-misses: the count is exact, examples are distinct tokens and bounded, tokens are length-capped', () => {
    const tokens = Array.from({ length: NEAR_MISS_EXAMPLES + 3 }, (_, k) => `RTL8367X${k}`);
    const text = ` ${[...tokens, ...tokens, 'rtl8367x0'].join(' ')} `;
    const r = detectSwitchFamily(bytesOf(text));
    expect(r.nearMisses?.count).toBe(tokens.length * 2 + 1);
    expect(r.nearMisses?.examples.map((e) => e.token)).toEqual(tokens.slice(0, NEAR_MISS_EXAMPLES));
    expect(nearMissAt(bytesOf(` RTL8367${'A'.repeat(100)} `), 1, 'rtl83', 2)).toHaveLength(32);
    expect(nearMissAt(bytesOf(' RTL8367 '), 1, 'rtl83', 2)).toBeNull();
    expect(nearMissAt(bytesOf('XRTL8367RB'), 1, 'rtl83', 2)).toBeNull();
  });

  it('truncated by the scan cap: bytes past the cap are never read, and the coverage says how many', () => {
    const buf = image(4096, [[3000, 'QCA8337']]);
    const r = detectSwitchFamily(buf, { maxScanBytes: 1024 });
    expect(r.verdict).toBe('none-observed');
    expect(r.coverage).toMatchObject({ bytesScanned: 1024, bytesTotal: 4096, completed: false, stoppedBy: 'scan-cap' });
    expect(r.coverage.statement).toMatch(/stopped at the 1024-byte cap; 3072 byte\(s\) were never read/);
    // The same bytes without the cap find it: the miss was the bound, not the image.
    expect(detectSwitchFamily(buf).verdict).toBe('single-family-lead');
  });

  it('a token starting inside the cap is read to its closing boundary even across the cap', () => {
    const r = detectSwitchFamily(image(64, [[28, 'QCA8337 ']]), { maxScanBytes: 30 });
    expect(r.verdict).toBe('single-family-lead');
    const rejected = detectSwitchFamily(image(64, [[28, 'QCA83370']]), { maxScanBytes: 30 });
    expect(rejected.verdict).toBe('none-observed');
  });

  it('truncated input: a token cut off at the end is undecided, not a hit and not a miss', () => {
    const cut = detectSwitchFamily(image(16, [[11, 'QCA83']]), { inputTruncated: true });
    expect(cut.verdict).toBe('none-observed');
    expect(cut.coverage).toMatchObject({ completed: false, stoppedBy: 'input-truncated', edgeUnresolved: 1 });
    expect(cut.coverage.statement).toMatch(/1 possible match\(es\) were cut off/);

    // A complete token ending exactly at a truncated end cannot have its boundary checked either.
    const whole = detectSwitchFamily(image(16, [[9, 'QCA8337']]), { inputTruncated: true });
    expect(whole.verdict).toBe('none-observed');
    expect(whole.coverage.edgeUnresolved).toBe(1);

    // Without the declaration the end of the buffer is the end of the data, and the token is a hit.
    expect(detectSwitchFamily(image(16, [[9, 'QCA8337']])).verdict).toBe('single-family-lead');
  });

  it('cap: records are capped per rule by lowest offset, counts stay exact, other families are not crowded out', () => {
    const strings: [number, string][] = Array.from({ length: 20 }, (_, k) => [1000 - k * 40, 'RTL8367']);
    strings.push([1100, 'QCA8337']);
    const r = detectSwitchFamily(image(2048, strings), { maxHitsPerRule: 4 });
    const rtl = r.candidates.find((c) => c.family === 'rtl83xx');
    expect(rtl?.hitCount).toBe(20);
    expect(rtl?.evidence.map((h) => h.offset)).toEqual([240, 280, 320, 360]);
    expect(r.candidates.find((c) => c.family === 'qca8337')?.evidence.map((h) => h.offset)).toEqual([1100]);
    expect(r.coverage.recordsDropped).toEqual([{ ruleId: 'rtl83xx-template', dropped: 16 }]);
    expect(r.coverage.statement).toMatch(/capped at 4 per rule \(lowest offsets kept\)/);
    expect(r.coverage.statement).toMatch(/rtl83xx-template: 16/);
  });

  it('cap: dropped vendor offsets are reported in recordsDropped and the statement', () => {
    const r = detectSwitchFamily(bytesOf(' Realtek '.repeat(20)), { maxHitsPerRule: 4 });
    expect(r.vendorMentions).toEqual([{ vendor: 'Realtek', count: 20, offsets: [1, 10, 19, 28] }]);
    expect(r.coverage.recordsDropped).toEqual([{ ruleId: 'vendor:Realtek', dropped: 16 }]);
    expect(r.coverage.statement).toMatch(/vendor offsets were capped at 4 per rule/);
    expect(r.coverage.statement).toMatch(/vendor:Realtek: 16/);
  });

  it('a UTF-16 literal is not matched, and the statement says the matcher is single-byte ASCII', () => {
    const wide = new Uint8Array(Buffer.from(' QCA8337 ', 'utf16le'));
    const r = detectSwitchFamily(wide);
    expect(r.verdict).toBe('none-observed');
    expect(r.coverage.statement).toMatch(/single-byte ASCII: a literal stored as UTF-16/);
  });

  it('counts distinct tokens over every match, not only the retained records', () => {
    const r = detectSwitchFamily(
      image(1024, [
        [10, 'RTL8367'],
        [100, 'rtl8367'],
        [200, 'RTL8370'],
      ]),
      { maxHitsPerRule: 1 },
    );
    expect(r.candidates[0]?.distinctTokens).toEqual(['RTL8367', 'RTL8370']);
    expect(r.candidates[0]?.evidence).toHaveLength(1);
  });

  it('bounds the context excerpt to the printable run, at most 40 bytes either side', () => {
    const long = `${'a'.repeat(60)} QCA8337 ${'b'.repeat(60)}`;
    const r = detectSwitchFamily(image(512, [[100, long]]));
    const hit = r.candidates[0]?.evidence[0];
    expect(hit?.offset).toBe(161);
    expect(hit?.contextOffset).toBe(121);
    expect(hit?.context).toBe(`${'a'.repeat(39)} QCA8337 ${'b'.repeat(39)}`);
  });

  it('rejects bounds that are not positive integers', () => {
    expect(() => detectSwitchFamily(new Uint8Array(4), { maxScanBytes: 0 })).toThrow(RangeError);
    expect(() => detectSwitchFamily(new Uint8Array(4), { maxHitsPerRule: 1.5 })).toThrow(RangeError);
  });
});
