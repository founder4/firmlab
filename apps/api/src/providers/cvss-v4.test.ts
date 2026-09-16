/**
 * CVSS v4.0 scoring tests.
 *
 * The point of this file is that none of its expected values were written from the same assumption as the code.
 * Every number here was produced by FIRST's own reference calculator (`cvss_score.js` + `cvss_lookup.js` +
 * `max_composed.js` + `max_severity.js`, BSD-2-Clause) run over the same strings, so a shared misreading of the
 * specification fails the suite instead of passing it twice — the trap `dynprobe-run.ts` paid for, where the
 * fixtures agreed with the bug.
 *
 * Three layers, narrowest first:
 *
 *   1. named vectors, each exercising one rule the specification states;
 *   2. every one of the 270 equivalence classes, because the score comes out of a table and a table is only as
 *      good as the entry that was never read;
 *   3. the whole base-metric space — all 104,976 combinations of the eleven mandatory metrics — collapsed to a
 *      digest. Regenerate it by running the reference calculator over the same nested loops in the same order.
 *
 * The full differential behind those digests (534,912 vectors: the base space exhaustively, all 270 classes
 * through 279,936 vectors spanning Threat, Environmental and Safety, and 150,000 pseudo-random full-metric
 * vectors) ran against the reference implementation outside the suite and matched on every one.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { cvssV4MacroVector, cvssV4Score } from './cvss-v4.js';

describe('cvssV4Score', () => {
  it('scores the maximum vector at 10.0', () => {
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')).toBe(10);
  });

  it('scores an unauthenticated remote total compromise with no subsequent system at 9.3', () => {
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBe(9.3);
  });

  it('scores a barely-exploitable, barely-impactful, unproven vector at the 0.1 floor', () => {
    expect(cvssV4Score('CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:U/CR:L/IR:L/AR:L')).toBe(0.1);
  });

  it('is 0 when nothing is impacted — a score, not a refusal to score', () => {
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N')).toBe(0);
  });

  it('scores vectors between the extremes as the reference calculator does', () => {
    const cases: [string, number][] = [
      ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', 8.7],
      ['CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 8.5],
      ['CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L', 1],
      ['CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', 6.3],
      ['CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N', 8.3],
      ['CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N', 5.1],
      ['CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', 8.6],
      ['CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', 1],
    ];
    expect(cases.map(([v]) => cvssV4Score(v))).toEqual(cases.map(([, s]) => s));
  });

  it('reads Threat maturity, and treats an omitted E as E:A rather than as the best case', () => {
    const base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
    expect(cvssV4Score(`${base}/E:A`)).toBe(9.3);
    expect(cvssV4Score(`${base}/E:P`)).toBe(8.9);
    expect(cvssV4Score(`${base}/E:U`)).toBe(8.1);
    expect(cvssV4Score(base)).toBe(cvssV4Score(`${base}/E:A`));
  });

  it('reads security requirements, and treats an omitted CR/IR/AR as H rather than as the best case', () => {
    const base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
    expect(cvssV4Score(`${base}/CR:M/IR:M/AR:M`)).toBe(9);
    expect(cvssV4Score(`${base}/CR:L/IR:L/AR:L`)).toBe(8.9);
    expect(cvssV4Score(base)).toBe(cvssV4Score(`${base}/CR:H/IR:H/AR:H`));
  });

  it('lets a Modified metric override the base one it shadows', () => {
    // A local vector re-scored as if it were reachable over the network lands on the network vector's score.
    expect(cvssV4Score('CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:N')).toBe(
      cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'),
    );
    // And the all-N shortcut reads the MODIFIED impacts, so an environment that removes every impact is 0.
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:N')).toBe(0);
  });

  it('raises a vector into the Safety class when MSI:S is declared', () => {
    const base = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N';
    expect(cvssV4Score(base)).toBe(8.2);
    expect(cvssV4Score(`${base}/MSI:S`)).toBe(9.2);
    expect(cvssV4MacroVector(`${base}/MSI:S`)?.[3]).toBe('0');
  });

  it('scores Supplemental metrics at nothing at all, as the specification requires', () => {
    const base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
    expect(cvssV4Score(`${base}/S:P/AU:Y/R:I/V:C/RE:H/U:Red`)).toBe(cvssV4Score(base));
    expect(cvssV4Score(`${base}/S:N/AU:N/R:A/V:D/RE:L/U:Clear`)).toBe(cvssV4Score(base));
  });

  it('treats an explicit X on an optional metric as the metric being absent', () => {
    const base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:H';
    expect(cvssV4Score(`${base}/E:X/CR:X/IR:X/AR:X/MAV:X/MSI:X/U:X`)).toBe(cvssV4Score(base));
  });

  it('does not depend on the order the metrics are written in', () => {
    const canonical = 'CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/CR:L';
    const shuffled = 'CVSS:4.0/CR:L/SA:N/VI:H/AC:H/UI:P/AV:A/SI:L/E:P/AT:P/VA:N/SC:H/PR:L/VC:L';
    expect(cvssV4Score(shuffled)).toBe(cvssV4Score(canonical));
    expect(cvssV4Score(canonical)).not.toBeNull();
  });

  it('refuses what it cannot read, rather than defaulting it', () => {
    // A v3 vector, a v2 one, a bare number: other versions are other procedures, and none of them is this one.
    expect(cvssV4Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBeNull();
    expect(cvssV4Score('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeNull();
    expect(cvssV4Score('9.8')).toBeNull();
    expect(cvssV4Score('')).toBeNull();
    // A missing base metric. All eleven are mandatory, and SC/SI/SA are the ones feeds truncate.
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H')).toBeNull();
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N')).toBeNull();
    // A value the metric does not have. `VC:X` is not "unspecified", it is malformed.
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:X/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    // Safety is a MODIFIED subsequent value; the base metric has no such level.
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N')).toBeNull();
    // An unknown metric, a repeated one, and a fragment that is not `metric:value`.
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:H')).toBeNull();
    expect(cvssV4Score('CVSS:4.0/AV:N/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/oops')).toBeNull();
    // A version this module does not implement must not be scored by the v4.0 procedure.
    expect(cvssV4Score('CVSS:4.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
  });
});

/**
 * One representative vector per equivalence class. The digits are chosen, not searched: EQ1 from AV/PR/UI, EQ2
 * from AC/AT, EQ3 and EQ6 together from the impacts and the requirements that meet them, EQ4 from the subsequent
 * impacts plus Safety, EQ5 from E. EQ3=2 (no HIGH impact anywhere) cannot meet a HIGH requirement, so it exists
 * only as `21` — which is why the table has 270 entries and not 324.
 */
const EQ1_REP = ['AV:N/PR:N/UI:N', 'AV:A/PR:L/UI:N', 'AV:P/PR:H/UI:A'];
const EQ2_REP = ['AC:L/AT:N', 'AC:H/AT:P'];
const EQ3EQ6_REP: [string, string][] = [
  ['00', 'VC:H/VI:H/VA:H'],
  ['01', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M'],
  ['10', 'VC:H/VI:L/VA:L'],
  ['11', 'VC:H/VI:L/VA:L/CR:M/IR:M/AR:M'],
  ['21', 'VC:L/VI:L/VA:L'],
];
const EQ4_REP = ['SC:H/SI:H/SA:H/MSI:S', 'SC:H/SI:H/SA:H', 'SC:L/SI:L/SA:L'];
const EQ5_REP = ['E:A', 'E:P', 'E:U'];

/**
 * The score of each of those 270 representatives, in the iteration order below, straight from the reference
 * calculator. It is the whole lookup table seen through the scoring procedure: an entry nobody can reach, or a
 * transcription slip in any of the 270, changes exactly one of these numbers.
 */
const EXPECTED_BY_CLASS = [
  10, 9.8, 9.5, 10, 9.3, 9.1, 9.3, 8.9, 8.1, 9.9, 9.5, 9.2, 9.6, 8.7, 8.1, 9, 8, 6.8, 9.8, 9.5, 8.9, 9.3, 8.9, 8, 8.8,
  7.8, 6.8, 9.5, 9.1, 8.2, 9.1, 8, 6.4, 7.9, 6.9, 4.6, 9.1, 8.1, 7.1, 7.9, 6.9, 5, 6.9, 5.5, 2.7, 9.9, 9.5, 9.2, 9.5, 9,
  8.4, 9.2, 8.2, 7.2, 9.7, 9.2, 8.4, 9.1, 8.3, 7.1, 8.1, 7.1, 5.3, 9.5, 9.1, 8.4, 9.2, 8, 7, 8.3, 7, 4.9, 9.2, 8.4, 7,
  8.1, 7.1, 5.7, 6.9, 5, 2.8, 8.5, 7.4, 5, 7.1, 5.2, 2.9, 6.3, 2.9, 1.7, 9.8, 9.3, 8.9, 9.4, 8.5, 7.6, 8.6, 7.3, 6.1,
  9.4, 8.6, 7.9, 8.8, 7.3, 6.2, 7.4, 6.2, 4.7, 9.3, 8.7, 7.4, 8.5, 7.3, 5.8, 7, 5.5, 4.8, 8.8, 7.5, 6.4, 7.5, 5.7, 4.7,
  5.5, 4.8, 2.3, 8.1, 6.8, 5, 6.4, 5.6, 2.5, 5.1, 2, 1.2, 9.4, 8.7, 7.4, 8.9, 7.4, 5.9, 7.5, 6.6, 4.8, 8.9, 7.4, 6.7,
  7.6, 6.1, 5, 6.4, 5.6, 2.8, 8.7, 7.4, 5.9, 7.3, 5.6, 4.4, 5.9, 5.3, 2.2, 7.5, 6.5, 5.1, 5.8, 5.3, 2.1, 4.7, 2.6, 1.3,
  6.9, 5.4, 2.7, 5.5, 2.5, 1.4, 2.1, 1.2, 0.5, 9.3, 8.5, 7.4, 8.6, 7.4, 5.6, 7, 5.2, 4, 8.6, 7.2, 5.7, 7.4, 6.1, 3.4,
  5.4, 4, 2.2, 8.4, 7.3, 6.1, 7.2, 5.5, 4.5, 5.2, 3.3, 1.8, 7.4, 5.4, 4.7, 5.6, 4, 1.8, 3.5, 1.8, 0.8, 6.3, 4.9, 1.9,
  4.7, 2.1, 1.1, 2.4, 0.9, 0.4, 8.7, 7.2, 5.8, 7.3, 5.9, 4.1, 5.4, 4.5, 2, 7.4, 5.2, 4.8, 5.5, 4, 2, 4.3, 2.2, 1.1, 7.3,
  5.7, 3.7, 6.1, 4.7, 1.9, 4.4, 1.6, 0.7, 5.5, 4.2, 1.9, 4.9, 1.8, 0.9, 1.7, 0.6, 0.2, 5.1, 2.3, 1.3, 2.4, 1.2, 0.5, 1,
  0.3, 0.1,
];

describe('every CVSS v4.0 equivalence class', () => {
  it('reaches all 270 MacroVectors and scores each one as the reference calculator does', () => {
    const macros: string[] = [];
    const scores: (number | null)[] = [];
    for (const [eq1, rep1] of EQ1_REP.entries()) {
      for (const [eq2, rep2] of EQ2_REP.entries()) {
        for (const [eq3eq6, rep36] of EQ3EQ6_REP) {
          for (const [eq4, rep4] of EQ4_REP.entries()) {
            for (const [eq5, rep5] of EQ5_REP.entries()) {
              const vector = `CVSS:4.0/${rep1}/${rep2}/${rep36}/${rep4}/${rep5}`;
              // The representative has to land in the class it was built for, or the score below proves nothing.
              expect(cvssV4MacroVector(vector)).toBe(`${eq1}${eq2}${eq3eq6[0]}${eq4}${eq5}${eq3eq6[1]}`);
              macros.push(`${eq1}${eq2}${eq3eq6}${eq4}${eq5}`);
              scores.push(cvssV4Score(vector));
            }
          }
        }
      }
    }
    expect(new Set(macros).size).toBe(270);
    expect(scores).toEqual(EXPECTED_BY_CLASS);
  });
});

describe('the whole base-metric space', () => {
  it('scores all 104,976 combinations exactly as the reference calculator does', () => {
    const impact = ['H', 'L', 'N'];
    const digest = createHash('sha256');
    let count = 0;
    let zero = 0;
    let maximal = 0;
    const distinct = new Set<number | null>();
    for (const av of ['N', 'A', 'L', 'P'])
      for (const ac of ['L', 'H'])
        for (const at of ['N', 'P'])
          for (const pr of ['N', 'L', 'H'])
            for (const ui of ['N', 'P', 'A'])
              for (const vc of impact)
                for (const vi of impact)
                  for (const va of impact)
                    for (const sc of impact)
                      for (const si of impact)
                        for (const sa of impact) {
                          const vector = `CVSS:4.0/AV:${av}/AC:${ac}/AT:${at}/PR:${pr}/UI:${ui}/VC:${vc}/VI:${vi}/VA:${va}/SC:${sc}/SI:${si}/SA:${sa}`;
                          const score = cvssV4Score(vector);
                          digest.update(`${vector}=${score}\n`);
                          count += 1;
                          distinct.add(score);
                          if (score === 0) zero += 1;
                          if (score === 10) maximal += 1;
                        }
    // Readable landmarks first, so a failure says roughly WHERE the arithmetic moved before the digest says THAT
    // it moved. 144 zeroes is the one impact combination with no impact at all, times the 144 ways to reach it.
    expect(count).toBe(104_976);
    expect(distinct.size).toBe(63);
    expect(zero).toBe(144);
    expect(maximal).toBe(9);
    expect(digest.digest('hex')).toBe('a2bca25a632d9b914404e48ed2d2105ddc8b90b608cfeffafdd2f12b7a9dfe3f');
    // A second or so on its own, and up to five when the whole suite runs its files in parallel — which is what
    // the explicit budget is for, not slowness in the scorer.
  }, 30_000);
});
