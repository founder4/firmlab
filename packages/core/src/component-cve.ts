/**
 * The curated component/CVE domain — pure: version parsing and ordering, the hand-verified rule table, version
 * extraction from a binary's printable strings, CVE matching, the cross-lane verdict and the finding drafts.
 *
 * `syft` keys off PACKAGE MANIFESTS (opkg/dpkg/apk databases). A stripped SOHO firmware that ships a bundled
 * binary with NO manifest — the classic TP-Link/MediaTek build — catalogues 0 packages, so `grype` returns 0
 * CVEs even when the image ships a decade-old `pppd` with a pre-auth RCE. This table closes that gap
 * deterministically: a curated set of high-value embedded components located by binary name, the version read
 * from the printable strings IN the binary, and a small, hand-verified table of well-documented embedded n-days
 * (the ones a manifest-only SBOM structurally cannot see).
 *
 * Honesty is preserved: the CVE table is intentionally SMALL and every entry is a famous, checkable n-day with an
 * explicit affected-version predicate — it never guesses "this era is probably vulnerable". A component found but
 * not matched is reported as an inventory fact, not a vuln.
 *
 * Everything here is bytes/strings in, structured data out. The rootfs walk, its entry budget and the bounded
 * file reads stay in `apps/api/src/providers/component-cve.ts`, which is the only runner.
 */
import type { FindingDraft, FindingSeverity } from './types.js';

/**
 * A dotted version, optionally with a trailing letter suffix: OpenSSL's `1.0.1f`, and its two-letter `1.0.2zd` once a
 * series outlived the alphabet — a real NVD bound, which a one-letter parser could not compare at all.
 */
export interface ParsedVersion {
  nums: number[];
  /**
   * The raw text of each numeric field, kept because the number alone loses information: `1.01` and `1.1` both
   * parse to `[1, 1]` and they are different releases. See `compareVersion`.
   */
  fields: string[];
  letter: string; // '' when absent
  raw: string;
}

/** Pure: parse `1.0.1f` / `2.4.3` into comparable parts. Returns null when it is not a dotted version. */
export function parseVersion(raw: string): ParsedVersion | null {
  const m = raw.match(/^(\d+(?:\.\d+)*)([a-z]{1,2})?$/);
  if (!m) return null;
  const fields = (m[1] as string).split('.');
  return { nums: fields.map((n) => Number.parseInt(n, 10)), fields, letter: m[2] ?? '', raw };
}

/** Is this field zero-padded (`01`) rather than plain (`1`)? A single `0` is the number zero, not padding. */
function isPadded(field: string): boolean {
  return field.length > 1 && field.startsWith('0');
}

/**
 * Pure: compare two parsed versions — numeric fields first, then zero-padding, then the trailing letter. -1/0/1.
 *
 * The padding tiebreak exists because parsing each field as a number silently merged two real, different releases.
 * BusyBox 1.01 shipped in 2005 and BusyBox 1.1 in 2006; both parse to `[1, 1]`, so a range boundary that fell
 * between them would have answered the same for either, and the WR940N in this corpus ships exactly `1.01`. A
 * padded field is ordered BEFORE the unpadded one of the same value, which is the order those releases actually
 * came in. BusyBox is the only component here that versions this way, and the distinction is preserved rather
 * than resolved by guesswork: `1.01` stays a version this code can tell apart from `1.1`.
 */
export function compareVersion(a: ParsedVersion, b: ParsedVersion): number {
  const len = Math.max(a.nums.length, b.nums.length);
  for (let i = 0; i < len; i++) {
    const d = (a.nums[i] ?? 0) - (b.nums[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  for (let i = 0; i < len; i++) {
    const pa = isPadded(a.fields[i] ?? '');
    const pb = isPadded(b.fields[i] ?? '');
    if (pa !== pb) return pa ? -1 : 1;
  }
  // Lexicographic, which is OpenSSL's order: `y` < `z` < `za` < `zd` (a prefix sorts first).
  if (a.letter === b.letter) return 0;
  return a.letter < b.letter ? -1 : 1;
}

/** Inclusive `low <= v <= high` on parsed versions. */
export function versionInRange(v: string, low: string, high: string): boolean {
  const pv = parseVersion(v);
  const pl = parseVersion(low);
  const ph = parseVersion(high);
  if (!pv || !pl || !ph) return false;
  return compareVersion(pv, pl) >= 0 && compareVersion(pv, ph) <= 0;
}

/**
 * A CVE this table looked at for a component and deliberately does NOT claim, with the reason it refuses.
 *
 * Data rather than prose because `sbom`/grype matches some of them from a package manifest on the SAME image:
 * the ledger then has to say the two lanes disagree and why, which a comment cannot do. See `curatedCveVerdict`.
 */
export interface RejectedCve {
  id: string;
  reason: string;
}

/** The three shapes NVD's affected-version data comes in, and the only three this table knows how to read. */
export type NvdBacking = 'bounded' | 'enumerated' | 'open-below';

export interface CveRule {
  id: string;
  title: string;
  severity: FindingSeverity;
  /** Affected range [low, high] — deliberately explicit, never an open-ended "old-ish" guess. */
  low: string;
  high: string;
  /**
   * `high` is EXCLUSIVE, because NVD bounded this CVE with `versionEndExcluding`.
   *
   * It exists so a faithful bound does not have to be guessed into an inclusive one. NVD says curl is affected
   * "< 8.4.0"; writing that as `high: '8.3.0'` asserts that 8.3.0 was the last release of that series, which is
   * a claim about release history nobody here verified — precisely the kind of recall this table refuses. The
   * flag carries NVD's own bound instead.
   */
  highExclusive?: boolean;
  /**
   * What NVD actually backs this rule with. Required, so a new entry cannot be added without saying.
   *
   *  - `bounded`    — NVD gives both ends. Nothing to decide; the rule copies them.
   *  - `enumerated` — NVD lists the affected versions individually. The strongest backing there is: an analyst
   *                   asserted those builds, so nobody here is inferring a floor.
   *  - `open-below` — NVD gives only an upper bound, which "affects" every release back to the project's first.
   *                   The rule must then set its own floor AND justify it in `floorRationale`.
   */
  nvdBacking: NvdBacking;
  /**
   * Why this rule's `low` is a defensible floor. Required whenever `nvdBacking` is `open-below`, and enforced
   * by `component-cve.test.ts` rather than left to reviewer memory.
   *
   * **This field is the policy**, and it is what settles the CVE-2016-2148 question. An open-below range is
   * claimable exactly when a floor can be defended from the advisory's own subject matter, and refused when it
   * cannot: "before 1.25.0" spans one continuous 1.x line with no series boundary inside it to floor at, so
   * there is nothing to write here for it and it stays in `rejected`. Making the justification a required
   * field rather than a comment means the next entry cannot skip the question, and a reader who disagrees can
   * see exactly what is being claimed and argue with it.
   */
  floorRationale?: string;
  /**
   * A configuration this CVE additionally requires, stated when the version fact alone does not settle it.
   *
   * Four of the seven DNSpooq entries need DNSSEC compiled in and enabled, and nothing this provider reads can
   * tell whether it is. A row carrying a precondition therefore does NOT reach `static_confirmed`: the version
   * is confirmed, the vulnerability is not, and `buildComponentFindings` drops it to
   * `needs_runtime_reproduction` with the condition named. Without this field the only options were to claim a
   * conditional flaw at the bench's strongest rung or to drop a real n-day, and both are worse.
   */
  precondition?: string;
}

/**
 * Pure: does this CVE rule's range cover `version`? Honours `highExclusive`.
 *
 * `matchCves` and `curatedCveVerdict` both go through here so a rule cannot mean one thing when this table
 * claims it and another when it comments on a grype row — they disagreed about nothing today, and that is worth
 * keeping true by construction rather than by coincidence.
 */
export function cveCovers(version: string, cve: Pick<CveRule, 'low' | 'high' | 'highExclusive'>): boolean {
  if (!cve.highExclusive) return versionInRange(version, cve.low, cve.high);
  const pv = parseVersion(version);
  const pl = parseVersion(cve.low);
  const ph = parseVersion(cve.high);
  if (!pv || !pl || !ph) return false;
  return compareVersion(pv, pl) >= 0 && compareVersion(pv, ph) < 0;
}

export interface ComponentRule {
  component: string;
  /** Binary basenames that carry this component. */
  binNames: string[];
  /** For a library whose file name carries its own version (`libuClibc-1.0.31.so`), which no fixed name can list. */
  binNameRe?: RegExp;
  /** Ordered version-extraction patterns (first match wins); capture group 1 is the version. */
  versionRes: RegExp[];
  /**
   * Marker-gated bare-version fallback. Many binaries print their version through a FORMAT STRING — the real
   * WR940N `pppd` embeds `pppd version %s` (the label) and `2.4.3` (the value) as SEPARATE string constants, so a
   * `pppd version (\d+\.\d+\.\d+)` pattern never matches. When `marker` is present in the strings we know the
   * component is here, so we accept the first bare version matching `bareVersionRe`. Kept component-specific
   * (e.g. pppd's 2.x series) so it cannot grab an unrelated number.
   */
  marker?: string;
  bareVersionRe?: RegExp;
  cves: CveRule[];
  /** CVEs evaluated for this component and refused, each with its reason. See `RejectedCve`. */
  rejected?: readonly RejectedCve[];
}

/**
 * Curated component table. SMALL BY DESIGN — each CVE is a famous, individually-verified embedded n-day that a
 * manifest-only SBOM cannot see because the component is a bundled binary with no package database entry.
 *
 * Every `versionRes` below was read off a REAL binary in this corpus, not guessed from what the string ought to
 * look like — that is how `dropbearmulti` got into `binNames` (TP-Link ships the multi-call build, and the
 * basename match is exact, so a rule naming only `dropbear` would have found nothing), and how the SSH banner
 * turned out to be the only place dropbear's version appears as literal text rather than through `%s`.
 *
 * Every range was read from the NVD CVE API against the version this corpus actually ships (2026-07-27, and
 * again 2026-09-19 for the entries added then), never from recall. **Checking the ranges is not optional and it
 * is not cheap-talk:** the nine BusyBox awk entries below look like one advisory with one range, and they are
 * not — their lower bounds are 1.16.0, 1.18.0, 1.21.0, 1.26.0 and 1.28.0, and one of them (CVE-2021-42383) has
 * no range at all, only an enumerated `1.33.1`. Copying the first range across the family would have claimed
 * four CVEs against BusyBox 1.18.4 that NVD does not put there.
 *
 * ─── When a CVE may be claimed, as this table actually decides it ───
 *
 * The bound NVD gives is used as NVD gives it; `highExclusive` exists so an exclusive upper bound need not be
 * guessed into an inclusive one. What needs a rule is the LOWER bound, because CPE ranges are routinely open
 * below — "dnsmasq before 2.83" matches a 2001 build of 1.10 as readily as a 2020 build of 2.82.
 *
 *  - **Bounded at both ends** → claim it as given. The strongest and least interesting case.
 *  - **One enumerated CPE at the exact version** → claim that version alone (`low === high`). This is the
 *    strongest evidence of all: an analyst asserted that build, not a range someone might have widened.
 *  - **Open below** → the rule sets its OWN floor, at the series the advisory is about, and the floor must be
 *    defensible from the advisory's own subject matter. An unbounded-below range is a modelling artifact of
 *    CPE, not evidence that a decade-older codebase contains the bug.
 *  - **Open below with no defensible floor** → it is REFUSED into `rejected`, with the reason. CVE-2016-2148
 *    is the worked example: "before 1.25.0" spans the whole 1.x line, there is no series boundary inside it to
 *    floor at, and BusyBox 1.01 sits twenty years deep in it.
 *
 ─── How the "only where NVD enumerates CPEs" question was settled (2026-09-19) ───
 *
 * An earlier version of this paragraph said the table claims a CVE "only where NVD enumerates CPEs for the
 * versions in hand", which made `CVE-2017-14491` look like a violation: it is claimed on the same shape —
 * open below, zero enumerated CPEs — that `CVE-2016-2148` is refused for.
 *
 * Settled by measuring rather than arguing. Of the 26 rules, 11 are `bounded`, 6 are `enumerated` and NINE are
 * open below, so the strict reading disqualifies all nine — `CVE-2016-7406` among them. That one matches the
 * Dropbear 2012.55 in this corpus and produces a correct finding on two images today, so the strict reading
 * costs a TRUE POSITIVE to satisfy a sentence. It was therefore never the rule: four of the five original
 * entries have zero enumerated CPEs, and the prose had mistaken the BusyBox rule's extra strength for policy.
 *
 * What actually separates a claimed open-below range from CVE-2016-2148 is whether a floor can be DEFENDED
 * from the advisory's own subject matter — and that was being asserted in comments instead of recorded. It is
 * now `nvdBacking` plus `floorRationale` on the rule itself, a test refuses an open-below entry that does not
 * justify its floor, and the justification travels onto the finding. The question stops being re-litigated
 * because the answer is on every row.
 *
 * The cost of all of this is under-claiming on genuinely ancient builds; they still surface as inventory facts.
 */
export const COMPONENT_RULES: readonly ComponentRule[] = [
  {
    component: 'pppd',
    binNames: ['pppd'],
    versionRes: [/pppd version (\d+\.\d+\.\d+)/i, /\bppp[- ]?(\d+\.\d+\.\d+)/i],
    // The real binary stores `pppd version %s` + a bare `2.4.3` — gate a 2.x bare-version pickup on that label.
    marker: 'pppd version',
    bareVersionRe: /\b(2\.\d+\.\d+)\b/,
    cves: [
      {
        id: 'CVE-2020-8597',
        nvdBacking: 'bounded',
        title: 'pppd EAP dispatch stack buffer overflow — pre-auth remote RCE',
        severity: 'critical',
        low: '2.4.2',
        high: '2.4.8',
      },
    ],
  },
  {
    component: 'openssl',
    binNames: ['openssl', 'libssl.so', 'libcrypto.so'],
    versionRes: [/OpenSSL (\d+\.\d+\.\d+[a-z]?)/],
    cves: [
      {
        id: 'CVE-2014-0160',
        nvdBacking: 'bounded',
        title: 'OpenSSL TLS heartbeat out-of-bounds read (Heartbleed) — memory disclosure',
        severity: 'high',
        low: '1.0.1',
        high: '1.0.1f',
      },
      // Added 2026-09-26 from the NVD CVE API queried against the three builds this corpus ships — 1.0.2p and 1.1.1d
      // (Tenda camera) and 3.0.13 (GL.iNet BE3600). NVD bounds each advisory once PER SERIES, so each series is its
      // own rule under the same id; every range below is copied as NVD states it, exclusive ends included.
      {
        id: 'CVE-2020-1967',
        nvdBacking: 'bounded',
        title: 'OpenSSL SSL_check_chain NULL pointer dereference during a TLS 1.3 handshake — remote denial of service',
        severity: 'high',
        low: '1.1.1d',
        high: '1.1.1f',
      },
      {
        id: 'CVE-2022-0778',
        nvdBacking: 'bounded',
        title: 'OpenSSL BN_mod_sqrt infinite loop on a crafted certificate — remote denial of service',
        severity: 'high',
        low: '1.0.2',
        high: '1.0.2zd',
        highExclusive: true,
      },
      {
        id: 'CVE-2022-0778',
        nvdBacking: 'bounded',
        title: 'OpenSSL BN_mod_sqrt infinite loop on a crafted certificate — remote denial of service',
        severity: 'high',
        low: '1.1.0',
        high: '1.1.1n',
        highExclusive: true,
      },
      {
        id: 'CVE-2022-0778',
        nvdBacking: 'bounded',
        title: 'OpenSSL BN_mod_sqrt infinite loop on a crafted certificate — remote denial of service',
        severity: 'high',
        low: '3.0.0',
        high: '3.0.2',
        highExclusive: true,
      },
      {
        id: 'CVE-2023-0286',
        nvdBacking: 'bounded',
        title: 'OpenSSL X.400 address type confusion in GENERAL_NAME comparison — memory read or denial of service',
        severity: 'high',
        low: '1.0.2',
        high: '1.0.2zg',
        highExclusive: true,
      },
      {
        id: 'CVE-2023-0286',
        nvdBacking: 'bounded',
        title: 'OpenSSL X.400 address type confusion in GENERAL_NAME comparison — memory read or denial of service',
        severity: 'high',
        low: '1.1.1',
        high: '1.1.1t',
        highExclusive: true,
      },
      {
        id: 'CVE-2023-0286',
        nvdBacking: 'bounded',
        title: 'OpenSSL X.400 address type confusion in GENERAL_NAME comparison — memory read or denial of service',
        severity: 'high',
        low: '3.0.0',
        high: '3.0.8',
        highExclusive: true,
      },
      {
        id: 'CVE-2024-6119',
        nvdBacking: 'bounded',
        title:
          'OpenSSL certificate name-check type confusion on othername subject alternative names — denial of service',
        severity: 'high',
        low: '3.0.0',
        high: '3.0.15',
        highExclusive: true,
      },
      {
        id: 'CVE-2024-6119',
        nvdBacking: 'bounded',
        title:
          'OpenSSL certificate name-check type confusion on othername subject alternative names — denial of service',
        severity: 'high',
        low: '3.1.0',
        high: '3.1.7',
        highExclusive: true,
      },
      {
        id: 'CVE-2024-6119',
        nvdBacking: 'bounded',
        title:
          'OpenSSL certificate name-check type confusion on othername subject alternative names — denial of service',
        severity: 'high',
        low: '3.2.0',
        high: '3.2.3',
        highExclusive: true,
      },
      {
        id: 'CVE-2024-6119',
        nvdBacking: 'bounded',
        title:
          'OpenSSL certificate name-check type confusion on othername subject alternative names — denial of service',
        severity: 'high',
        low: '3.3.0',
        high: '3.3.2',
        highExclusive: true,
      },
    ],
  },
  {
    component: 'busybox',
    binNames: ['busybox'],
    // Verbatim from both rootfs in this corpus: `BusyBox v1.7.2 (2016-03-09 22:33:37 CST)` on DVRF and
    // `BusyBox v1.01 (2026.05.28-02:39+0000) multi-call binary` on the WR940N. Literal text, no format string.
    versionRes: [/BusyBox v(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)/],
    cves: [
      {
        // udhcpc runs on every one of these routers and the attacker is whatever answers DHCP, so this is a
        // reachable primitive rather than a paper finding.
        //
        // This entry is here and CVE-2016-2148 — a CRITICAL udhcpc heap overflow, "before 1.25.0", which would
        // also match both builds — is in `rejected` below, and the difference is the whole discipline of this
        // table. NVD backs
        // CVE-2011-2716 with 90 individually enumerated CPEs, `busybox:1.01` and `busybox:1.7.2` among them: an
        // analyst asserted these exact versions. CVE-2016-2148 carries zero enumerated CPEs and one range with no
        // lower bound — the same shape refused two rules down for dnsmasq 1.10, and refusing it there while
        // inheriting it here would make the principle decorative. A 2005 BusyBox is probably vulnerable to it;
        // probably is not what `static_confirmed` means.
        id: 'CVE-2011-2716',
        nvdBacking: 'enumerated',
        title: 'BusyBox udhcpc passes DHCP option values to the shell — command injection from a DHCP server',
        severity: 'medium',
        low: '1.0.0',
        high: '1.19.4',
      },
      // ─── The awk applet. Nine 2021 entries, and their lower bounds are NOT the same number ───
      //
      // Read one at a time from NVD on 2026-09-19. They share an upper bound (1.33.1, inclusive) and a CVSS
      // vector (3.1 AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H, 7.2), which is exactly what makes assuming a shared
      // LOWER bound tempting and wrong: 1.16.0, 1.18.0, 1.21.0, 1.26.0 and 1.28.0 all appear. Against the
      // BusyBox 1.18.4 in this corpus that difference decides four of the nine.
      //
      // awk is not decoration on these devices — vendor rc scripts and CGI handlers parse with it constantly —
      // but whether attacker-influenced text reaches an awk pattern is a reachability question this row does
      // not answer, exactly as for every other entry in the table.
      {
        id: 'CVE-2021-42378',
        nvdBacking: 'bounded',
        title: 'BusyBox awk use-after-free in getvar_i',
        severity: 'high',
        low: '1.16.0',
        high: '1.33.1',
      },
      {
        id: 'CVE-2021-42379',
        nvdBacking: 'bounded',
        title: 'BusyBox awk use-after-free in next_input_file',
        severity: 'high',
        low: '1.18.0',
        high: '1.33.1',
      },
      {
        id: 'CVE-2021-42380',
        nvdBacking: 'bounded',
        title: 'BusyBox awk use-after-free in clrvar',
        severity: 'high',
        low: '1.28.0',
        high: '1.33.1',
      },
      {
        id: 'CVE-2021-42381',
        nvdBacking: 'bounded',
        title: 'BusyBox awk use-after-free in hash_init',
        severity: 'high',
        low: '1.21.0',
        high: '1.33.1',
      },
      {
        id: 'CVE-2021-42382',
        nvdBacking: 'bounded',
        title: 'BusyBox awk use-after-free in getvar_s',
        severity: 'high',
        low: '1.26.0',
        high: '1.33.1',
      },
      // No range at all in NVD — a single enumerated CPE, `busybox:1.33.1`. Claimed at that version only.
      {
        id: 'CVE-2021-42383',
        nvdBacking: 'enumerated',
        title: 'BusyBox awk use-after-free in evaluate',
        severity: 'high',
        low: '1.33.1',
        high: '1.33.1',
      },
      {
        id: 'CVE-2021-42384',
        nvdBacking: 'bounded',
        title: 'BusyBox awk use-after-free in handle_special',
        severity: 'high',
        low: '1.18.0',
        high: '1.33.1',
      },
      {
        id: 'CVE-2021-42385',
        nvdBacking: 'bounded',
        title: 'BusyBox awk use-after-free in evaluate',
        severity: 'high',
        low: '1.16.0',
        high: '1.33.1',
      },
      {
        id: 'CVE-2021-42386',
        nvdBacking: 'bounded',
        title: 'BusyBox awk use-after-free in nvalloc',
        severity: 'high',
        low: '1.16.0',
        high: '1.33.1',
      },
      // Enumerated CPE `busybox:1.35.0`, no range. Nothing in this corpus is 1.35.x, so it matches nothing
      // here — kept because an exact-version CPE is the strongest shape this table accepts and it costs a line.
      {
        id: 'CVE-2022-30065',
        nvdBacking: 'enumerated',
        title: 'BusyBox awk use-after-free in copyvar',
        severity: 'high',
        low: '1.35.0',
        high: '1.35.0',
      },
      // Three more, each with a single enumerated CPE at `busybox:1.36.1` — the version the GL.iNet BE3600 in
      // this corpus actually ships. CVSS 3.1 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H), availability only.
      {
        id: 'CVE-2023-42364',
        nvdBacking: 'enumerated',
        title: 'BusyBox awk use-after-free in the evaluate function',
        severity: 'medium',
        low: '1.36.1',
        high: '1.36.1',
      },
      {
        id: 'CVE-2023-42365',
        nvdBacking: 'enumerated',
        title: 'BusyBox awk use-after-free in the copyvar function',
        severity: 'medium',
        low: '1.36.1',
        high: '1.36.1',
      },
      {
        id: 'CVE-2023-42366',
        nvdBacking: 'enumerated',
        title: 'BusyBox awk heap buffer overflow in next_token (awk.c:1159)',
        severity: 'medium',
        low: '1.36.1',
        high: '1.36.1',
      },
    ],
    rejected: [
      {
        id: 'CVE-2016-2148',
        reason:
          'NVD backs it with a single range open below ("before 1.25.0") and zero enumerated CPEs, so no analyst ' +
          'asserted any specific version and the range matches a 2005 build as readily as a 2016 one.',
      },
    ],
  },
  {
    component: 'dropbear',
    // TP-Link ships the multi-call build, so the basename is `dropbearmulti`; `dbclient` is the same binary again.
    binNames: ['dropbear', 'dropbearmulti', 'dbclient'],
    // The version reaches the strings ONLY through the SSH identification banner — `SSH-2.0-dropbear_2012.55` on
    // the WR940N. Every human-readable mention (`Dropbear sshd v%s`, `Dropbear multi-purpose version %s`) is a
    // format string, so the obvious pattern matches nothing. The banner is also what the daemon puts on the wire.
    versionRes: [/SSH-2\.0-dropbear_(\d+\.\d+)/],
    cves: [
      {
        id: 'CVE-2016-7406',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, at `before 2016.74`, written in the year.release scheme',
          'Dropbear adopted at 2011.54 — so the floor is the first release that scheme has. The older 0.5x',
          'numbering is not what the bound addresses, and such a build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'Dropbear SSH server format-string vulnerability — remote arbitrary code execution',
        severity: 'high',
        // Floored at the year-versioned series NVD itself bounds CVE-2019-12953 with. The advisory ("before
        // 2016.74") also covers the older 0.5x scheme, but this table will not claim a range it cannot bound from
        // below: a 0.5x Dropbear falls through to the inventory fact instead.
        low: '2011.54',
        high: '2016.73',
      },
    ],
  },
  {
    component: 'dnsmasq',
    binNames: ['dnsmasq'],
    // Same shape as pppd: `dnsmasq version %s` is a format string and the value sits beside it as a bare string
    // (DVRF's build carries `1.10`). Both real series are 1.x and 2.x, so the bare pattern is gated on the label.
    versionRes: [/dnsmasq[- ]?(?:version )?(2\.\d+)\b/],
    marker: 'dnsmasq version',
    bareVersionRe: /\b([12]\.\d+)\b/,
    cves: [
      {
        id: 'CVE-2017-14491',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, in the 2.x numbering, and the advisory addresses the 2.x',
          'codebase. 1.x is a distinct major series this rule does not claim to cover, so the floor is the start',
          'of the series the advisory is about and a 1.x build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'dnsmasq heap buffer overflow in DNS reply parsing — remote code execution',
        severity: 'critical',
        // NVD's CPE match for this is open below and therefore "affects" a 2001 build of 1.10. It is about the
        // 2.x codebase, so the floor is 2.0 and DVRF's 1.10 is reported as a version, not as a critical CVE.
        low: '2.0',
        high: '2.77',
      },
      // ─── DNSpooq (2021). Seven CVEs, all bounded by NVD as "< 2.83" with zero enumerated CPEs ───
      //
      // Same evidence shape as CVE-2017-14491 above and floored the same way, at the 2.x series the advisories
      // are about, so the 1.10 in this corpus stays an inventory fact. The Asus router here ships 2.78, which
      // is inside all seven. `highExclusive` carries NVD's own `< 2.83` rather than asserting which release
      // was the last before it.
      //
      // FOUR OF THEM NEED DNSSEC, and this provider cannot see whether it is compiled in, let alone enabled.
      // They carry a `precondition` and therefore land at `needs_runtime_reproduction` instead of
      // `static_confirmed`: the version is confirmed, the vulnerability is conditional, and the row says which.
      // The three cache-poisoning entries have no such gate — CVE-2020-25685 is specifically about the CRC32
      // hash used when dnsmasq is built WITHOUT DNSSEC — so they stay at the version rung.
      {
        id: 'CVE-2020-25681',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, in the 2.x numbering, and the advisory addresses the 2.x',
          'codebase. 1.x is a distinct major series this rule does not claim to cover, so the floor is the start',
          'of the series the advisory is about and a 1.x build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'dnsmasq heap overflow sorting RRSets before DNSSEC validation (DNSpooq)',
        severity: 'high',
        low: '2.0',
        high: '2.83',
        highExclusive: true,
        precondition: 'dnsmasq must be built with DNSSEC support and have validation enabled',
      },
      {
        id: 'CVE-2020-25682',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, in the 2.x numbering, and the advisory addresses the 2.x',
          'codebase. 1.x is a distinct major series this rule does not claim to cover, so the floor is the start',
          'of the series the advisory is about and a 1.x build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'dnsmasq buffer overflow extracting names before DNSSEC validation (DNSpooq)',
        severity: 'high',
        low: '2.0',
        high: '2.83',
        highExclusive: true,
        precondition: 'dnsmasq must be built with DNSSEC support and have validation enabled',
      },
      {
        id: 'CVE-2020-25683',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, in the 2.x numbering, and the advisory addresses the 2.x',
          'codebase. 1.x is a distinct major series this rule does not claim to cover, so the floor is the start',
          'of the series the advisory is about and a 1.x build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'dnsmasq heap overflow in get_rdata with DNSSEC enabled (DNSpooq)',
        severity: 'medium',
        low: '2.0',
        high: '2.83',
        highExclusive: true,
        precondition: 'dnsmasq must be built with DNSSEC support and have validation enabled',
      },
      {
        id: 'CVE-2020-25687',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, in the 2.x numbering, and the advisory addresses the 2.x',
          'codebase. 1.x is a distinct major series this rule does not claim to cover, so the floor is the start',
          'of the series the advisory is about and a 1.x build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'dnsmasq heap overflow in sort_rrset with DNSSEC enabled (DNSpooq)',
        severity: 'medium',
        low: '2.0',
        high: '2.83',
        highExclusive: true,
        precondition: 'dnsmasq must be built with DNSSEC support and have validation enabled',
      },
      {
        id: 'CVE-2020-25684',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, in the 2.x numbering, and the advisory addresses the 2.x',
          'codebase. 1.x is a distinct major series this rule does not claim to cover, so the floor is the start',
          'of the series the advisory is about and a 1.x build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'dnsmasq accepts a reply without matching address/port to the pending query — cache poisoning (DNSpooq)',
        severity: 'low',
        low: '2.0',
        high: '2.83',
        highExclusive: true,
      },
      {
        id: 'CVE-2020-25685',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, in the 2.x numbering, and the advisory addresses the 2.x',
          'codebase. 1.x is a distinct major series this rule does not claim to cover, so the floor is the start',
          'of the series the advisory is about and a 1.x build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'dnsmasq matches a forwarded query by a weak CRC32 name hash — cache poisoning (DNSpooq)',
        severity: 'low',
        low: '2.0',
        high: '2.83',
        highExclusive: true,
      },
      {
        id: 'CVE-2020-25686',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, in the 2.x numbering, and the advisory addresses the 2.x',
          'codebase. 1.x is a distinct major series this rule does not claim to cover, so the floor is the start',
          'of the series the advisory is about and a 1.x build is reported as a version, not this CVE.',
        ].join(' '),
        title: 'dnsmasq forwards duplicate queries for the same name, multiplying birthday chances (DNSpooq)',
        severity: 'low',
        low: '2.0',
        high: '2.83',
        highExclusive: true,
      },
    ],
  },
  {
    component: 'curl',
    // Read off the GL.iNet BE3600 rootfs on 2026-09-19, both spellings, because they are different strings in
    // different files: `/usr/bin/curl` carries `curl 8.6.0 (aarch64-openwrt-linux-gnu) %s` (the tool banner,
    // with the platform triple before the format string) and `/usr/lib/libcurl.so.4.8.0` carries the
    // `libcurl/8.6.0` User-Agent token. A pattern written for one finds nothing in the other.
    binNames: ['curl', 'libcurl.so', 'libcurl.so.4'],
    versionRes: [/\bcurl (\d+\.\d+\.\d+) \(/, /libcurl\/(\d+\.\d+\.\d+)/],
    cves: [
      {
        id: 'CVE-2023-38545',
        nvdBacking: 'bounded',
        title: 'curl SOCKS5 proxy handshake heap buffer overflow when the hostname exceeds 255 bytes',
        severity: 'critical',
        // NVD bounds it 7.69.0 (incl) – 8.4.0 (excl) against `libcurl`: bounded at both ends, so no floor is
        // invented. The 8.6.0 this corpus ships is OUTSIDE it and is reported as a version, not a CVE — which
        // is the behaviour worth having, and `component-cve.test.ts` pins it against that exact version.
        low: '7.69.0',
        high: '8.4.0',
        highExclusive: true,
      },
    ],
  },
  {
    component: 'hostapd',
    // Read off real binaries on 2026-09-26: `hostapd v0.5.9` (all three TP-Link images) and `hostapd v2.9` (IMOU).
    binNames: ['hostapd'],
    versionRes: [/\bhostapd v(\d+\.\d+(?:\.\d+)?)\b/],
    cves: [],
    rejected: [
      {
        id: 'CVE-2022-23303',
        reason:
          'NVD backs it with a single range open below ("before 2.10") and no enumerated CPEs. The advisory is about the ' +
          'SAE implementation, and no release at which that code entered hostapd was verified here to floor at.',
      },
      {
        id: 'CVE-2022-23304',
        reason:
          'NVD backs it with a single range open below ("before 2.10") and no enumerated CPEs. The advisory is about the ' +
          'EAP-pwd implementation, and no release at which that code entered hostapd was verified here to floor at.',
      },
    ],
  },
  {
    component: 'wpa_supplicant',
    // `wpa_supplicant v0.5.9` on the three TP-Link images, read the same day. The same two advisories are refused for
    // the same reason, so a grype row on either lane reads the same.
    binNames: ['wpa_supplicant'],
    versionRes: [/\bwpa_supplicant v(\d+\.\d+(?:\.\d+)?)\b/],
    cves: [],
    rejected: [
      {
        id: 'CVE-2022-23303',
        reason:
          'NVD backs it with a single range open below ("before 2.10") and no enumerated CPEs, and no release at which ' +
          'the SAE code entered wpa_supplicant was verified here to floor at.',
      },
      {
        id: 'CVE-2022-23304',
        reason:
          'NVD backs it with a single range open below ("before 2.10") and no enumerated CPEs, and no release at which ' +
          'the EAP-pwd code entered wpa_supplicant was verified here to floor at.',
      },
    ],
  },
  {
    component: 'uclibc-ng',
    // The file name carries the version (`libuClibc-1.0.31.so` on IMOU and Tenda), and so does the banner inside it:
    // `uClibc-ng release release version 1.0.31.` — the doubled word is in the real binary. The banner is what is
    // read; the name only selects the file. The older uClibc 0.9.30 on the TP-Link images carries no such string and
    // is left unversioned rather than read off its file name.
    binNames: [],
    binNameRe: /^libuClibc-\d+\.\d+\.\d+\.so$/,
    versionRes: [/uClibc-ng release (?:release )?version (\d+\.\d+\.\d+)/],
    cves: [
      {
        id: 'CVE-2021-43523',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, against the `uclibc-ng_project:uclibc-ng` product, whose own',
          'numbering starts at 1.0.0. The older uClibc 0.9.x line is a separate CPE product this rule does not claim,',
          'so the floor is the first version the bounded product has and nothing below it is inferred.',
        ].join(' '),
        title: 'uClibc-ng resolver mishandles special characters in DNS-returned domain names',
        severity: 'critical',
        low: '1.0.0',
        high: '1.0.39',
        highExclusive: true,
      },
      {
        id: 'CVE-2022-30295',
        nvdBacking: 'open-below',
        floorRationale: [
          'NVD bounds this advisory only from above, against the `uclibc-ng_project:uclibc-ng` product, whose own',
          'numbering starts at 1.0.0. The older uClibc 0.9.x line is a separate CPE product this rule does not claim,',
          'so the floor is the first version the bounded product has and nothing below it is inferred.',
        ].join(' '),
        title: 'uClibc-ng resolver uses predictable DNS transaction IDs — cache poisoning',
        severity: 'medium',
        low: '1.0.0',
        high: '1.0.40',
      },
    ],
  },
  {
    component: 'gnutls',
    // `Enabled GnuTLS 3.8.3 logging...` in the GL.iNet `libgnutls.so.30.37.1`. Inventory only: the one NVD match for
    // 3.8.3 on 2026-09-26 was not an entry this table exists for.
    binNames: ['libgnutls.so'],
    versionRes: [/Enabled GnuTLS (\d+\.\d+\.\d+) logging/],
    cves: [],
  },
  {
    component: 'lua',
    // The RCS-style `$Lua: Lua 5.1.5 Copyright …$` ident in the GL.iNet `liblua.so.5.1.5`. Inventory only.
    binNames: ['liblua.so'],
    versionRes: [/\$Lua: Lua (\d+\.\d+\.\d+)/],
    cves: [],
  },
  {
    component: 'avahi',
    // `avahi 0.8` is its own string in the GL.iNet `avahi-daemon` (every other mention is `%s 0.8`), so the pattern is
    // anchored to the whole line rather than to any number after the word.
    binNames: ['avahi-daemon'],
    versionRes: [/^avahi (\d+\.\d+(?:\.\d+)?)$/m],
    cves: [],
    rejected: [
      {
        id: 'CVE-2021-26720',
        reason:
          'NVD\'s range ("through 0.8-4") is the Debian package revision, and the flaw is in Debian\'s own ' +
          'avahi-daemon-check-dns.sh hook — not upstream avahi, and not a file a non-Debian firmware ships.',
      },
    ],
  },
];

export interface ComponentHit {
  component: string;
  version: string;
  path: string;
}

/** Pure: extract a component version from a blob's printable strings using the rule's patterns (first match). */
export function extractComponentVersion(strings: string, rule: ComponentRule): string | null {
  for (const re of rule.versionRes) {
    const m = strings.match(re);
    if (m?.[1]) return m[1];
  }
  // Marker-gated bare-version fallback (format-string binaries — see ComponentRule.marker).
  if (rule.marker && rule.bareVersionRe && strings.includes(rule.marker)) {
    const m = strings.match(rule.bareVersionRe);
    if (m?.[1]) return m[1];
  }
  return null;
}

/** Pure: the CVEs from a rule whose affected range covers `version`. */
export function matchCves(rule: ComponentRule, version: string): CveRule[] {
  // One CVE may carry one rule per release series (OpenSSL's 1.0.2 / 1.1.1 / 3.0 ranges); a version sits in at most
  // one of them, but the id is still reported once whatever the table's shape.
  const seen = new Set<string>();
  return rule.cves.filter((c) => cveCovers(version, c) && !seen.has(c.id) && seen.add(c.id));
}

/**
 * ─── Which CVE standard applies when both lanes run, and what the other lane is then allowed to say ───
 *
 * Two lanes claim CVEs on the same image and they do NOT apply the same standard. This table matches a version
 * read out of a bundled binary against a hand-verified range: bounded at BOTH ends, and only where NVD enumerates
 * CPEs for the versions in hand. `sbom`/grype matches a package manifest against the vulnerability databases as
 * they are modelled, open-below CPE ranges included. Neither is wrong, and they mostly do not even overlap — a
 * bundled binary has no manifest entry, which is why this provider exists. What WAS wrong is that which standard
 * an image got was an accident of which provider happened to run: grype accepts CVE-2016-2148 for BusyBox 1.18.4
 * from a manifest while the rule three screens up refuses it, and nothing in the ledger said so.
 *
 * The decision, and it is a decision about what a row SAYS, never about which rows exist:
 *
 *  1. **Both lanes always run and neither suppresses the other.** Deleting the grype rows this table cannot
 *     corroborate would turn a stricter standard into a smaller finding count — the "empty means clean" lie in a
 *     new place. The claim changes; the count does not.
 *  2. **Only this lane reaches `static_confirmed`.** A grype row stays `needs_runtime_reproduction` on the
 *     `external_advisory` channel even when this table claims the same CVE: what grype measured is a manifest
 *     entry, not the version string in the shipped binary. Corroboration is not a transfer of evidence, and the
 *     reverse never happens either — grype cannot raise a curated row.
 *  3. **Where this table has an opinion about a grype row, the row carries it**, as one of three different
 *     sentences: the CVE was evaluated and REJECTED (`rejected`, an open NVD range with no enumerated CPE), the
 *     version falls outside this table's own floored range, or this table claims it too.
 *  4. **Silence is not agreement.** An unmapped component, or a manifest version this table cannot parse
 *     (`1.18.4-1` — a distro package revision), returns NO verdict rather than a false "outside the range".
 *
 * Components are matched by exact name: grype's `busybox` is this table's `busybox`. An alias table would have to
 * be measured against real manifests, and inventing one (`libopenssl` → `openssl`) is the guess this codebase
 * refuses everywhere else. Unmatched means no verdict, which reads as no opinion — see rule 4.
 */
export type CuratedVerdictKind = 'claimed' | 'rejected' | 'outside_curated_range' | 'version_not_comparable';

export interface CuratedVerdict {
  kind: CuratedVerdictKind;
  /** The sentence the corroborated or disputed row prints. */
  note: string;
}

/**
 * Pure: what the curated table has to say about one CVE another lane matched to `component` `version`, or null
 * when it has nothing to say. Never suppresses and never upgrades — it only supplies the sentence.
 */
export function curatedCveVerdict(component: string, version: string, cveId: string): CuratedVerdict | null {
  const rule = COMPONENT_RULES.find((r) => r.component === component);
  if (!rule) return null;
  // Deliberately version-independent: the refusal is about how NVD models the CVE, not about this build.
  const refused = rule.rejected?.find((r) => r.id === cveId);
  if (refused) {
    return {
      kind: 'rejected',
      note: `The curated table evaluated ${cveId} for ${component} and refuses to claim it: ${refused.reason} This row stands on grype's broader standard alone.`,
    };
  }
  // Every range the table carries for this id, not the first: OpenSSL advisories are bounded once per series, and
  // judging a 3.0 build against the 1.0.2 range alone would call a claimed row "outside the curated range".
  const ranges = rule.cves.filter((c) => c.id === cveId);
  if (ranges.length === 0) return null;
  const range = ranges.map((c) => `${c.low}–${c.highExclusive ? '<' : ''}${c.high}`).join(', ');
  if (!parseVersion(version)) {
    return {
      kind: 'version_not_comparable',
      note: `The curated table carries ${cveId} for ${component} ${range} but cannot compare the manifest version "${version}", so it neither corroborates nor disputes this row.`,
    };
  }
  if (ranges.some((c) => cveCovers(version, c))) {
    return {
      kind: 'claimed',
      note: `The curated table claims ${cveId} for ${component} ${range} as well; its own row is static_confirmed from the version string in the binary, which is evidence this manifest match does not carry.`,
    };
  }
  return {
    kind: 'outside_curated_range',
    note: `${component} ${version} falls outside the curated range ${range} for ${cveId}, which is floored at the series the advisory is about where the database range matched here is open below.`,
  };
}

/**
 * Pure: turn located component versions into findings. A matched CVE is `static_confirmed` (the version string is
 * literally in the binary; the CVE's affected range is public fact) — the reachability of the flaw is a separate
 * concern noted in the rationale, so this is a fingerprint fact, not a device verdict. A component with no CVE
 * match is emitted as an `info` inventory fact so the operator sees it was checked, not skipped.
 */
export function buildComponentFindings(hits: ComponentHit[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  for (const hit of hits) {
    const rule = COMPONENT_RULES.find((r) => r.component === hit.component);
    const cves = rule ? matchCves(rule, hit.version) : [];
    if (cves.length === 0) {
      drafts.push({
        kind: 'component-version',
        title: `${hit.component} ${hit.version} (bundled binary, no manifest)`,
        severity: 'info',
        proofState: 'static_confirmed',
        evidence: { component: hit.component, version: hit.version, path: hit.path },
        rationale:
          'Component version fingerprinted from the binary strings (no package manifest, so a manifest-only SBOM ' +
          'misses it). No known CVE matched this version in the curated table.',
      });
      continue;
    }
    for (const cve of cves) {
      const range = cve.low === cve.high ? cve.low : `${cve.low}–${cve.high}${cve.highExclusive ? ' (exclusive)' : ''}`;
      drafts.push({
        kind: 'component-cve',
        title: `${cve.id} — ${hit.component} ${hit.version}: ${cve.title}`,
        severity: cve.severity,
        // A precondition this provider cannot check means the version fact no longer settles the question, so
        // the row comes off the strongest rung. `static_confirmed` is for a property that is literally in the
        // bytes; "affected IF DNSSEC is enabled" is not, and claiming it there would be the over-statement the
        // ladder exists to prevent.
        proofState: cve.precondition ? 'needs_runtime_reproduction' : 'static_confirmed',
        evidence: {
          cve: cve.id,
          component: hit.component,
          version: hit.version,
          affected: range,
          nvdBacking: cve.nvdBacking,
          ...(cve.floorRationale ? { floorRationale: cve.floorRationale } : {}),
          path: hit.path,
          ...(cve.precondition ? { precondition: cve.precondition } : {}),
        },
        rationale: [
          `The bundled ${hit.component} binary reports version ${hit.version}, inside the published affected range ${range} for ${cve.id}.`,
          cve.nvdBacking === 'enumerated'
            ? 'NVD lists the affected versions individually, so an analyst asserted this build rather than a range catching it.'
            : cve.nvdBacking === 'open-below'
              ? `NVD bounds the advisory only from above, so the floor of ${cve.low} is this table's own: ${cve.floorRationale}`
              : 'NVD bounds the advisory at both ends and this rule copies them.',
          cve.precondition
            ? `The version is a static fact; the vulnerability is NOT, because ${cve.precondition} — and nothing this provider reads can tell whether it does. That condition, not the version, is what a reproduction has to settle.`
            : 'Version + CVE range are both static facts; runtime reachability of the flaw is a separate confirmation step.',
          'Found by binary fingerprinting — a manifest-only SBOM returns 0 CVEs here.',
        ].join(' '),
      });
    }
  }
  return drafts;
}

/** Pure: extract printable ASCII runs (>= 4 chars) from a binary buffer as one newline-joined string. */
export function binaryStrings(buf: Uint8Array): string {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] as number;
    if (b >= 0x20 && b <= 0x7e) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= 4) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= 4) out.push(cur);
  return out.join('\n');
}

/** Pure: the rule whose binary a basename is (exact, a versioned `.so.N` shared-object variant, or `binNameRe`). */
export function matchesBinName(base: string): ComponentRule | undefined {
  return COMPONENT_RULES.find(
    (r) => r.binNames.some((n) => base === n || (n.endsWith('.so') && base.startsWith(n))) || r.binNameRe?.test(base),
  );
}
