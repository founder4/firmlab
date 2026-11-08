# Unlisted uImage matches skip the payload CRC — 2026-11-08

Scope: one reproduced performance defect in `scanSignaturesDetailed` (`packages/core/src/signatures.ts`), and
nothing wider. This is **not** a claim that checksum work in the scanner is bounded in general.

## The defect

The listing cap (`maxHits`) stops the scan adding rows, never looking: every match still runs its rule's check,
because a rejection changes `rejected`, `rejectedByRule` and the id set that `inferIdentity` reads. The uImage
check ends with a CRC-32 over the payload its header declares. That CRC never rejects — it only chooses between
`consistent` and `verified` — yet it ran for every uImage match, listed or not. N header-CRC-valid uImage headers
that each declare "the rest of the buffer" therefore cost O(N × length) bytes of CRC work even when a single row
is listed. Reproduced on 512 KiB of synthetic inert bytes with 64 such headers: `maxHits: 0` listed one uImage,
counted 64 matches, and spent ~157 ms (an invalid-header control costs ~19 ms).

## The change

- `SignatureRule` gains an optional internal hook, `verifyUnlisted`. The scanner decides `listable`
  (`!(hits.length >= maxHits && seenIds.has(rule.id))`) **before** the check — the same predicate that previously ran
  after it, with nothing in between that mutates either value — and runs `verifyUnlisted` only for a match it will
  not list, falling back to `verify` for every rule without the hook.
- The hook's contract: return `rejected` exactly when `verify` would. Its non-rejected tier and rationale are
  never emitted, because the hit is not listed.
- Only `uimage` has the hook: `uimageVerify(buf, off, false)` runs every header decision (header-past-end,
  header CRC, declared-size-past-end) unchanged and stops before the payload CRC, returning `consistent` with a
  rationale saying the payload CRC was not computed. `uimage` never rejects, so survival, `matched`, `rejected`,
  `rejectedByRule`, `distinctIds` and the id set are unchanged by construction; the test pins the agreement anyway.
- A rule's first match is always listable, so a new id that appears after the list is full still gets the full
  `verify`, payload CRC included. Every listed row keeps its tier, score, rationale and `meta` exactly.
- The registry's `verify` for `uimage` is still the full check; a direct call behaves as before.

Not changed: the cap, its default, the rule set, the CRC algorithm, tiers and rationales of listed hits, identity
inference, the scan's full walk to the end of the buffer, and every other rule. No HTTP, Settings or model option.

**Explicitly deferred, not claimed fixed:** TRX (HDR0) CRC, TP-Link v1 MD5, and every other checksum or digest a
rule recomputes still run for unlisted matches, as do the Sercomm, MediaTek and Realtek checks. Repeated headers
of those formats can still amplify work after the cap. None was measured here.

A payload CRC that was not computed is not a negative and not a clean result: it is a question this scan did
not ask for a hit it does not show. An unlisted header that looks valid says nothing about the bytes behind it.

## Evidence

**Unit regression** (`packages/core/test/signatures.test.ts`, suite *unlisted uImage matches skip the payload
CRC, nothing else*). It counts indexed reads through a transparent `Proxy` over the caller's buffer (typed-array
methods bound to the real target; no production hook) and never asserts on time. Against the pre-change
`signatures.ts` (765235c) the three read-bound cases and the registry-hook case fail —
`expected 680009 / 2248397 / 4339598 to be less than 393216` (6 × length) for 16 / 64 / 128 headers in 64 KiB,
while the fixed scan reads under 3 × length — and every equality case passes, which
is the point: they compare each capped scan (caps 0, 1, 16, 5000) with an uncapped control and require identical
`matched`, `rejected`, `rejectedByRule`, `distinctIds`, id set, and listed rows. Also covered: header CRC
valid/invalid, payload CRC matching/mismatching on the listed hit, header past the end, payload past the end,
a late first TRX after the list is full (listed `verified`), a late first uImage after other ids filled the list
(listed `verified`, full payload read), direct-registry `verify` unchanged, `verifyUnlisted` agreeing with
`verify` on reject-or-survive and differing only by the withheld payload rung, and the caller buffer unmutated.
After the change: core 799/799 tests, `tsc` check and build, scoped Biome and the NUL check pass.

**Container probe** — compiled core only, synthetic bytes generated in-process; no firmware, DB, corpus, HTTP,
upload or provider. Image `758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`
(`firmlab-campaign-20261108/firmware:trixie-304e663`), Node v22.23.4:

```bash
docker run --rm --network none --read-only --memory 1g --cpus 2 \
  -v "$E/core-old:/probe/core-old:ro" -v "$E/core-new:/probe/core-new:ro" \
  -v "$E/scripts:/probe/scripts:ro" -v "$OUT:/out" \
  758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  node /probe/scripts/uimage-unlisted-probe.mjs /probe/core-old /probe/core-new /out/probe-result.json
```

(The probe used the full compiled `dist/` of each build; only `signatures.js` differs, and those two files are
kept as evidence.) Evidence in `/Users/agfil/orca/campaign-evidence/uimage-unlisted-work-20261108/`, SHA-256:

| file | sha256 |
|---|---|
| `scripts/uimage-unlisted-probe.mjs` | `e240a675a08c39852f28a82e3d01e14dc92cc86fe6e446814e96402a9f1c48df` |
| `core-old/signatures.js` (765235c) | `c2c6e930cbe7e52b13ae99c1cb67416046caa258b66c9bc7ac81fd448b650964` |
| `core-new/signatures.js` (this change) | `86259c383d9af7c04f841a1b8a9a5305cdbfbd8e418801314e5770fde0bf28d4` |
| `probe-result.json` | `e5fb419f9fb069f081349c00090d804fe413f0b799b6a40ffc894662f3a08b18` |

512 KiB synthetic buffer, `maxHits: 0`. Reads are indexed byte reads through the proxy; times are a median of
five unproxied runs, **descriptive only, not an acceptance criterion**:

| headers | header CRC | reads before | reads after | uncapped (after) | ms before | ms after |
|---:|---|---:|---:|---:|---:|---:|
| 16 | valid | 5,450,325 | 1,519,065 | 5,450,475 | 54.2 | 21.1 |
| 64 | valid | 18,028,812 | 1,517,520 | 18,029,442 | 156.7 | 22.1 |
| 128 | valid | 34,800,137 | 1,515,469 | 34,801,407 | 184.7 | 22.3 |
| 128 | invalid | 990,712 | 990,712 | 991,982 | 19.2 | 19.4 |

In every row the listed uImage is the one at offset 0 (`verified`, or `magic` for the invalid control), the
`JSON.stringify` of the whole scan is byte-identical between the old and new core at caps 0, 1, 16 and 5000, and
the buffer's SHA-256 is unchanged after scanning. Counts in the 128-header rows (`matched` 129, `rejected` 1)
include one coincidental non-uImage magic in the filler, identical before and after.

Limits: synthetic bytes only; one buffer size; the uncapped scan is still O(N × length) by design, because every
listed hit is fully verified — the fix bounds the work the cap exists to skip, not the work of listing.

Coordinator compatibility follow-up: replacing the original exclusion with a less-than comparison changes
legacy behavior for `maxHits: NaN` (the original scan lists all matches, while `length < NaN` is false). A new
regression reproduced that difference (three uImage rows became one), then passed after retaining the literal
negation of the original exclusion predicate. The output contract stays unchanged even for that option; no
new option normalization or global checksum budget is introduced.
