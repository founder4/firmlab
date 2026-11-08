# Structure map selection — 2026-11-08

The recorded fields in the structure map were available only on mouse hover. A labelled native selector now
lists every displayed segment, including a one-byte band. Its explicit selection survives blur and a temporary
pointer preview; returning from the preview restores the selected details. New analysis data clears the
selection. The proportional ribbon, signature claims, recorded labels/metadata and coverage caveat remain.
Empty listings have an explicit message and no selector; old segments without metadata render their known
range/label without inventing a digest status. English and Spanish controls use the existing theme.

Validation on the built production web assets:

```sh
pnpm --filter @firmlab/web build
pnpm --filter @firmlab/web run test StructureMap visuals
node apps/web/src/components/StructureMap.qa.mjs /absolute/path/to/evidence
```

The focused suite passed 36 tests in three files. Chromium passed 12 combinations: English/Spanish,
dark/light and widths 320/390/1440. Each case tested the labelled selector and every listed option,
keyboard focus/Tab departure, explicit Playwright selection, persistent details, pointer preview/restore,
a long recorded value, old metadata absence and an empty listing. Touch viewports also passed synthesized
tap-to-focus. The selector is 44 px high; measured text contrast was above 4.5:1 in both themes. There was no
horizontal document overflow, console/page exception, failed request or HTTP error. All recorded requests were
GETs to an ephemeral loopback-only in-memory fixture server; no real API, database or upload was involved.
The mobile Spanish/light and desktop English/dark full-page screenshots were visually inspected.

Evidence: `/Users/agfil/.local/state/orca-campaign/firmlab-20261108-034811/structure-inspector-ui/`
(`results.json`, `requests.json`, twelve full-page screenshots) and adjacent build/test/QA logs.

Limits: all analysis/metadata are explicitly synthetic UI fixtures, including `not_verified` and `mismatch`.
They do not prove any digest computation, real firmware, deployed service or physical device. Native menu
selection by keyboard could not be established through this macOS Chromium automation: ArrowDown/Enter did
not commit an option even in an isolated HTML select, in both headless and visible Chromium. The harness
therefore records real keyboard focus separately from programmatic option selection; neither is claimed as a
physical phone picker or assistive-technology acceptance test. Those platform interactions remain unverified.
An initial fixture omitted required `analysis.size`, causing a render error; correcting the fixture resolved
it without a product change. That diagnostic is retained as `structure-inspector-ui-initial-fixture-size.log`.
