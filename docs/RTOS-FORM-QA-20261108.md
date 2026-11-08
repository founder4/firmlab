# FreeRTOS snapshot form: browser validation — 2026-11-08

The new wait-list editor retained a four-column layout at phone widths. At 390 px,
adding a row reduced its object/member name and hexadecimal address inputs to 60 px.
The page had no horizontal overflow, so the previous empty-form browser check missed
this usability problem. A separate 320 px check also showed the long integrity-option
label increasing the implicit form grid width to 335.5 px (document scroll width 367 px).

The editor now wraps whole fields according to available space, including narrow
desktop columns. The snapshot form has a bounded grid track; fieldsets and long
checkbox labels can shrink and wrap. Labels, tab order, validation, defaults and API
request semantics remain the same. The module comment now reflects the existing
unordered Event Group support. No provider or proof-state behavior changed.

The committed `RtosTaskSnapshotPanel.qa.mjs` now adds a real wait-list row, fills its
name/address, checks readable field widths and keyboard traversal, and checks page
overflow, console exceptions and failed HTTP requests. It captures the row separately
from the full page. All requests go to an ephemeral loopback fixture serving the built
web application; no deployed API, database, firmware or stored setting is used.

Eight cases passed in Chromium: English and Spanish at 320×844, 390×844, 768×1000 and
1440×1000. The two phone widths use synthesized touch input to add a row; keyboard
Tab then reaches the address from the name. No console exceptions, failed requests or
horizontal page overflow occurred. Name inputs remain at least 200 px and address
inputs at least 120 px. The existing Renode refusal check still shows exactly one
warning and preserves the explicit unavailable-tool reason. The build and focused
component suite also pass.

The Impeccable source detector reported no findings; visual inspection confirmed the
mobile wrapping and compact desktop row. This is focused form/refusal validation,
not a claim that all result tables, contrast combinations or loading states were
audited. Physical phones, Safari and native mobile keyboards were not exercised.
