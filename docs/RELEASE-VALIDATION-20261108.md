# Release and existing-firmware validation — 2026-11-08

The operator authorized push, deployment and real checks using already available firmware. Main `2ff7a22`
was pushed and GitHub CI [42485431643](https://github.com/founder4/firmlab/actions/runs/42485431643) passed
quality/tests and Docker smoke. Its app candidate was built from a clean release checkout on the existing
Debian 13 tools image `2d0aba372d9d`, without incorporating the seven pre-existing local files.

Before promotion, 28 bounded tool probes, provider integration, the existing FreeRTOS fixture and security
smokes passed offline. Ghidra produced 40 nonempty pseudocode functions; angr executed a symbolic step;
AFL++/QEMU produced coverage; mitmproxy completed HTTP/HTTPS and saved-flow readback. The encrypted backup
was restored into a disposable volume: SQLite integrity passed, retaining 27 images and 2,395 findings.
The candidate started on that restored database and ten GET checks passed before recreating only `firmlab`.

The deployed candidate `f6d3a5393542` served the exact `2ff7a22` revision and became healthy. Existing volumes,
authentication labels, isolation/capability configuration, stored settings and the local view sidecar were
preserved; no host port was added. The LAN authentication route returned 401 before and after rollout.
This is a local LAN check, not proof of a separate remote client's access. No host/Tailscale/network settings
were changed. A retained previous-image reference and the verified encrypted backup support rollback.

## Existing sample coverage

The checks ran in the deployed image by immutable ID, using the restored samples read-only and networking
disabled. Detailed private outputs and exact identities are under
`/Users/agfil/.local/state/firmlab/release-20261108-142942/`; firmware, secrets and raw results stay local.

| Area | Observed result | Boundary |
| --- | --- | --- |
| Static intake and digest coverage | 27/27 stored firmware hashes match; analysis finishes; source buffers/files remain unchanged; digest execution/byte ceilings hold. | No MediaTek/Realtek positive image occurs in this sample set. Zero candidates does not validate those formats on manufacturer firmware. |
| Legacy signature work | 108 comparisons of listed uImage/TRX/TP-Link results against the prior deployed core, at caps 0/1/16/5000, agree exactly. | These are output comparisons on existing samples, not a global checksum-work bound. |
| PICOBIN/RISC-V | The existing `Pico-RP2040_CTF.bin` actually declares a validated RP2350 RISC-V PICOBIN loop. radare2 admits eight targets, uses eight decoder invocations and lists 24 direct edges. | Only two functions complete; 13 decode stops/failures, ten excluded targets and two unresolved callsites remain explicit. No mapped-outside call was observed. Runtime remains blocked by missing verified platform/ROM/peripheral models. A filename never decides chip identity. |
| RTOS symbols and RAM | Zephyr STM32L072 captures 20,480 bytes; Contiki STM32F4 captures 262,144 bytes, both offline. ELF symbol tables are read; neither supplies resolved FreeRTOS symbols. The stripped Dragon ELF correctly reports no static symbol table. | RAM capture is not scheduler/task proof. Remote SVD references were refused; their potential behavioral effect was not measured. The separate controlled FreeRTOS fixture verifies known task/list occupants. |
| Actual SBOM/PURL | Syft and offline Grype complete on nine existing extracted rootfs: 2,346 packages and 721 advisory rows. Of those rows, 505 carry exact measured identity. | 216 Go stdlib rows disagree between artifact `go1.25.7` and PURL `1.25.7`; they remain unmatched for VEX. No rows/severity/proof states are removed or upgraded. These counts are bounded by the retained database, not current global intelligence. |
| Vendor VEX discovery | All nine available rootfs are searched under discovery bounds. No vendor VEX document is found. | No positive CSAF/OpenVEX manufacturer assertion is validated on this sample set. Their controlled contract tests supplement, rather than replace, that missing evidence. |
| MediaTek producer controls | Current compiled core/API replay 20 accepted and eight refused existing producer cases, plus three fresh `mkimage` outputs. Payload/digest mutations, missing capability and the eight-execution limit retain honest states. | These are inert generated controls. SHA-256 covers GFH/payload, not the first 0x600 bytes, digest field or tail; it proves neither authenticity nor execution. |
| Realtek producer controls | Current compiled parser/scanner accept 56 recorded outputs and refuse four controls. All original input hashes match. | The two case-distinct controls use the already-preserved case-fix files and unique replay names, avoiding APFS aliases. Only checksum location is established: consistent/85 maximum. |

## Browser validation and corrective patch

The first production pass rendered 84 pages in EN/ES, desktop/mobile and light/dark, using GET requests only.
It found no JavaScript or HTTP errors, but did find page overflow on mobile Capabilities. Four structure-select
failures were driver synchronization errors: the test could read the previous image before the new analysis
arrived. All three affected images retain selection after blur when correctly stabilized. The original failed
evidence is preserved; it is not presented as an all-green run.

This revision contains the narrow Capabilities correction: named native sections contain horizontally scrollable
tables without hiding columns, and a 640px minimum preserves readable cells. Existing desktop layout and wording
remain. `apps/web/src/pages/Capabilities.qa.mjs` reproduces the old overflow at 320px and verifies containment,
named regions and actual ArrowRight scrolling on the fixed built UI at 320/390/1440px, in EN/ES and both themes.
All four corrected scenarios pass. The browser is Chromium with emulated viewports; physical phone/native-picker
and assistive-technology acceptance are not claimed. Focused web suites pass 32 tests.

Final revision, image IDs, subsequent exact-SHA CI, rollout receipts, full gates and the stabilized production
browser rerun are recorded in the local release state after this commit, avoiding a self-referential revision
claim. Core/API source hashes are compared before reusing their completed real-sample evidence after this UI-only
correction. No additional firmware was acquired, and test outputs did not rewrite production analysis/findings
or stored lanes.
