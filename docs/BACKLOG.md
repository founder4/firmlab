# FirmLab — running backlog

Flat ledger of surfaced-but-unimplemented work. Append here whenever something is deferred; the prioritized
rationale lives in [`METHODOLOGY-GAPS.md`](METHODOLOGY-GAPS.md) and the phase status in the project memory.

Status: `▶ building` · `▢ planned` · `◐ partial` · `— out of scope`.

## Dynamic & runtime (FSTM 7–8) — the biggest gap
- ✅ **The W9 chain fires on its own** (2026-07-27, deploy `8700bdd`) — `binvuln → symreach → dynprobe` completed end to end with no operator, on the real DVRF_v03: sweep → 3 reachability probes → `sprintf` **reached** in `sbin/diag_tracertbutton` → re-plan scheduled the reproduction → gdb ran it. The blocker was never the lead ordering the previous note blamed. `FINDING_CAP` truncated the sweep's findings **by arrival**, and the walk is a LIFO stack that descends `usr/` first, so the 43 candidates reported on DVRF were the prefix of a reverse-alphabetical walk — `bin/`, `sbin/` and the whole `pwnable/` tree overflowed, and `pwnable/Intro/stack_bof_01` never became a candidate at all. Uncapped, the same rootfs yields **106 candidates, not 43**. Fixed by ranking before capping (round-robin across kinds, smallest binary first) and ordering the leads the same way. _Two defects the run then exposed, both fixed: gdb's `attached` flag was inferred from a "Remote debugging using" line that `gdb -batch` never prints, so a probe that attached, ran and simply did not reach the sink was reported as `not_attached` — "a failure of the harness" — when it was a real, weak result; and ranking by size promoted DVRF's ~6 KB iptables `.so` plugins (15 of 30 listed candidates) to the front of a queue whose question they structurally cannot answer, now filtered by `isRunnableElf` (ET_EXEC, or ET_DYN carrying PT_INTERP)._
- ✅ **qemu's own stderr was discarded** (2026-07-28, deploy `9908bdb`) — `dynprobe-run.ts` spawned with `stdio: 'ignore'`, so the target's own account of its death never reached `classifyRun`. Now piped, bounded at 64 KB with the truncation stated. **The separation is the work, not the capture:** the probe feeds a cyclic pattern as argv, so a target printing `Aa0Aa1…: No such file or directory` is behaving CORRECTLY on garbage input, and counting it would invent an emulation failure out of a successful run. ENOENT counts against the sandbox only for `/dev`, `/proc`, `/sys` — kernel interfaces qemu-user genuinely does not implement and that no argv of ours can name — alongside unsupported syscalls, unloadable libraries and ENOSYS. Everything else is kept as `targetOutput`: evidence, never able to downgrade a verdict. `sandboxShortfalls` reaches the evidence of *every* verdict, since a crash whose run also missed `/dev/nvram` is weaker than one whose run did not. **Validated in-container on real DVRF bytes: `sbin/diag_tracertbutton` went `ran_clean` → `emulation_artifact` carrying `/dev/nvram: No such file or directory`, while `stack_bof_01` still reproduces `crash_input_controlled` at offset 204.** _One defect the real run exposed and the tests had not: `qemu: uncaught target signal 11 (Segmentation fault)` was being counted as a sandbox shortfall, but qemu prints it on EVERY unhandled fault — it is qemu faithfully reporting the target crashing, i.e. the result this probe exists to find. The verdict survived only because the input-controlled branch runs first; a real crash that missed the sink would have been graded `emulation_artifact` and the finding discarded as harness noise. Removed and pinned (`904ee7f`→`295b431`)._
- ✅ **The finding cap is severity-blind** (2026-07-28, `e8b23c0`) — the round-robin fixed the walk-order defect and over-corrected: an equal share is only fair when the kinds are equally serious, and it handed 30 of 60 DVRF slots to `info` cmdexec sinks while dropping 76 `medium` stack-overflow candidates. Now two halves, each stopping the other's failure mode: a floor of `ceil(cap / 2k)` seats per kind (the anti-crowding guarantee, so severity cannot delete a kind), then the rest pooled and awarded on severity → smallest binary → path. DVRF moves 30/30 → 45 medium / 15 info, where a pure severity sort would have given `info` none. A cap too small to seat every kind hands the floor to the kinds carrying the worst leads first, so it degrades by severity rather than alphabet; an unknown severity ranks as `info` so a typo cannot outrank a real critical.
- ▢ **The `info` share is `1/(2k)`, and only two kinds have ever existed.** With a third kind each floor falls to a sixth of the cap. That is the intended shape, but it is untested against a real three-kind sweep because this provider emits two. Related: `runBinVuln`'s reason states the total dropped and the candidate split, from which the sink split is derivable, but does not break the drop count down by severity — worth doing if a third kind appears.
- ✅ **The probe rank measures answerability AND interest — enabled 2026-07-29 after measuring it.** It sat built-but-inert since `f993c3e` on a prediction: that DVRF's exposed daemons are large, so promoting them would spend half the probe allowance on timeouts. **The corpus contradicts the prediction on both halves.** Measured across all 7 rootfs-bearing images by driving the real `reachabilityLeads` both ways and then running angr on what each ordering would actually have asked: no-op on 5 (the interest set and the candidate set are disjoint), neutral on WR940Nv6 (+4.6 s, inconclusive → inconclusive), and on **MR3220v2 it converts a measured 0-of-3 into `strcpy` proven reachable in `usr/bin/httpd` — 63 steps, 8.6 s, reproduced twice.** The feared timeout does not exist: every promoted probe finished in 8.6–15 s of a 90 s budget, twice by exhausting angr's SEARCH SPACE rather than the clock, and the 90 s ceiling was never hit on any image. And on DVRF specifically the rank promotes nothing at all, because `runServiceMap` enumerates **zero** services there. _Never worse on any image, strictly better on one, and the finding it buys is a reachable `strcpy` in a router's web server._
- ▢ **Size is a weak predictor of answerability, which is the premise smallest-first rests on.** Across the 22 probes the corpus has run, 6 of 18 under 20 KB reached a sink, while IMOU's **7.9 MB `sonia` reached `strcpy` in 39 steps**. Worth re-deriving the ordering from what actually converges rather than from file size.
- ✅ **The listing cap hid exactly the binary the rank exists to promote** (2026-07-30, deploy `a234b9a`) — `selectFindings` ordered equal-severity candidates smallest-first, so on a rootfs with more candidates than the cap the LARGEST was dropped first, and the exposed daemon is always the largest. **Reproduced on the real WDR3600 rootfs before the fix: 124 ELFs → 58 candidates → 45 listed, and `usr/bin/httpd` was NOT among them**; the three at the head were `lib/libutil-0.9.30.so` (3964 B), `lib/libmsglog.so` (4644 B) and `sbin/pktlogconf` (7548 B) — i.e. the cap spent the ledger on precisely the uClibc stubs the entry below complains about. **Neither of the two fix shapes this entry proposed was taken**, because both leave the ledger wrong and only repair the leads: if a binary is worth probing it is worth listing, and a lead naming a binary the ledger omits was the side effect the entry itself flagged. Instead exposure became a **ranking key** between severity and size, supplied as an optional `ReadonlySet<string>` so `selectFindings` stays pure (the same shape as the UEFI module ranking's optional corpus). After: `usr/bin/httpd` is listed at **position 0**, 1,717,140 B, carrying `strcpy/strcat/sprintf/vsprintf/sscanf`. Exposure does NOT outrank severity — a `critical` in an unreferenced binary still beats a `medium` in a daemon, or a listening socket could launder a weak lead to the top of the ledger.
  **`undefined` ≠ `new Set()`, and this is the load-bearing part:** no signal means W3/W4 did not run, an empty signal means they ran and named nothing — which is real, since `runServiceMap` returns zero services on DVRF. The two rank identically and are opposite facts, so `reason` separates them in prose and the ranking is unchanged in both. Exposure is now computed **before** the sweep; it used to be assembled only for the probe rank, which is why the cap never had it.
  Verified on the deployed build that the fix is not inert: the real `runServiceMap` on the WDR3600 yields `httpd | /usr/bin/httpd | autostart: true`, `interestingBinaries` turns that into `{usr/bin/httpd → "it is an autostart network daemon (httpd)"}`, and in **every** device class that runs this sweep the plan puts `servicemap` (@6) and `webtaint` (@14) ahead of `binvuln` (@15), so the signal always arrives. _One defect the tests caught: exposure is a TIER, not an override — between two exposed daemons size still decides, so at cap 1 the 900 KB dropbear takes the seat and the 1.7 MB httpd is the one named as dropped. The first assertion said the opposite, written reading exposure as a total order._ An exposed binary can still miss the cap (cap smaller than the exposed set, or a higher severity fills it), so those are **named** in `exposedDropped`, not counted — optional forever, since `[]` would be a claim about a ranking that never had a signal.
- ▢ **`runnable` lets uClibc's shared objects through, and they are what smallest-first buys.** `lib/libutil-0.9.30.so` and `lib/libcrypt-0.9.30.so` pass the filter because uClibc gives them an entry point, and they are the two smallest candidates on all three TP-Link images — so they take 1–2 of every 3 probes and return "search space exhausted" in 1–8 steps, 0.9–1.6 s. The cheapest possible non-answer. The `.so` filter's premise is that a library has no entry point to be reachable from; the real predicate is whether that entry point is a *program*. **Measured again 2026-07-30 on the deployed build, and it is worse than "they take some probes" — they take the LEDGER:** with no exposure signal the WDR3600's 45 listed candidates open with `lib/libutil-0.9.30.so` (3964 B) and `lib/libmsglog.so` (4644 B) at positions 1–2. The exposure key now moves an autostart daemon ahead of them, which repairs the head of the list and does nothing about the tail: every stub still occupies a seat that a real program could hold, and on an image where W3/W4 do not run the ordering is exactly as it was. Impact: medium — this is now the largest remaining distortion in the sweep's ledger.
- ▢ **The exposure signal rests on `network && autostart`, with no port evidence behind it.** Surfaced 2026-07-30
  while validating the exposure ranking, not implemented. `exposedDaemon` is `s.network && s.autostart`, and on
  the real WDR3600 the service map returns `httpd | /usr/bin/httpd | autostart: true | ports: []` — so `network`
  was decided without a single declared port. That is consistent with the `planForwards` entry below (no corpus
  image declares ports) and it is defensible for RANKING, which orders leads rather than claiming anything. But
  the same predicate feeds `daemonLeads`, whose findings *do* read as claims about an exposed service, and there
  the absent port is the difference between "listens on the network" and "is named like something that would".
  Impact: low for the cap, medium for anything that reports exposure as a fact rather than as an ordering.
- ▢ **`runServiceMap` returns ZERO services on DVRF**, a rootfs that does have init scripts. That is the prior question behind "promoting `stack_bof_01` needs a signal no worker produces" — it is not that the pwnable is unflagged, it is that nothing on that image is flagged at all. Answer why the service map comes back empty before designing the missing "standalone argv-taking executable no config references" predicate.
- ▢ **Promoting `stack_bof_01` needs a signal no worker produces.** The missing predicate is "a standalone argv-taking executable that no config references" — the opposite shape from W3's autostart daemons and W4's web handlers, which is why neither finds it. Until that exists, or until the two-queue rank is measured in-container against the corpus, the interest parameter above stays unwired.
- ▢ **Libraries are permanently unasked.** Filtering `.so` out of the reachability queue is right for the question as posed, but it leaves a vulnerable library as a candidate nothing will ever settle. Loading the `.so` and starting symbolically from an exported function is a distinct rung, not a variant of this one.
- ✅ **webprobe** — drives the booted service for command-injection (marker/nonce) + path-traversal (`/etc/passwd`); a reproduced hit → `confirmed_in_emulation`. `providers/webprobe.ts` + `/webprobe` route + panel. Validated against a real vulnerable HTTP server. _Follow-up: auth-bypass / default-creds checks, POST-body injection._
- ✅ **Dynamic reproduction — GDB in emulation** (2026-07-27) — `providers/dynprobe.ts` (pure: `cyclicPattern` / `patternOffset` / `buildGdbScript` / `parseGdbOutput` / `classifyRun` / `buildDynFindings`, 22 unit tests) + `providers/dynprobe-run.ts` + `POST/GET /images/:id/dynprobe` + a `dynprobe` executor and `reproduce-crash` lead in W9. `Dockerfile.tools` gains **gdb-multiarch**; qemu-user already exposed a gdbstub (`-g PORT`).

  **Why this and not another static layer:** across the corpus **85 of 114 findings (75%) sat at `needs_runtime_reproduction`** — the honest ceiling of static analysis. `binvuln` finds a precondition, `symreach` proves the sink is on a live path, and neither can say the program misbehaves, so the lead stayed a lead forever. This runs it: breakpoint the exact call site angr resolved, feed a cyclic input, read the registers at the fault. Three claims in increasing strength — the sink executed; the program crashed; the faulting PC is input bytes, so the input reached the saved return address and the offset is recoverable from the pattern (self-evidencing, not asserted).

  **Three refusals, by design.** Not a device claim: `confirmed_in_emulation` is the ceiling and the rationale says why (qemu-user has a different libc, no NVRAM, no peripherals). Not an exploit: the offset is crash triage, which is what a crash report contains, and FirmLab stops there — no ROP, no shellcode. And never reads a non-crash as safety: a clean run is a statement about ONE input, and an emulation artefact (a fault before the sink, with the emulator complaining) is reported as the artefact it is rather than counted as a reproduction.

  **Validated end to end through the API on the real DVRF_v03** (deploy `1a9731b`): `pwnable/Intro/stack_bof_01`, `strcpy` at `0x00400a30`, 400-byte cyclic input → **`crash_input_controlled`, SIGSEGV at `0x41386741`, offset 204 (`"Ag8A"`, little-endian), 2 sink hits** → `critical` / `confirmed_in_emulation`, *"input controls the saved return address at offset 204"*. **The first `confirmed_in_emulation` memory-safety finding this workbench has ever produced.** Two real defects the run exposed, both fixed and pinned: (1) the route refused with "architecture is unknown" — `identity.arch` is a guess from the raw bytes and IS unknown for DVRF, while extraction had already measured `mipsel` from the ELF headers of the 218 binaries in question; preferring the guess over the measurement was backwards. (2) The faulting PC came back `0x0`: gdb states a fault across two lines and the address is on the SECOND (`0x41386741 in ?? ()`), while the parser was reading `info program`'s later wording after the script had continued past the fault — which downgraded `crash_input_controlled` to a plain `crash` and discarded the offset, i.e. the entire point.

  _Follow-up: **the W9 auto-chain has not fired end to end yet.** It is wired (`reproductionLeads` turns a `sink-reachable` finding into a `reproduce-crash` spec carrying angr's addresses) and unit-pinned, but in the validating scan all three reachability probes the budget allowed returned inconclusive, so there was no `reached` sink to hang a reproduction on. Related and worth fixing: `reachabilityLeads` takes candidates in filesystem-walk order, which is arbitrary — it picked `arp`/`bpalogin`/`brctl` and never reached `pwnable/Intro/stack_bof_01`, the binary that actually crashes. Ordering by ascending binary size is defensible (bounded symbolic execution converges on small binaries and reliably times out on large ones) and would get more answers per unit of budget. Also open: stdin as an input channel (only argv today), and multi-input search rather than one cyclic pattern._
- ✅ **Symbolic reachability (angr)** (2026-07-27) — `providers/symreach.ts` + `scripts/angr-reach.py`. One checkable question per sink: is the call site reachable from the entry point under symbolic argv/stdin? `binvuln` candidates become `prove-reachability` leads (capped at 3/run) that W9 re-plans into `symreach` steps, keyed `symreach:<path>` so re-runs are idempotent. angr lives in its OWN venv (`FIRMLAB_ANGR_PYTHON`) so it cannot collide with chipsec; `ToolSpec.timeoutMs` exists because importing angr takes seconds and the 4 s default would have misreported it absent (the Ghidra bug again). **Honesty contract:** reached ⇒ `static_confirmed` phrased as REACHABILITY, never exploitability; not reached ⇒ keeps `needs_runtime_reproduction` and records which budget expired, whether states were pruned, and how many were lost to angr-internal crashes — never `false_positive`; angr absent ⇒ `blocked_by_platform`. **Validated in-container on the real DVRF_v03**: W1 carved 235 files, W5 swept 218 ELFs → **39 stack-overflow candidates**, W9 re-planned 3 reachability probes, and **`sscanf` in `usr/sbin/bpalogin` came back `reached` from the entry point** with the concrete argv[1] and a 12-block path tail; `arp`/`brctl` returned honest inconclusives. _Follow-up: angr 9.2.213's `sscanf` SimProcedure raises a raw `TypeError` (`format_parser.py:258`, `claripy.BVV()` on a symbolic position) — the probe now drops the crashed state and continues instead of aborting the sink, but those paths are genuinely unexplored and are reported as such._
- ✅ **Manual reachability route + W4-driven questions** (2026-07-27) — the prober had exactly one caller, so a working symbolic prover could not be asked anything. Two ways in now:
  - **`POST/GET /images/:id/symreach`** (`routes/symreach.ts` + `SymReachPanel` in the Binaries tab, sharing the binaries-table selection with radare2 triage): any rootfs ELF, any sink. `pickSinks` gained a `SinkPolicy` — `unsafe-copy` (autonomous: settle a W5 candidate) vs `as-given` (manual: `system`, `memcpy`, a vendor `doSystem` are the same question). Blank sinks ⇒ **derived** from the binary's own imports (`binvuln.assessBinaryFile`, the sweep's per-file step, now exported), so a lead that names a target but not its symbols works too. Guards state the mistake instead of failing later: not-in-rootfs, not-an-ELF, non-symbol sink names (`validateSinkNames`), and "imports no unbounded copy — but it does import `system`/`popen`". Budget 15–600 s. Findings sync under the same idempotent `symreach:<path>` source W9 uses.
  - **W4 taint chains as the reachability questions** (`taintReachabilityLeads` + pure `execTargetFromSnippet`): a tainted handler's `os.execute("/usr/sbin/gl-tor " .. params.enable)` names a native binary statically (the constant head of the command), and that binary receives attacker-controlled **argv** — exactly the channel the probe makes symbolic. Strictly better premise than the sweep's syntactic "imports strcpy, no canary". Deliberately NOT scheduled: the httpd itself (its input arrives on a socket, so a `reached` under an argv model would be a claim about the wrong channel — it keeps its decompile lead); shell scripts (angr loads executables); interpolated command names (`os.execute(cmd .. …)` ⇒ null, guessing would be fabrication); and **bare shell builtins** (see validation below). The angr allowance is now **global per run** (`countReachabilityProbes` over the agenda), so W4's questions claim the slots ahead of binvuln's, and the sweep's summary reports how many candidates were left unasked.

  **Validated in-container on real bytes (2026-07-27, deploy `8402b1a`).** DVRF_v03 (235 files, mipsel): the manual route derived `strcpy` from `pwnable/Intro/stack_bof_01`'s own imports and angr proved it **reached** from the entry point (MIPS32, 22 steps, concrete argv[1]); an operator-named `system` in `usr/sbin/generate_pin` also came back **reached** while `memcpy` came back honestly `absent` — a question the W5 sweep structurally cannot pose. Guards fire with the reason, not a late crash: non-ELF (`pwnable/Intro/README`), symlink escaping the rootfs (`etc/passwd → /dev/null`), non-symbol sink (`os.execute`), and "imports no unbounded copy — but it does import `system`" on `sbin/chkntfs`. GL.iNet BE3600 4.9.0 (W1 carve → 6497 files, arm64): W4 found 54 handlers / 2 tainted and re-planned the uhttpd decompile; the sweep's `gl-arp-scan` candidate got the reachability slot and returned an honest inconclusive. **Two defects the real-bytes run exposed and that are now fixed + unit-pinned:** (1) manual findings keyed by binary alone made a second question DELETE the first question's confirmed answer (`system` in generate_pin vanished when `sprintf` was asked) — the manual source now carries the sink set, while a derived-sink probe keeps W9's bare per-binary key; (2) W4 scheduled a probe on `bin/echo`, read out of the real tor handler's `os.execute("echo \"ExitNodes " .. countries .. "\" >> /etc/tor/torrc")` — a correct parse and a useless question, since `os.execute` goes through `/bin/sh`, which resolves `echo` as a builtin so that ELF never runs, and the injection is into the shell command line rather than any argv the prober models.
  _Follow-up: the sink set in the manual source key means a derived-sink probe and an explicit probe for the same sink coexist as two rows making the same claim — redundant but each from a genuinely distinct question; merging them would reintroduce the deletion bug._
- ▢ **Cross-binary dataflow** — extend the single-binary taint scaffold (wairz `trace_dataflow` / `cross_binary_dataflow` / stack+global layout).
- ▢ **Library-level fuzz harness** — cross-compile a harness against an extracted `.so` to fuzz a specific exported fn; `patch_function_return` to stub a blocking check (wairz `harness-build`).
- ▢ **cmplog / compcov** — magic-byte solving for AFL++.
- ▢ **Prebuilt guest-arch libdesock** — so the network fuzz harness works out-of-the-box, not only with `FIRMLAB_DESOCK`.

## UEFI / BIOS deep analysis
- ✅ **The corpus has a UEFI image at last, and the lane produces findings on it** (2026-07-30). The #1 item on the
  re-derived §4 list was that the corpus is the binding constraint — no UEFI image, so every `chipsec`/`fwhunt`
  branch was tested against fixtures. Closed with **OVMF**, taken from Debian's own `ovmf` package rather than
  downloaded firmware: `OVMF_CODE_4M.secboot.fd` (3.7 MB, a Secure Boot EDK2 build) and `OVMF_VARS_4M.snakeoil.fd`
  (541 KB, the TEST-KEY variable store), both carrying the `_FVH` volume signature and both now in
  `~/Downloads/firmwares` beside the other samples. The classifier calls the volume `uefi-bios` unprompted.
  **fwhunt on real bytes: 106 of 108 rules ran** — against 17 of 108 on the earlier whole-image-only probe — over
  136 carved modules, and **11 matches**: `BRLY-2022-028 (RsbStuffingCheck)`, a MitigationFailure, across 11 modules.
  First real matches this lane has produced. The reason keeps its denominator and its refusal: *"No match means the
  known families were not found, never that the firmware is implant-free."*
  **chipsec on the snakeoil VARS:** 1 volume, 1 EFI module, 1 NVRAM variable (`CustomMode`), and the posture degrades
  exactly as designed — *"SecureBoot was not among them, so the state is not something this decode can say — it is
  NOT a platform with Secure Boot off."* The honest-degradation branch, on real bytes, for the first time.
  _This is the "corpus is the binding constraint" thesis paying out immediately: one sample turned a lane that could
  only report its own limits into one that reports findings._
- ▢ **`detectTestKey` is STILL unexercised, and the snakeoil store is why it is not.** The variable store chosen
  precisely because it carries a test key surfaces only `CustomMode` to chipsec's offline decode — no PK, no KEK, no
  db — so `testKey` came back `null` and the detector has still never fired on real bytes. That is chipsec's
  extraction boundary rather than a defect here, and it means the test-key path needs either a vendor firmware dump
  with a readable auth store or a different extraction route. Impact: medium — it is the one UEFI branch that
  remains fixture-only now that the rest have real input.
- ✅ **Per-module FwHunt pass** (2026-07-28) — `scan-firmware` alone ran 17 of 108 rules on a real EDK2/OVMF build; scanning the 125 carved modules takes it to 106. `scan-module` is an alias of `scan` with no rules dir and no target/volume-GUID test, so the corpus enumeration and filtering live in the provider, and a module-only match is graded one step down because the pass ignores the volume scoping the rule's author set. _Two pre-existing defects fell out of the real bytes: the output parser dropped every verdict of the one rule that actually triggers (its `meta.name` carries spaces and parens), and the rule index keyed on filename while the scanner prints `meta.name` — different for 5 of 108 rules._
- ▢ **The 2 `target: bootloader` rules examine nothing in either pass.** The analyzer has `scan-bootloader`, but its input is an OS bootloader off an ESP (`bootmgfw.efi`, `grubx64.efi`), which FirmLab does not carve. Until it does, those rules are permanently inapplicable and the coverage note should keep saying so.
- ✅ **The module budget is spent alphabetically** (2026-07-28, `22a7961`) — three keys now sit ahead of the name. How many of the rules this pass is about to offer actually name the module (normalised to lowercase alphanumerics; labels under 5 chars are not tested at all, since `Dxe`/`Pei`/`Smm` occur across most of the corpus and would rank every driver first), then privilege — SMM → boot cores → PEIM → runtime DXE → drivers → applications — read from three independent signals (the FFS type chipsec stamps into the directory name, the extension the analyzer appends, the EDK2 naming convention). **When the signals disagree it takes the MOST privileged**: over-ranking costs one slot, under-ranking costs the highest-privilege code in the image its only look. No signal is `unclassified`, never promoted on a hunch. The corpus arrives as an optional input so the function stays pure. _A path tiebreak was added and is load-bearing: the same driver can appear under one label in two volumes, and that tie previously fell through to V8's stable sort — which is carve order, the exact artifact the function exists to avoid._
- ▢ **`CorpusRule` does not carry the rule's `description`, which is where modules are most often named.** The ranking above matches on `meta.name` and filename only, so `CVE-2023-45230` — whose description names `Dhcp6Dxe` while neither its name nor its filename does — contributes nothing. Reading one more `meta` scalar in `parseRuleMeta` would materially strengthen the strongest of the three keys. Separately, the corpus declares **volume** GUIDs and never file GUIDs, so `CarvedModule.guid` cannot be matched against it at all and the ranking is label-based by necessity. And `handle.log` still reports only counts for the pass — the persisted `skipReason` states the ordering, so nothing is hidden from the ledger, only from the live log.
- ▢ **chipsec's carve is thrown away.** `runChipsec` builds its work tree with `mkdtempSync` and `rmSync`s it in a `finally`, so the `<img>.dir` of extracted modules never survives the call and fwhunt re-carves its own (validated identical, ~1 s). Persisting it under `<dataDir>/extract/<imageId>/uefi/` and threading the path in as `modulesDir` would share one carve between the two providers.
- ▢ **fwhunt results stored before 2026-07-28 under-report** by the `RsbStuffingCheck` verdicts the old parser silently discarded. A re-run fixes any given image; nothing flags the stale ones.
- ✅ **`FIRMLAB_FWHUNT_MODULE_CAP` and `FIRMLAB_RESEARCH_CACHE_TTL_HOURS` are documented** (2026-07-28) — in a `DEPLOYMENT.md` table alongside the other thinly-documented ones (`FIRMLAB_ANGR_PYTHON`, `FIRMLAB_UEFI_IOC`, `NVD_API_KEY`…), plus the note that network-lane flags are DB-persisted since the Settings toggles landed, so an unset env var no longer means the lane is off.
- ▢ **New finding kind `uefi-fwhunt-module-match`** reaches the ledger — check whether the web UI maps finding kinds to labels and needs the addition.
- ✅ **chipsec Secure Boot / NVRAM posture** — offline NVRAM variable enumeration + SecureBoot/SetupMode/CustomMode reading + documented test-key detection (DO NOT TRUST / Snakeoil / AMI Test), all from `uefi decode`'s `nvram_*.nvram.lst`. Honest degradation: a state not among the extractable vars → `unknown`, never assumed secure. Validated in-container on real OVMF VARS (chipsec 1.13.16 surfaces only CustomMode from the OVMF auth-store, so the posture honestly reports the rest `unknown`; real vendor firmware extracts the full set). `providers/chipsec.ts` (`parseNvramVariables` / `interpretSecureBoot` / `detectTestKey` / `secureBootFindings`, unit-tested).
- ✅ **FwHunt integration** (2026-07-27) — `providers/fwhunt.ts` (pure `parseFwHuntOutput` / `buildFwHuntFindings` / `ruleCategory` / `indexRuleCorpus`, unit-tested) + `POST/GET /images/:id/fwhunt` + a `UEFI · FwHunt implant scan` step in W9's `uefi-bios` chain + a `fwhunt` tool entry. `Dockerfile.tools` gains **rizin built from source** (Debian bookworm has no package and upstream publishes a Linux binary for x86_64 only — this deployment is arm64, so source is the only route), **fwhunt-scan in its own venv** (`FIRMLAB_FWHUNT_PYTHON`; chipsec owns the system interpreter and runs against the SAME UEFI images, so sharing a dependency closure invites a clash), and the **binarly-io/FwHunt rule corpus** (`FIRMLAB_FWHUNT_RULES`, 108 rules incl. BlackLotus / CosmicStrand / LoJax / MoonBounce / MosaicRegressor / ESPecter). Last layer, fault-tolerant, like angr and bettercap. **Why this and not a GUID feed:** the families that matter have no stable public file-GUIDs, which is precisely why FwHunt rules match on code patterns (esil / hex strings / NVRAM usage); a hand-assembled list would have looked like intelligence and been fabrication. FirmLab therefore ships the scanner and the rules as DATA and authors neither — a match is attributed to the rule and its category, never restated as FirmLab's own verdict. **The honesty work is the denominator, not the numerator:** a rule only runs when the image carries the volume or module it is scoped to, and on real OVMF **27 of 108 rules ran**, so every scan emits a coverage finding carrying `rulesRun`/`rulesInCorpus`/`rulesNotApplicable`, a clean scan is titled *"which is not 'no implant'"*, an unparseable verdict is counted as unknown rather than folded into "nothing matched", and W9 marks the stage `degraded` when most of the corpus sat out. `--force` is passed so rules declaring no volume GUID run instead of being silently skipped. The parser was written against the analyzer's REAL output captured from a probe image — the first version was written against a guess and was wrong in every field. The existing `FIRMLAB_UEFI_IOC` GUID/name hook stays for operator-supplied IOCs. **Validated in-container end to end on real bytes (2026-07-27, deploy `98405ef`):** `.fd` added to `ALLOWED_EXT` (the standard UEFI volume extension was missing, i.e. the exact input this track exists for could not be uploaded), OVMF ingested → W0 classified it `uefi-bios` → W9 planned `chipsec → FwHunt` → the scan ran **17 of 108 rules, 0 matches**, and W9 marked the stage **degraded** with "91 rule(s) never applied to this image". **Two build/UX defects the real run exposed, both fixed:** (1) the tools layer shipped rizin present and fwhunt-scan ABSENT while reporting success — `rm -rf /tmp/rz` deleted the shell's own working directory and the pip that followed failed inside a cwd that no longer existed, which the trailing `|| echo` swallowed; the recipe now `cd /`s first, is split into two attributable layers, and asserts the analyzer file and rule count before declaring success. (2) coverage read "3 finding(s) across all 2 applicable stages" while its own table showed the degraded stage — the verdict now names degraded stages in every branch and stays `ambiguous`, the third instance of that same headline-absorbs-the-caveat shape. _Follow-up: `scan-module` against chipsec's already-carved modules (finer attribution than whole-image `scan-firmware`), and pinning the rule corpus to a ref instead of tracking `main` — **done**, `ARG FWHUNT_RULES_REF` pins `a2e3be6` so "17 of 108 rules ran" stays a reproducible statement between rebuilds._
- ▢ **LogoFAIL image-parser bug class** + SMM callout analysis (efiXplorer-class).
- ▢ **SPI protected-range / BIOS-lock posture.**

## Static analysis (FSTM 3–5)
- ✅ **Rootfs security audit** (firmwalker/FACT-class) — `providers/fsaudit.ts`: weak/empty/legacy creds, extra UID-0, init-spawned root shells / telnetd, permissive ssh/telnet/ftp, notable key material (hashes redacted).
- ✅ **Certificate analysis** — `providers/certs.ts`: embedded X.509 via Node crypto — expired, weak RSA, test/self-signed, embedded CA.
- ✅ **Component dependency map** — `providers/compmap.ts`: rootfs ELF → DT_NEEDED graph (rabin2; unresolved + orphans surfaced).
- ✅ **U-Boot / bootloader** — `providers/uboot.ts`: decode the env + audit posture (init=/bin/sh, interruptible autoboot, net-boot, serial console).

## Comparison / n-day
- ✅ **Function-level diff** (2026-07-27) — `providers/funcdiff.ts` (pure: `parseFunctions` / `isSyntheticName` / `matchFunctions` / `classifyDiff` / `formatRatio` / `buildFuncDiffFindings`, 18 unit tests) + `providers/funcdiff-run.ts` + `POST/GET /images/:id/funcdiff?against=<older>`. Pairs binaries across two extracted rootfs **by path**, hash-compares first (most of a rootfs is byte-identical between releases, and the identical count is itself the shape of the release), then fingerprints every function on both sides with radare2 `aflj` (size / nbbs / cc / ninstrs / edges) and matches: real symbol names first, then structural fingerprints for the stripped remainder. **Three honesty constraints drive the design.** (1) *A toolchain bump rewrites everything* — above `RECOMPILE_THRESHOLD` (40% of matched functions) the verdict is `recompiled` and the candidate list is **withheld**, because a 400-entry list has no localizing power and showing it with a caveat invites the reading the caveat forbids. (2) *Firmware is stripped* — `fcn.00400abc` encodes the ADDRESS and moves whenever anything earlier moves, so those are matched structurally and ONLY on a fingerprint unique to both sides; an ambiguous shape is reported `unmatchable`, never paired by guesswork. Writing the test caught the inverse bug: `sym.gone` was being paired with `sym.fresh` on shape, inventing a match their names contradict — the structural pass now only sees synthetic names. (3) *A changed function is a fact, not a fix* — `static_confirmed` on "these differ between the builds"; which one is the security patch is an inference the diff does not make. The per-run cap and the `recompiled` verdict both reach the ledger (`function-diff-truncated` / `function-diff-inconclusive`), because a truncated comparison must not read as complete and a rebuild must not read as "no change found". Changed functions are sorted **tightest delta first** — a bounds check is a couple of instructions, a rewrite is many.

  **Validated on real compiled bytes (2026-07-27, deploy `e29284c`)**, ground truth controlled: two static mipsel builds of one source differing in exactly one function (`set_name` gains a length check) → **`patched`, 1 of 873 matched functions, correctly `sym.set_name`, zero false positives** (+3 nbbs / +1 cc / +14 ninstrs — the shape of an added bounds check). The rebuild guard: the same source at `-O0` vs `-O3`, dynamically linked → **`recompiled`, 31/39 (79%), list withheld**, finding `function-diff-inconclusive`. A third run was instructive about the guard rather than the tool: `-O1` vs `-O2` *statically* linked moved only 4 of 873 functions and correctly did NOT trip the threshold — 869 of those are libc, identical regardless of the flag, so the two builds genuinely are 99.5% the same. That run also exposed a cosmetic-but-real defect now fixed and pinned: "4 of 873 (0%) changed" printed a percentage contradicting the count beside it, hence `formatRatio`'s `<1%`. _Follow-up: no version PAIR exists in the current corpus, so the real-firmware run is still open — the OTA learning surface (`capture/learning.ts`) already groups families and orders versions, so it is the natural source. **Decompiled-text diff shipped (2026-07-27)** — `providers/funcdiff-text.ts` (pure: `normalizeDecompiled` / `maskCommentAddresses` / `diffLines` [LCS] / `summarizeTextDiff` / `renderUnified`, 13 unit tests) + `withText` on the route. For a `patched` verdict only — on a `recompiled` binary the candidate list is withheld precisely because it means nothing, so decompiling from it would render noise at greater cost — it decompiles the tightest changed functions on both sides and emits a unified diff, attached to the finding that named the function. Honest capability ladder: `pdg` (r2ghidra, real C) when present, else stock radare2's `pdc` pseudo-C; **which one produced the text is carried in the result**, because two `pdc` renderings sit considerably further from source than two Ghidra outputs and the hunks should be weighted accordingly. Both are RECONSTRUCTIONS, and a diff of two of them carries decompiler noise, so `summarizeTextDiff` grades each and says plainly when widespread churn is likely register allocation rather than semantics. **Validated on the same controlled mipsel pair: the diff shows the added guard itself** — `t9 = [sym.strlen]` / `v0 = (unsigned) (v0 < 0x40)` / `if (v0) goto …` inserted before the `strcpy`, i.e. `strlen(in) < sizeof(buf)`. Three real defects the work exposed, all fixed and pinned: (1) `looksTargeted` used churn alone, so wrapping one call in a guard inside a 9-line function scored ~44% and was graded "widespread" — the textbook targeted fix called noise; a small ABSOLUTE edit is now targeted whatever the function's size. (2) `normalizeDecompiled('')` returned one blank line rather than none, adding a phantom `-` to every diff against an empty side. (3) inserting the guard shifted every later address, so radare2's XREF comments rewrote themselves on every line and buried the two lines that mattered — hex addresses are now masked **inside `//` comments only**, since an address in code is meaning (`0x40` IS `sizeof(buf)`) and only the digits are masked so a change in xref COUNT still shows._
- ▢ **Kernel module (.ko) CVE surface** — correlate kernel/modules to CVEs beyond userland SBOM.

## RTOS / bare-metal
- ✅ **RTOS blob analysis** — `providers/rtos.ts`: Cortex-M vector table, base-address recovery, flash/RAM memory map, RTOS-kernel detection. (Task enumeration = a deeper follow-up.)
- ▢ **Peripheral / MMIO fuzzing** (Fuzzware / µEmu / P2IM) — exercise the HAL, not just boot.
- ▢ **RTOS task enumeration** — walk pxCurrentTCB/thread lists (deeper than the current static blob analysis).

## Emulation UX
- ✅ **Full-system emulation claimed a boot from a timeout** (2026-07-28) — `proofState: 'confirmed_full_system'`, *"booted and stayed up"*, was returned whenever qemu had not exited in 120 s, on the strongest rung of the whole proof ladder. **Reproduced on real bytes**: the firmadyne mipsel kernel panics at 0.4 s with `VFS: Unable to mount root fs on unknown-block(0,0)` and then sits there — qemu stayed alive to the timeout, so the old code graded a panicked kernel `confirmed_full_system`. The runner now spawns rather than exec-to-completion so the run can be watched: `looksBooted` reads the markers a Linux kernel prints on the way up and treats a panic as evidence AGAINST, and `classifyFullSystem` orders the claims — an answered TCP port is strongest, a booted kernel with nothing listening is real but weaker and says so, a guest panic is `blocked_by_platform`, and a timeout with neither refuses the claim. Validated by feeding that captured panic through the classifier: `blocked_by_platform`, where the old code said `confirmed_full_system`.
- ✅ **One hardcoded port forward hid an entire remote surface** (2026-07-28) — `hostfwd=tcp::8080-:80` with the guest side fixed. `providers/portmap.ts` (PURE, 16 tests, parsers written against files pulled from the corpus) reads what the firmware itself declares: UCI `list listen_http`/`option Port '22'` including the IPv6 `[::]:80` form, lighttpd, boa, and the `-p` on a command line that servicemap discards. **Measured on real rootfs**: GL.iNet BE3600 → `22/ssh` (etc/config/dropbear), `80/http` and `443/https` (etc/config/uhttpd), each with its evidence line, now three forwards where one existed; WR940N and DVRF declare nothing and keep the 80 fallback, with the reason stating that an absence of config is not evidence nothing listens. A declared port that no booted service answers is logged as the gap it is.
- ✅ **servicemap returned ZERO network daemons on a real OpenWRT rootfs** (2026-07-28) — `parseRcScript` needs a start indicator and a daemon name on the same line, and a procd script has neither: it binds the binary to a shell variable and launches it from `start_service()`. The GL.iNet, demonstrably serving on 80 and 443, scored 0 — which reads as "this image starts nothing" and meant "this parser does not know this format". `parseProcdScript` resolves the variable and skips what it cannot resolve. **Measured: 0 → 65 services, 3 network daemons** (dnsmasq/53, dropbear/22, uhttpd/80).
- ✅ **qemu-system could never start in this deployment** (2026-07-28) — the args carried no `-nodefaults` and no explicit serial, so qemu instantiated its default VGA and died with `failed to find romfile "vgabios-cirrus.bin"` before executing one guest instruction. Nothing reported it, because the drive error masked it. Fixed with `-nodefaults -serial mon:stdio -append console=ttyS0`, which is also what makes the console readable — and the boot verdict is drawn from that stream.
- ✅ **Nothing assembled the raw disk image the full-system rung boots** (2026-07-28) — `providers/rootfs-image.ts`: `mkfs.ext2 -d` populates a filesystem from a directory WITHOUT root, so it works in an unprivileged container. Whole-disk ext2 booted as `root=/dev/sda` (no partition table, no loop devices), sized 2.5× the rootfs with a 32 MB floor, reused while newer than the rootfs, half-written output deleted on failure. It also stages `/firmadyne/libnvram.so`, which the firmadyne kernels preload into every process — without it the first real boot reached userspace and died on `/sbin/init: can't load library`. The caveat travels with every result: this is a REBUILT filesystem and an unprivileged extraction restores no device nodes, setuid bits or ownership.
- ✅ **THE FULL-SYSTEM RUNG BOOTS REAL FIRMWARE** (2026-07-28) — the TP-Link WR940N comes up under `qemu-system-mips`, its own init printing `exec_Cmd: OPEN ALL PHY ETH!!` and its HTTPS daemon loading a certificate and private key. Verdict `confirmed_full_system`, earned from the kernel's own `Freeing unused kernel memory` rather than from survival. **Four separate wrong assumptions were stacked on this rung, each hidden behind the one in front of it**, and only running it exposed them in order: no disk image existed; the kernel path was `vmlinux.${arch}.4` while firmadyne ships `vmlinux.mipseb.4`; `QEMU_SYSTEM_BY_ARCH` handed big-endian MIPS the little-endian emulator, which refuses a BE kernel outright; and `-device e1000` demanded an `efi-e1000.rom` the Debian packages do not ship.
- ✅ **A stray emulator answered the probe and earned a false `confirmed_full_system`** (2026-07-28) — the first run to reach the new classifier claimed a boot with the guest kernel still at `NR_IRQS:256`. Three things were true at once: `pkill` is not installed here, so `teardown()` caught the ENOENT in the same branch as "matched nothing" and logged *"Teardown complete (emulators killed)"* regardless — the module's first stated invariant has never held in this deployment while reporting that it did; the forward base was a fixed 8080, so a survivor from an earlier run owned the port being probed (the constant-port defect `dynprobe` already paid for, verbatim); and accepting a connection was read as a service answering, when qemu's user networking completes the host-side handshake before it knows whether the guest will take it. Host ports are asked of the OS per run, the probe sends a request and requires data back, and teardown says plainly when it could not sweep.
- ✅ **The console cap evicted the boot markers it classifies on** (2026-07-28) — capped with `slice(-CAP)`, keeping the tail, while a kernel prints its markers at the START. 262 KB of vendor chatter pushed `Freeing unused kernel memory` out of the window and a fully booted firmware was graded "no recognisable boot". Both ends kept now, elision stated in the text.
- ✅ **The port probe speaks the protocol each port actually uses** (2026-07-28) — it sent `HEAD / HTTP/1.0` at everything, so a live HTTPS service could never answer. HTTPS now gets a real TLS handshake with `rejectUnauthorized: false` (firmware ships self-signed certs by construction, and the question is whether something is SERVING, not whether it is trustworthy); a TLS-level failure COUNTS as an answer, since an alert or a version mismatch means a TLS implementation is on the other end and firmware stacks routinely fail modern handshakes — reading that as "no service" would discard the result on exactly the images most worth looking at. SSH and telnet are listened to rather than spoken at, because they greet the client and an HTTP request written into an SSH server can get the connection dropped before its banner arrives.
- ✅ **A loopback-only guest is diagnosed rather than left ambiguous** (2026-07-28) — `guestNetwork` reads the firmware's own network setup out of the boot log (the firmadyne kernels trace every execve). The real WR940N runs `ifconfig lo 127.0.0.1 up` and nothing else: its vendor init brings the LAN up through Atheros switch hardware that `-M malta` with an e1000 does not emulate, so **eth0 never gets an address and no forwarded port can answer however many daemons are listening**. The verdict now says that instead of offering "or they listen somewhere this run did not forward", which would send an operator hunting for a port that was never the problem.
- ✅ **Network inference, two-pass** (2026-07-29, `c958e91`) — boot once to learn, boot again to reach. **Pass one's premise was false and only measuring showed it:** the WR940N's 305 KB boot log contains `192.168` zero times while the guest ARPs as 192.168.0.1 throughout, because TP-Link's `/usr/bin/httpd` addresses `br0` by ioctl — no execve trace, no printk, not even firmadyne's own `__inet_insert_ifa` hook names it. So pass one also runs `-object filter-dump` and reads the guest's own frames; a qemu without that filter degrades to console-only and says which it used. Four inference outcomes, each stating what it assumed (console address · wire address with `/24` flagged as an ASSUMPTION · kernel `ip=` read back rather than presumed to have taken · nothing, with the evidence quoted). **No service became reachable — that is the honest result** — but the gap moved from "the guest has no network" to a located blocker per image: WR940N absorbs 157 SYNs with neither reply nor RST (dropped INSIDE the guest, which is not "no service"), WDR3600 and MR3220 return RSTs for every SYN so both stacks are reachable at L4 with nothing listening, and MR3220's `httpd` SEGVs at 1.6 s on `/proc/simple_config/system_mode`. DVRF panics → `blocked_by_platform`.
- ✅ **The emulated guest had outbound internet, and the workbench's headline claim said it should not** (2026-07-30, deploy `f969750`) — `-netdev user` gave the guest unrestricted egress unless `FIRMLAB_EMU_ISOLATE` was set, and that flag was opt-IN, so *"with every flag off: no network, no cost, deterministic behaviour"* was **false by default**: the WDR3600 reached **three public NTP servers** from a deployment with every lane switched off. **The condition the original note set for flipping it — whether any rung DEPENDS on outbound — was already answered in the database and nobody had read it.** Two full-system boots of the same WDR3600 image sixteen minutes apart, one open and one isolated, recorded the **same 15 external attempts and the same `confirmed_full_system` verdict**; across every recorded full-system boot, only that one image ever addressed anything external at all. Reproduced twice more today (`4910fc43-42b` isolated by override; `c0df50a3-e89` on the new build isolated **by default with no override at all**) — four boots, `ext=15` and `confirmed_full_system` in every one. **Isolation costs no rung anything, and the run confirms on real bytes what `egress.ts` had only asserted:** blocking the traffic does not hide the attempt, because `filter-dump` captures the frame before slirp decides its fate. The default is now a declared catalogue property (`defaultOn`) rather than an accident of `=== '1'`. _Three defects the change exposed, all fixed: (1) `resolveFlags` read `=== '1'` directly, which would have silently un-done the new default and shown the switch OFF in Settings while the emulator was in fact isolating; (2) `enabled` alone conflates "nobody asked" with "the operator asked" as soon as a flag may default on — `decideFlag` separates them, and the dangerous direction is the other one, since an open guest can now only happen because somebody opened it; (3) the suite pinned the OLD default with a passing assertion (`expect(f.enabled).toBe(false)` — "which is the permissive direction"), the fixture and the code written from the same assumption, exactly the trap this codebase has already paid for._
  _Deliberately NOT renamed to a `FIRMLAB_EMU_EGRESS` opt-in, which would have made the table exception-free: a real deployment had `FIRMLAB_EMU_ISOLATE=1` stored as an **override**, and renaming would have changed what that persisted row meant — the "a stored value is data written by an older build" trap, applied to settings rather than to results. The opt-out-among-opt-ins shape is therefore accepted and paid for in the prose, because the alternative was a false headline._
- ✅ **`open: []` was the same silence for five different problems** (2026-07-29) — the full-system rung reports
  which ports answered, that list is empty on every image in the corpus, and until now it was one word for five
  situations wanting five different responses. `providers/boot-diagnose.ts` (pure, 14 tests) reads the answer out
  of evidence already being captured and simply not read: the firmadyne kernels trace every `execve`, `open` and
  `exit`, and `parseGuestWire` already counts SYNs, SYN-ACKs and RSTs. **Measured, and the three real images give
  three different verdicts:**
  - **MR3220 → `service-died`.** `/usr/bin/httpd` opened `/proc/simple_config/system_mode` and exited **139**
    (128 + SIGSEGV) at 3.5 s. Nothing answered because the daemon is gone, and forwarding more ports cannot reach
    a process that already exited.
  - **WR940N → `guest-dropped`.** 158 SYNs in, **zero** back — no handshake and no refusal — while the same
    console prints `SSL_CTX_use_certificate_file success!` beside an `ebtables bug: Wrong len argument`. A closed
    port answers with a RST, so silence means the packets die inside the guest. **This is not "no service".**
  - **WDR3600 → `guest-dropped` (mixed).** 159 SYNs, **4** RSTs. The first version of the rule called that
    "nothing is bound" and threw away the 155 that vanished — caught by running the module against the real
    console, not by any of the synthetic cases, and now reported as a stack that refused a few and then started
    dropping.
  _It never touches `proofState`: `classifyFullSystem` owns the ladder, and a reason why nothing answered is not
  evidence that something did._
- ✅ **The blocker for the dynamic rung was NOT `planForwards` — and the thing it prescribed is now built**
  (2026-07-30, `6ad7423`). This entry refuted the obvious next fix for every image in the corpus and named what was
  actually needed: *"a boot-time intervention in the guest… which is what firmadyne/FirmAE's `preInit` does and what
  `rootfs-image.ts` is already positioned to stage"*, plus the condition that it be **a decision, not a task** —
  recorded, and qualifying the result. That is exactly what shipped: the repair runs the firmware's OWN
  `/etc/rc.d/iptables-stop`, is staged through the same hook as the libnvram shim, is armed only by
  `FIRMLAB_EMU_REPAIR`, and travels on every finding as an `intervention`. The WR940N went `open: []` → `open: [80,
  443]` against a freshly-rebuilt unrepaired control. Full account in *Emulation UX* above; what remains open is WHY
  it answered, since the repair's own markers never reported.- ✅ **The emulation rung was writing into the evidence, and its own comment said it was not** (2026-07-29) —
  `stageFirmadyneShim` copies `/firmadyne/libnvram.so` into the rootfs so `mkfs.ext2 -d` picks it up, and its
  header claimed it copied "into a COPY of the extraction, never into the extraction itself". It never did.
  **Seven extractions across the corpus were carrying a shim that is part of no firmware** — both TP-Link routers,
  the MR3220, DVRF, the GL.iNet carve and two IMOU trees — each verified byte-identical to a
  `/opt/libnvram/libnvram-<arch>.so` the container ships before being removed.
  Every other provider walks that same tree as evidence. Nothing had surfaced it yet only because the stored
  extraction results predate the first full-system boot; a re-run of `fsaudit`, `gitleaks` or the file browser
  after one would have listed a file this workbench put there as the firmware's. **This is the third instance of
  the same shape**: a comment that was true about an intention and never about the code.
  Fixed by removing the staged directory in a `finally` — the file only has to exist for the length of the `mkfs`
  call, and copying a whole rootfs per boot is the expensive answer to a cheap problem. _Its test is written
  against `unstageFirmadyneShim` directly, NOT through `ensureRootfsImage`: the suite runs on a host with no
  `mkfs.ext2`, so the round trip returns before staging anything and a green integration test would prove only
  that nothing happened — the guard-success-path trap, avoided by naming it._

- ✅ **The extractor neutered escaping symlinks to `/dev/null` silently, and every provider read an empty file as
  an absent one** (2026-07-30, deploy `92553de`). `unsquashfs` refuses to write a symlink whose target would leave
  the extraction root and substitutes `/dev/null`; the substituted entry is indistinguishable, through
  `readFileSync`, from a file the vendor shipped empty or never shipped. **126 such entries across six corpus
  images**, DVRF with `etc/{passwd,shadow,group,hosts,resolv.conf}` and the IMOU Ranger with 93.
  **CORRECTION to this entry as originally written: the account-file half was ALREADY solved and the entry did not
  know it.** `inspectAccountFile` detects `symlink-escapes` and `auditAccountSources` emits
  `account-db-redirected` / `static_confirmed` — verified on the real DVRF rootfs, which returns
  `{"state":"symlink-escapes","target":"/dev/null"}` for all four account files and produces the finding. What was
  actually open was everything else.
  **The fix is not a patch in each of a dozen readers.** `providers/extract-neutered.ts` (pure
  `classifyExtractedPath` / `stageImpact` / `neuteredFindings`, thin `scanNeutered`, 15 tests) records the fact
  where it is DISCOVERED — once, on the extraction result and as an `extract-integrity` finding — so any provider's
  later silence about one of those paths is already explained. The classifier judges a symlink on its TARGET before
  any size, because `statSync` on `etc/passwd -> /dev/null` returns 0 bytes and a reader that stops there has
  converted the extractor's refusal into a statement about the vendor's filesystem. `stageImpact` says which
  QUESTION went unasked rather than which path was cut.
  **What it refuses to claim:** the original target. The substitution discarded it, so a cut entry proves the
  firmware had something there and nothing about what — never "empty", never "missing", never a guess.
  Escaping symlinks get a separate finding precisely because their target survived and stays legible.
  **The ELF sweep now counts them**, separately from relocatable objects (those were passed over as out of scope;
  these were shipped and destroyed). On the real IMOU that reads **24 ELFs examined against 31 entries cut** — the
  extractor destroyed more paths than the sweep opened, and that number did not exist before. Nothing was deleted:
  the entries are the extractor's own record of its refusal.
- ▢ **`scanNeutered` surveys only the rootfs in use, not the sibling carve trees.** Surfaced 2026-07-30 while
  validating the above, not implemented. The IMOU has TWO `.extracted` trees and 93 cut paths between them; the
  stored extract points at `_IMOU-Ranger-2C.bin-0.extracted/squashfs-root`, which holds 31. The other ~62 are
  unsurveyed — and `auxsecrets` deliberately reads sibling partitions, so they are paths a provider does open.
  Impact: medium. The survey should take the extraction OUTPUT DIR, as `diagnoseNoRootfs` does, not the rootfs.
- ▢ **Every extract result stored before 2026-07-30 carries no `neuteredPaths`, and nothing flags the stale ones.**
  Verified: the IMOU's stored row reports the field absent, which correctly reads as "never surveyed" rather than
  "nothing was cut" — the optional-forever rule working. But it means the corpus reports no cut paths until each
  image is re-extracted, and no code path says which images are in that state. Same shape as the stale-fwhunt
  entry above. Impact: low, but it makes a corpus-wide count of the problem read as zero.
- ▢ **`fsaudit.readInside` still collapses missing, unreadable and escaping into `''`** for every path that is not
  one of the four account files — `etc/inittab` and the service configs among them. The rootfs-wide finding now
  explains the silence in general, which is the important half; the per-path distinction inside that provider is
  still a `''` that three different situations produce. Impact: low now that the fact is reported once, and it is
  the remaining instance of the pattern.
- ⚠ **RETRACTED 2026-07-30: the guest repair is wired and it did NOT make the WR940N answer.** The entry that stood
  here claimed the causal result, with a control, and it was wrong. What is still true: `guest-repair.ts` is wired,
  the line IS written into the booted image (dumped straight out of the ext2 with `debugfs`: `(ping -c 20 127.0.0.1
  …; echo FIRMLAB_RULES_BEGIN; iptables-save …; /etc/rc.d/iptables-stop …; echo FIRMLAB_FLUSHED) &` at the tail of
  `/etc/rc.d/rcS`), `rcS` is restored byte-for-byte afterwards, and the disposition travels on the result.
  **What is false is that it ran.** The firmadyne kernel traces every `execve`, and across the repaired boot there
  are **zero** traces of `ping`, `iptables-save` or `iptables-stop`, and none of the three markers. The last trace
  `rcS` emits is at kernel time 1.428 s: `do_execve[PID: 114 (rcS)]: argv: echo 75` — that is line 45 of 46. The
  appended line is line 47. It was never reached.
  **And the control settles it in the opposite direction.** The unrepaired boot's last `rcS` trace is
  `argv: echo 200` — line 46, one line FURTHER than the repaired boot got. Both started `httpd`. So the
  `open: [{80},{443}]` against the control's `open: []` cannot be the repair's effect, because the repair did not
  execute; the two boots differ in how far `rcS` got, in the direction opposite to what a working repair predicts.
  The honest reading is that the difference is nondeterminism in this rung, and `ruleset.ran: false` — which the
  entry reported and treated as a caveat — was the result telling the truth while the headline did not.
  _What made the wrong claim believable: a control was run, both images were freshly rebuilt, and the numbers were
  real. The step missing was asking whether the intervention EXECUTED, which the `execve` trace answers directly and
  which nothing checked. `ruleset.ran: false` was on the screen the whole time._
- ✅ **An image that cannot boot was cached as valid** (2026-07-30, `e67b503`) — found chasing the entry that
  stood here, and it is a bigger defect than the one it replaced. A disk image was a cache keyed on its mtime and the
  repair marker, recording neither the ARCHITECTURE it was built for nor whether the NVRAM shim went into it. Both
  are load-bearing: the firmadyne kernels preload `/firmadyne/libnvram.so` into every process, so an image without it
  kills init.
  **What it cost:** an `ensureRootfsImage` call made out of band with `mipseb` — an arch with no shim, where the
  shims are `arm`/`arm64`/`mips`/`mipsel` — logged its warning, built the image anyway and wrote the repair marker,
  so the image looked current and correctly-dispositioned. The next real boot reused it and panicked:
  `/sbin/init: can't load library '/firmadyne/libnvram.so'` → `Attempted to kill init`. **And the reuse path logged
  no shim line at all**, so the panicking boot's log contained no trace of the cause — the ABSENCE of a line was the
  evidence.
  A JSON stamp beside the image now records `arch` and `shimStaged`, written only after a successful mkfs, and reuse
  consults it BEFORE acting on the freshness verdict — a current, correctly-dispositioned image can still be
  unbootable. The reuse path now says what the image contains, and a build without the shim states its own
  unbootability in its `reason`. Three refusals, separately: **an absent stamp is not a bad image** (built before
  stamps existed, so nothing is known → rebuild rather than refuse or trust); arch mismatch; no shim.
  Validated on real bytes, both directions: a real WR940N boot hit the no-stamp branch (*"carries no build stamp, so
  what it was built for is unknown — not known to be wrong"*), staged the mips shim, and came back
  `confirmed_full_system` with no panic and `{"arch":"mips","shimStaged":true}` on disk; then the accident was
  reproduced deliberately — a `mipseb` build reported *"WITHOUT the NVRAM shim, so a boot will panic on init"* and
  stamped `shimStaged:false`, and the next `mips` boot refused it with *"built for mipseb and this boot is mips"*.
- ✅ **CORRECTED: the full-system rung IS reproducible on the WR940N — measured, n=5** (2026-07-30). The claim that
  stood here was wrong, and it was itself an n=3 inference. **Five consecutive boots of one build, repair off, are
  identical**: `confirmed_full_system` / `open: 0` / no panic, five times; console 262,193 bytes in all five; guest
  time 94.6–96.0 s. What the earlier three showed was one boot explained by the poisoned cache (a defect since fixed)
  and one that opened two ports — so the real anomaly is narrower and sharper than "the rung is unstable".
  **The remaining anomaly is a single boot, and the rule now refuses it.** The repair-on arm has exactly one usable
  boot (the other panicked from the cache defect), and it is the one that opened two ports. Run against the real
  record, `comparisonIsAttributable` returns *"At least one arm is not reproducible"* — which is the correct answer
  and the one that was missing when that boot was credited to the repair. The cheapest next measurement is five boots
  with the repair ON; until then the two-port observation stands as an unexplained single boot.
  **The rule is enforced in code** (`providers/boot-reproducibility.ts`, pure, 16 tests) and live: a real boot on the
  deployed build reports `kind: single`, `n: 1`, `incomparable: 20`, `supportsCausalClaim: false`.
- ✅ **The reproducibility verdict counted boots across BUILDS as repeats** (2026-07-30, `94e90dd`) — a defect in the
  module written hours earlier, found by running it on the real record rather than on fixtures. Over the WR940N's 17
  stored boots it reported `varies`; those 17 span the shim fix, the per-run port allocation, the measured-arch fix
  and the build stamp. **What varied was the codebase**, and a reader would have concluded the emulator is unstable
  from a record of it being repaired. Boots now carry `buildRev`, the verdict filters on it, and the excluded count is
  REPORTED — `single` beside 20 excluded boots is a different situation from `single` on a fresh image, and only one
  of them is fixed by booting again. A boot that recorded no build counts as incomparable, not as this one's.
- ▢ **Five boots with the repair ON is the next measurement, and it is cheap.** ~25 minutes, and it is what would
  settle whether the two-port boot was the repair or noise — bearing in mind the repair demonstrably never executes,
  so a stable two-port repair-on arm would mean the appended LINE changes the boot without running, which would be a
  more interesting finding than the one originally claimed. Impact: medium-high, and it is the last thing standing
  between this rung and a characterised error bar.- ▢ **`agent/session.ts:627` passes the rootfs DIRECTORY where `runFullSystem` wants the disk image.** Surfaced 2026-07-30 while threading the repair through the call sites, not fixed (out of this iteration's scope): `runFullSystem(arch, rootfsPath, 8080, h, rootfsPath)` hands the extraction directory as `rootfsImage`, so qemu is given `-drive file=<dir>` and the agent's full-system rung cannot ever have booted. The route path builds the image with `ensureRootfsImage` first; the agent path never does. Impact: medium — one of the two entry points to the highest rung is inert, and it also means the agent's boots carry no `repair` disposition.
- ▢ **`webprobe` needs a live target, not new logic.** `runWebProbe(baseUrl, …)` would take `http://127.0.0.1:<host port>` straight from `open[]`, but the rung tears the guest down before returning — driving it needs a hook that runs while pass two is still up, inside `bootOnce`'s probe loop. That is the last step between this rung and a dynamic answer.
- ▢ **`planForwards` forwards only declared ports plus an 80/443 floor.** On all four corpus images nothing is declared, so a service on 8080/22/23 is missed even now that two guests are reachable at layer 4. Worth widening now that reachability is no longer the blocker.
- ✅ **Service enumeration** — `providers/servicemap.ts`: statically map the network daemons the rootfs starts (inittab/inetd/SysV/systemd) = boot-time attack surface.
- ✅ **Saved emulation presets** — `routes/presets.ts` + `emulation_preset` store table + `PresetsPanel`: save/run/delete named emulation configs.
- ▢ **Interactive/introspectable emulation** — `run_command_in_emulation`, self-diagnostics (`diagnose_emulation_environment`) on a LIVE boot (service-enum above is static).

## Recon & acquisition
- ✅ **FCC-ID lookup** — `providers/fcc.ts`: extract FCC IDs + link to public filings (fccid.io + FCC OET). Schematics/changelog lookup still open.
- ◐ **Phase-6 Capture** — acquire firmware from a live device (OTA MITM), gated `FIRMLAB_CAPTURE` (`CAPTURE-DESIGN.md`).
  - ✅ **6.0 — discovery + backend detection + provenance schema.** `capture/backends.ts` (registry of 6 backends auto-detected like `tools.ts`: PATH/Linux-caps/USB/serial probes, honest `available/reason`), `providers/discover.ts` (pure arp-scan/nmap/avahi/OUI/subnet/type-guess parsers + a passive sweep runner that degrades honestly), non-image-scoped `capture_sessions`/`devices` tables + `capture_provenance` schema, `capture/scan.ts` fire-and-forget scan anchor, routes `GET /capture/{status,backends,devices}` + `POST /capture/discover` (flag + per-scan operator ack) + `GET /capture/discover/:scanId`, a top-level **Capture** web section (backend table + honest transport ceiling + device radar). Discovery is passive — nothing intercepted. Dockerfile.tools gains nmap/arp-scan/iproute2/avahi-utils. Validated end-to-end (backends probe honestly; ack/flag gates 400; a scan with no sweep tool degrades to a session `error` with zero fabricated devices). Gate: core 73 + api 396 + web 29.
  - ✅ **6.1 — network capture (proxy) + firmware-aware carving + auto-ingest.** `providers/flowscore.ts` (pure: scores each intercepted response 0..100 via core signatures + entropy + content-type + size + URL heuristics), `capture/proxy.ts` (mitmdump on-path with an embedded addon → manifest + saved bodies; FirmLab scores + carves; `capture_flows` table), `capture/ingest.ts` (carved blob → the exact upload intake → an `images` row + a `capture_provenance` row), `capture/flow-manifest.ts` (pure JSONL parser). Routes `POST /capture/session` (flag + ack) + `GET /capture/session/:id` (scored flow feed) + `POST …/ingest` + `POST …/teardown` (time-boxed, guaranteed). Web: per-device Capture button + scored flow feed + one-click ingest. Dockerfile.tools adds mitmproxy. Validated end-to-end vs the real API (synthetic SquashFS OTA → score 100 → carved → ingested → analyzed image + provenance; HTML → 0, rejected). Live mitmdump-over-positioned-proxy validated on the deploy. Gate: core 73 + api 405 + web 31.
  - ✅ **6.2 — active on-path (spoof) + LAN capture agent.** `capture/spoof.ts` (ARP-spoof one target via bettercap; pure `buildBettercapArgs`; availability = the on-path-spoof backend probe; composed into the capture session's positioning choice gateway/spoof/manual with guaranteed ARP restore on teardown). LAN agent (the Docker answer, design §5c): `capture/agent.ts` + token-authed `POST /capture/agent/{session,flow}` (remote agent streams carved flows → scored by the same flowscore → ingestable by the same path), `apps/api/scripts/capture-agent.mjs` reference agent (mitmproxy + bettercap on a LAN box, streams over the token channel). Off unless `FIRMLAB_CAPTURE_AGENT_TOKEN` set; base64 body ⇒ 8 MB cap (raw/chunked streaming is a follow-up). Validated vs the real API (agent session → streamed SquashFS OTA scored 100 → carved → ingested; tokenless → 401; positioning → honest `manual`). Gate: core 73 + api 408 + web 31.
    - ✅ **Spoof made real, and honestly bounded** (2026-07-27) — the leg above shipped against a toolchain that never carried `bettercap` (0 matches in `Dockerfile.tools`), so it had been reporting itself absent since the day it was written: a documented capability that did not exist in any deploy. `bettercap` now ships (last layer, so it cannot invalidate the multi-GB tool builds). Installing it alone would have created the opposite problem — the probe checked binary + caps only, so a bridge-networked container with `cap_add` would have claimed a spoof that reaches nothing. New pure `assessL2Reach` + `looksLikeHostNetns` gate the backend on **layer-2 reach first**: ARP poisoning must answer for the gateway on the target's own segment, and a container on a Docker bridge is on a private NATed subnet whose ARP frames never leave it. A bridge deployment is now told the spoof is *impossible here* and pointed at `--network host` or the LAN agent, instead of at a `--cap-add` that cannot help. **Spoof is host-only by design**; the Traefik-fronted deploy is bridge-networked on purpose (host networking would break the routing and the tinyauth/CrowdSec gate with it), so its answer stays the LAN agent — which is why §5c exists. Recorded in CAPTURE-DESIGN §5b + the backend table. **Validated on the real deploy both ways**, which is what caught the second over-claim: the bridge deploy reports the spoof impossible with `bettercap: true` in the detail (so it is visibly the SEGMENT, not the tool), while `--network host --cap-add=NET_ADMIN --cap-add=NET_RAW` first reported `available: true` — wrongly, because this host is OrbStack and `--network host` shares the *Linux VM's* namespace (docker0 + veth pairs, indistinguishable from a real Docker host) while still sitting one NAT behind macOS. `looksLikeVmBackedRuntime` (OrbStack / Docker Desktop LinuxKit / Lima / WSL2, off `/proc/version`) now catches that, and the remedy string is chosen by *why* the segment is out of reach — a VM-backed host is never told to try `--network host`, since that is not a fix at any layer there.
  - ✅ **6.3 — capturability ladder + preflight + pinning + Frida unpin.** `capture/preflight.ts` (pure, unit-tested: ranks viable strategies cheapest-and-most-complete-first + states the honest acquisition ceiling captured_plaintext/metadata_only/blocked_by_pinning/blocked_needs_hardware + unlock hint; `realizedCeiling` from a session's actual flows so pinning is observed, not guessed — the proxy addon logs a `tls-pinned` flow when a client refuses the CA). `capture/frida.ts` universal Android TLS-unpin Frida template at `GET /capture/frida-unpin`; `GET /capture/preflight/:deviceId` card; session GET returns the realized ceiling. Web: per-device Preflight ladder + pinned-session Frida download. Validated vs the real API (metadata_only + "Install mitmproxy" honestly on a bare host; Frida template downloads, 3 hooks). Gate: core 73 + api 417 + web 32.
  - ✅ **6.4 — BLE backend (Nordic-style DFU reassembly).** `capture/dfu.ts` (pure, unit-tested: `reassembleDfu` concatenates the ordered DATA-characteristic writes back into the image; `parseDfuInitSize` sanity trailer), `capture/ble.ts` (`createBleSession` + `stageBleDfu` → a carved `ble-gatt` flow, always carved since a DFU transfer is firmware by construction, ingestable by the normal path). Routes `POST /capture/ble/{session,dfu}` (base64 DATA-write chunks). Reassembling a provided capture needs no dongle (validates anywhere); the live nRF52840 sniff → DATA-write adapter is deploy/hardware-validated. Validated vs the real API (60 KB SquashFS split into 20-byte writes → byte-exact reassembly → carved → ingested).
  - ✅ **6.5 — Zigbee backend (OTA Upgrade cluster 0x0019).** `capture/zigbee-ota.ts` (pure, unit-tested: `reassembleOtaBlocks` + `parseZigbeeOtaHeader` [magic 0x0BEEF11E → mfr/imageType/fileVersion] + `extractOtaImage` unwraps the tag-0x0000 upgrade-image sub-element to the actual firmware) + `capture/zigbee.ts` (`createZigbeeSession` + `stageZigbeeOta` → a carved `zigbee-ota` flow, ingestable by the normal path; rejects a non-OTA stream honestly). Routes `POST /capture/zigbee/{session,ota}` (base64 Image-Block chunks). Reassembly needs no dongle; the live CC2531/ConBee sniff is the radio adapter (deploy). Validated vs the real API (synthetic OTA wrapping a 40 KB SquashFS → reassembled → header parsed → unwrapped to the exact inner firmware → carved → ingested; non-OTA → 400). Gate: core 73 + api 433 + web 33.
  - ✅ **6.6 — learning surface.** `capture/learning.ts` (pure, unit-tested: `buildLearningSurface` over enriched `capture_provenance` → per-family OTA timeline, per-vendor priors [plaintext-http/https/mixed/ble-gatt + CDNs], CDN→families graph; `hostOf`/`familyKey`). `listCaptureProvenance` store helper; `GET /capture/families`; web "OTA learning" panel (families + timelines + priors + "diff prev" link). Validated vs the real API (two versions from one CDN → one family, both ordered, + the CDN edge). Gate: core 73 + api 428 + web 33.
- ▢ **Live-device UART bridge** — host-side serial → containerized backend (wairz UART bridge). Software foothold into hardware.
- ▢ **A Flipper Zero tab — the physical acquisition axis Phase 6 does not have.** Every capture backend that shipped acquires *over the air or over the wire* (proxy/MITM, BLE DFU, Zigbee OTA); each one needs the device to consent to transmitting its own firmware. The Flipper reads it off the silicon instead — SPI NOR 25-series (`spi_mem_manager`), I2C EEPROM 24Cxx (`24cxxprog`), ARM SWD (`swd_probe`) — which is the one axis where `capture/preflight.ts`'s `blocked_needs_hardware` ceiling is *terminal today*: the ladder names the obstacle and stops. A Flipper backend turns that rung into a named tool with a stated cost (a SOIC-8 clip) rather than the place the ladder ends. **The provenance argument is the stronger one**: a chip-off dump is first-party evidence with a physical chain of custody, an evidentiary standard the `capture_provenance` schema currently has no kind for — it is not a vendor URL and it is not a synthetic upload, and collapsing it into either loses exactly what makes it worth more. Second rung, cheaper to reach: `dap_link` makes the Flipper a CMSIS-DAP probe, so **`gdb` — already a provider — points at real silicon instead of QEMU**, giving `dynprobe` a hardware target for the cases where the emulation ladder cannot get a guest to boot. That is a new answer to an existing question, not a new question. **The open problem is transport, and it is not the radio.** Firmware moves off the Flipper over its serial CLI (`storage read` / `write_chunk`), and at the deliberately conservative pacing used to install apps by hand that settles around ~10 KB/s — fine for a 64 KB EEPROM, roughly a quarter of an hour for an 8 MB SPI flash, and that is a self-imposed send rate rather than a measured ceiling of the CDC link, so it is worth benchmarking before designing around it. The honest first cut is probably not streaming at all: let the Flipper dump to its own microSD and ingest the card directly, with the serial path reserved for small targets and for driving the probe. Either way the ingest itself is solved — it lands in the same intake as every other carved blob.

- ◐ **Two CVE sources with different evidentiary standards, on the same image.** IMOU's ledger carries `CVE-2016-2148 — busybox 1.18.4` from `sbom` (grype, via a manifest syft could read) while the curated `compcve` table declines that exact CVE for the exact reason recorded above — NVD gives it no enumerated CPE. No contradiction is visible to the operator (each row names its source) and the broader net is arguably right when a manifest exists, but the two standards should be a deliberate, written policy rather than an accident of which provider ran.

## External intelligence
- ✅ **The fingerprinted components reach the CVE machinery** (2026-07-27, deploy `c6930b5`) — was the highest-value wiring left in W2, and it was wiring, not new analysis. `research/run.ts` builds its OSV and NVD candidate sets from the SBOM job's `packages` alone, i.e. from what syft found in a package manifest. The WR940N catalogues **1 package**, so the components this workbench fingerprinted straight out of the bytes — `pppd 2.4.3`, `busybox 1.01`, `dropbear 2012.55` — are never queried against NVD, whose own module doc says it exists precisely to reach "components OSV can't map (busybox, dropbear, the kernel, vendor daemons)". Two sources that were built for each other, not connected. `runComponentCve`'s `ComponentHit[]` now join `nvdCandidates`; measured on the WR940N that takes the NVD queue from 1 name to 4. The care went into the ledger, since this changes what leaves the machine: `mergeNvdCandidates` is pure and de-duplicates BEFORE the ledger is built (a promise computed from a list that `queryNvdBatch` quietly shortens afterwards is not a promise), and the NVD line declares the split between manifest names and fingerprinted ones. **Still gated behind `FIRMLAB_RESEARCH`, which is unset on the deployment — turning the network on is an operator decision, not a code one.**
- ▢ **lighttpd / goahead: looked for, not found.** Both were on the W2 list, and the two cameras that were the likely goahead carriers were extracted specifically to ground a pattern: **neither ships one**. The Tenda tree has no web server at all and the IMOU's only hit was `usr/config/board.ini` matching a `*boa*` glob. Nothing in the corpus carries lighttpd either (WR940N and DVRF ship a vendor `httpd`, GL.iNet ships uhttpd). So the item stays open for the honest reason — no bytes to write the rule against — rather than for want of looking. BeanView is the remaining untried carrier and currently extracts to nothing (below).
- ✅ **The three empty extractions are diagnosed** (2026-07-27, deploy `a136c6e`) — `providers/extract-diagnose.ts`. They were three different situations behind one `rootfsPath: null`, and two of them are damaged input rather than a tool gap: **Asus-Router** carves a coherent SquashFS (581 inodes, LZMA, `bytes_used` exactly the carved length) whose id table at 2536098 lands inside 512 bytes of trailing zeros — re-carving from the original at binwalk's offset changes nothing, and unsquashfs/sasquatch both answer "File system corruption detected", which reads as a missing extractor and is not. **AliExpress-Repeater**'s kernel LZMA decompresses 384 KB of a declared 7.6 MB and stops. **BeanView-Camera** is not empty at all: 54 volumes, 666 files of camera data partitions, a `private_key.pem` among them. _Two defects the feature hit on its own first real run, both fixed: it told AliExpress "nothing was extracted" while a 3.8 MB LZMA blob sat on disk, and it accused the extractor of failing on 29 `.jffs2` blobs whose volumes had come out fine._
- ❌ **~~BeanView's `private_key.pem` is extracted and unanalysed~~ — withdrawn, the item was wrong twice over.** Written from a filename without opening the file, which is the precise failure this workbench exists to prevent, and `auxsecrets.ts`'s own header had already recorded the answer: the file begins `-----BEGIN PUBLIC KEY-----`, openssl reads it as a 2048-bit public key and refuses it as a private one. It is the same overstatement the autonomous pass made in §7, and the provider declining to flag it is the guard working. The wiring was not broken either: the plan marks the worker `needsRootfs: false` and `extractRun` sets `outputDir` before it ever checks for a rootfs, so the sweep does run on a rootfs-less image — executed by hand over BeanView it scans **178 key-ish files across the carved partitions and finds 0 embedded private keys**. Nothing to fix; the finding never existed.
- ✅ **Second-pass recovery for the blobs binwalk leaves** (2026-07-27, deploy `96af0cf`) — `providers/extract-recover.ts` + `lzop` in the tools base. Dispatches on MAGIC, not extension, because binwalk's `.7z` is a raw LZMA stream rather than 7-Zip. Measured on the corpus: BeanView's `4F0010.lzo` is **partial at 225460 bytes** ("ignoring trailing garbage"), AliExpress's `50040.7z` is **partial at 511555 bytes** of a declared 7660784 with unlzma's own "Compressed data is corrupt", and `persondet_230511_v200.lzma` opens fully to 1305600 bytes and is not a filesystem. **None of the three images is rescued, and that was known before the code was written** — the gain is that "unexamined" became "examined, truncated or damaged, and not a missing tool". _One defect the real run exposed: on the stdout path (`unlzma -c`) a failed decompression's partial bytes live on the rejected process's stdout and were being discarded, so AliExpress read as "could not open it" — pointing at the tool — instead of "stopped at 511 KB", pointing at the image. Fixed with the same rescue dynprobe-run.ts does on gdb's output._
- ✅ **Concurrent dynamic probes collided on a fixed port** (2026-07-28, deploy `26b00a4`) — `BASE_PORT = 14500` was justified by "one probe runs at a time per job anyway", true per job and false once W9 schedules reproductions in two scans at once, which the runner does at its default concurrency of 2. **Reproduced deliberately**: two probes launched together, the first returns a verdict and the second reports "gdb produced no output" even with DVRF's `stack_bof_01` as its target. Sequential probes were fine, which is why the scan logs made it look per-binary. The blocked probe was the *good* outcome — the same constant also allowed gdb to attach to the other probe's stub and return a verdict about a different binary. Each probe now takes a free port from the OS. _One defect the fix itself introduced and the same test caught: the new readiness check connected to the stub to prove it was live, and a qemu gdbstub accepts exactly ONE client — the check consumed it, and BOTH concurrent probes then failed. Readiness is tested by trying to bind the port instead (EADDRINUSE = the stub has it); nothing connects to the stub except gdb._ Validated concurrently: `pktlogconf` → `sink_executed`, `stack_bof_01` → `crash_input_controlled` at offset 204, in the same pair of simultaneous jobs.
- ✅ **`sink_executed` now earns its claim from the observed argument** (2026-07-28) — the verdict asserted the call site "really does run with attacker-supplied data" while WDR3600's own evidence recorded the copied string as `/proc/sys/ath_pktlog/system/enable`, a constant. `argumentCarriesInput` decides it from the bytes. _The existing test caught the first version collapsing a third state: when no argument was readable at the breakpoint, "we did not read it" is not "it was not our input", and reporting the latter is the same overclaim pointing the other way. Tri-state now — our bytes, a constant, or unknown — each with its own wording, title and severity (`low` only for the constant case)._
- ✅ **A recovered rootfs is not a fully-opened image, and now says how much it is not** (2026-07-28, deploy
  `47ce86c`) — the second-pass recovery runs only when NO rootfs was found, so an image yielding a small rootfs
  beside multi-MB unopened payloads reported the rootfs and said nothing about the rest. New pure
  `surveyUnopenedPayloads` in `extract-recover.ts` reads sizes and magic only — it **surveys, never decompresses**,
  because the corpus already established those particular blobs are a kernel and two corrupt streams rather than a
  hidden rootfs, and the gap was that nothing STATED the unopened bytes. Wired into `finalizeRootfs`, so it reaches
  the success path where the silence was. **Measured on the deploy: the Tenda camera's 97-file rootfs sits beside
  49 payloads totalling 54.1 MB, two of them 15.7 MB `.xz`; the IMOU's 113-file rootfs beside 4 payloads and
  24.2 MB.** _One defect the real bytes exposed and the first version had: excluding only the CURRENT `rootfsPath`
  counted a PREVIOUS extraction run's entire tree as unopened payload — a re-extraction leaves `_img.extracted`
  beside the live `_img-0.extracted`, and IMOU reported `_IMOU-Ranger-2C.bin.extracted/squashfs-root/usr/lib/
  modules.7z` while its live rootfs was in the `-0` sibling. The exclusion now follows what a directory IS, by the
  same >=2-of-`bin`/`etc`/`sbin`/`lib` rule `findRootfs` uses, rather than what this run happened to name; IMOU went
  8 payloads/25.7 MB → 4/24.2 MB._
- ◐ **The camera rootfs are suspiciously small** — Tenda 97 files, IMOU 113, both with a complete-looking top level (`bin`, `etc`, `lib`, `sbin`, `usr`). Plausible for a minimal camera build and equally plausible as a partial carve; nothing here settles it, and an IP camera with no web server on disk is the part that does not fit. Worth resolving before either image is used as evidence about what cameras contain.
- ▢ **CVE-2021-36369 for the Tenda camera's dropbear 2020.81** — the range (`<= 2020.81`) covers it exactly, and it was rejected for the same reason as CVE-2016-2148: zero enumerated CPEs, one open-below range. Recorded so the rejection is visible as a decision rather than an oversight, and so it can be revisited if a per-version source turns up.
- ▢ **A per-version-backed critical for old BusyBox.** CVE-2016-2148 (udhcpc heap overflow, CRITICAL, "before 1.25.0") would match both builds in the corpus and was deliberately left out: NVD gives it zero enumerated CPEs and one range with no lower bound, the same shape refused for dnsmasq 1.10. CVE-2011-2716 covers the same images and IS backed per-version (90 enumerated CPEs, `1.01` and `1.7.2` among them), so nothing is lost in coverage — only in severity. Claiming 2148 honestly needs a source that asserts per-version (a distro advisory) or source archaeology for when the vulnerable udhcpc code appeared.
- ✅ **`parseVersion` collapsed zero-padded components** (2026-07-28, `ed83fab`) — BusyBox `1.01` parsed to `[1, 1]` and compared equal to `1.1`, because each dotted field was `parseInt`-ed. Two releases a year apart (1.01 shipped 2005, 1.1 in 2006) and the WR940N in this corpus ships exactly `1.01`, so the collapse was live rather than theoretical; it was harmless only because no range boundary happened to fall between the two.
- ✅ **NVD was being asked the wrong question** (2026-07-28, deploy `8ef0453`) — `buildNvdQuery` used `keywordSearch=<name> <version>`, which matches CVE DESCRIPTIONS, and a description names the release that FIXED the bug ("Dropbear SSH before 2016.74"), never the vulnerable one somebody shipped. Asking for the version in hand was close to unanswerable: `keywordSearch=dropbear 2012.55` → **0 results** against the live API. A mapped component now asks by `virtualMatchString` against NVD's own CPE product identity, the field that encodes affected version RANGES. **The map is curated and MEASURED, not derived** — deriving it is impossible: `pppd` returns ZERO entries from the CPE dictionary (the daemon's binary name is not its product identity; the mapping was read off the CPEs attached to CVE-2020-8597, the pppd CVE the curated table already claims), and several components carry competing identities — dropbear also exists as `matt_johnston:dropbear_ssh_server` (40 dictionary entries) and `dropbear_project:dropbear` (28), openssl as `openssl_project:openssl` (89) — of which, at the versions this corpus ships, **each alternate returned 0**. Those are recorded in the code as measured-empty rather than dropped, so "we chose one of three" stays visible. Unmapped components keep the keyword query (a weak question beats an invented vendor string) and every result carries `matchedBy`, with the batch reporting the split — because an empty CPE answer means the version is in no affected range, while an empty keyword answer means almost nothing, and without the label a keyword-only run that found nothing reads as a clean bill of health. **Validated end to end on real bytes**: the WR940N went from **0 advisories to 37** — dropbear 2012.55 → 15, busybox 1.01 → 17, pppd 2.4.3 → 5, each matching the count measured directly against the API before the code was written, and the returned descriptions state the diagnosis themselves ("BusyBox *before 1.20.0*"). IMOU: busybox 1.18.4 → 20. _Three follow-ups below._
- ✅ **The NVD cap truncated by ARRIVAL ORDER, so the CPE fix bought nothing on a real rootfs** (2026-07-28, deploy `2800fa6`) — running syft on the GL.iNet BE3600 for the first time produced **500 packages**, of which 72 reach NVD (66 kernel modules + `binary` + the fingerprinted three). `queryNvdBatch` took `unique.slice(0, cap)`, and syft lists alphabetically, so the entire anonymous budget of 6 went to `act_connmark`/`act_csum`/`act_gact`… — kernel modules syft versions with the literal string `UNKNOWN` — while `dnsmasq 2.92`, `pppd 2.4.9` and `openssl 3.0.13`, the three carrying a curated CPE identity AND a real version, were never asked anything. **0 asked by CPE, 6 by keyword, 0 advisories.** This is the defect `selectFindings` was written for in `binvuln.ts`, unapplied here: a bound must not make its own result an artifact of scan order. Candidates are now ranked by answerability before the cap (`cpe-versioned` → `cpe-unversioned` → `keyword-versioned` → `keyword-unversioned`, stable within a tier), `UNKNOWN` is treated as the absence of a version rather than as one, and `notQueriedRule` names the tiers dropped — because dropping 66 unversioned module names is a bound working as designed while dropping one `cpe-versioned` component is the budget being too small, and the same count means opposite things. **Measured: 0 → 29 advisories on the same image.**
- ✅ **The keyword fallback is validated on real bytes** (2026-07-28) — it had never executed: every NVD candidate in the corpus resolved to a mapped component until the GL.iNet's SBOM landed. That run asked 2 by keyword (`curl 8.6.0`, `ffmpeg 6.1.2`) and both returned nothing, which is what motivated mapping them.
- ✅ **The CPE map reaches beyond the fingerprint table's five** (2026-07-28, deploy `dcff56c`) — the GL.iNet's `keyword-versioned` tier was exactly `curl 8.6.0` and `ffmpeg 6.1.2`, both real products with real CVEs asked a question that cannot answer. Measured and added: `haxx:curl` → 35 at 8.6.0, `ffmpeg:ffmpeg` → 18 at 6.1.2. **curl is the sharpest argument for curating this table by hand: the obvious `curl:curl` returns 0.** A guessed vendor string does not fail loudly — it queries a product that does not exist and returns nothing, which reads exactly like "no CVEs". **Measured: 29 → 67.** _Anything the SBOM surfaces beyond these seven still gets the keyword question; extending means measuring each addition against the live API, never guessing one._
- ✅ **A page of advisories was being presented as the set** (2026-07-28, deploy `904ee7f`) — three silent bounds on one list and none of them said so: the request asked `resultsPerPage=20`, `parseNvdResponse` independently sliced at 50, and the panel rendered `slice(0, 8)` with no indicator. Only the middle was visible in code and the tightest was invisible. Measured: curl 8.6.0 matches **35** CVEs and openssl 3.0.13 matches **26**, while the panel showed 20 of each and 8 of those — **21 advisories discarded before anyone could count them**, with the row reading as complete. Request page and parser slice are one constant now, whatever it still cuts is reported against NVD's own `totalResults` (which the response always carried and the parser threw away), and `totalMatching` is null rather than 0 when the field is absent because "we did not read it" is not "there are none". **Measured: 67 → 88, and every component now equals NVD's own count.**
- ◐ **A component can live under a CPE identity the map does not carry.** The alternates are DATA now, not a comment, and an empty CPE answer names them (`uncheckedIdentities`) instead of presenting the zero as settled — dropbear returning nothing under `dropbear_ssh_project` is a different claim from dropbear having no CVEs in NVD. Still open: actually QUERYING them. Each costs a slot against an anonymous budget of six, and the ranking work above established what that budget is worth, so it needs a policy (probably: only when an `NVD_API_KEY` lifts the cap to 40). Not yet observed on real bytes either — the one empty CPE answer in the corpus is `pppd 2.4.9`, which has a single known identity.
- ▢ **Vendor-PSIRT / CNA sources** — no single free API; per-vendor adapters.
- ▢ **Hardened egress** — proxy / slirp4netns for the research allowlist.
- ✅ **Corpus OSV/NVD/KEV cache** (2026-07-28) — `research/cache.ts`, read-through, on-disk under the data root, keyed on the QUESTION (request body/URL) not the image, so every image asking about BusyBox 1.01 asks once. TTL `FIRMLAB_RESEARCH_CACHE_TTL_HOURS` (default 24). A stale entry is re-queried rather than served, a failed lookup is never stored (a cached 429 would become a durable "no CVEs"), and the RAW payload is cached rather than our parse of it so a later parser fix applies to old answers. NVD's 6.5 s courtesy delay is no longer paid for a request that does not go out. _It also made the egress ledger untrue — declared before any request, while a cache hit contacts nobody — so the ledger now states a ceiling and the run reconciles it afterwards._
- ✅ **The advisory cache never evicts** (2026-07-28, `4691583`) — `FIRMLAB_MAX_RESEARCH_CACHE_BYTES` and `FIRMLAB_MAX_RESEARCH_CACHE_AGE_DAYS`, both unset by default, so behaviour is unchanged until an operator asks. It is a **disk-pressure release valve, not expiry** — past-TTL entries stay unless a cap is set, because the record is the reproducibility half. A malformed value turns the cap OFF rather than defaulting, the inverse of the TTL rule beside it and deliberately so: guessing a TTL costs a re-query, guessing a deletion threshold costs the record. `planCacheEviction` is pure and lives in `research/cache.ts` because `retention.ts` imports `store.js` and a sweep written there could not have been unit-tested at all. Oldest-first with a path tiebreak so the evicted set is never a readdir artifact; an entry stamped in the future is never age-evicted (an age we cannot state is not a decision); the walk is bounded and reports `truncated` instead of passing a partial total off as the whole; a failed deletion is reported, not counted as removed. Called before `sweepRetention`'s early return, since the two limit sets are independent.
- ▢ **`GET /storage` does not report what the research cache costs.** `sweepResearchCache` already returns `totalBytes`/`entryCount` ready for it, but wiring them touches `routes/storage.ts` and the web types. Until then the UI cannot show the size of the one directory that grows without an image behind it. Separately, `*.tmp` files left by a process killed mid-write are swept by nothing — deliberately excluded from eviction so a live write is never broken, bounded and small, but nobody owns them.
- ▢ **`FIRMLAB_RESEARCH_CACHE_DIR` override** — pinning a corpus snapshot to a specific directory (for reproducing a scan months later, or shipping the evidence with a report) was skipped to keep the env surface small. Cheap if it turns out to be wanted.

## Source hygiene
- ✅ **English and Spanish across the shell and the generated documents** (2026-07-29) — a Settings control switches the workbench instantly and per device, and the HTML report and disclosure draft take `?lang=en|es`, defaulting to English. **The catalogue is typed, not string-keyed**: each Spanish namespace declares itself as `Messages['<ns>']`, so an untranslated key is a COMPILE error in the file that owns it rather than a runtime fallback that ships looking finished — verified by deleting one and watching tsc name it. Messages that interpolate are FUNCTIONS, because Spanish agrees in gender and number where English does not and a placeholder scheme forces both through English's grammar. A runtime test covers the hole types cannot: a Spanish value present but still holding the English string. **Proof-state codes are never translated** — they cross the API into SQLite, so only the gloss moves, and a test pins the Spanish for `blocked_by_*` to keep saying *NO es un resultado negativo*. Findings keep the wording the provider recorded; section ids stay English because they are route segments.
- ▢ **Interface prose the API composes still renders English in a Spanish UI.** Distinct from findings, and the distinction matters: a finding's title is a recorded measurement and correctly stays as written, but a lane flag's `effect`/`egress` sentences, `ToolStatus.unlocks` on Capabilities, `coverage.verdict`, a capture preflight `reason` and an agent `goal` are **interface copy** that merely happens to be built server-side. They sit beside fully Spanish chrome and read as an oversight. The API now has its own typed catalogue (`apps/api/src/i18n/`) built for the report, so the machinery exists; what is missing is threading a locale into those responses. Mapping them client-side by id would break the property that a new `ToolSpec` appears in Capabilities for free, so the fix belongs server-side.
- ▢ **`mcp/server.ts` fetches the report and disclosure endpoints with no `?lang`**, so MCP resources are always English. Defensible for a machine consumer, but it should be a decision rather than an oversight.
- ✅ **`scripts/check-comment-glob.sh` — the comment-terminating glob cannot ship again** (2026-07-29) — a `*/` inside a doc-comment path (`` `locales/*/coverage.ts` ``) ends the comment, the prose after it parses as code, and tsc reports TS1443/TS1434/TS1160 far below the real line while esbuild cannot transform the module at all. It hit three files in one session and blocked every agent's test run. The guard lexes block comments, line comments and strings in one `awk` pass, then applies two rules: a `*/` GLUED to its surroundings inside a comment, and a lone `*/` with no comment open (which cannot be valid code, so it is a certainty rather than a heuristic). The character set was chosen from the tree, not from imagination — all 2934 block-comment terminators were enumerated first and none is preceded by `/` or followed by an alphanumeric, so the rule has zero overlap with legitimate code here. _Every cannot-look branch exits non-zero: `git`/`awk` missing, `git ls-files` failing, zero files matched, a file `awk` cannot read, and an EXIT-trap backstop that forces 2 even when the abort carried 0. The success line states files scanned AND block comments walked, so "found nothing" cannot be confused with "looked at nothing". Its own header records what it does NOT claim: it skips a line rather than inventing an offender._
- ✅ **`BinariesPanel` deleted — 444 lines that nothing rendered** (2026-07-29) — the panel plus `GhidraDecompile`, `TriageTable` and `HardeningBadges`, whose only references were inside the panel itself (which is exactly why the dead-export sweep missed it: it is referenced textually within its own file). Verified four ways before deleting — a repo-wide grep, the self-reference check, a hunt for `React.lazy`/dynamic imports and string-keyed component maps, and a check that no test covered the subtree. **No test was removed**; `mockApi.binaries` stays because the dossier uses it. The orphaned `binaries`/`ghidra` catalogue namespaces went with it in both languages, and the ES-typed-against-EN compile check is what proved the deletion was symmetric.
- ✅ **Two literal NUL bytes in tracked sources, and a gate that refuses more** (2026-07-28) — CLAUDE.md's third trap, found twice in one day. `run-summary.ts` had just acquired one (a sentinel for the image-wide bucket in `groupRunsByTarget`) and sweeping the repo turned up a second that had shipped in `8b159f6`: `compmap.ts` keying a map on `from`-NUL-`to`. Both are exactly what the note predicts, because a NUL genuinely IS the right separator for a key whose fields must not collide. **Nothing catches it** — tsc compiles it, biome formats it, vitest runs it and the tests pass, since the code is correct; what breaks is everything around it, and `file` calling the source `data` while grep skips it *without saying so* is how a large, correct change comes to look like it was never made. That silence is what surfaced it: a grep over a 14 KB file returned nothing. Both are `\u0000` escapes now and `scripts/check-nul.sh` runs inside `pnpm biome`. _Two things the guard's own first version got wrong, both fixed: it carried a NUL in its own comment block, and it scanned only `git ls-files` output — so it never looked at itself, a file being at its most dangerous before its first commit. It now scans tracked AND new-but-not-ignored files, and names the offending line via `cat -v` since grep cannot._

- ✅ **The web suite's six standing warnings, one of which was a live network call** (2026-07-28) — the suite passed while printing four React `act` warnings and two React Router future-flag notices, and a warning that always prints is a warning nobody reads. Two were real. `SimulationMenu.test.tsx` mocked seven `api` methods and spread the rest from the real client, so **`api.binaries` stayed live**: every test in the file made an actual fetch into jsdom, and its rejection set state after the test had ended. The unmocked method is invisible precisely because the spread makes the mock object look complete — nothing lists what was left real. `FileSearch`'s submit handler is async, so the state it sets lands a microtask after `fireEvent` returns; the click is now made inside `act()`. The router flags are now taken explicitly (both inert here — no splat routes, and `v7_startTransition` only marks router updates non-urgent), which exposed that **nothing in the suite navigated through the real `HashRouter`**, so the opt-in rested on behaviour no test exercised. There is now a navigation test through it, and the assertion had to be chosen against the same trap: identifying the destination by the image filename passes on the ORIGIN route too, because Overview lists filenames as well — that version was green with the nav link pointed at the wrong route. It identifies Dashboard by its filter box instead, and was confirmed to fail against that mutation before being kept. _Remaining and NOT ours: Node's experimental-`localStorage` notice, emitted by the runtime on Node 26 against a repo targeting Node ≥ 22; every access in `theme.ts`/`onboarding.tsx` is already guarded._
- ✅ **Six exported accessors nothing had ever called** (2026-07-28) — a dead-export sweep over the 803 exported runtime bindings in api/core/web found six reachable from nowhere: `listSessions`, `listCaptureSessions`, `latestCaptureSession`, `provenanceForImage` (store.ts) and `isolationNetnsArgs`, `resetIsolationCache` (providers/isolate.ts). Each was a speculative accessor a sibling already covered. Two near-misses worth recording. **`isolationNetnsArgs` looked like it might be hiding a real bug** — it hands out the probed unshare flags "for callers building their own invocation", and if `buildIsolatedInvocation` had defaulted to `-n` while `detectIsolation` had selected the rootless `-rn`, every isolated run under Docker/OrbStack would have failed in exactly the case the fallback was added for. It does not: `runIsolated` passes `cachedNetns` explicitly. **`resetIsolationCache` is a test seam for a test nobody wrote** — `isolate.test.ts` exercises only the pure builders and never populates the cache, so no order-dependence was hiding behind it either. _The sweep was grep-based on purpose: this repo's note that the code graph under-approximates CALLS edges through local wrappers applies directly to a dead-code question, where a missing edge reads as an orphan and invites deleting live code. The graph proposed candidates; textual reference decided them._
- ▢ **Make the dead-export sweep a repeatable script, and mind the tree it walks.** The sweep above was a throwaway. Its first pass reported a seventh victim, `parseBinwalkOutput` — which is NOT dead: core keeps its tests in `packages/core/test/`, outside the `src` roots the sweep walked, so its only caller was invisible. **A sweep is only as good as the tree it walks**, and that is the same failure shape as the guard traps already in CLAUDE.md. Two further honest limits any permanent version must state rather than paper over: a symbol used only inside its own file is *over-exported*, not dead (the two are different findings and were conflated in the first pass, giving 90 candidates instead of 6), and a symbol reached only from its own tests is not dead here at all — this codebase deliberately exports pure decision logic so vitest can reach it, per the store-free-sibling rule.
- ✅ **Nothing enforced that an `api` spread-mock covered what the component calls** (2026-07-28, `8cb4251`) — `test-api-mock.ts` enumerates the surface from the real client at runtime, so a method added to `api.ts` is covered the day it is added, and every method starts as a `vi.fn()` throwing `unmocked api call: <name>`. Migrating the 13 spread-pattern files found **five live network calls**, each firing on mount in every test in its file: `runs` in FuzzPanel / SymReachPanel / OpacidadPanel / SimulationMenu (all four via the shared `RunHistory`) and `tools` in App (via Overview). **Four of five are one shared child** — a component grew a dependency and the hand-written lists did not follow — which is the class this entry predicted, not a run of unrelated slips. `SimulationMenu` is the proof: fixed by hand in `11cb8b9` for `binaries`, and still fetching through `WebProbePanel`. The guard's failure path was exercised five times, not just its success path. Arguments stay typed, so `toHaveBeenCalledWith` is now checked where `ReturnType<typeof vi.fn>` had made it `any[]`. _Scope is narrow and the module states it: `src/api.ts` is the only module under `apps/web/src` that calls `fetch`, which is what makes a complete `api` mock a complete network guard — and a component that swallows its own errors would swallow this one too._
- ✅ **Nothing stopped the NEXT web test file from hand-writing the mock** (2026-07-28, `09dd66e`) — `scripts/check-web-api-mock.sh`, chained into `pnpm biome`. Two rules, deliberately different in scope: no web source may spread the real client, AND a test that `vi.mock`s the client must delegate to `buildApiMock` — the second matters because the first is sidesteppable by writing the literal out by hand, and it is what preserves the enumerate-at-runtime property. `test-api-mock.ts` is exempt, and the exemption is load-bearing: without it the guard flags that file's own doc comment, which quotes the shape it refuses. Scans untracked files too. All branches exercised, including tools-missing and listing-failed (both exit 2, never 0).
- ✅ **`check-nul.sh` reported clean when it could not look** (2026-07-28, `09dd66e`) — **the fourth instance of the SUCCESS-path trap, found while writing the guard above.** The file list came through `done < <(git ls-files …)`, and a process substitution's exit status is DISCARDED: with git unavailable or failing the loop read nothing, `found` stayed 0, and it printed *"no literal NUL bytes in tracked sources"* and exited 0 — from a check that had opened no file. Proven by shadowing `git` with a stub exiting 128. True since the guard was written, including the day it caught three real instances. Now: the listing is captured and its failure checked, the tools it shells out to are verified present first, the success line states the count (338 files) because *found nothing* and *looked at nothing* are only the same sentence when the count is invisible, and the root is resolved by parameter expansion rather than `dirname` — which ran before the tool check and so failed first on a stripped PATH, reporting the wrong problem.
- ✅ **`--theme light` produced dark screenshots** (2026-07-28, `1bf7465`) — `ui-drive.mjs` set Playwright's `colorScheme`, which drives `prefers-color-scheme`, and `theme.ts` consults that ONLY when the stored preference is `system`; its default is a hard `'dark'` and a fresh capture profile stores nothing. So the flag set the media query, the app ignored it, and the run reported a dark render as light — every light-theme check ever made this way. It now seeds `firmlab.theme` via `addInitScript`, as the tour suppression beside it already did. Verified: both captures differ, the light one is light, and the header toggle shows the matching control active. _Found by the agent building the component-map view, which needed a light capture to check its tokens and got a dark one — the tool lying is worse than the tool missing._
- ▢ **`ImageDetail`, `Corpus`, `Settings`, `Agents` and `Capabilities` have no test file at all**, so the unmocked-api defect class is untested there rather than absent — the guard above only constrains files that exist.

## Deploy & operations
- ✅ **`deploy.sh` aborted silently, which is what made the guard bug expensive** (2026-07-28) — `set -e` kills the script wherever a command returns non-zero and says nothing, so the defect below surfaced as three lines of normal output and an exit code, and locating it took a `bash -x` session. An `ERR` trap now names the line and the command. _Its first version was wrong in exactly the way it was written to catch: a plain `trap … ERR` is **not** inherited by shell functions, subshells or command substitutions, which is precisely where the abort happened, so it printed nothing for the very bug it existed for. `set -E` (errtrace) propagates it. Verified by reintroducing the original defect on a copy: the trap now prints `abortó en la línea 116 … listeners="$(lsof …)"`._
- ✅ **The anti-squatter guard aborted every deploy on a CLEAN port** (2026-07-28) — `check_port_squatter` assigns the output of an `lsof` pipeline, and lsof exits **1** when nothing matches; under the script's own `set -euo pipefail` that status propagates out of the assignment and killed the script there, silently, with exit 1 and no message. Precisely inverted: a squatted port ran to completion, a clean one refused to deploy. It stayed invisible because the guard was only ever exercised against the zombie it was written for — that `pnpm dev:api` was listening on 8799 the day the guard landed and every day after, so lsof always matched and always exited 0. **Killing the zombie is what disabled deploys.** The same shape as the traps in CLAUDE.md: a guard whose success path was never run, and fixtures written from the same assumption as the code. Both branches are now validated — clean port proceeds, a listener deliberately bound to 8799 is still named and refused.
- ✅ **`deploy.sh` port-squatter check** (2026-07-27) — the compose publishes NO host port (Traefik reaches the container over `proxy_net`), so anything listening on host `8799` is by definition not the deployment. A leftover `pnpm dev:api` there is the worst kind of stale: it serves a plausible FirmLab from an old tree and an old DB, so you verify against the wrong process and believe it — which already cost real debugging time once. `check_port_squatter` runs on every invocation (including `--check`), uses `lsof` or `ss`, exempts Docker's own forwarder (`docker-proxy`/`com.docker`/`vpnkit`, which would mean the compose was changed to publish a port), and stays silent when it has no way to look rather than implying the port is clean. **Caught the ghost on its first run**: `node dist/index.js` (pid 46986, started 2026-07-23) serving `{"build":"dev"}` on 127.0.0.1:8799.

## Semantic debt (minor, deliberately deferred)
Small, well-understood gaps — each already described in full where the feature lives; gathered here so a short list
of "known-incomplete semantics" exists without hunting through the sections above.

- ◐ **W2 component table** — dropbear, dnsmasq and busybox landed (2026-07-27); lighttpd/goahead remain, for want of a sample (see *External intelligence*). Original scope: extend beyond pppd/openssl to dropbear, lighttpd/goahead, dnsmasq (+ Go-module
  fingerprints inside static binaries). See *W2 component-fingerprint CVE*.
- ✅ **W3 nvram store parser** (2026-07-28) — `providers/nvram.ts` + `POST/GET /images/:id/nvram`, wired into every class (it reads the RAW image, so it can never be skipped for want of a rootfs). 9 stores across 16 images, 0 false positives against 10,712 extracted files. Values are redacted in evidence; only key, offset, length and well-known-default status are kept.
- ▢ **DVRF's credentials are NOT in an nvram store** — `AUTONOMOUS-WORKERS.md` §3.2(5)/§9 says they "lived in an nvram blob"; there is no store in that image. They sit in the Broadcom `router_defaults[]` string pool in `usr/lib/libshared.so` (`http_passwd\0admin\0` at 0xa7dcc), a pointer array whose name→value pairing lives in RELOCATIONS, not adjacency — `http_username\0` is followed by alignment padding, not its value. Recovering it needs relocation-aware ELF parsing. The doc should be corrected either way, since it currently sends a reader looking for the wrong thing.
- ▢ **U-Boot redundant environment** (CRC + a 1-byte active flag) is unsupported — no sample in the corpus to ground it.
- ▢ **Cross-image nvram correlation** — "the same WPA PSK on every unit of this model" is the finding operators care about, and it needs a value digest in the corpus. Deliberately not done: a truncated hash of a short password is a crackable oracle, so it needs thought rather than a hash.
- ✅ **`/etc/shadow` cracking** (2026-08-03) — the other half of the original W3 entry, whose nvram-store parser
  landed 2026-07-28 (see *W3 nvram store parser* above). Done as a self-referential cross-reference rather than as
  hashcat: see *Cross-reference credential hashes against the strings the image itself ships*. Note the entry's
  `root:sohoadmin` shorthand attached the plaintext to the wrong image — it is the WDR3600 that ships the string,
  not the WR940N, and both carry the same hash.
- ▢ **W7 RP2350 `decode()` reversing** — the CTF's `ror+sub+xor` obfuscator hides the flags; plaintext extraction
  honestly will not recover them, so this needs real on-device routine reversing. See *W7 Bare-metal/RTOS worker*.
- ✅ **Corpus OSV/NVD/KEV cache** — done 2026-07-28; see *External intelligence*.

## Workbench UI — the run ledger
- ✅ **A stored result is data from an older build, and the types said otherwise** (2026-07-28, deploy `eeb0976`) — opening IMOU-Ranger-2C blanked the entire image view. The dossier mounts `ResearchPanel`, which rendered `nvd.uncheckedIdentities.map(...)`, and that image's research result had been persisted BETWEEN two commits of the same session: it carries `matchedBy` and `askedByCpe` but not `uncheckedIdentities`. `undefined.map` threw and React unmounted the tree. **The defect is the type, not the missing guard.** A provider result is JSON on a job row, written once and re-read for as long as the image exists, so every field added after the fact is absent from every result stored before it — declaring them required made the type assert something about persisted data it cannot know, and the compiler had no reason to object. Marking them optional turned the class of crash into a compile error AND located this instance immediately. **3 of the 4 images carrying a research result would have crashed**, so this was not one bad image. _Two related over-claims fixed with it: a component whose `matchedBy` predates the CPE/keyword split now reads "not recorded" instead of defaulting to "keyword" — a provenance claim manufactured from a missing field — and the badge tooltip says the split was not recorded rather than rendering "undefined asked by CPE version match"._
- ▢ **Every other provider result has the same exposure.** `chipsec.secureBoot`, `DynProbeResult.blockedBy`, `ProbeResult.environmentFailures`/`targetOutput`, `FuzzResult.harnessNote`, `SymReachResult.derivedSinks` and anything added to a result shape from here on are all required in the web types while being absent from rows stored before they existed. Only `nvd` has been made honest. The rule worth adopting: **a field added to a persisted result type is optional forever**, and a re-analysis is what fills it in.
- ✅ **Twenty routes exposed only the LAST run of each kind** (2026-07-28, deploy `174b058`) — every per-kind GET answered with `listJobs(id).find(j => j.kind === … && j.status === 'done')`, so probing three binaries showed one result while the other two sat unread in the database. Nothing said three had happened, what they targeted, or what came back. `GET /images/:id/runs` reads them back and `providers/run-summary.ts` (PURE, store-free, unit-tested) turns a stored job into a line. **`status` and `outcome` stay separate fields**: `done` says the process finished and says nothing about what was learned, and a probe that completed without reaching its sink and one blocked for want of `/dev/nvram` are both `done`. Vocabulary is `proven`/`lead`/`empty`/`blocked`/`failed`/`running`, with `blocked` styled warn rather than danger because nothing failed. **Measured on the real DVRF: 21 runs across 5 targets, where the UI previously showed 1** — including two `blocked` probes from the old fixed-port bug and a `crash` that is weaker than its siblings, all of which had been invisible.
- ✅ **Binaries + Emulation restructured into a Test bench** (2026-07-28) — the two sections were split by TOOL, which is the wrong axis for "what do I know about this binary". Now one surface lists targets (examined ones first), every run under each with its question, its bound and its outcome, and an unexamined binary says *not examined* rather than rendering an empty result. **The dynamic probe's hidden prerequisite is the other half:** it breaks on an exact call site so it needs a sink ADDRESS, which only a reachability run produces — pressing it without one returned a 400 explaining that afterwards. The bench harvests addresses from finished reachability runs and offers `Probe sprintf at 0x500010` directly; with none, the button is disabled and names what to run first. *Emulation recipes* stays its own section because "how can this IMAGE boot" is a different question.
- ✅ **The other per-kind panels read only their latest run** (2026-07-28, deploy `0f64c30`) — closed with a shared `RunHistory` rather than by rewriting each panel: same ledger, same pure summarizer, so a `blocked` run reads as blocked there too instead of as an empty one. Collapsed by default and **silent when there is nothing the panel above is not already showing**, so it costs a panel nothing until it has something to say. Wired into deep analysis (7 kinds in one component), fuzzing, reachability, autonomous scan, web probe, SBOM, diff and research. _The per-kind routes are deliberately unchanged: they serve "show me the full current result" and their shapes are load-bearing._
- ✅ **A broken harness was graded as a platform block** (2026-07-28) — split at the source, which is where the conflation was: `unavailable()` now takes `blockedBy: 'platform' | 'harness'`, so "gdb is not installed" and "gdb produced no output" stop arriving identically. The ledger renders the second as `failed`, and the finding's rationale tells an operator whether a retry is worth anything. The finding keeps `blocked_by_platform` in both cases — the proof-state vocabulary has no third option and inventing one would be worse than the imprecision. **Both paths validated on the real deploy**: a binary absent from the rootfs → `platform`/`blocked`, and a non-ELF target whose gdbstub never came up → `harness`/`failed`. _Rows written before this carry no `blockedBy` and stay `blocked`, which is the conservative reading._
- ✅ **The bench polled a job to completion in the browser** (2026-07-28) — it blocked in a `for` loop over `api.job(jobId)`, so a run existed only while the component stayed mounted. The job was always a row in SQLite, so it follows the ledger now: the running row renders from persisted state, the log comes from the stored job, and polling stops on its own when nothing is running, so an idle bench makes no requests.

- ✅ **The Agents console read `done` for every finished agent session** (2026-08-03, **not yet deployed**) — the
  Runs table's outcome column ("What came of it") rendered `run.status` plus a transcript count for agent rows, and
  for anything finished that string is `done` by construction. Measured against the deployed corpus's 18 real
  sessions: the 7 that ran the full chain read `done · 7 steps` and the 11 that never reached a target read
  `done · 4 steps`, so a session that formed 8 zero-day candidates was indistinguishable from one that formed none,
  and both from one that had nothing to analyse at all. **Scan rows were already honest** — the defect was only in
  the agent lane. `readAgentSession` (pure, exported from `pages/Agents.tsx`, unit-tested) reads the verdict back
  out of the transcript the session already wrote — halt reason, approval gate, governor leash, candidate count,
  last node, deterministic preflight strategy — and states it in the run ledger's OWN vocabulary rather than a
  second one. The three readings deliberately kept apart: never reached a target → `blocked` (it could not ASK its
  question — not a pass, not a failure); zero-day node ran and formed nothing → `empty` (a result for that
  scaffold, not a clean image); candidates → `lead`, never `proven`, since they are written
  `needs_runtime_reproduction`. `proven` requires an emulation step that came back `confirmed_*`, and even then it
  proves the sandbox.
- ▢ **`OUTCOME_CLASS` now exists twice** — `components/RunHistory.tsx` and `pages/Agents.tsx` each hold the same
  six-entry outcome→class map, because the first is private to that file. Lift it (with the
  `t.shell.runHistory.outcome` lookup beside it) into one shared module before a third copy appears.
- ▢ **An agent session is not a job row, so it is invisible to the run ledger** — `providers/run-summary.ts` reads
  `job` rows, and sessions live in `agent_session`/`agent_step`. The consequence is that the session's outcome is
  computed in the WEB layer and nothing else can state it: not `GET /images/:id/runs`, not the dossier, not the MCP
  surface, so an agent asking "what came of the last session" still gets a status. The reading is small and pure
  and belongs beside `summarizeRun` as a `summarizeSession`, with the console consuming it instead of owning it.
- ✅ **Five honesty defects closed together** (2026-08-03, deploy `d2e19c9`) — the run ledger read a full-system
  boot as a user-mode run (`e713fa6`), `ghidra` composed no rows at all (`f958046`), a sandbox shortfall was filed
  as the program failing (`cc9db2f`), ten route guards told an operator to run an extraction that had already run
  (`8dddaa3`), and the Agents console answered "what came of it" with a process status (`d2e19c9`). Each is
  recorded at its own entry. Verified on the deployed corpus: the Xiaomi eCos images now answer **422** with
  extraction's own LZMA diagnosis instead of `400 "Run extraction first"`, the WR940N's boot reads
  *"Full-system boot confirmed — nothing answered on a forwarded port"* where it read *"Ran under user-mode
  emulation, exit ?"*, and the console's 18 sessions read `blocked` / `lead 8 zero-day candidates` /
  `nothing found` instead of eighteen identical `done`s.
- ▢ **The rootfs gate's structured body lands in the UI as one long sentence** — `AnalysisActionsPanel` renders
  `error` in a warning banner and `SbomPanel` in its log block, so the full ~700-character refusal DOES appear and
  nothing is hidden. But `state`, `retryable` and `extractionDiagnosis` are separate fields for a reason: a badge
  for the state, the diagnosis as a quoted block (the way `ComponentMap` already quotes extraction's verdict), and
  a visibly different treatment for `retryable: false` would read far better than a wall of prose.
- ▢ **The MCP surface flattens the gate back into a string** — `mcp/client.ts` `post` throws `detail.error`, so an
  agent driving FirmLab gets the honest sentence and loses `state` / `retryable` / `extractionDiagnosis`. It
  therefore cannot tell "wait, extraction is still running" from "this image will never have a rootfs" without
  parsing prose. `getWithStatus` already exists for exactly this and is unused on the POST path.
- ▢ **The user-mode emulation route takes its rootfs from the gate and its suggested binary from
  `latestExtract`** — two different job rows in principle. The gate returns a rootfs from ANY completed extraction
  (deliberately: a later failed re-run must not hide a rootfs sitting on disk), while `latestExtract` returns the
  most recent one, so on an image with two extractions the suggestion can come from a run that recovered nothing.
  Harmless today (every corpus image has one extraction) and wrong in principle; the gate should return the
  suggestion alongside the path.

## Workbench UI — prose and layout (2026-07-29, deploy `163b652`)
- ✅ **Three LLM surfaces showed their Markdown SOURCE** (2026-07-29) — the research brief, the copilot
  interpretation and the autonomous scan's narrative all landed in a `white-space: pre-wrap` block, so the reader
  got `## 🔍 Intelligence Brief`, `**Vendor:**` and `[[NVD](https://…)]` verbatim. Closed with a hand-written
  `apps/web/src/markdown.tsx` (no dependency: the web package has three runtime deps and no chart library, and a
  remark/sanitiser stack is a large transitive surface for four panels of prose). It emits React elements and
  never touches `innerHTML` — this text is model output derived from documents fetched off the internet on the
  research lane, so an escaping bug would be a script injection rather than a typo. **The narrative was Markdown
  with every LLM flag off too**: `composeDeterministicNarrative` writes headings, bullets and `code` spans by
  hand. Two grammar rules are load-bearing rather than cosmetic — intraword `_` follows CommonMark so
  `needs_runtime_reproduction` is not italicised into `needs<em>runtime</em>reproduction`, and a `#` href is
  refused because HashRouter turns it into a route change (the live brief emits `[[OSV](#)]`). Pinned by unit
  tests plus `markdown.corpus.test.tsx`, which runs the REAL deepseek brief and narrative from the deployed
  container through the renderer and asserts no marker reaches the reader.
- ✅ **The findings table's last column hung off the right of the page** (2026-07-29) — `.report-builder` is
  `grid-template-columns: 300px minmax(0, 1fr)`, and `minmax(0, 1fr)` bounds the TRACK while a grid item keeps
  `min-width: auto`. The paper therefore could not shrink below the table's min-content width, and "Proof state"
  left the viewport at any width under ~1400px. `min-width: 0` on the items is only half of it: once it *can*
  shrink, a 300px config rail plus print margins leaves the five-column table ~620px on a 1280 laptop and
  `critical` wraps to "critic/al" — so the stacking breakpoint moved from 1040px to 1400px (below it the paper
  takes the full width) and the table states its column shares in a `colgroup` shared with the HTML export
  instead of letting `table-layout: auto` give the title column everything. Body cells wrap with
  `overflow-wrap: anywhere` and headers deliberately do not.
- _Both validated against the DEPLOYED container (`163b652`, via the socat sidecar) rather than only the dev
  build: brief, narrative and report re-read at 1600/1440/1366/1280/1152 over General, Findings & report,
  Autonomous scan and Agent — every element inside its panel and inside the content edge, no console exception,
  no failed request. The step timeline is excluded from that measurement on purpose: it is an `overflow-x: auto`
  scroll container, so a child past its box is the design, not a defect._
- ▢ **The agent transcript's `step.rationale` is still plain text.** It is LLM prose like the three above and can
  carry `code` spans; it renders in `StepCard` as an italic `<div>`. Left alone because it is one sentence and a
  block renderer inside an italic line is the wrong shape — it wants inline-only Markdown, which `parseInline`
  already provides.
- ▢ **An unreproduced overflow report in *General*.** Reported alongside the two above: "certain items go off the
  right margin" in the dossier. Probed at 1600/1440/1366/1280/1152/1024 against all 16 corpus images and every
  section, measuring each element against both its panel's content box and the `.content` inner edge — the
  dossier came back clean at every width, before AND after the deploy, and the only hit anywhere was the report
  builder above. Needs the
  reporter's viewport width and a screenshot; the likeliest candidate is the copilot output, which no image in
  the corpus has ever had stored, and which is now inside the `.md` measure and `overflow-wrap: anywhere`.

## Emulation — the guest's own egress (2026-07-29)
- ✅ **The emulated guest had unrestricted internet and nothing recorded it** (2026-07-29, deploy `fb3a89e`) — the
  full-system rung hands the guest `-netdev user`, emulation is behind no flag, and the shell says *"Local-only.
  Never expose to the internet"*. **The design turned on one measurement**: does cutting the egress also cut the
  visibility of the attempt? Run in-container on a MIPS BE guest built from the WR940N's own busybox, pinging
  8.8.8.8, booted twice with nothing changed but `restrict` — `on` gave 9 frames (the guest's ARP, its 3 ICMP to
  8.8.8.8, no replies), `off` gave 12 (the same 3 ICMP plus 3 replies). `filter-dump` hangs off the netdev, so a
  frame the guest emits is captured before slirp decides whether to forward it: **blocking the traffic does not
  hide the attempt.** Both captures ship as fixtures and pin exactly that. So `providers/egress.ts` (pure, 26
  tests) records destinations and DNS QNAMEs unconditionally, and `FIRMLAB_EMU_ISOLATE` is a separate switch.
  `filter-dump`'s `maxlen` went 128 → 256 because a DNS question's name starts 54 bytes in and 128 cut real vendor
  hostnames in half. _Two defects the guards caught before the first commit: six literal NUL bytes used as
  composite-map-key separators (the exact trap CLAUDE.md documents, in a file at its most dangerous moment), and
  the real bug underneath — a DNS label is length-prefixed, so its content is arbitrary bytes, and that string was
  being joined into a map key and rendered into a panel. `parseDnsQName` refuses a non-hostname label now._
- ✅ **The flag defaulted to PERMISSIVE — flipped 2026-07-30 after measuring it** (deploy `f969750`). It shipped
  named for what enabling it does (`FIRMLAB_EMU_ISOLATE`) precisely so it would not have to be an opt-out switch
  in a list of opt-ins, and the accepted cost was that the headline claim stayed false by default. The condition
  the note set — *whether any rung depends on outbound* — came back **no**, on four boots of the image that talks:
  open and isolated are indistinguishable in attempts, verdict and forwards. So the default is ON, the
  misreadable shape is accepted, and `defaultOn` makes it a declared property that `resolveFlags` and
  `decideFlag` both honour. The prose in both languages now leads with ON BY DEFAULT / ENCENDIDO POR OMISIÓN,
  because a reader consults the `egress` line *before* flipping a switch and the old wording ("while this is off")
  would have left them believing absence still meant permissive. Full account in the *Emulation* section above.
- ▢ **A single boot is a floor, not a total — measured, and it nearly produced a wrong conclusion.** Three
  full-system runs of the WDR3600: permissive → **15 external destinations** (a hardcoded NTP pool, UDP/123, no
  DNS involved); isolated → **0**; isolated again → **the same 15**. The empty run differs from its own isolated
  twin, not from the permissive one, so the variance is the guest's boot and not the flag — and reading the first
  isolated run alone would have said "isolation hides the attempt", the opposite of what the controlled capture
  proves. The panel now states that a boot is a sample. What is open is doing something about it: repeated boots
  merged, or a stated confidence, rather than leaving the reader to discover the variance the way this did.
- ▢ **IPv6 is skipped entirely.** `parseEgress` reads IPv4 only; a firmware that phones home over v6 is invisible
  to it. Deliberate — the rung's networking is v4 and a partial v6 story would be worse than none — but it is a
  hole in a panel whose whole job is "what did it try to reach".
- ▢ **`environmentValue` answers a different question now, and no reader was updated.** Surfaced while flipping
  the isolation default (2026-07-30), not implemented: the field means "what the container's environment says,
  independent of any override", and for a `defaultOn` flag with nothing in the environment it now resolves to
  **true** — which is correct as *"remove your override and you get isolation back"*, and wrong if any reader
  still renders it as *"compose says off"*. Its one consumer is the Settings panel. Impact: low, but it is the
  same shape as the persisted-result trap — one field, two questions, and only one of them was asked when the
  reader was written. Worth either renaming it to what it now answers (`withoutOverride`) or having it report the
  raw environment plus the resolved default as two fields.
- ▢ **The three-sentence egress policy reaches the LOG and not the panel.** `describeEgressPolicy` composes the
  distinction, and `SimulationMenu` still switches on the boolean `isolated` alone — so the panel cannot tell an
  operator that the guest was opened *deliberately*, which is the only way it can now be open. The isolation note
  fixed in iter 9 is adjacent and correct; this is the run's policy provenance, a different fact from the
  observation. Impact: medium — the log is job-scoped and the panel is what a reader actually opens.
- ⚠ **The corpus barely talks, and that is the finding that should decide the interception work.** The egress
  observation run across every image that can reach the full-system rung (2026-07-29, deploy `9c485b6`), one boot
  each except the WDR3600's three:

  | image | boot | guest frames | external | DNS | protocols |
  |---|---|---|---|---|---|
  | TP-Link WDR3600 | booted | 19 / 116 / 19 | **15** / 0 / **15** | 0 | UDP/123 only |
  | TP-Link WR940N | booted | 135 | 0 | 0 | — |
  | TP-Link MR3220 | booted | 116 | 0 | 0 | — |
  | DVRF | kernel panic | 0 | 0 | 0 | — |
  | IMOU Ranger 2C | never reached userspace | 0 | 0 | 0 | — |
  | GL.iNet BE3600 | `blocked_by_platform` | — | — | — | no arm64 kernel here |

  **Across eight boots of six images there is not one outbound TCP connection and not one DNS question.** The only
  external traffic anywhere is the WDR3600's hardcoded NTP pool on UDP/123 — and `guestfwd` is TCP-only (verified:
  `guestfwd=udp:…` is rejected as an invalid rule), so the one mechanism that needs no new privilege cannot touch
  the one thing there is to see. A Burp-style intercept is an HTTP tool and there is currently no HTTP to
  intercept.
  **The blocker is not the redirection mechanism, it is how far the boots get**: `open` is empty on every image,
  so no service answered anywhere, and a firmware whose web UI never comes up never does an OTA check either.
  Spending the spike on transparent redirection would be optimising a stage nothing reaches.
  _And the zeros are floors, not negatives — the WDR3600 gave 15, 0 and 15 across three identical runs, so a
  single boot reporting 0 is a sample, not a statement about the firmware. Repeated boots come before conclusions._
- ▢ **The interception mechanisms, ranked by what was measured rather than by preference.** DNS-controlled
  redirection dies on hardcoded addresses (0 DNS questions observed anywhere). `guestfwd` per destination is
  TCP-only. TAP + `iptables REDIRECT` needs `/dev/net/tun` (**absent in the container**) and `CAP_NET_ADMIN`
  (**not granted**), i.e. a compose change that widens the deployment's privilege, on the VM-backed runtime
  `looksLikeVmBackedRuntime` already paid for. That leaves a userspace stack behind `-netdev socket`/`stream`
  (gvisor-tap-vsock, slirp4netns, vpnkit): full control including UDP and per-connection approval, at the cost of
  a new dependency in the data path. The real choice is privilege-in-the-container versus dependency-in-the-path,
  and neither is worth paying until a boot produces traffic worth intercepting.

- ▢ **`webprobe` and the interception ladder** — the observation is peldaño 1 of the design the operator asked
  for: see, then AUTHORISE, then inspect and edit (a Burp for emulated firmware). Peldaño 2 is a two-pass
  approve-then-boot, which fits the rung's existing learn/reach shape. Peldaño 3 re-targets `capture/proxy.ts` —
  mitmproxy already ships — and emulation gives it something a real device cannot: the rootfs is on disk, so the
  CA can be injected into the guest's trust store before `rootfs-image.ts` builds the image, the same hook that
  already stages `/firmadyne/libnvram.so`. The one real unknown is transparent redirection: qemu's user
  networking has no per-destination allowlist, so intercepting arbitrary destinations needs a controlled DNS and
  a single mapped endpoint, and the TAP alternative needs `NET_ADMIN` on a bridge-networked VM-backed runtime —
  the lesson `assessL2Reach`/`looksLikeVmBackedRuntime` already paid for. Deserves its own spike.

## Workbench UI — the visibility audit (2026-07-29)

A full sweep of what the API produces and the web never renders. Ordered by what the absence COSTS, and the
ordering is the point: a field that hides a limitation is worse than a whole capability nobody can reach, because
the first one makes a gap read as a clean result and the second is merely missing.

- ✅ **The capability matrix under-claimed three built techniques** (2026-07-29) — `TechniqueCoverage.tsx` is the
  only place the workbench states what it can do, and it announced `symreach`, `functionDiff` and `fwhunt` as
  `planned` while all three have providers, routes and (for symreach) a panel. Under-claiming here is the same
  defect as over-claiming, pointed the other way: an operator reads the matrix to decide what to ask of the bench.
- ◐ **Fields that make a limitation invisible.** Four landed (2026-07-29):
  **`Finding.rationale`** — the sentence saying why a finding sits at its proof state, which reached the reader on
  operator disputes only. It could not simply be printed: 98% of this corpus's 1230 rows carry one, median 196
  characters, so always-on would triple a 740-row table. It opens per row behind a real focusable button with
  `aria-expanded`, and a row whose provider wrote none offers no toggle — an empty chevron would promise an
  explanation that does not exist.
  **`UpdatePathResult.elfBudgetExhausted`** — "no updaters found" from a sweep that STOPPED is a cap, not an
  answer. Now stated on the found path too, because a partial list misleads exactly as much as an empty one when
  the reader cannot tell it is partial.
  **`FilesSearch.coverage`** — the counts existed, were reduced to one boolean by `isCompleteSearch` and thrown
  away, so "3 files unreadable" and "0" rendered identically. The non-zero holes are now named against their
  denominator; a row of zeros would bury the one count that matters.
  **`kev.reason` / `kev.catalogSize`** — the badge was conditional on `kev.checked`, so a lookup that did not
  happen made the whole block VANISH, and a missing block is indistinguishable from a clean one. There is always
  a badge now, and the not-checked one carries the provider's reason.
  _Still open in this class_: `ResearchResult.hashLookup` entirely (a hash skipped for salt looks like one that
  never existed); `BootDiagnosis.daemonsStarted`/`daemonsExited`; `SecureBootPosture.note`;
  `DeviceTreeResult.rejected`; `OperatorAssertion.withdrawnReason`; `FuzzResult.reason`; `osv.skipped`,
  `nvd.notQueried`, `nvd.truncated[]`, `egress.neverSent`.

- ✅ **Whole capabilities with a route and no reader** (2026-07-30, `04af0f4` + `98fc9cd`) — `yarascan`, `funcdiff`,
  `fwhunt`, `nvram` and `ghidra` had POST+GET routes and zero references in `apps/web`, and `DynProbeResult` was not
  typed in the client at all, so `controlOffset` — the whole point of the dynamic probe — had nowhere to be read.
  A `deepscans` section now renders all six with `capabilities.ts` (pure, 13 tests) deciding the state.
  **The entry said two states and there are THREE**, which is the distinction this workbench is built on:
  `not-run` (nobody asked — about the workbench), `unavailable` (`available: false`: the question WAS asked and this
  deployment could not answer — about the deployment, and never a negative), and `ran` (the only one that says
  anything about the firmware, and even then bounded by its coverage numbers). Collapsing `unavailable` into either
  neighbour was the defect hiding inside the fix.
  An absent denominator prints as unknown, never as 0 — an invented zero is a measurement nobody made.
  **All three states validated live on one screen** (`/image/a2c03536/deepscans`, deploy `98fc9cd`, 0 console
  errors): `yarascan` → *could not answer*, "no rule corpus is configured: FIRMLAB_YARA_RULES is unset" — with yara
  now installed, which is exactly the "yara is installed" ≠ "this deployment can answer" split its `ToolSpec`
  comment always claimed; `nvram` → *ran*, 0 findings, "0 stores examined · this provider reports no denominator",
  beside the provider's own refusal to be read as "the device has no nvram"; `dynprobe` → *could not answer*, with
  the gdbstub timeout verbatim; `fwhunt`/`ghidra` → *has not run*; `funcdiff` → its missing BASELINE named as a
  missing input rather than as a stage nobody ran.
  Named `deepscans` and not `capabilities` because the global nav already has a *Capabilities* page (the tool
  matrix), and two different things under one word is how a reader is misled.
- ▢ **`deepscans` renders each capability's STATE and denominator, not its payload.** Deliberate and recorded rather
  than half-built: the matches list, the nvram stores, ghidra's pseudocode and funcdiff's per-binary detail still
  have no surface. What the closed entry above was about — a stage that never ran being indistinguishable from one
  that ran and found nothing — is fixed; a rich per-provider view is separate work. Impact: medium for `yarascan`
  and `fwhunt`, whose matches are the finding itself.
- ▢ **`deepscans` is reachable only by URL, like the four sections in the entry below.** Adding it made that entry's
  count five rather than four: the step timeline is a curated pipeline and does not list it, and the sidebar carries
  no per-image sections at all. It should be closed together with `structure`/`files`/`hardware`/`compmap` rather
  than separately. Impact: high — a panel nobody can navigate to is a panel with no reader, which is the defect this
  iteration just closed arriving one level up.
- ▢ **`scripts/ui-drive.mjs` TRUNCATES the visible text it reports, mid-sentence, with no marker.** Found while
  validating the above: the page rendered six capability rows and the text dump stopped inside the third one's prose
  ("…so ther"), so grepping it for `dynprobe` returned nothing and the row looked absent. The screenshot was correct
  and the text was not. This is the loop's own validation instrument understating what it saw — the same class of
  defect as a bound reading as an answer, in the tool used to catch them. It should say it truncated. Impact: medium.
- ◐ **Thirteen API methods with no caller — the sharpest is closed and the diagnosis of the rest is corrected**
  (2026-07-30, `666047a`). Re-measured: still 13, and one of them (`funcdiffResult`) is one the previous iteration
  added. **`amendAssertion` is closed.** `OperatorPanel` rendered the full amendment history — `amendedAt`,
  `supersedes`, every superseded revision, read defensively — and no UI could produce one: a reader for a writer
  that was never built, the inverse of the defect that iteration closed. There is now an inline amend form on each
  live assertion row.
  **The pure decision is the DIFF, not the form.** The operator ledger is the most careful surface here — assertions
  carry no proof state and travel in their own array so they can never be mistaken for a measurement — so an
  amendment that changes nothing must not be recorded: it would push the original into `supersedes` and replace it
  with an identical claim, manufacturing a revision history out of a form submit. And the two nothings differ again:
  a form nobody touched, versus a field retyped to the same text. Identical values, different events, different
  sentences, both refused. `amend.ts`, 8 tests.
  Validated on the real deployed build (`/image/a2c03536/operator`, 0 console errors): a real assertion created and
  amended through the API leaves `amendedAt` set with 1 superseded revision, the row reads *"Amended 2026-07-30; 1
  earlier claim is kept in the record"*, the form opens pre-filled with what is stored, and with nothing edited it
  prints *"Nothing was edited, so there is nothing to amend… which manufactures a revision out of a form submit"*
  with **Save amendment disabled**. The WITHDRAWN table offers no amend action — a retraction is history and its
  whole value is that it stands as written.
  _Two defects of my own on the way: I gated the button on an author, which is wrong twice over — the amend route
  deliberately does not accept one (`assertedBy` is carried over so an edit cannot reassign authorship) and
  requiring it disabled the button for nothing the API asks; and the retyped-field test proved nothing, because
  `fireEvent.change` with the value already in the DOM fires no React `onChange` at all, so it passed as
  "untouched". It now types away and back, which is what retyping is._
  **STILL OPEN, with the diagnosis corrected — and it is ONE defect, not twelve.** The remaining twelve are almost
  all `*Result` getters, and the reason they have no caller is that **every panel reads the result of the job IT
  launched, never the stored one**: `SimulationMenu` calls `runChipsec`, `WebProbePanel` calls `runWebProbe`,
  `TestBench` calls `decompile`. So a chipsec, renode, webprobe, decompile or kernel-posture result that IS in the
  database vanishes from the screen on reload, and the getter that would fetch it is the uncalled method. The entry
  said "a result lives only in the tab that launched it" and that is exactly right — but the fix is one hydration
  pattern applied at ~5 call sites, not thirteen wirings. Impact: high; it is the same "the data exists and cannot
  be read" class the `deepscans` section just closed for the other five.
- ▢ **An amendment records no author, while a withdrawal does.** Surfaced 2026-07-30 while building the amend form,
  not fixed (it is an API change). `withdrawOperatorFinding` requires `withdrawnBy` — *"name who is retracting the
  claim"* — and the amend route deliberately takes no author at all, so `assertedBy` is carried over and
  `amendedAt` records only WHEN. A claim can therefore be reworded by someone other than its author, and the ledger
  attributes the new wording to the original author with no trace of the editor. In the one surface whose entire
  purpose is provenance. Impact: medium-high. The fix is an `amendedBy` on the assertion, optional forever.
- ▢ **`scripts/ui-drive.mjs --click` clicked the wrong element and said nothing** — FIXED 2026-07-30 (`40205bc`),
  kept here because it is the second defect found in this script in two iterations and the pair is the point. The
  whole implementation was `getByText(x, {exact:false}).first()`, so `--click "Amend"` landed on the row's PROSE
  (the attribution contains "Amended 2026-07-30", and that paragraph is earlier in the document); clicking a `<div>`
  succeeds, so nothing failed and the screenshot showed an unopened form. It now tries interactive elements first,
  exact before substring, and PRINTS which it clicked. The other finding — that it truncates the visible text it
  reports, mid-sentence, unmarked — is still open above. **Two false negatives from the loop's own instrument in
  two iterations is itself the finding:** everything this loop claims to have seen was seen through it.
- ✅ **Sections with no link anywhere in the app — and there were TEN, not four** (2026-07-30, `8457011`).
  Measured: the app had exactly THREE places that navigate to a section — the step timeline's 8 steps, one link to
  `operator`, one to `dossier` — against 20 sections in `SECTION_IDS`. URL-only: `structure`, `files`, `secrets`,
  `hardware`, `compmap`, `deepscans`, `testbench`, `diff`, `opacidad`, `agent`. This entry named four and did not
  count `secrets` or `testbench` at all. A `SectionIndex` on the dossier now links every one of them.
  **And the shell's own hint was half the defect**: *"Navigate the analysis from the step timeline at the top of the
  page"* pointed at a control reaching 8 of 19. A hint that answers the question wrongly is worse than none — it is
  not only that the link was missing, it is that the shell said where to look and it was not there. Corrected in
  both languages, and it now names the count.
  **What the index refuses to do**: decide which sections a device CLASS routes to. That mapping exists once in
  `specsForClass`, and a second copy in the web would be two lists of the same thing one commit from disagreeing —
  the trap this codebase already names about its own `SECTION_TITLES`. Everything is listed and reachable for every
  image; nothing is hidden on a guess. What the rows DO say is why a section may be empty on arrival, from the two
  facts the page already holds — and `extraction-not-run` is kept apart from `extraction-found-no-rootfs`, because
  collapsing them sends an operator to run an extraction that already ran. A section with no rootfs is still LINKED:
  reachability was the defect, and locking it would trade an unreachable panel for a needlessly closed one.
  `overview` is omitted — a dead id `resolveSection` remaps to `dossier`, and listing it would offer two links to
  one page and imply a section that does not exist.
  Validated on the deployed build (0 console errors): DVRF `/dossier` renders **19 linked sections**, `files` reads
  `ready`; the Pico RP2040 — extraction ran, no rootfs — renders `files`/`secrets`/`testbench` as
  `extraction-found-no-rootfs` with *"That is a measured property of this image, not a stage nobody started"*, while
  `entropy` stays `ready` because it does not read the rootfs. _One defect of my own, visible only by looking: I
  appended the index at the END of the dossier, i.e. below a 110-row findings ledger, 16,500 px down. An index
  nobody scrolls to is an index that does not exist — the defect it exists to fix, reintroduced by its position. It
  is now at 312 px of an 8,480 px page._
- ▢ **The step timeline still covers 8 of the 19 sections, and it is the primary navigation.** Surfaced 2026-07-30
  while closing the entry above, not implemented. The index makes everything reachable, but the timeline is what a
  reader uses to move through an analysis and it stops at `findings` — `deepscans`, `testbench`, `opacidad`,
  `operator` and `diff` are all stages of real work that never appear in the sequence. Whether they belong there is
  a design question (the timeline models the ANALYSIS pipeline, not the section list), which is exactly why it
  should be decided rather than left as a side effect of when each section was added. Impact: medium.- ✅ **Per-binary hardening was collected and never shown — and the blank INVERTED the finding** (2026-07-30,
  `84450d3`). `BinaryEntry` carries `nx`, `canary`, `pic`, `bits`, `importsSummary` and `emulationStatus`, and not
  one had a reader, while the matrix announced `hardening: done` labelled *"Binary hardening (NX / canary / PIC /
  RELRO)"*.
  **Measured, and it is worse than "collected and not shown": 2007 binaries in the corpus, 2 triaged, 2 with any
  hardening flag.** The fields are populated by radare2 triage, which is per-binary and on demand, so 2005 of 2007
  rows carry `null` in every column — on the DVRF, all 218. **And RELRO is measured NOWHERE in the API**: no
  provider, no column, not even the string, while the matrix named it in the technique's own label and called the
  technique done.
  So the load-bearing decision is not the rendering, it is what `null` MEANS. `nx: 0` is a measurement — this binary
  has no NX. `nx: null` is the absence of one. A column rendering both as a blank tells a reader that 2005 binaries
  are unhardened when nothing has looked at any of them, which does not lose the fact but **inverts** it. This is
  the one place in the workbench where the empty value points at the ALARMING conclusion rather than the reassuring
  one, and the three readings therefore share neither a word nor a colour. A third nothing gets its own number:
  triaged and yielding no flags at all — radare2 read the binary and recorded nothing, which a stripped or packed
  target legitimately produces. And when nothing has been measured the panel leads with WHY instead of drawing a
  grid of blanks, because a grid of blanks is the shape a reader skims past and skimming past it is how the
  inversion goes unnoticed. The matrix is now `partial` — its own catalogue header says *"`partial` must never sound
  finished"* — and the label no longer advertises RELRO as measured.
  Validated on the deployed build, both cases: DVRF renders *"a blank NX is not an absent NX"* with **654 badges,
  every one `not-measured`** (218 × 3, not one reading `off`); the IMOU renders *"hardening measured on 2 of 24
  binaries"* with the flags splitting **3 `on` / 3 `off` / 66 `not-measured`** — the two triaged binaries' six real
  readings kept apart from the 66 absences.
- ▢ **The hardening technique is effectively unexercised on this corpus: 2 of 2007 binaries.** Surfaced 2026-07-30,
  not implemented. radare2 triage is per-binary and on demand, and nobody has run it — so a technique the matrix
  lists has one image's worth of evidence behind it, from a session months ago. The question is not the renderer
  (closed above) but whether triage should be swept over the exposed/candidate binaries the way the ELF sweep
  already is, which would make the columns mean something on more than two rows. Impact: medium — it is the
  difference between a column that can be read and one that merely can be trusted to say it was not measured.
- ▢ **RELRO is measured by no provider, and the UI now says so rather than the gap being closed.** `checksec`-class
  data comes from radare2, which does report RELRO; the provider simply does not read or store it, and there is no
  column for it. `UNMEASURED_HARDENING` in `apps/web/src/hardening.ts` is the single place to change when it lands.
  Impact: low-medium — one of four advertised properties, now honestly labelled as absent.
- ▢ **`importsSummary` and `emulationStatus` still have no reader.** Two of the six fields the closed entry named:
  the hardening flags and `bits` now render, these do not. `importsSummary` is the per-binary import list radare2
  already extracted (the sweep's own signal for what a binary can call), and `emulationStatus` is what the emulation
  ladder recorded about that target. Neither is a hardening flag, which is why they were not folded into the badge
  row rather than left half-rendered. Impact: low for `emulationStatus` (the run ledger beside it carries the same
  story), medium for `importsSummary` — it is the evidence behind every `binary-pwnable-candidate`.- ▢ **PDF export** of reports.
- ✅ **External MCP tool surface** (2026-07-27) — `apps/api/src/mcp/` (`server.ts` + `client.ts` + pure, unit-tested `format.ts`) + project-scoped `.mcp.json`. A stdio MCP server exposing **10 tools** — `list_images`, `coverage`, `findings`, `list_binaries`, `capabilities`, `extract`, `run_worker`, `autonomous_scan`, `symbolic_reachability`, `job_status`. Talks to FirmLab over its own HTTP API rather than importing the providers, deliberately: the routes are where findings sync under idempotent sources and where the honest guards live, and the API process holds SQLite open, so a second in-process writer is a lock conflict waiting to happen. Transport is stdio and the deployed container publishes no host port, so **the `docker exec -i` channel IS the transport** (`claude mcp add firmlab -- docker exec -i firmlab node /app/apps/api/dist/mcp/server.js`); `FIRMLAB_API` + `FIRMLAB_MCP_HEADERS` cover a remote/SSO'd instance. **The non-façade part is `format.ts`:** handing this output to a model reintroduces the conflation the CoverageBanner exists to prevent, at a layer with no banner — `{"findings": []}` becomes "no vulnerabilities were found", which an empty list cannot support. So a result that could read as a negative carries its own verdict *inline, in the first field*: `findingsPayload` never emits a list without the coverage sentence and the names of the stages that produced nothing; `scanPayload` lifts the workers that did NOT complete above the narrative; `reachabilityPayload` restates `not_reached_in_budget` as the absence of a result rather than a negative one; and the server's `initialize` instructions brief the model on the proof-state ladder plus the two inferences that are always wrong here. Documented as AUTONOMOUS-WORKERS §10. **Validated in-container against the real bench (2026-07-27)** by driving the server over the `docker exec -i` channel exactly as an agent would: handshake at protocol `2025-06-18` with all 10 tools listed and a 1607-char instruction brief; 16 images and 19/19 tools enumerated; `symbolic_reachability` on the real DVRF derived `strcpy` from `pwnable/Intro/stack_bof_01` and returned **reached** (MIPS32) with the reachability-not-exploitability meaning attached, while an operator-named `system` on `sbin/chkntfs` returned `absent` carrying "nothing was learned"; a full agent-driven `autonomous_scan` ran **15 workers → 94 findings** with the 3 incomplete workers and the honest gaps ordered *above* the narrative, and coverage then closed the loop at 15/15. **Two defects the real run exposed, both now fixed + unit-pinned:** an image holding real findings from individually-run stages was headlined `UNEXAMINED` beside a verdict calling those findings real (now `COVERAGE UNKNOWN`), and the manual-probe hint claimed a binary "imports" a symbol that the sweep had only seen in its strings — angr resolved no PLT entry for it (see the `binvuln` entry below). _Follow-up (updated 2026-07-27): resources, prompts and the write path are now **closed** — `firmlab_add_image` ingests a file the SERVER can read (it tells the agent to `docker cp` first when the file is on the host and the server is in the container), three resources expose the proof-state guide plus report/disclosure-draft templates, and three prompts encode the methodology (`triage_image`, `hunt_memory_safety`, `compare_versions`), each written to steer away from the inferences the instructions warn about. Still open: the **third pass has not been run**_

## Autonomous workers — the *opacidad* section (see [`AUTONOMOUS-WORKERS.md`](AUTONOMOUS-WORKERS.md))
Surfaced by the two-pass app-vs-autonomous experiment (15 firmwares). Ordered by payoff; §refs into the design doc.
- ✅ **W0 · Triage/identity worker** — entropy-gated, device-class-aware image identity in `@firmlab/core` (`structure.ts inferIdentity` + `signatures.ts` esp-parttable/picobin recognizers + `mcu.ts parsePicobin`). Ordered class decision: `esp-parttable@0x8000→esp-soc` (arch from the ESP image-header `chip_id` — authoritative Xtensa-vs-RISC-V), `PICOBIN→baremetal` (ISA from the IMAGE_TYPE item, never the chip name), `UEFI→uefi-bios`, `FIT(dtb@0)+UBI→openwrt-fit-ubi`, strong-fs/uimage→`embedded-linux`, **whole-image entropy gate→`encrypted`** (before any 2-byte magic), corroborated JFFS2 node stream (≥4 valid node types)→`embedded-linux`. Kills the jffs2 2-byte false-positive. `FirmwareClass` gained the 4 new classes; `Architecture` gained `xtensa`; `ImageIdentity.classRationale` carries the honest "why / not Linux" line; preflight routes the new classes to `static-only`. **Validated on the real corpus: all 6 classes correct.** _Follow-up: precise ESP arch/app inventory belongs to W6; per-class UI banner still open (see below)._
- ✅ **W1 · Extraction worker** — recursive, format-graph carver in `apps/api/src/providers/carve.ts` (pure, unit-tested): `parseFitImages` (FDT walk → sub-image data ranges), `parseUbiVolumes` (PEB-size detect + per-volume LEB reassembly + names from the layout volume, **skips the empty overlay instead of aborting**), `pickRootfsVolume` (largest SquashFS, never `wifi_fw`), `planCarve` (FIT→UBI→SquashFS loop + step trace). `runRecursiveCarve` extracts via `unsquashfs`/`sasquatch`, degrading honestly (a carved-but-unextracted volume is a real result, never "0 files"). `extract.ts` routes `openwrt-fit-ubi` here + falls back when binwalk finds no rootfs; `ExtractResult.carveTrace` is the chain-of-evidence. **Validated on the real 111 MB GL.iNet FIT: selects `ubi_rootfs` (97 MB SquashFS) out of [wifi_fw, kernel, ubi_rootfs].** _Follow-up: the `unsquashfs` tail needs an in-container run to confirm the 7553-inode extraction; add cpio/jffs2/ubifs terminal-format handlers + ESP partition carve._
- ✅ **W9 · Orchestrator (opacity controller)** — `opacidad.ts` (+ pure `opacidad-plan.ts` / `opacidad-narrative.ts`, unit-tested) + `routes/opacidad.ts` + `OpacidadPanel` on a new "Autonomous scan" section. From W0's class it plans the ordered worker chain, runs the EXISTING providers feeding W1's rootfs forward, syncs findings under each route's source, and composes the reasoning trace (findings summary + `source→sink→privilege` attack path + honest gaps). Narrative is deterministic by default, LLM-phrased when `FIRMLAB_AGENT` is on (reorganizes real facts, never invents). Honest by construction: not-built deep workers (W6/W8/W4) → `not-built`, rootfs-less stage → `skipped`, absent tool → `degraded`; "0 findings" is never "clean". **Validated end-to-end on the real corpus** (DVRF Linux chain with certs/uboot/fcc on real bytes; GL.iNet W1 carve running inside W9 on the real 111 MB FIT down to the 97 MB SquashFS; ESP32→W6 not-built). **Re-planning added:** the class DAG is now only the SEED of a dynamic **worklist** — `opacidad-plan.ts` gained a pure `replan`/`scheduleLeads`/`specKey` (lead → follow-up spec, deduped, capped at 8 dynamic steps with an honest overflow gap); `opacidad-leads.ts` resolves leads from real worker output (each autostart network daemon → decompile it; the httpd serving a tainted W4 handler → decompile it, resolving the binary inside the rootfs). A new **W5 targeted binary-vuln** executor (`decompileRun`) runs the scheduled decompile + taint scaffold, syncing under the same idempotent `binary:<path>` source as the manual route. Re-planned steps carry `origin:'replan'` + the triggering lead through the narrative + `OpacidadPanel`. **Validated on real `runServiceMap` output over a DVRF-like rootfs: the 9-worker seed grows to 12 as dropbear/httpd/telnetd schedule targeted W5 steps.** _Follow-up: LLM-narrative still validated only offline; symbolic-reachability leads (angr) as a further re-plan source._
- ✅ **W6 · ESP/IoT-SoC worker** — `apps/api/src/providers/esp.ts` (pure, unit-tested): `parsePartitionTable` (0xAA50 entries @0x8000 → app/ota/nvs/spiffs/coredump inventory), `parseNvsRegion` (4096-byte NVS pages → 32-byte `ns/type/span/crc/key/data` entries, multi-span blob reassembly, **entry-state bitmap** written/erased + superseded-duplicate detection, blob_data/blob_idx pairing), `assessSecurePosture` (Flash-Enc/Secure-Boot/anti-rollback inferred from a plaintext app image, honest `unknown` when indeterminate). `analyzeEsp` composes → `critical` NVS key material (full value in evidence, redacted title), `high` stale/erased-recoverable entries, `high` OFF posture, `info` partition inventory. Wired into W9 (`provider:'esp'`, `esp-soc` → built). **Validated on the real ESP32 dump: recovers the exact 32-byte signing key `98a39f0b…8877e893` from NVS ns=4 `privkey` blob_data, the erased credential lineage `aaronf→aaron→founder3→founder4`, and Flash-Enc/Secure-Boot/anti-rollback OFF.** _Follow-up: `nvs_keys`-encrypted NVS, coredump parsing, live eFuse reads for definitive posture._
- ◐ **W7 · Bare-metal/RTOS worker** — vector table + **load-base recovery** done (Cortex-M). **Plaintext flag/UART-credential extraction added (2026-07-22, 1762de3)**: `providers/rtos.ts` `extractFlags()` emits `baremetal-flag` findings on the non-Cortex-M path too, and `detectEcos()` gives eCos MIPS/RISC-V images real output. _Still open: on-device **decode-routine reversing** (the RP2350 CTF's `ror+sub+xor` `decode()` hides the flags behind an obfuscator — plaintext extraction honestly won't recover those)._
- ✅ **W8 · Encrypted-blob worker** — `apps/api/src/providers/encrypted.ts` (pure, unit-tested): `parseOtaHeader` (big-endian length field, plaintext ASCII tags, framed `AA55…16…55AA` IV block, ciphertext-body offset — each degrades honestly to null on an unframed blob), `classifyCipher` (16-byte IV ⇒ 128-bit block ⇒ AES; high-entropy body + no repeated 16-byte blocks + IV ⇒ CBC/CTR; repeated blocks ⇒ ECB; reuses core `windowEntropy`). `analyzeEncrypted` → `high`/`static_confirmed` cipher diagnosis (IV in evidence), `high`/**`blocked_by_security`** "unrecoverable without the key" verdict with the key-recovery path named, `info` plaintext-metadata leak. Never a silent empty — even a headerless high-entropy blob gets the verdict. Wired into W9 (`provider:'encrypted'`, `encrypted` → built). **Validated on the real GE800 OTA: length 0x036212d9, `fw-type:Cloud`, the exact 16-byte IV `4c5e831f…8bf7da1` @ 0x116, body entropy 8.00, AES-128 CBC/CTR — matching the §7.5 headline.** _Follow-up: known-plaintext crib detection; bootloader-key extraction is Phase-6 capture._
- ✅ **W4 · Web attack-surface worker** — `apps/api/src/providers/webtaint.ts` (pure parse, unit-tested): `parseHandler` (exec sinks — flagging the injectable **string-concat** form vs a hardened **argv-array**; sources `params.*`/`uci:get`/CGI-env; `fromUci`; `runsAsRoot` from root-owned-path writes), `extractRpcArgPattern` + `patternPermitsNewline` (models Lua `%s` permitting `\n` → the torrc-directive-injection primitive), validator/`no-auth-methods`/per-object-validator resolution over the rootfs. `buildTaintFindings` → `critical`/`static_confirmed` cmdi with the **source→sink→privilege** chain in evidence (renders in W9's attack path) + the `web-taint-restore-bypass` (uci import sidesteps the RPC validator). Wired into the Linux chain (`provider:'webtaint'`, needs rootfs). **Validated on a faithful synthetic GL.iNet rootfs AND end-to-end in-container on the REAL GL.iNet BE3600 4.9.0** (redeployed `028ca16`, uploaded via the loopback API, ran `/opacidad`, then deleted): W1 carved the real FIT→UBI→SquashFS→`unsquashfs` rootfs (**6497 files**, arm64), and W4 flagged **2 tainted handlers → 4 findings** on the real bytes — the crown-jewel `usr/lib/oui-httpd/rpc/tor` `os.execute` root-RCE (`params.enable → uci → shell as root`, critical) + its config-restore bypass, AND the secondary `rpc/wg_client` `io.popen` cmdi (correctly downgraded to `high` because a per-object validator `gl-validator.d/wg_client.lua` exists) + its restore bypass. W9 re-planning then scheduled + ran a W5 decompile of the serving `uhttpd` (taint surface 9 sinks/3 sources); 10 workers, 633 findings, LLM narrative live. _Follow-up: refine `extractRpcArgPattern` (the 4.9.0 validator `^[%a_-][%w_-]-` was captured slightly truncated — verdict correct, evidence string imperfect); multi-line sink args; WR940N httpd C-source cmdi._
- ✅ **W2 component-fingerprint CVE** — `providers/component-cve.ts` (2026-07-22, ea81dfa): fingerprint bundled binaries (pppd/openssl) by the version string IN the binary and match a curated table of verified embedded n-days a manifest-only SBOM can't see. **pppd 2.4.2–2.4.8 → CVE-2020-8597 (critical)** closes the WR940N + WDR3600 0-CVE gap; openssl 1.0.1–1.0.1f → Heartbleed. Pure version algebra, wired into the Linux chain as `compcve`. _Follow-up: extend the table (dropbear, lighttpd/goahead, dnsmasq) + Go-module fingerprint inside static binaries._
- ◐ **W3 secret extraction + offline cracking** — device stores (NVS via W6) done. **Embedded-private-key-by-CONTENT scan added (2026-07-22, 8ba5f45)**: `fsaudit.scanContentSecrets()` flags a PEM key inside any file (caught Tenda's `O=Tenda` RSA key regardless of filename). **Offline cracking done 2026-08-03** as `providers/credmatch.ts` — a cross-reference of the stored hashes against the image's own strings, which needs neither a wordlist nor a GPU and recovers `Td2N3ww1` (Tenda CP3) and `sohoadmin` (WDR3600) on the real corpus. _Still open: nvram store parser._
- ✅ **W0 eCos / RTOS-on-application-CPU classification** (2026-07-22, 1762de3) — `core/structure.ts looksLikeEcos()` marker gate (`cyg_*`/RedBoot/zxrouter); an eCos monolith with no Linux fs now classifies as `rtos` (mips→mipsel/LE) instead of `embedded-linux`, and `rtos.ts detectEcos()` surfaces the version/RedBoot/app. Both Xiaomi repeaters now classify correctly. A real Linux image that merely mentions RedBoot still wins on its filesystem.
- ✅ **W1/W3 auxiliary-partition secret extraction** (2026-07-22, 58d414d) — `providers/auxsecrets.ts` `runAuxSecrets()` scans the WHOLE extraction output (every carved filesystem), SKIPPING the recognized rootfs subtree (fsaudit covers it), content-scanning the rest. **Validated in-container: Tenda-Camera's 1024-bit RSA private key `jffs2-root-0/-1/version/privkey.pem` — in a sibling partition `findRootfs` never recognizes — now emits 2 `embedded-private-key` findings.** Honesty note: **BeanView-Camera's `private_key.pem`/`devinfo` are actually PUBLIC keys** (`BEGIN PUBLIC KEY`), NOT a cloud secret — the pass-1/re-run "cleartext cloud pairing secret" headline was an autonomous overstatement; the content scan correctly does not flag public keys. _Follow-up: parse the `devinfo`/`DeviceInfo` KV blobs for a real provisioning token if one exists._
- ✅ **Corrupted / decoy-image honest verdict** (2026-07-22, 0436836) — `providers/decoy.ts` `assessDecoy()`: when a filesystem was CLAIMED but no rootfs was recovered AND the image is mostly zeros, `opacidad`'s extract stage emits a `corrupt-decoy` finding (medium, static_confirmed) instead of a silent empty. Asus-Router.bin (93% zeros) now reads as "payload destroyed", not "clean".
- ✅ **`binvuln` reads the real symbol table** (2026-07-27) — it used to title findings "`X` imports `system`" off `extractSymbols`, which lifts C-identifier tokens out of the ELF's printable strings and is *a superset of the imports* by its own docstring. Proven over-broad while validating the MCP surface: `sbin/chkntfs` was flagged as importing `system` and angr resolved **no PLT or symbol entry** for it. New pure `parseDynamicSymbols` walks the section headers to `.dynsym`/`.dynstr` in both widths and both endiannesses (no `readelf` dependency) and reads the names the loader must actually resolve. Writing its test caught a real bug in it: **`sh_link` sits at 0x18 in ELF32 and 0x28 in ELF64**, and ELF32 is the overwhelmingly common case in firmware — the mips-BE case is now pinned. Where there is no readable table (a truly static binary) the string scan still runs and the finding SAYS so: "references" instead of "imports", with the rationale stating a mention is not proof of an import, and `symbolSource` recorded in the evidence. **Measured on the real DVRF_v03: 39 → 43 candidates**, i.e. the string heuristic was both over- and under-reporting.
- ✅ **W5 · Binary-vuln sweep (breadth)** (2026-07-22, eeaec41) — `providers/binvuln.ts`: rootfs-wide scan of every ELF for unbounded-copy imports (gets/strcpy/strcat/sprintf/scanf-family) + ABSENCE of a stack canary → `binary-pwnable-candidate` (medium, needs_runtime_reproduction lead), plus `binary-cmdexec-sink` for system/popen/exec imports. Complements the existing W9-scheduled targeted decompile; closes the DVRF "zero pwnables surfaced" gap — **confirmed in-container on the real DVRF_v03 (2026-07-27): 218 ELFs scanned, 39 candidates.** _Follow-up: full memory-safety proof — done, see the angr symbolic-reachability entry above; a candidate whose sink is proven reachable is upgraded by a separate `sink-reachable` finding rather than by mutating the candidate._
- ✅ **UI: honest-degradation banner** (2026-07-27) — `providers/coverage.ts` (pure `buildCoverage`, unit-tested) + `GET /images/:id/coverage` + `CoverageBanner` above the Findings stage. Reads `specsForClass` — the SAME plan W9 executes, never a re-derivation — plus the last opacidad run's per-worker outcomes, and emits one sentence that can never conflate the cases: nothing ran ⇒ "an empty findings list here means UNEXAMINED, not clean"; some ran ⇒ "zero findings covers only the stages that ran" and it NAMES the uncovered ones; all ran ⇒ "a real negative for what this deployment can check statically — not proof the firmware is secure". The expandable per-stage table answers "what can I even run on this image?" up front, marking each stage found / ran-empty / degraded / no-input / not-built / not-run, and lists W9's dynamically re-planned workers as coverage the class DAG never named.
- ✅ **UI: corpus-level coverage on the Dashboard** (2026-07-27) — `GET /coverage` (same `buildCoverage`, one row per image) + a Coverage column and an "N of M unexamined" chip on the Images panel, sortable so "what has nobody looked at?" is one click. Without it the listing presented a never-analyzed image and a fully-scanned one identically — the per-image banner's conflation, reintroduced at corpus scale. Honest in the failure case too: if the corpus report does not load, the column shows `—` and the unexamined tally counts nothing, because "we could not check" is not "unexamined" (a unit test pins this — the first implementation got it wrong). **Validated in-container on the real 17-image corpus**, which immediately exposed a verdict defect now fixed: DVRF_v03 read "Nothing has analyzed this image yet" next to its own 28 findings, because coverage measures only the autonomous scan's per-worker outcomes and a stage run from a manual route is invisible to it. With `executed === 0` **and** findings present the verdict now says coverage is UNKNOWN and names where those findings came from, instead of a sentence its own row contradicts.
- ✅ **Corpus re-analysis** (2026-07-27) — `POST /images/:id/analysis` + `POST /analysis/reanalyze-all`. `identityJson` was written once at upload and never refreshed, so every image ingested before a W0 improvement kept its original class — and BOTH `specsForClass` (W9's plan) and the coverage banner route off it. Re-uploading was the only workaround and it discards findings and job history. A failed re-analysis leaves the stored analysis alone: a stale class is bad, replacing it with nothing while reporting success is worse. **Run on the real 16-image corpus: 7 reclassified** — both Xiaomi repeaters `embedded-linux → rtos`, `Pico-RP2040_CTF` and `pico.bin → baremetal`, `GL.iNet-BE3600 → openwrt-fit-ubi`, `GE800 → encrypted`, `ESP32-DevBoard → esp-soc`. Nearly half the bench had been planning against the wrong device class.

## Deployment — environment hazards (found 2026-07-27)
- ✅ **A stray host-side `pnpm dev:api` silently shadows the deploy** — `scripts/deploy.sh` now runs `check_port_squatter 8799` and in-container `docker exec … curl` is the documented validation path. The container publishes NO host port (the homelab compose fronts it), so `curl 127.0.0.1:8799` on the Mac can hit a leftover dev server instead — it answers, it looks right, and it reports `"build":"dev"` with none of the container's tools, so extraction "fails" for reasons that have nothing to do with the deploy. Cost real debugging time. Worth a guard: have `scripts/deploy.sh --check` warn when something other than the container is listening on 8799, and drive in-container validation through `docker exec … curl` as the documented path.
- ✅ **bettercap is not in `Dockerfile.tools`** — closed 2026-07-27 by *Spoof made real, and honestly bounded* (Recon & acquisition, 6.2): bettercap ships as a last layer, and the honest answer turned out to be BOTH halves of this entry — the tool is installed AND spoof is host-only by design, because `assessL2Reach` gates on layer-2 reach first and a bridge-networked deploy is told the spoof is impossible there rather than pointed at a `--cap-add` that cannot help.

## Deployment — build architecture
- ✅ **Invert the image layering** — done: `Dockerfile.firmware` is `FROM firmlab-tools:latest` with the app copied on top. Was: `FROM firmlab:latest` (tools layered ON TOP of the app), so ANY app-code change rebuilds ALL heavy tool layers (incl. the ~20-min AFL++ QEMU compile). Restructure to a `firmlab-tools` base (tools only) + the app copied on top, so app changes are a fast final layer. Big win for iteration speed.

## Deployment — tool-recipe fixes (ALL RESOLVED 2026-07-21)
- ✅ **libnvram cross-build** — missing target libc headers; add `libc6-dev-{mipsel,mips,armel,arm64}-cross`. All 4 guest `.so` build + present in deploy. Unlocks chroot-service.
- ✅ **firmadyne kernels** — the raw-repo path 404s; kernels live in GitHub Releases (`pr0v3rbs/FirmAE_kernel-v4.1` v1.0). 4 kernels present in deploy. Unlocks full-system.
- ✅ **Ghidra** — two bugs: (a) `api.github.com/releases/latest` was rate-limited mid-build → pin a DIRECT release URL; (b) Debian bookworm has no JDK 21 (Ghidra 12.x needs it) → fetch a portable Temurin JDK 21 from Adoptium. Also fixed the app detection (`tools.ts` ran the JVM with a 4s probe timeout → reported absent → refused to run; now detected by PATH existence).
- All six heavy tools (chipsec, Renode, AFL++, libnvram, firmadyne kernels, Ghidra) now install + activate in the deploy.

## Peer-tooling cross-check (wairz + the installed tool set, 2026-07-28)
Second pass over wairz, this time against the local checkout (**110 AI tools**, enumerated from
`backend/app/ai/tools/`) rather than its docs, crossed with what `tools.ts` actually probes for (23 specs).
Most of what it surfaces is already on this ledger — interactive emulation, the UART bridge, cross-binary
dataflow, the library fuzz harness, cmplog, RTOS task enumeration, PDF export, `.ko` CVEs — and is not repeated
here. What follows is what was **not**, each verified absent from this file, from `METHODOLOGY-GAPS.md` and from
the code, ordered by value ÷ effort. The bookkeeping item is last and is the one worth reading first.

**Five of these shipped the same day, built in parallel in isolated worktrees and merged as
`integrate-crosscheck`** — the filesystem read surface, operator assertions, kernel posture, device-tree intel
and update-path integrity. Each is marked ✅ below with what it measured on real corpus bytes; the follow-ups
they surfaced are gathered under *Follow-ups from the five* at the end of this section. Gate on the merged
tree: `pnpm check` 3/3, **1307 tests** (75 core / 1160 api / 72 web), biome clean, `check-nul.sh` clean.

- ✅ **The extracted filesystem can be opened** (2026-07-28) — `providers/fsbrowse.ts` (pure, 48 tests against
  real temp trees with real symlinks) + `routes/files.ts` + `firmlab_list_files`/`firmlab_read_file` +
  a `files` workbench section. The root is the extraction dir rather than the rootfs, so BeanView (54 volumes,
  no rootfs) and Asus-Router (truncated SquashFS) browse as what they are instead of as empty trees. The guard
  is three layers and the third is the one that matters: the lexical containment test the other providers share
  passes a symlinked *ancestor*, and only a `realpath` check catches it — **the test asserts the lexical test
  passes it first, so it cannot rot into agreeing with the code.** Text-vs-binary is decided from the bytes,
  never the extension. **Validated in-container: BeanView's `private_key.pem` reads 460 bytes of
  `-----BEGIN PUBLIC KEY-----` over HTTP** — the surface that would have caught the withdrawn entry above.
  GL.iNet walks 6279 files / 740 symlinks in 113 ms with one directory capped (`usr/lib/opkg/info`, 2219
  entries) and the rule stated. _Three defects the real bytes exposed: `truncated` ignored bytes skipped BEFORE
  the window, so a tail read reported as a complete file; a literal NUL byte reached the source **in the
  NUL-check itself**, invisible to grep and caught only by `scripts/check-nul.sh`; and Asus-Router's stored
  extract result predates `extract-diagnose.ts`, so "no diagnosis was recorded" read as though the extractor had
  nothing to report rather than as a missing field._
- ✅ **A person can write to the ledger without writing a proof state** (2026-07-28) — `operator-findings.ts`
  (pure, store-free, 27 tests) + `routes/operator.ts` + `OperatorPanel` + an `image_note` table. **`ProofState`
  did not grow a rung**; the *field* widened by exactly one non-rung value (`operator_assertion`), and an author
  picks a **claim** from a vocabulary disjoint from the ladder — no shared token, so no careless `includes()`
  can slide an assertion onto it. Four independent layers keep it separable, so no single lapse collapses the
  distinction: disjoint vocabulary · a self-describing sentinel (a reader predating the feature renders an
  unfamiliar string rather than mapping it to a measurement) · `operator:%` excluded **inside the SQL** of
  `deleteFindingsBySource`, not by callers remembering · and the MCP client stamping `x-firmlab-author-kind`
  unconditionally and last, so an agent cannot sign as a human. The agent loop is closed explicitly: assertions
  are lifted out of `findings` *and* out of `proofStateCounts`, and an agent's own rows come back
  `selfAuthored` under a notice that a record of a claim is not evidence for it. Withdrawal is first-class and
  requires a reason; nothing is ever deleted. **Validated against a read-only copy of the live 14 MB database:
  coverage arithmetic unmoved at 17 applicable / 16 executed / 101 findings with the prior verdict string
  surviving verbatim, and re-running `certs`/`compmap`/`fsaudit` removed 7 provider rows while the 2 operator
  rows stood.** _One defect the tests caught first: `slugify` mangled accented names (`Aarón` → `aar-n`), so the
  same person writing with and without the accent landed in two namespaces and had their record split by a
  keyboard layout. Fixed with NFD + `\p{M}` — the property escape, not a literal combining-mark range, since
  those are invisible in source in the same way the NUL byte is._
- ▢ **A measured fact cannot be corrected by an operator who knows better.** wairz has `set_firmware_arch`,
  `set_rootfs`, `set_kernel`, `redetect`. FirmLab has `POST /images/:id/analysis`, which re-derives — it cannot
  be told anything. The corpus is full of cases where that costs: DVRF's `identity.arch` is `unknown` (the
  dynprobe route had to learn to prefer extraction's measurement over it), Asus-Router carves a SquashFS whose
  id table is inside trailing zeros, and the two camera rootfs are "suspiciously small" with nothing able to
  settle it. **The class is the expensive one** — it drives `specsForClass`, so a wrong class means the whole
  plan was wrong, and re-uploading is the only remedy while it discards findings and job history. Fits the
  vocabulary already spoken here: an override is a claim with different provenance (`measured` vs
  `operator-asserted`), and coverage must say the plan ran against an asserted class.
- ✅ **Rule-based scan of a Linux rootfs** (2026-07-29, `12bb016`) — `providers/yarascan.ts`, the FwHunt recipe one layer down. **FirmLab authors no signatures**: the corpus is operator-supplied via `FIRMLAB_YARA_RULES` with an empty built-in, for the reason this file already records about hand-guessed UEFI GUIDs. Each rule file compiles into its own YARA namespace so a hit is attributed to its rule and source, and the rationale says a rule named after a malware family is that author's label rather than an identification of this firmware. Severity comes from the rule's own `meta` when it declares one, marked `firmlab-placement` when it does not. The clean scan reads *"no rule matched — 1/2 rule(s) applied over 2/2 file(s), which is not 'no implant'"*, and the denominator accounts for the gap: `private` rules examine nothing on their own and are not coverage, and a file this yara build refused to compile is named with why. A failed combined compile probes each file individually and drops only the bad ones. The cap ranks by what the first bytes say a file IS, then location, then path — never walk order. **Seven outcomes stay apart**, only one of which may be read as a statement about the firmware.
- ✅ **The rule-matched branch had never met a real yara — it has now, and the run was worse than predicted** (2026-07-30, `12fbd79`). `yara` 4.2.3-4/arm64 installed and driven against the real DVRF rootfs with a 3-file corpus, one file deliberately broken. **yara prints compiler diagnostics in TWO shapes and this module knew one**, because the parser was authored from `cli/yara.c`'s print order: `mod.yar(1): error: unknown module "string"` (file-scoped, which worked) versus `error: rule "Broken" in bad.yar(1): undefined string "$nope"` and `warning: rule "Slow" in w1.yar(1): string "$a" may slow down scanning` (rule-scoped, dropped entirely — and the COMMON shape, since it is what any broken or slow rule in an operator's corpus produces).
  **It was not a formatting defect. It disabled the recovery path.** `compileEachRuleFile` — drop the file that will not compile, re-run with the rest — is gated on `parseCompileDiagnostics(...).some(d => d.level === 'error')`, which was `[]` for the real shape, so it never fired. Measured A/B on the same real bytes: **before** `state: scan_failed`, reason `"Command failed: yara -e -g -a 60 …"`, declared 5 / **applied 5** / rejected 0, **0 matches, no files recorded as scanned**; **after** `state: scanned`, declared 5 / applied 4 / rejected 1, 4 match groups, 5 findings, **235 files scanned**. So one malformed rule in a public ruleset returned zero matches while the denominator claimed all five rules had been applied — a bound reading as an answer, which is the thing this provider exists to prevent. It is also the third instance of *"a guard is only as good as its SUCCESS path, and that is the path nobody runs"*.
  `CompileDiagnostic` gains `rule`, optional forever and ABSENT rather than empty for a file-scoped diagnostic, where there is no rule yet — not the same as a rule whose name could not be read. Test fixtures are now strings CAPTURED from the live binary. `Dockerfile.tools` gains `yara` in its first apt block.
  **Correcting a prediction this entry carried:** it said a Debian build lacks the `cuckoo` module. It does not — measured on 4.2.3-4/arm64, `import` succeeds for cuckoo, magic, hash, dotnet, math, pe, elf, time, console, macho and dex; only a deliberately invented name fails. So `missing-module` has no trigger on this platform, which is a fact about that branch's coverage rather than a reason to drop it. Also verified: `-a` is `--timeout=SECONDS` (the provider's use is correct), and `--scan-list` output order is NOT the list order — yara scans threaded, so nothing may depend on it.
- ✅ **The tools base was rebuilt the same day, so the deployed image HAS yara** (2026-07-30, `deploy.sh --tools`, build `8011ea2`). `/api/tools` now reports **25 of 25 available**, yara 4.2.3 among them — it was the only absent tool. Validated end to end on the deployed build, no hand-copied module: a 2-file corpus with one broken rule over the real DVRF rootfs gives `state: scanned`, 235/235 files scanned, 0 too large / 0 over cap / 0 failed, the rejected file named (`broken.yar · undefined-identifier · undefined string "$nope"`), and `Telnetd_Binary [network,backdoor]` matching `bin/busybox` at `medium` / `static_confirmed` — beside the coverage finding *"1 rule matched — 1/2 rule(s) applied over 235/235 file(s)"*, which is the denominator staying honest about the rule that was dropped.
- ▢ **A rule-scoped WARNING now parses and still changes nothing.** `parseCompileDiagnostics` keeps warnings — the module's comment always promised it and the code now delivers it — but nothing downstream reads them: `compileEachRuleFile` filters to `level === 'error'`, so `string "$a" may slow down scanning` is parsed and discarded. A slow rule is a coverage risk (yara may time out per file under `-a`), which is exactly the kind of bound this provider reports elsewhere. Impact: low, and it is a promise the prose still overstates.
- ▢ **yarascan has no web panel and no coverage routing.** `ImageDetail.tsx` has no section for it and neither `coverage.ts` nor `opacidad-plan.ts` routes to the stage, so the coverage banner does not count it and the result is API/MCP-only. Until it is routed, a scan that never ran is invisible rather than reported as not-run — the conflation the banner exists to prevent.
- ▢ **`include` directives undercount `rulesApplied`.** A rule pulled in via `include` is counted once, in the included file's own entry, but compiled into every including namespace — so the applied count understates what yara actually ran. Conservative in direction and still wrong. Also: `--scan-list` is YARA ≥ 4.0, and on an older build the run reports `scan_failed` with yara's usage error rather than naming the version as the cause; and `-s/--print-strings` is off, so a match carries no matched bytes as evidence.
- ▢ **capa — capability inventory, which is a different question from vulnerability.** `capa` reports what a
  binary *can do* ("spawns a shell", "reads /dev/mem", "communicates over raw sockets", "implements XOR crypto")
  with evidence at addresses. That is `static_confirmed` in the strictest sense — a code fact, no exploitability
  claim attached — and it answers "what does this vendor daemon actually do", which today is answered only by
  hand through decompile triage. **Measure before promising:** capa's rule corpus is x86-centric and this corpus
  is mipsel/arm/arm64, so the honest first step is running it against DVRF and the GL.iNet and reporting the
  coverage, exactly as the FwHunt rule count was measured before it was claimed.
- ▢ **The non-ELF attack surface has one vendor-specific parser and no general lane.** `webtaint` reads
  GL.iNet's `oui-httpd` Lua RPC shape and found the crown jewel there — and it structurally cannot read
  WR940N's C httpd, a busybox-ash CGI, a PHP admin panel or a Python service, which is most of what the corpus
  actually ships. A generic pass over shell/lua/php/python with a small hand-written ruleset (unquoted
  `$QUERY_STRING` reaching `eval`/backticks, `system()` on a CGI env var) generalizes the W4 *result* instead of
  duplicating the W4 *parser*. The existing "WR940N httpd C-source cmdi" follow-up is one image; this is the lane.
- ✅ **The kernel's own posture, in three states, never two** (2026-07-28) — `providers/kernelposture.ts` (pure,
  49 tests, fixtures read out of the container with `strings` rather than remembered) + `routes/kernel.ts` +
  `W2 · Kernel posture` in `LINUX_CHAIN`. Nine questions (KASLR, `STRICT_DEVMEM`, `IO_STRICT_DEVMEM`, `DEVKMEM`,
  `MODULE_SIG`, `STACKPROTECTOR`, `STRICT_KERNEL_RWX`, `kptr_restrict`, `dmesg_restrict`) plus age, located in
  priority order: shipped `.config` → module set → carved blob → `/boot` → raw image. **The three-state logic
  is the feature and it held on real bytes**: 53 undetermined answers spread over *three distinct reasons*
  (`option-postdates-kernel` 23, `no-kernel-config-shipped` 22, `no-kernel-blob` 8) against 10 determined ones,
  so it never collapsed to the two-state overclaim this codebase has paid for twice. `CONFIG_*` tokens are
  **measured not to be an oracle** — the 2.6.x kernels carry zero of them and one of the three in the 4.x
  kernels occurs only inside the printk `"initcall_blacklist requires CONFIG_KALLSYMS"` — so they are recorded
  and never consulted; markers are symbols and printks instead. The mirror trap is handled too: `/dev/kmem`
  *predates* `CONFIG_DEVKMEM` (2.6.26), so gating the device on the switch would have reported DVRF's 2.6.22 —
  which demonstrably ships `kmem` — as "the option does not exist here". **Measured across the corpus: the four
  TP-Link/DVRF images run 2.6.22–2.6.31, kernels 22 years old, one of them (WR940N) with a 2026 build date; the
  BE3600 is 5.4.213 read from module vermagic with 375 modules and 0 signed.** _One defect the real bytes
  exposed: the first run reported the BE3600 as kernel 4.4.0 read from `carve/rootfs/usr/sbin/tailscaled`, a
  30 MB Go binary embedding a `Linux version` string — the doc promised banners are never read from a rootfs,
  and the unit test had placed the rootfs BESIDE the extract dir, so it agreed with the code instead of checking
  it._
- ✅ **The device tree becomes a result, and there is now one FDT walk** (2026-07-28) — `providers/fdt.ts` (the
  reader, 22 tests) + `providers/devicetree.ts` (analysis, 30 tests) + `routes/devicetree.ts` + entries in both
  `LINUX_CHAIN` and `RECON_ANY_CLASS`. `carve.ts`'s `parseFitImages` was **reimplemented on top of it** and its
  duplicate token loop deleted, so a second subtly-different FDT parser never exists; `parseFitConfigurations`
  joined it there. The `/chosen` command line was factored into `providers/boot-cmdline.ts` and emits the
  **same codes** `uboot.ts` already emits (`uboot-root-shell`, `uboot-serial-console`) with provenance in the
  evidence, rather than a second dialect for the same fact. **Read off real firmware: the BE3600 is
  `GL.iNet BE3600, Inc. IPQ5332/AP-MI04.1-C2` / `qcom,ipq5332`, 378 nodes reached through FIT → UBI → kernel
  volume → inner FIT → `flat_dt` and selected by `/configurations default = config-1`, with its console UART at
  `/soc/serial@78af000` resolved through `stdout-path`; the Tenda camera carries TWO trees with nothing
  declaring which the device uses, and real `root=/dev/mtdblock5 init=/sbin/init mem=64M`.** _The defect the
  bytes exposed is the reason the provider requires a complete walk: the GL.iNet raw image has a **perfectly
  valid FDT header** at offset 10186216, but the tree lives inside a UBI volume, so the raw file splices
  eraseblock metadata through it — it diverges from the true blob at byte 37820, the strings block is clobbered
  so **826 property names decode wrong while the values still look right**, and the walk dies at 10224040. A
  header check cannot see that; finishing the walk can, and the raw hit is reported in `rejected` with the
  `UBI#` located as evidence. Two parser rules the spec would also have got wrong: availability follows the
  kernel's `of_device_is_available` (that tree spells `status = "ok"` 32× against one `"okay"`, and Tenda adds
  `"disable"`), and property typing uses dtc's exact `util_is_printable_string` — the naive version reads
  `clock-frequency = <0x7d00>` as a string._
- ▢ **The fuzzer has no input side.** The ledger carries cmplog and libdesock — both about the *harness*. wairz
  carries `generate_fuzzing_dictionary`, `generate_seed_corpus`, `analyze_fuzzing_target`, `triage_fuzzing_crash`
  and `diagnose_fuzzing_campaign`. AFL++ pointed at a firmware parser with an empty corpus and no dictionary
  mostly measures the harness, and both inputs are straight deterministic derivations from bytes already on
  disk: the dictionary from the target's own strings, the seeds from the rootfs's own config/data files matching
  the format the target parses. **Crash triage is the ledger half** — N crashes that are one bug must not become
  N findings, which is the `syncFindings` idempotence argument applied to fuzzing output.
- ▢ **`qemu-*-static -strace` on a probe run, for free.** `sandboxShortfalls` currently infers what the sandbox
  failed to provide by pattern-matching the target's stderr — real work, and an indirect measurement. The
  syscall trace of the same run says directly what the binary tried to open (`/dev/nvram`, a missing config, a
  socket) and would turn that inference into evidence. No new tool: the flag is on a binary already installed
  and already invoked by `dynprobe-run.ts`.
- ▢ **The MCP surface cannot navigate a binary.** 10 tools against wairz's 110, and the asymmetry is not
  uniform: FirmLab's tools are *better* where they overlap, because `format.ts` refuses to emit a list without
  its coverage verdict, which is precisely what wairz does not do. What is missing is the exploratory half —
  `xrefs_to`/`xrefs_from`, `find_callers`, `find_string_refs`, `list_imports`/`list_exports`/`list_functions`,
  `resolve_import`, `hexdump_data` — i.e. every question that sits *between* "here is a lead" and "here is a
  verdict". radare2 already answers all of them for `compmap` and `binvuln`; nothing exposes them. **The third
  app-vs-autonomous pass is still unrun, and this is the change most likely to move it.**
- ▢ **binwalk v2 is the only carver — and the diagnosis module makes a second one cheap to evaluate honestly.**
  `extract-diagnose.ts` established that two of the three empty extractions are damaged input rather than a
  missing extractor, which is a real result and not a hedge. `unblob` has materially wider format coverage and
  sandboxed per-format extractors, so running it over the same three images is a **measurement, not a promise**:
  if it opens what binwalk did not, the diagnosis was wrong and we learn where; if it does not, the diagnosis is
  independently confirmed. Either outcome is worth the run, which is not true of most tool additions.
- ✅ **Update-path integrity — the #4 priority that was never built and never recorded** (2026-07-28) —
  `providers/updatepath.ts` (pure, 58 tests) + `routes/updatepath.ts` + an `ISTG-FW · Update-path integrity`
  stage in `LINUX_CHAIN`, deliberately `needsRootfs: false` because the image half is answerable from raw bytes
  and skipping the stage for want of a rootfs would turn "never looked" into a silent absence. It found this
  entry's own premise correct: `METHODOLOGY-GAPS.md` §4 ranked it **#4 of 7** and every other item on that list
  had shipped. Three questions — does the image carry integrity metadata, does the updater verify anything, is
  there rollback protection — each scoped to what was actually opened. **The negative is the careful part**:
  `update-no-signature-verification-found` is titled *"the N updater(s) located import and invoke no
  signature-verification routine"*, sits at `needs_runtime_reproduction`, carries the six unexamined places
  (bootloader, mask ROM, static blob, vendor wrapper, server-side check, unwalked blobs) in evidence, and its
  rationale contains the literal string `NOT "the firmware is unsigned"` with a test asserting the title never
  matches `/unsigned/`.

  **The GL.iNet BE3600 is the result worth reading, and both halves are true at once.** The image *is* signed —
  an appended usign signature 167 bytes from EOF, `signed by key 06a6bf2ad909388f` — and `/usr/bin/usign` ships.
  But `lib/upgrade/fwtool.sh`'s `fwtool_check_signature` opens with `[ ! -x /usr/bin/ucert ] && { … return 0; }`,
  **`ucert` is in no path in the rootfs**, and `REQUIRE_IMAGE_SIGNATURE` — the only variable that would turn
  that branch into `return 1` — appears nowhere except inside `fwtool.sh` reading it. So the check returns pass
  unconditionally: a guard that fails open because a dependency was not packaged. Verified by hand against the
  extracted bytes, not inferred. The honest bound is that this is `static_confirmed` about the script's control
  flow and says nothing about a bootloader-level check. The three TP-Link images contrast sharply: the updater
  lives inside `usr/bin/httpd` and is found only by symbol (`upgradeFirmware`, `isSysUpgradeNeedChecksum`), it
  imports `md5_verify_digest` and **zero** signature entry points, and the keyed MD5 at 0x4c was **verified by
  recomputation** with `mktplinkfw md5salt_boot`, byte-for-byte on all three — which authenticates nobody, the
  salt being public. Tenda's "verification" is a hardcoded string compare with the MD5 check sitting inside a
  `: <<'COMMENT'` heredoc, and it writes with `dd of=/dev/$upgradeblock`.

  **The side effect matters more than the feature.** Extending `parseDynamicSymbols` with a `PT_DYNAMIC`
  fallback (rather than writing a second symbol reader) revealed that **OpenWrt strips section headers**, so
  `e_shoff == 0` on every ELF in the GL.iNet rootfs and the existing section-header walk returned `null` for all
  of them — the richest image in the corpus had been falling back to the string superset everywhere. `binvuln`
  gets the fix for free, which flips those findings' verb from "references" to "imports".
  _Five defects only the real bytes exposed: `ota` matched **`quota`**, so on DVRF an iptables plugin became
  "the 1 updater located"; the candidate cap truncated **by directory order** and evicted `sbin/sysupgrade`
  behind 30 `lib/upgrade/keep.d/*` manifests — the exact failure `selectFindings` exists to prevent, reappearing
  in a new provider; the key-material scan returned the whole Mozilla CA bundle and fed a root cert to the
  conjunction; a fixed-width window read the shipped usign **public key** as a signature over the image; and one
  OpenWrt update path produced four separate HIGH "flashes without checking" findings across five files._

### Follow-ups from the five
- ✅ **The modules the sweep stopped asking about got their own question** (2026-07-28, deploy `ab7f9bf`) —
  excluding ET_REL from `binvuln` was right and left 375 `.ko` files with nothing to say about them. `kernelposture`
  now reads each module's `.modinfo` for `intree=`, `license=` and `name=`, and reports **attack surface, never
  defects**: an out-of-tree module runs with full kernel privilege outside the process that reviews and patches the
  kernel, so an upstream fix does not reach it and no distribution security team tracks it — a test asserts the
  title never says "vulnerable", because nothing here opened a module and looked.
  **Provenance is decided from the SET, never from a remembered kernel version.** `intree=Y` postdates the oldest
  kernels in this corpus (DVRF ships 2.6.22), and hard-coding the release it arrived in would be the recall-based
  claim `component-cve.ts` refuses to make about CVE ranges. So: if not one inspected module carries the tag, the
  build does not use it and the question is unanswerable here — `blocked_by_platform`, never "all in-tree".
  **Measured on the deploy: 375 of 375 modules, 307 in-tree, 68 out-of-tree, 3 declaring `Proprietary`.**
  _Three defects, each found only because a measurement disagreed with another:_
  (1) *the licence regex ran to the next space*, so `Dual BSD/GPL` and `GPL v2` — the licences that matter most —
  would have been truncated; the space-separated test fixture hid it, and NUL-separated fixtures exposed it.
  (2) *the sample cap made the count an artifact of the alphabet*: 200 of 375 modules opened, sorted by name,
  reported "25 of 200 out of tree" as though 200 were the total, and all three proprietary modules sort past the
  cap so they vanished from a result presented as a measurement. The cap now covers the corpus and the finding
  states what it opened either way.
  (3) *the record-boundary rule dropped the FIRST record of every module*: it demanded a NUL before a key, but
  the first `.modinfo` record is preceded by whatever the previous section ended with — 0x08 on the real
  `ath_pktlog.ko`, which cost the corpus a tainting module. A printable predecessor is still rejected, so
  `filename=` is not read as `name=`.

Surfaced while building the above and deliberately not built. Ordered roughly by value.

- ✅ **A guard whose enabling variable nobody sets is DISABLED, not skipped** (2026-07-28, deploy `d30350c`) —
  pure `findEnforcementFlags` + `buildEnforcementFindings`. A curated name pattern (`REQUIRE_*`, `*_REQUIRED`,
  `ENFORCE_*`) read **in a test expression** inside a script already identified as part of the update path, cross
  referenced against every script the walk read to ask whether ANYTHING assigns it. The asymmetry is the design:
  guards are looked for in the update path, assignments everywhere, because a flag legitimately set by an
  unrelated init script is not this defect. Comment and heredoc stripping applies to both sides, so a
  commented-out assignment does not clear a guard.
  **Measured on the deploy across six images: the GL.iNet finds 2 flags and reports exactly 1**
  (`REQUIRE_IMAGE_SIGNATURE`, unassigned), while `REQUIRE_IMAGE_METADATA` is correctly cleared because
  `lib/upgrade/platform.sh` sets it — that discrimination, on real vendor scripts, is what makes the pass worth
  trusting. **The other five images report zero: no false positives.** The finding states the FACT as
  `static_confirmed` (read here, assigned nowhere in this filesystem) and marks the CONSEQUENCE as a strong
  inference rather than a certainty, because the value could still arrive from the invoking environment, a
  bootloader variable or a binary's `setenv` — none of which this pass reads.
  _Honest limit: the corpus contains exactly ONE positive, and it is the case the detector was written from. The
  generalisation past OpenWrt is designed, not demonstrated; a vendor updater using a different idiom (a C flag, a
  uci option, a file's presence) would not be caught, and only more firmware families can settle whether the name
  pattern is the right net._
- ✅ **`etc/passwd → /dev/null` is claimed now, and the silence has four causes** (2026-07-28, deploy `10ce0c3`)
  — `readInside` returned `''` for a file that is absent, empty, unreadable, OR a symlink resolving outside the
  rootfs, and `auditCredentials('', '')` then emitted nothing, which renders as "no credential findings" and reads
  as "no credential problems". DVRF is the worked example: it symlinks its ENTIRE account database — `passwd`,
  `shadow`, `group`, `gshadow` — to `/dev/null`, so every read is empty, every check passes, and the image looked
  clean on the one axis `fsaudit` exists to examine. New pure `auditAccountSources` + `inspectAccountFile`
  (`lstat`/`readlink`, because `safeJoin` validates the path it is HANDED and `etc/passwd` is perfectly in-root
  right up until the kernel follows it out). Redirected ⇒ `medium`/`static_confirmed` stating that an empty
  credential list here is a gap and not a negative; nothing readable at all ⇒ `blocked_by_platform`; an ordinary
  rootfs simply missing `gshadow` stays quiet, because flagging that would be noise. **Measured on the deploy:
  DVRF's fsaudit went from 0 findings to 1 naming all four redirected paths and their target.** _Where DVRF's real
  credentials live — the Broadcom `router_defaults[]` string pool in `usr/lib/libshared.so` — remains a separate
  open item; the point closed here is only that this provider stops implying it looked and found nothing._
- ✅ **`binvuln` now reads stripped binaries — measured, and the claim it was recorded with was wrong**
  (2026-07-28, deploy `fa168fe`) — the follow-up said the `PT_DYNAMIC` fallback "flips **every** GL.iNet ELF from
  `symbolSource: 'strings'` to `'dynsym'`". Run against the deployed bench on the real carve: **8 of 22, not 22.**
  Stored findings from the previous build were 22/22 `strings`, all titled *references*; the new run is 8 `dynsym`
  (*imports*) and 14 still `strings`. The overstatement is the same shape this ledger keeps catching — a claim
  about a whole set, written from the case that was inspected.
- ✅ **The `binvuln` sweep claimed something impossible about kernel modules — and the noise was the smaller half**
  (2026-07-28, deploy `47ce86c`) — 14 of the BE3600's 22 findings were `lib/modules/5.4.213/*.ko` reported as
  *"Command-exec sink: … references system"*, a userland call a kernel module cannot make. New pure
  `isRelocatableObject` rejects ET_REL before the file is counted as scanned, and the reason states the exclusion
  (`relocatableSkipped`), because a reader comparing "400 ELFs" against a rootfs they know holds 375 modules must
  be able to see where the difference went. `isRunnableElf` did not catch this: that predicate answers "can a probe
  run it", which is also false for a `.so` that IS worth listing — **the axis is the object type, not runnability**,
  and a test pins that a shared library is still reported.

  **The real defect was the budget, not the noise.** `ELF_SCAN_CAP` is 400, and on the BE3600 **375 of those 400
  were `.ko`** — the sweep spent 94% of its examination allowance on files whose question does not apply, left
  roughly 25 real userland binaries examined out of the whole rootfs, and reported "400 ELF binaries" as though
  that were thorough. This is the `selectFindings` lesson one layer earlier: a bound that fills with the wrong
  population makes its own result an artifact. **Measured on the deploy: BE3600 22 → 60 findings, symbol source
  8 dynsym/14 strings → 59 dynsym/1 strings; DVRF skips 44 `.ko` and returns 60 findings, all dynsym.** _The
  `.ko` files themselves remain a genuinely open question — the kernel `.ko` CVE surface below — and deserve a
  provider that speaks kernel, not a userland sweep's vocabulary._
- ✅ **The three new providers measured across the whole corpus** (2026-07-28, deploy `fa168fe`) — 48 jobs over 16
  images through the deployed API, and the numbers reproduce what each agent measured in isolation, which is the
  independent confirmation that mattered. **Device tree found on 2 of 16** (BE3600 `qcom,ipq5332` 12 peripherals;
  Tenda `AK3918EV300L` 8) — the other 14 are honest `found:false`, including three TP-Link OpenWrt-derived images
  that carry no FDT at all. **Kernel located on 7 of 16**: 2.6.22–2.6.31 on the four TP-Link/DVRF images (22 years
  old), 4.4.282 Tenda, 4.9.84 IMOU, 5.4.213 BE3600. **Updater found on 6 of 16**, and the BE3600 reproduces the
  fail-open result on the deploy — 12 updaters, 4 verifying, **1 missing verifier**, `high` / `static_confirmed`.
  The BE3600 ledger is now 685 findings across 12 sources. _The honest one worth quoting: kernel posture emits
  `blocked_by_platform` — "8 of 9 kernel posture questions could not be answered" — rather than presenting a
  posture it could not read as a clean one._
- ✅ **Content search across the extraction** (2026-07-28) — `providers/fssearch.ts` (pure, 10 tests) +
  `GET /images/:id/files/search` + `firmlab_search_files` + a `FileSearch` panel under the file browser. Answers
  "which file says this", the direction the browser cannot go.
  **The bound was the whole design problem, not the matching.** A grep over 6497 files is a `for` loop; what is
  hard is that every decision not to open a file removes it from the answer, and each one makes a SHORT list look
  like a COMPLETE one — this ledger's oldest failure mode. So the result is a `SearchCoverage` first and hits
  second, `formatCoverage` writes the sentence once so the route, the MCP payload and the panel cannot invent
  three accounts of the same limits, and the panel renders the verdict **even on a clean search**, because a
  caveat shown only on failure teaches people not to look for it. `searchPayload` gives the MCP surface an
  explicit `isCompleteSearch`, since a model reading `hits: []` will not go hunting for a coverage object.
  Binaries ARE searched — a firmware's most interesting strings live in ELFs — and a binary hit carries a byte
  offset and **no line number**, because "line 4211 of busybox" is a fiction. Literal queries are escaped, so
  `a.out` does not also match `about`.
  **Validated on the real DVRF extraction: `/dev/nvram` → 8 hits, all in binaries, with the real `sbin/rc`
  strings including "Failed to find /dev/nvram", 454 files searched of 880 walked in 29 ms — and `sohoadmin` → 0
  hits under a COMPLETE verdict**, which corroborates from a second direction that this image's credentials are
  not in its rootfs (its account database is symlinked to `/dev/null`, closed above).
  **Deployed and measured on the GL.iNet (deploy `861aa20`), which is where the design earned itself:**
  `updates.gl-inet.com` returns 0 hits — and the default answer refuses to call that a negative, because 10 files
  exceed the per-file cap. A plain grep would have printed "0 matches" and been read as "this firmware does not
  phone that host". `BEGIN CERTIFICATE` hits the 200-cap and says so.
  _That measurement also showed the default makes a COMPLETE search impossible on that image, so `deep=1` buys
  one. Its FIRST version made things worse and the tool reported it: using the whole byte budget as the per-file
  cap opened the 106 MB `.ubi` and the 92.6 MB `carved_rootfs.squashfs` first, spent the budget on them and
  skipped **4385** files — trading 10 holes for 4385. Those two are also precisely the files not worth reading: a
  raw UBI volume and a SquashFS image are containers whose contents are already searched one extracted file at a
  time beside them. Deep now caps at 64 MB (clearing every real binary — the largest is `AdGuardHome` at 32.9 MB)
  with a 1 GB budget: **6469 files searched, 2 skipped, both containers.** Pinned by a regression test._
- ▢ **Update-path: reach past the file that was read.** ✅ **(a) DONE** (2026-07-28, `d485237`) — `sysupgrade` is
  credited with `fwtool.sh`'s `ucert -V`, so the entry point stops being reported as
  `update-no-signature-verification-found` AND `update-flash-write-without-check`, both false for the same reason.
  Directives are read at command position only over the inert-text stripper (a `source` in a comment or a
  `datasource=` assignment is not one), `include DIR` expands OpenWrt-style to every `*.sh` — precisely the edge
  that reaches `fwtool.sh` — and reached files are assessed with the existing `assessScript` into their own
  `sourced` field, never merged into `verifyCommands`. **Evidence stays keyed to the file the line is physically
  in**, so a reader is never told `sysupgrade` contains a line it does not, and the same fact reached two ways
  produces one finding. No source edge raises a proof state, and the chain says it would READ the file, which is
  not the same as calling what it defines. Containment is done on the string to stay pure: `..` above the root is
  refused WITH a reason, `$`/backtick makes it an honest unknown, a slash-less operand is refused because POSIX
  `.` searches `$PATH`; cycles are named, diamonds read once, and depth/file/mention caps feed
  `boundsThatTruncatedTheSearch`. _A defect surfaced from the SUCCESS-path test: the depth bound announced
  "anything lib/c.sh itself sources was not followed" at a leaf that sources nothing — a false bound that would
  have weakened every negative finding it touched._
  Still open: **(b)** decode OpenWrt's `FWx0` fwtool trailer so the appended ucert/metadata blobs are parsed
  rather than recognised by their armor — the layout was not verified against bytes, so it stays out; guessing it
  would fabricate. **(c)** actually verify the detached signature when image, block and on-device key are all
  present (`usign -V` is a one-shot Ed25519 check), taking `update-verify-chain` from "the mechanism is built" to
  "this image validates under the shipped key".
- ▢ **The source credit does not reach the web, and two narrower gaps beside it.** `apps/web/src/api.ts`
  `UpdaterCandidate` has no `sourced`/`unresolvedSources`/`sourceBounds`, so the UI shows the credit's *effect*
  (the findings) but never the chain that produced it — all optional, so nothing breaks, it is simply invisible.
  A sourced file joins the enforcement-flag guard set only if it carried verify/flash/rollback evidence, so one
  holding *only* a `REQUIRE_*` guard is still unscanned. And only `verifierPresent`'s `BIN_DIRS` decide "the
  executable is absent", so a verifier reached by an absolute path outside those dirs reads as missing.
- ▢ **Device tree: vendor partition bindings.** No corpus image declares a standard `fixed-partitions` node. The
  BE3600 carries a vendor `gl-mtd` node (`compatible = "gl-mtd-rw"`) whose `mtd_read_only` children name nine
  partitions by label — `0:SBL1`, `0:MIBIB`, `0:BOOTCONFIG`, `0:QSEE`, `0:DEVCFG`, `0:TME`, `0:CDT`,
  `0:APPSBLENV`, `0:APPSBL` — with no `reg`, because on IPQ5332 the offsets live in the on-flash MIBIB table.
  Reading it needs a MIBIB parser, and a rule for how far to chase vendor bindings before the provider is just a
  vendor table.
- ✅ **Cross-check the device tree against the U-Boot env** (2026-07-28, `61357da`) — `boot-cmdline-disagreement`,
  `static_confirmed`, fires only when BOTH sources yield a line and the two survive normalisation unequal.
  Normalised as cosmetic: whitespace, order of independent parameters, and repeats the kernel resolves last-wins.
  **Deliberately not** normalised: `console=` order/repetition (every occurrence registers and the LAST becomes
  `/dev/console`, so a reorder is a different boot), anything after a standalone `--` (init's argv), case, and
  parameter *values* — `root=/dev/mtdblock2` vs `root=31:02` may name one device but deciding that needs the flash
  layout. The bias is one-directional on purpose: a key wrongly treated as last-wins can only hide a difference,
  never invent one. Absence is a separate axis — `disagree | agree | device-tree-only | uboot-env-only | neither |
  unresolved-variables`, and only the first mints a finding. _Real bytes found what the tests could not:_ the only
  corpus image carrying both stores `bootargs` as a **template** (`console=${console} root=${mtd_root} …`), so a
  literal compare reported `console=` as differing while the env's own variable held exactly the tree's value.
  Expansion is now a property of the SOURCE (a DT string is literal, a `$` stays a `$`) and an unresolvable
  reference **refuses** the comparison rather than comparing `${…}` to a value. The live result is a real
  disagreement: tree `root=/dev/mtdblock5 rootfstype=squashfs`, env `root=/dev/mtdblock3 rootfstype=jffs2`.
- ✅ **The UI sweep of 2026-07-28, and the two defects only it could find.** Ten features from two agent rounds were driven against the DEPLOYED container and the real corpus, in both themes, with console exceptions and 4xx/5xx watched alongside what rendered. Everything below was verified on real bytes, not fixtures. **(1) An empty source chain and an unasked question were the same absence** (`93e6cc1`) — the Tenda's `usr/bin/force_upgrade` genuinely sources nothing, so the fields were omitted and the panel could only say it did not know *which*; re-running did not help, because a fresh run produced the same absence. The panel was telling the truth about an ambiguity the provider had built in. `sourcesFollowed` now marks every candidate the pass considered. **(2) The browser-composed report interleaved assertions into the measured findings table** (`6e19ea2`) — under a "Proof state" column, printing the raw `operator_assertion` sentinel, counted in the executive summary, and a `high` assertion would have inflated the critical/high note with a severity the workbench never measured. It survived because nothing tested that component. _Also confirmed live: compmap 6 unresolved → 1 after a rebuild driven from the UI; the full assertion round-trip (assert → the row is annotated → amend → history appends → withdraw → the annotation stops and the record survives); the report's partition; the new `Cross-check · Kernel command line` stage appearing in the coverage banner as honestly not-run._
- ✅ **`bootcmd` can re-set `bootargs`, and on the Tenda it does** (2026-07-28, `47218e9`) — `readBootScript` walks `preboot`/`bootcmd`, follows `run`, and reconstructs the `setenv bootargs` a script performs. It returns a LIST plus `ambiguous`, never one answer: both branches of an `if` are reported, and the reason says this is a static read showing the assignment is on the path U-Boot would run, not that this board ran it. **The Tenda finding survives and sharpens** — before, `mem, memsize, root, rootfstype` differed; after, `mtdparts, root, rootfstype`, because `mem`/`memsize` agree once the right line is compared. Two of the four were an artefact of the wrong string. _Two traps the real bytes set: `boot_normal` writes `${mtdparts1}`, a name absent from that environment, so a blanket refusal would have deleted the finding — `variablesComplete` now permits U-Boot's own "unset expands to nothing" ONLY where the parser can prove it dropped nothing; and the same image stores a `setcmd` assembling a THIRD line that nothing runs, which a grep-for-`setenv bootargs` would have reported as reachable._ Its `boot_normal` assembles a THIRD variant
  (`… ${mtdparts} ${mem} ${memsize}`) that matches the device tree more closely than the stored `bootargs` does —
  so the stored variable is not the operative line on that board, and the cross-check above is comparing against
  the wrong one of the two. Auditing the command line a `bootcmd`/`preboot` script *assembles* is the real
  follow-up and would sharpen the finding rather than merely add to it.
- ✅ **The cross-check has a coverage stage** (2026-07-28, `47218e9`) — `coverage.ts` is UNCHANGED: the row arrives purely from `specsForClass`, which is the property keeping the banner and W9 from disagreeing. Verified live in the banner as `Cross-check · Kernel command line`, honestly listed as never-run on an image where it has not run. `bootCmdlineRun` syncs nothing when a half did not run, so an unasked question is not a retraction of an earlier finding.
- ▢ **The cross-check still fires only from W9**, not from the manual `routes/uboot.ts` / `routes/devicetree.ts` paths,
  so an operator running the two providers by hand never gets it. Also: two device trees disagreeing with *each
  other* (a FIT's board variants) is counted and mentioned in `reason` but mints no finding, and `coverage.ts` has
  no stage of its own for the cross-check — it folds into the uboot/devicetree steps, so the arithmetic balances
  but no "was this question asked" row exists for it.
- ▢ **Kernel posture: the authoritative path is untested on real bytes.** The provider prefers a shipped kernel
  config over every inferred source, and **no image in the corpus ships one** — no `/proc/config.gz`, no
  `IKCFG_ST` segment — so that branch is unit-tested only. Add an official OpenWrt build (they ship
  `/proc/config.gz`) and re-validate, then inflate the IKCONFIG segment the reader already detects.
- ▢ **Kernel posture: three questions have no in-blob marker on MIPS/ARM vendor kernels.** `STRICT_DEVMEM`,
  `STRICT_KERNEL_RWX` and KASLR came back undetermined on **every** corpus image, because the printks they are
  read from are largely x86-side. Either find arch-specific markers and validate them against real bytes, or
  make them permanently config-only and say so in the question text.
- ▢ **Operator assertions: corpus-wide view and cross-image reuse.** Assertions are per-image only. Indexing them
  the way `artifact_occurrence`/`credential_occurrence` index computed findings needs care: those tables record
  *measured* occurrences, and letting an assertion in would turn one person's claim into a cross-image prior —
  the laundering this feature exists to prevent, one layer out. Wants its own table and a prevalence signal
  explicitly labelled "asserted by N operators".
- ✅ **The three new surfaces reached the workbench, and the physical way in became a section** (2026-07-28) —
  `AnalysisKind` gained `kernel`/`updatepath`/`devicetree`, `AnalysisActionsPanel` runs them, and `BOOT_KINDS` in
  `StepTimeline` lists them (it did not, so a stage that had actually run still read `pending`). The panel went from
  7 providers to 10, at which point a flat grid stops being scannable, so the providers are now **grouped by the
  question they answer** — boot & platform · filesystem & configuration · update & supply chain · device & radio.

  **New `hardware` section** (`components/HardwareInterfaces.tsx`, 14 tests): the console, the declared buses, and
  the flash map, assembled from three providers that each held a piece and none of which put it on one screen. It
  answers the question an analyst with the board on the bench actually asks, and it **refuses the one inference it
  would otherwise invite**: FirmLab reads the image and connects to nothing, a UART the tree marks `okay` says
  nothing about populated pads or an attached console, and `read-only` on a partition is a request to the kernel,
  not write protection — all three sentences render on screen, not only in the module doc. **JTAG/SWD gets its own
  row saying FirmLab cannot answer it**, because a list of UART and SPI that silently omitted JTAG would read as
  "no JTAG here".

  _The defect that matters was found by running the real provider instead of trusting the type._ The first fixture
  was invented and gave the BE3600 `bootargs = "console=ttyMSM0,115200n8 …"`. Running `runDeviceTreeAnalysis` over
  the real 111 MB image returns `bootargs = "clk_ignore_unused"` — **no `console=` at all**; that board's console is
  known solely because `stdout-path = serial0` resolves to `/soc/serial@78af000`. The component's provenance line
  was gated on *both* sources being present, so the corpus's actual case rendered a bare node path with nothing
  explaining it, and the invented fixture agreed with the code instead of checking it — CLAUDE.md's trap, in the
  UI layer. The fixture is now the provider's real output, including `status: "(absent)"` and the empty partition
  list with its explanatory note. Two smaller defects the tests caught the same way: a node whose status is
  literally `disabled` rendered "disabled disabled", and an unanalysed image repeated "no device tree has been
  read" under every heading instead of showing one consolidated empty state.
- ▢ **`funcdiff` has no web surface at all.** Function-level diffing and the decompiled-text diff shipped
  2026-07-27 with a route (`POST/GET /images/:id/funcdiff?against=`), pure logic and 31 tests — and **zero
  references anywhere in `apps/web`**. The Diff section only offers the image-level `diff`. A whole shipped
  capability is reachable only by curl, which is how it goes unused and unvalidated on real firmware; the backlog
  already notes the real-firmware run is open, and no UI is part of why.
- ▢ **Two navigations list different sets of sections.** The sidebar (`SECTION_GROUPS`) and the pipeline strip
  (`ANALYSIS_STEPS`) overlap on only five ids: the sidebar omits `bootloader` — now ten deep providers — and
  `findings`, while the strip omits `structure`, `secrets`, `files`, `hardware`, `testbench`, `diff`, `opacidad`
  and `agent`. Everything is reachable from one or the other, so nothing is lost, but which one a section appears
  in is currently an accident rather than a rule. Decide the rule (pipeline stages in the strip, everything in the
  sidebar) and apply it.
- ▢ **The `bootloader` section id no longer describes its contents.** It holds U-Boot, device tree, kernel posture,
  rootfs audit, certificates, services, update-path, component map, RTOS and FCC. The id should stay for old links
  the way `binaries` did when it became `testbench`, but the label should say what it is.
- ▢ **`AnalysisActionsPanel` uses emoji where the rest of the shell uses the line-icon family** in `icons.tsx`,
  whose own doc comment says it exists "so the chrome reads as one system instead of the old grab-bag of unicode
  glyphs". Three more emoji were added rather than deepening the divergence silently — recording it instead of
  quietly redesigning a panel that was not in scope.
- ✅ **Assertions never reached the HTML report, and `disputes_finding` was inert** (2026-07-28, `422c18f`) — all
  three fixed. Assertions render in their own section, placed elsewhere on the page, and the caller cannot
  interleave them (`renderLedgerSections` returns two finished strings, not the pieces); partitioning is by the
  `operator_assertion` sentinel, not by source, so a hand-set `source: 'sbom'` still lands on the operator side.
  **No proof-state markup at all** — a test asserts `class="proof"` appears in the measured section and never in
  the operator one. A contested row is annotated in place with who/when/basis and states in the same block that
  its proof state was decided by code and the dispute changes, downgrades and removes nothing; a dangling target
  (a provider re-run renumbers rows) is surfaced, not dropped. **The row cap exempts contested rows**, or the cap
  would make disputes inert again on exactly the largest images. Amendment is append-only **without a schema
  change** — `assertionJson` already holds arbitrary JSON, so the superseded state appends to `supersedes[]`, both
  new fields optional forever and read defensively. A stale `disputesFindingId` left behind when an amendment
  moves off `disputes_finding` is now dropped (it survived on the revision that made it and would have rendered as
  a live dispute). _Rendered against a copy of the real corpus DB, which caught what no test would: under
  `word-break: break-word` the wide annotation column collapsed the others to one character per line._
- ✅ **Amendment history and disputes reach every surface** (2026-07-28, `97aadfe`, `6e19ea2`) — MCP carries history under a `HISTORY, NOT A LIVE CLAIM` note, and **no field inside a superseded claim is named `claim`/`title`/`rationale`** (they are `supersededClaim`/`supersededTitle`/`supersededBasis`), so a model reaching for the live keys cannot come back holding a retired sentence. The disclosure draft gains both plus a withdrawn-assertions section and marks a contested bullet in the draft EMAIL, not only the attachment. The web gained inline dispute annotation, collapsed history, and the update-path source chain. _Rendering found what no fixture would: the "Contests" wording promised the target row carries an annotation — false for a WITHDRAWN dispute, which annotates nothing._
- ▢ **The remaining surface gaps after that round.** `mcp/format.ts` `shapeAssertion` does not surface
  `supersedes` (an agent sees only the current claim), `apps/web/src/api.ts` `OperatorAssertion` lacks
  `supersedes`/`title` so the web `OperatorPanel` shows no history and the web findings table carries no dispute
  annotation at all, and `providers/disclosure.ts` omits both from the vendor draft. The report is currently the
  only surface that tells the whole truth about the ledger. Also: `POST` validates that a dispute target exists,
  but nothing revalidates after a provider re-run renumbers rows — the report states the dangling case rather
  than repairing it.
- ▢ **Device tree: `/reserved-memory` and `/memory` are parsed but not surfaced.** A TrustZone/QSEE carve-out is
  useful context for an emulation attempt. Same for partition flags beyond `read-only` (`lock`, `slc-mode`).
- ▢ **An older extract result cannot say why it has no rootfs.** Asus-Router's stored row predates
  `extract-diagnose.ts`, so the browser can only report that the diagnosis is missing. Nothing marks stored
  results as produced by a build older than the field they lack.

## Peer-tooling cross-check — the UI axis (wairz frontend, 2026-07-28)
The two earlier passes over wairz — `METHODOLOGY-GAPS.md` §6 and the section above — both read its **analysis**
surface, and neither opened its frontend. This one did (84 `.ts`/`.tsx` under `frontend/src`). Its dependency list
declares most of the difference before a line is read: Monaco, xterm, React Flow + dagre, react-arborist,
html-to-image — against FirmLab's four runtime deps (`react`, `react-dom`, `react-router-dom`, `@firmlab/core`) and
hand-rolled SVG.

**What wairz lacks is recorded first, because it decides how much of the rest to take: its UI carries no notion of
proof state or coverage at all.** The single `Coverage` label across its 84 files is AFL++ edge coverage
(`FuzzingPage.tsx:630`). `CoverageBanner`, `TechniqueCoverage`, the proof-state badges and `OperatorPanel` have no
counterpart there. Nothing below is worth having at their expense.

Three things read as gaps and are not: the hex view exists already (`FileBrowser.tsx`, `view: 'hex'` with offset
seek), PDF export exists already (`ReportBuilder.tsx` → self-contained HTML, Markdown, and print-to-PDF; what is
missing is a *server-rendered* PDF, which is a narrower item than the `Reporting & integration` entry reads), and
`react-arborist`-style virtualization is **declined on purpose** — `FileBrowser`'s pager states the bound AND makes
it navigable, which is the more honest shape and is argued in that file's own header.

- ▢ **The sidebar shows every section for every device class.** `SECTION_GROUPS` (`apps/web/src/App.tsx:44`) is a
  static list, so an RTOS blob is offered Filesystem, File browser and SBOM — sections that are structurally empty
  for it, and whose emptiness then has to be explained by a coverage note instead of never being offered. wairz
  declares `kinds: ['linux'] | ['rtos'] | ALL_KINDS` per sidebar entry and even switches the label by kind
  (`'File Explorer'` vs `'Project Files'`). The routing answer already exists here — `specsForClass` is the same
  plan the autonomous scan executes and `coverage.ts` already reads it — so this is filtering a constant against
  data the app holds. Cheapest item in this section by a wide margin.
- ▢ **The component map is computed and never drawn.** `providers/compmap.ts` builds the rootfs DT_NEEDED graph with
  unresolved libraries and orphans surfaced, and in `apps/web` the string `compmap` appears exactly four times: a
  job-kind union member (`api.ts:754`), a launch button, a timeline row and a technique-coverage tick. **Zero
  occurrences in `ImageDetail.tsx`.** The graph is produced, persisted, counted towards coverage, and has nowhere to
  be seen. wairz gives it a page (React Flow + dagre auto-layout, MiniMap, edge details, click-through to the binary,
  PNG/SVG export via `html-to-image` in `MapControls.tsx`); `SbomGraph.tsx` is the precedent that this shell draws
  graphs by hand, so the dependency is not required — the view is.
  ✅ **BUILT** (2026-07-28, `0acf818`) — Components → Component map, no new dependency, plain `<svg>` in an
  `overflow-x:auto` wrapper, zero literal colours (all `.cmap-*` over existing tokens, checked in both themes).
  Evidence is placed ABOVE the picture: the header states DT_NEEDED is what the *linker* recorded and a `dlopen(3)`
  library leaves no edge, so silence here is silence about linking, not loading; then counts, then the
  unresolved-reference table (the actual content), then the drawing, then orphans. **Four states, not one empty**:
  not-run ("a statement about this workbench, not about the firmware"), no-rootfs (extraction verdict quoted, Build
  disabled since the POST would refuse), empty ("a real answer, and a plausible one — a busybox-only or fully
  static rootfs links nothing dynamically"), tool-absent ("an absent tool is an absent answer"). The drawing's cap
  ranks unresolved-first, then degree, then name — never arrival order — and every unresolved reference stays in
  the table regardless of what the picture had room for. _Three defects only the render caught: a basename note
  explaining a discrepancy that had not happened; 55 orphans, most of them `.so` files, described as "top-level
  executables"; and a column headed "binary" over a list of `.so` files._
- ✅ **`compmap.ts` skipped symlinks, so a soname provided by one always read unresolved** (2026-07-28, `f4f7725`) — the walk still refuses to descend through a link; it now reads the link's target NAME (`readlinkSync` does not traverse) and resolves it **lexically** inside the carve, so a link to `/lib/libc.so.6` is checked against the carve's own copy and a `..` above the root provides nothing. A real-filesystem test builds links pointing at files that genuinely exist on the host and asserts we still refuse them — a `realpath` implementation fails it. Three outcomes stay distinct: walked file, link-provided (a weaker fact, labelled), unresolved; and `unresolved` is DERIVED from the `lib` nodes so the two cannot drift. Measured: IMOU 2 → 0, GL.iNet 143 → 65, and **through the deployed UI the Tenda went 6 → 1** with the provider line reading "6 external libraries, 5 of them only through a symlink, 1 unresolved".
- ▢ **compmap's caps truncate by arrival order, which rule 4 forbids.** The 65 that remain on the GL.iNet are cap artifacts, not link artifacts: `WALK_CAP` reached 4,000 of 6,496 files and `BINARY_CAP` stopped at 300 ELFs, so a real 590 KB `lib/libc.so` that 298 binaries reference was never seen. The result is now honest about it (`walkTruncated`, a sentence in `reason`, a caveat on the broken-link rule after the same cap produced a false `dangling`), but the counts still lean the same way. **The fix is to split the bounds**: name/link indexing is readdir-only and cheap, so it should cover the whole tree, while the expensive bounds — file opens, rabin2 invocations — stay where they are. That also needs resolution against walked-file basenames rather than ELF entries, i.e. a fourth state.
- ▢ **The MCP server has no surface in the UI that exposes it.** `apps/api/src/mcp/server.ts` ships and the only way
  to discover it is to read `CLAUDE.md`. wairz's `McpConnectionCard.tsx` (212 lines) shows a copyable
  `claude mcp add … -- docker exec -i …`, the Claude Desktop JSON block, and four starter prompts. Pure UI over a
  capability that already exists, and the thing most likely to make the MCP lane actually used. Pairs with the
  exploratory-tools item above (§*Peer-tooling cross-check*, "The MCP surface cannot navigate a binary").
- ▢ **No interactive console into an extracted rootfs.** wairz's `backend/app/routers/terminal.py` forks, resolves
  *"the firmware to chroot into"*, `execve`s `/bin/bash` on a PTY and streams it over a WebSocket to xterm
  (`components/explorer/TerminalPanel.tsx`). FirmLab has the chroot rung in `emulate.ts` and no interactive surface
  anywhere. This is the UI face of the existing *Interactive/introspectable emulation* entry, and it carries a
  constraint that entry does not yet state: **a chroot shell is not the device and is not even emulation** — it is
  the host kernel running foreign binaries. A console invites the operator to conclude more than the rung supports,
  so the pane has to be labelled before it is opened, and anything observed through it is at most
  `confirmed_in_emulation`. wairz can skip this problem because it has no proof states; this workbench cannot.
- ▢ **The firmware switcher is flat.** The header `<select>` (`App.tsx:283`) lists every image with no notion of
  family or version, while `capture/learning.ts` already groups provenance into per-family OTA timelines with the
  versions ordered. wairz puts a `FirmwareVersionPicker` in the layout. The data exists; the control does not.
- ▢ **No in-app reference documentation.** The onboarding tour opens once on a fresh profile and is gone. wairz has a
  `HelpPage` with collapsible sections (Getting Started, Firmware Upload & Unpacking, **Firmware Kind (Linux vs
  RTOS)**, File Explorer…). For a workbench whose central discipline is a vocabulary the operator must understand —
  seven proof states, coverage verdicts, what an operator assertion is and is not — a page to return to is worth more
  here than it is there.
- ▢ **The file viewer is plain text.** Monaco gives syntax highlighting and in-file search, which is most of the time
  an operator spends in an extraction (init scripts, UCI config, `/etc/*`). Ergonomics rather than capability, and
  the lowest-value item here, but the one that is felt on every image.

## Product direction — a second peer (galert), and three proposals (2026-07-28)
`~/Documents/galert` is an LLM-driven pentest agent: **56 markdown skill cards** (40 web, 10 firmware, 6 cloud)
mounted into a worker that runs against a live URL plus a source repo. It is the **architectural inverse** of this
workbench, and reading it settled what to take and what to refuse. The decisive artefact is
`skill-cards/firmware/binary-sink-analysis.md`, which instructs a model to run `rabin2 -I/-z/-i`, hunt
`system`/`strcpy`/`sprintf`, take xrefs with `axt sym.imp.system`, escalate to Ghidra headless — and closes with
*"Do not claim RCE without showing the attacker-controlled path into the sink — otherwise mark it
`needs_runtime_reproduction`."* **That is this project's own vocabulary, asked of a model as an instruction rather
than enforced by code.** A prompt is exactly what a model can silently fail to follow; `syncFindings` and the
normalizers make the state a property of the row. That single line is the whole difference, and it is why the two
rejections below are rejections.

- — **Firmware skill-card agents, as a lane inside FirmLab.** All ten of galert's firmware cards map onto providers
  that already exist: `binary-sink-analysis` → `binvuln` + `symreach` + `dynprobe`, `embedded-linux-audit` →
  `fsaudit`, `firmware-triage-extraction` → `extract` + `extract-diagnose` + `extract-recover`, `kernel-analysis` →
  `kernelposture`, `uefi-bios` → `chipsec` + `fwhunt`, `emulation-bringup` → the ladder, `firmware-acquisition` →
  Capture, `rtos-baremetal` → `rtos` + Renode, `fuzzing-harness` → `fuzz`. Adding them would put **two
  implementations of the same question, with different reliability, writing into one ledger** — the failure mode this
  workbench is built to prevent. _One card has no counterpart: `firmware-dsp-analysis`. That argues for a provider,
  not for an agent lane, and is recorded as such below._
- — **Web/cloud agents as a section of this app.** The gap they address is real and self-declared —
  `METHODOLOGY-GAPS.md` §2 marks ISTG **UI · companion app & cloud API** as ✗ and **DES · protocol-aware service
  testing** as ◐, and a device's companion app and cloud API genuinely are part of its attack surface. But this is a
  different product, not a tab: it changes the object from *bytes you possess* to *someone's running system*
  (authorization and scope become first-class, which nothing here models — Capture's per-scan operator ack is the
  seed, not the mechanism); it ends "every flag off ⇒ no network, no cost, deterministic"; it needs a
  `confirmed_on_target` rung that, unlike every existing one, describes a machine that is not ours; and it imports an
  exploitation posture wholesale (`exploit-development-poc`, `exploit-acquire-build-verify`, `waf-filter-evasion`,
  `advanced-web-attack-chains`) against a boundary stated in three documents. If it is ever built: its own lane, its
  own flag, its own scope model — decided deliberately, not arrived at through a sidebar entry.
- ✅ **The evidence CHANNEL is recorded, beside the proof rung** (2026-07-29, deploy `c7f3b3f`) — `ProofState`
  answers how far something was proven and says nothing about the means, so `static_confirmed` covered both "these
  bytes are a private key" (read directly) and "angr proved this sink is on a live path" (a solver's conclusion
  about a program nobody ran). The means were prose inside `rationale`, where nothing could group, filter or audit
  by them. `EvidenceChannel` in core is the second axis — `static_bytes` · `symbolic_execution` · `emulated_run` ·
  `probe_response` · `captured_traffic` · `external_advisory` · `operator_report` — with two rules pinned by test:
  the same rung must carry different channels (or the axis is redundant), and **absent means NOT RECORDED, never
  `static_bytes`** (or the field manufactures the provenance it exists to make honest). No backfill: all 1230 live
  rows migrated to NULL, which is the only correct reading of a column that did not exist when they were written.
  `symreach`'s blocked row is deliberately left channel-less — angr was absent, so nothing was symbolically
  executed. **Validated on the deploy**: a re-run stamped 12 gitleaks rows `static_bytes` through
  normalizer → `syncFindings` → SQLite → API → ledger, with the other 300 rows correctly blank.
- ▢ **Most providers still have no channel.** `sbom` (531 rows), `binvuln` (299), `certs` (156), `updatepath`,
  `kernel`, `devicetree`, `nvram`, `compcve` and the rest emit none, so they read as "not recorded" — honest, and
  incomplete. Each needs its own judgement rather than a sweep: `compcve` is `external_advisory` like `sbom`, but
  `binvuln`'s sink candidates are `static_bytes` while its *reachability* claims are not, and getting that wrong
  reintroduces exactly the conflation the axis was added to remove.
- ▢ **`interventions` exists and nothing writes to it yet, by design.** It is the field the boot-time repair
  depends on: what the workbench CHANGED about the subject to obtain an observation, absent meaning "as shipped".
  It qualifies a proof state without lowering it — the rung really was reached, against an altered subject — which
  `ProofState` structurally cannot express. Free sentences rather than a taxonomy on purpose: there are no
  interventions yet, and inventing a vocabulary for behaviour that does not exist would be guessing at the shape of
  the thing the field exists to keep honest. Derive the taxonomy from the first three real ones.
- ▢ **There is no verdict for "out of scope".** galert carries `OUT_OF_SCOPE_INTERNAL` for a finding that would be
  exploitable but depends on access outside the engagement. Here that collapses into `needs_runtime_reproduction`
  and therefore **reads as a lead when it is a scope decision** — a distinct kind of not-answered from
  `blocked_by_platform` (we asked and could not) and `blocked_by_security` (a control stopped us). _Both this and the
  channel field touch `ProofState` in `packages/core` and land on results that are persisted JSON re-read from rows
  written by older builds: **a field added to a persisted result type is optional forever**, a trap already paid for
  once._
- ▢ **`firmware-dsp-analysis` has no counterpart.** The one galert firmware card with nothing behind it here.
  Unprioritized until an image in the corpus needs it — recorded so it is not rediscovered as novel.

**Three proposals raised in the same session, with the reservations that shaped them.**

- ▢ **Bench — a live-device section, distinct from the declared one.** The value is not convenience: every rung today
  tops out at emulation, and `confirmed_full_system` explicitly does *not* speak about the physical board. A UART
  console or a JTAG halt on the real device is the only path by which that rung becomes a statement about hardware.
  Four constraints, each from something already paid for: **(1)** `HardwareInterfaces.tsx` (486 lines) already exists
  and its header reads *"This section reads the image. It never touches hardware, and it must never imply
  otherwise."* Two sidebar entries both meaning "hardware" would re-commit the conflation this UI committed once
  already — **Declared** vs **Attached**, with the live one consuming the static one ("the tree says console on
  ttyS0 @115200; here is the port"). **(2)** Design it host-agent-first. The deploy is a port-less container on a
  VM-backed runtime; `/dev/ttyUSB0` does not exist inside it, and the Capture lane already paid for this exact
  lesson with `assessL2Reach` / `looksLikeVmBackedRuntime`, where a bridge deployment is told the thing is
  *impossible here* rather than pointed at a `--cap-add` that cannot help. An in-container design reports
  `available: false` forever on the real deployment. **(3)** Three verbs, not one: UART is a console (a terminal is
  right), JTAG is halt/step/read-memory via OpenOCD (a debugger, not a terminal), and SPI flash is a **dump that
  should re-enter `capture/ingest.ts` with a provenance row** — a flash read is firmware acquisition, FSTM-2, which
  closes the loop with the lane that already exists. **(4)** Writes get the human-approval gate unconditionally:
  a JTAG or flash write is irreversible and outside anything `isolate.ts` contains. _This item also forces a
  decision the file currently contradicts itself on: `Out of scope` lists JTAG/SWD/SPI extraction as hardware-lab
  work, while `Live-device UART bridge` sits open under `Recon & acquisition`. A host-side bridge changes the
  calculus for all three; the out-of-scope line should be re-read rather than left standing beside its exception._
- ▢ **An agent audit trail — the prompt as SENT, not a prompt library.** Raised as "a tab listing the workers'
  markdown prompts", after galert's `prompts/skill-cards/`. Two facts redirect it: there are no `.md` prompts here,
  and **the autonomous workers have no prompts at all** — `opacidad-plan.ts` maps `W1 · Extraction` → provider
  `extract`, a deterministic chain, and W9's only LLM is `buildLlmPrompt` in `opacidad-narrative.ts`, whose header
  states the narrative composes fully with the LLM off and which is pinned by a test named *"LLM prompt forbids
  invention"*. Real prompts live in four files of the `FIRMLAB_AGENT` lane (`agent/nodes.ts`, `copilot.ts`,
  `agent/zeroday.ts`, `agent/intel.ts`). A prompt LIBRARY would exert steady pull toward prompt-driven workers,
  which is the differentiator dissolving slowly. What is genuinely missing is the audit: **no prompt is persisted
  anywhere** — nothing in `agent/session.ts` or `store.ts` records one — so what the model was told cannot be read
  back after the fact. Per run: the interpolated prompt as sent, the response, which judgment node, and the
  governor's spend. Rendered from the module the runtime calls, never from a copy on disk: a viewer showing an
  `.md` while the code uses a TS string is *a comment that was true when written*. The deterministic plan
  (`specsForClass`) belongs on the same screen and is not a prompt — it is the routing table.
- ▢ **Corpus: restructure, and split the knowledge store in two.** `pages/Corpus.tsx` (209 lines) already carries the
  right doctrine in its header — *"Everything here is a prior / cross-reference: it says where things recur, never
  that something is vulnerable"* — and that sentence has to survive any rewrite. **The safe half is documents with
  external provenance** (datasheets, FCC filings, vendor advisories, CVE text): citable, and a natural extension of
  `fcc.ts` and the research lane's egress ledger. Use SQLite **FTS5, not embeddings**: at corpus scale here lexical
  search wins on recall, and a local embedding model is a heavy new dependency while a hosted one ends *"every flag
  off ⇒ no network, no cost, deterministic"*. Reach for vectors when lexical search is **measured** to fail.
- ▢ **Agent-authored lessons — only under the assertion provenance model, or not at all.** The other half of the
  proposal above: agents recording what went wrong, dead ends, and what it took to get unstuck. The hazard is
  specific — it is a citation loop with no proof state, where one run writes *"on this vendor X worked"* and a later
  run retrieves it as ground truth. That is the withdrawn `private_key.pem` entry's failure (written from a filename
  without opening the file) reproduced at scale and self-reinforcing: **a wrong lesson is not corrected, it is
  retrieved.** The mechanism to reuse already exists — operator assertions carry their own provenance, no proof
  state, count towards no stage, are returned in their own array and can be withdrawn. An agent lesson should be a
  third provenance class under that same machinery, attributed to the run that wrote it, never citable as evidence.
  **If it cannot be withdrawn, do not build it.** One framing note: "how the analysis got unstuck" is in scope;
  a growing playbook of working attacks reads differently against a stated FSTM-9 boundary, and what such a store is
  allowed to emit into a report deserves the care the disclosure lane already got.

## Pass 4 — three arrangements over the whole corpus (2026-08-03)

The corpus was re-ingested (18 images) and all three arrangements run over it at once: **A** the app with every
provider it can run, **B** the app's own agent (DeepSeek behind the governor), **C** one blind Claude agent per
image with a shell into a `firmlab-tools` container, no access to FirmLab and no access to this repository —
`AUTONOMOUS-WORKERS.md` §7 is an answer key and a contestant that reads it is reciting. The rubric was fixed
before any result was read, and **every finding below was verified against the bytes by the judge, not accepted
from an agent.** Full record in `AUTONOMOUS-WORKERS.md` §11.

- ✅ **Big-endian MIPS gets the little-endian emulator in the user-mode rung** (fixed 2026-08-03, `135e16a`,
  deployed `bde3f2d`) — impact **high**, one line.
  `providers/preflight.ts:19` maps `mips: 'qemu-mipsel-static'`. Measured on the WR940N: `emulate-user` exits 255
  with `qemu-mipsel-static: …/usr/bin/httpd: Invalid ELF image for this architecture`, while the ledger row for
  that same binary reads `usr/bin/httpd · mips · 32 · big` and `decompile` in the same run reads `"endian":"big"`.
  Three things make it worse than a typo: the **correct** mapping already exists at `providers/dynprobe-run.ts:34`
  (`mips: 'qemu-mips-static'`) under a comment claiming it is *"the same mapping the emulation provider uses"*;
  `QEMU_SYSTEM_BY_ARCH` ten lines below in the same file was fixed for this exact reason and says so; and
  `qemu-mips-static` 7.2.22 is installed in the deployed container. `identity.arch` is `"mips"` with
  `identity.endianness: "unknown"`, so the map keys on a string that cannot express endianness while the ledger
  holds `big`, measured from the ELF header. Every big-endian MIPS image fails this rung — WR940N, WDR3600,
  MR3220. Third instance of *"a comment that was true when written"*, second of *"big-endian MIPS given the
  little-endian emulator"*.

  **Closed**, and the fix needed a `ToolId` that had never been declared (`qemu-mips-static`) even though the
  binary ships in the container. `dynprobe-run.ts`'s map now IS `QEMU_USER_BY_ARCH` by spread rather than a copy
  claiming to be one — that divergence is what let the correct mapping sit ten files away for weeks. **Verified on
  the deployed build against the real WR940N rootfs**: `usr/bin/httpd` no longer exits 255 on an invalid ELF, it
  *executes* — the run's stderr carries the firmware's own `==>power_led_blink_start<2457> Create
  power_led_blink_thread Thread Failed` — and the ledger now holds a row for it. **Neither map was pinned by any
  test**, which is how the second instance survived the fix for the first; five pins added, including one that
  fails if any arch with a user-mode emulator lacks a system one.
  _Follow-up surfaced by that same run: the user-mode composer has no sandbox-shortfall separation. The httpd run
  also printed `cache '/etc/ld.so.cache' is corrupt` and exited on a signal, and the row reads
  `binary-execution-nonzero` — "the program exited non-zero" — when the more likely reading is that the sandbox
  came up short. `parseTargetStderr` in `dynprobe.ts` already draws exactly this line and is right there to reuse._
- ◐ **The dynamic tier runs and the ledger does not move** — impact **high**, and it is the pass's biggest
  structural result. **The emulation half is wired as of 2026-08-03 (`bde3f2d`); `renode` and `ghidra` are not.** Measured over the whole corpus after the full sweep: **1302 findings from 28 distinct
  sources**, and the seven heaviest rungs contribute **none of them**.

  | in the ledger | absent from it entirely |
  |---|---|
  | `sbom` 474 · `binvuln` 337 · `certs` 156 · `kernel` 36 · `updatepath` 34 · `nvram` 28 · `symreach` 28 · `zeroday` 28 · `devicetree` 24 · `fwhunt` 19 · `compcve` 19 · `binary` 17 · `fsaudit` 14 · `services` 13 · `gitleaks` 13 · `uboot` 10 · `auxsecrets` 8 · `compmap` 7 · `yarascan` 7 · `rtos` 5 · `dynprobe` 5 · `chipsec` 4 · `webtaint` 4 · `esp` 4 · `secrets` 3 · `encrypted` 3 · `boot-cmdline` 1 · `triage` 1 | `emulate` · `emulate-system` · `fuzz` · `decompile` · `ghidra` · `renode` · `webprobe` |

  Those seven ran in this pass — 7 user-mode runs, 7 full-system boots, 7 fuzz campaigns, 7 decompiles, 7 Ghidra
  passes — and produced **zero rows**. Their results are on the job rows and reachable through the per-kind
  endpoints; nothing composes them into findings the way `symreach` and `dynprobe` are composed.

  **The proof-state census is the same fact from the other side:**

  | state | count |
  |---|---|
  | `needs_runtime_reproduction` | **894** (69 %) |
  | `static_confirmed` | 349 |
  | `blocked_by_platform` | 57 |
  | `confirmed_in_emulation` | **1** |
  | `blocked_by_security` | 1 |
  | `confirmed_full_system` | **0** |

  **Three boots returned `proofState: confirmed_full_system` in their stored result and not one produced a finding
  carrying that state** — the ladder's top rung has zero rows in the entire corpus. Meanwhile 894 findings are
  leads explicitly waiting for the runtime reproduction that this tier performed 21 times and never fed back.
  Every one of those leads still reads *"a precondition was observed, nothing was proven"* on images where the
  kernel booted.

  This is not the ladder failing — the rungs work, three kernels booted, and the single `confirmed_in_emulation`
  row is a **negative** (`sbin/pktlogconf: strcpy executed at runtime, but on constant data rather than the
  supplied input`) that no static pass could have produced. It is that the wiring stops at the job row. The
  pattern already exists and is used twice: a route `startJob`s a provider and calls `syncFindings` under a stable
  source. **Closing this converts work already being done into evidence, which is a better return than any new
  worker on the §4 list.**

  **Correction to the diagnosis above, made while fixing it: it is not seven providers, it is four.** Read from
  the routes rather than from the census, `decompile` has always called `syncFindings` under `binary:<path>` —
  those are the 17 `binary` rows in the table — and `fuzz` (`fuzz:<binary>`) and `webprobe` both sync too, but
  only on a crash and only on a reproduced hit respectively, so their absence from the census is them finding
  nothing, not them being unwired. The providers that genuinely lacked the second half were `emulate` (all three
  rungs), `emulate-system`, `renode` and `ghidra`. **A census counts rows; it cannot tell "never wired" from
  "wired and empty", and this entry read one as the other.**

  **Done (`bde3f2d`): `emulate` and `emulate-system`, both rungs and both lanes.** Two pure composers beside the
  logic that already decides the verdict — they carry `proofState` verbatim rather than re-deriving it — plus the
  same rows on the agent's approved-emulation path, so an image's dossier no longer depends on who started the
  run. Every outcome earns a row, including the blocked and unconfirmed ones, because the ledger going quiet is
  what let a missing map key read as a platform limit. **Verified on the deployed build against the real corpus,
  and the census moved for the first time: 1302 → 1305 findings, `confirmed_in_emulation` 1 → 2, and
  `confirmed_full_system` 0 → 1.** That last row is the WR940N boot — `system-boot-confirmed`, evidence channel
  `emulated_run`, and its rationale ends in the reproducibility verdict verbatim: *"One boot. It reports what THAT
  run did … and nothing about what the next one will do"*, with `supportsCausalClaim: false` in the evidence. The
  BE3600 carries a `system-boot-blocked` row and the WR940N an `emulate:usr/bin/httpd` row; none of the three
  existed before.
  `renode` followed the same day (`dae1e81`) — it matters more than the qemu rungs for the RTOS and bare-metal
  images, whose lack of a rootfs skips every other stage, making it their only dynamic question. **Still open:**
  `ghidra`, whose output is a decompilation, so what a row would assert needs deciding first.

  ⚠ **CORRECTION — "a confirmed boot does not reach back to upgrade the leads it might settle" was the wrong
  diagnosis, and it was written here twice.** Measured over the deployed corpus (1310 findings, 906 at
  `needs_runtime_reproduction`, 899 of them on the 7 rootfs-bearing images):

  | count | kind | can any rung settle it? |
  |---|---|---|
  | **474** | `cve` (grype, package-level) | **No.** Evidence is `{id, packageName, packageVersion}` — no binary, no call site. Deliberately a lead by policy (*present ≠ reachable*). A boot proves the image runs, not that the CVE's code path is reached. |
  | 210 | `binary-pwnable-candidate` | Yes — by **symreach/dynprobe per binary**, not by a boot. 86 are `.so` and 74 are non-runnable, so 136 are eligible; the scan asks **3 per run**. |
  | 127 | `binary-cmdexec-sink` | **No lead kind exists for it.** `reachabilityLeads` filters on `binary-pwnable-candidate` alone. The largest addressable untouched class. |
  | 22 | `sink-reachability-inconclusive` | No, by design — budget exhaustion is not an answer. |
  | 12 + 21 | gitleaks heuristics · image-wide (`update-*`, `nvram-*`, `uboot-netboot`, …) | No rung applies. |
  | 7 | `network-daemon-autostart` | **Yes — and these are the ONLY ones a boot can honestly touch**, via a forwarded port that answers. |

  So **529 of the 906 (58 %) are not the kind of thing any rung can settle**, and of the rest the answering rung
  is per-binary, which a full-system boot does not help with — `dynprobe` is strictly qemu-user over a gdbstub and
  has no path into a booted guest at all. **The bottleneck is arithmetic, not epistemics: caps of 3/3/8 against
  136 eligible candidates, plus 127 rows with no lead kind.**

  And the boot does not even deliver its own seven: the corpus's single `confirmed_full_system` row has
  `open: []` — two forwards, 158 SYNs, not one answer, `guest-dropped`. **No image in the deployed corpus has a
  booted guest with a port that answers**, so there is nothing to point a web probe at today.
  **What is actually worth building, in order:**
  - ▢ **A lead kind for `binary-cmdexec-sink`** (127 rows), asking symreach for `system`/`popen` — the manual
    route already supports exactly that question and phrases it well. Measure before enabling, the way the probe
    interest rank was measured: it competes for the same budget of 3.
  - ▢ **Schedule off STORED findings.** Every lead builder today reads the drafts a provider just returned; no
    code path turns an existing ledger row into a scheduled question, so the 906 are unreachable by construction
    even where a rung exists.
  - ▢ **Drive a web probe inside the boot's live window.** `runFullSystem` tears the guest down, and the forwards
    are ephemeral high ports, so the stored `open[]` cannot be probed afterwards — pointing a later probe at that
    port number would connect to whatever else grabbed it, which is the fixed-port trap in reverse. The probe has
    to run before teardown. (`WebProbePanel` still defaults to `http://127.0.0.1:8080`, which the ephemeral
    forwards made permanently wrong.)
  - ✅ The re-plan's cap message called every dropped lead a "daemon lead" whatever it was — fixed, it now names
    the kinds it dropped.
- ✅ **`arm64` is missing from `QEMU_SYSTEM_BY_ARCH`, and the block says the deployment lacks a tool it has**
  (fixed 2026-08-03, `135e16a`, deployed `bde3f2d`) — impact **high**, same file and same shape as the entry above. The BE3600 full-system rung returns
  `{"ran":false,"proofState":"blocked_by_platform","reason":"No qemu-system emulator/machine for arch \"arm64\"
  in this deployment"}`. That reason is false about the deployment: `qemu-system-aarch64` **is installed** in the
  container. `providers/preflight.ts:24-32` lists `mipsel`, `mips`, `arm` and no `arm64`, while
  `QEMU_MACHINE_BY_ARCH` two lines below already carries `arm64: 'virt'` — the machine was chosen and the
  emulator never mapped. The comment immediately above is the record of the *previous* instance of this exact
  bug (*"every full-system boot of a big-endian image … died before executing one instruction, on a machine where
  qemu-system-mips was installed the whole time"*). So: three instances of one shape in one file — mips→mipsel in
  user mode (still open, above), mips→mipsel in system mode (fixed, and its comment is the warning), and now
  arm64 unmapped. It blocks the rung on the corpus's flagship modern image, and `blocked_by_platform` makes it
  read as an honest platform limit rather than a missing map key.

  **Closed, and it moves the failure rather than enabling a boot — which is the whole point.** The BE3600 now
  answers `No firmadyne kernel for arch "arm64" in /opt/firmae/kernels (tried nothing — this architecture has no
  mapping)`, verified on the deployed build: the block names the asset that is actually absent instead of a tool
  that is present. firmadyne ships no arm64 kernel and none was invented. **The fix forced a second one**:
  `hasSystemKernel` was `fs.existsSync(FIRMADYNE_KERNELS_DIR)` — a bare directory check, true for every image as
  soon as the deployment shipped any kernel at all — so mapping arm64 would have made the preflight plan
  `full-system` and advertise a `confirmed_full_system` ceiling for an architecture that cannot boot here. It is
  now per-architecture, and the kernel catalogue moved up to `preflight.ts` where that question is answered.
  _Surfaced by the same run, not fixed: the 973 MB ext2 disk image is assembled BEFORE the kernel gate is checked,
  so an unbootable architecture pays a full image build to be told the deployment has no kernel for it. The gate
  is pure and could run first._
- ▢ **The agent's full-system rung is handed a directory where the route hands a disk image** — impact **high**,
  found 2026-08-03 while wiring the ledger, not fixed because nothing has ever run it end to end. `routes/emulate.ts`
  calls `ensureRootfsImage(rootfsPath, arch, handle)` first and passes `image.imagePath` to `runFullSystem`; the
  approved-emulation path in `agent/session.ts` calls `runFullSystem(arch, rootfsPath, 8080, h, rootfsPath)` —
  the extracted **directory** as the disk image. That is the *"no code path built the disk image it was handed"*
  defect, fixed once for the operator route and never carried across, and it sits behind a human-approval gate
  which is why no sweep has hit it. Both lanes should call one helper.
- ▢ **The run ledger reads a full-system boot as a user-mode run** — impact medium, one function.
  `summarizeRun` (`providers/run-summary.ts`) handles kind `emulate` by looking at `ran`/`timedOut`/`exitCode`
  only, and never at `proofState` — so a boot that returned `confirmed_full_system` renders in the Test bench as
  `outcome: 'lead'`, headline *"Ran under user-mode emulation, exit ?"*. The three rungs share one job kind, and
  this summary assumes the cheapest one. The findings rows now say the right thing while the run ledger beside
  them says the wrong one.
- ▢ **A missing emulator throws instead of returning a blocked result** — impact medium. `runUserModeEmulation`
  throws when the arch maps no emulator or the tool is absent, so the job fails and the ledger gets nothing —
  where every other provider returns `available: false` and earns a `blocked_by_platform` row. The auto-run lane
  now degrades honestly (its runner reports a spawn failure as `ran: false`, which composes a blocked row), but
  the operator route still throws. Rule 2 of the proof-state discipline, on the one path that predates it.
- ✅ **An embedded TLS private key inside an ELF is invisible to BOTH secret scanners** (fixed 2026-08-03,
  `b4675e6`) — impact **high**.
  `usr/bin/httpd` in the WR940N holds one `BEGIN RSA PRIVATE KEY` and one `BEGIN CERTIFICATE` in plain PEM
  (verified by grep on the extracted rootfs; the blind agent additionally proved possession by signing with the
  key and verifying against the certificate's public half, `CN=tplinkwifi.net`, expired 2019-05-30, in a 2026
  build). The app answers `certs → {"certCount":0,"reason":"No X.509 certificates found."}` and `secrets → []`.
  Two independent causes: (a) `providers/certs.ts:186` `ROOTFS_FILE_CAP = 256 KB` skips the 1,948,552-byte binary
  and **nothing counts or reports the skip**, so a cap reads as an answer — rule 4; (b)
  `fsaudit.scanContentSecrets` is documented *"Found by content, not filename"* and is, but
  `collectContentScanFiles` only ever hands it paths passing `isContentScanCandidate`
  (`providers/fsaudit.ts:629`), an extension whitelist plus extensionless files under `etc/` — so the content
  scanner never sees the file. `CONTENT_SCAN_BYTES = 512 KB` would truncate it anyway.

  **Closed.** Both scanners now walk the bytes for the `-----BEGIN ` marker instead of trusting an extension or a
  size, and a block counts only with a label, a matching END and a base64-armor body — the third condition being
  what separates a key from `libwolfssl`'s format strings (the WR940N holds **19 markers and only 3 complete
  blocks**, and the other 16 are reported rather than dropped). What is CLAIMED is decided by decoding the body
  with `node:crypto`: the same binary's `DH PARAMETERS` are not claimed, and an undecodable block is reported as
  unclaimed. Real bytes, in-container: `usr/bin/httpd` → the RSA-1024 private key at offset 1894844 AND
  `CN=tplinkwifi.net` expired 2019-05-30, where the deployed build had answered `certCount: 0`. Bound chosen after
  measuring all 18 extractions (worst case, the BE3600 carve: 450 MB read in 261 ms; nothing was ever dropped by
  the total budget) and the coverage now travels in the result, so a zero cites what was read. New true positives
  across the corpus: Tenda ×2, DVRF `libpolarssl.so`, IMOU ×3 plus an encrypted `privkey.pem` reported **without**
  claiming a decode, BE3600 `libgnutls`.
  **Follow-ups, in order of value:**
  - ▢ **Possession is one comparison away.** The WR940N key's public half matches the certificate in the SAME
    binary. `createPublicKey(key).export()` vs `cert.publicKey.export()` raises "a private key is present" to
    "the shipped TLS identity is forgeable" — which is what the blind agent proved by hand, and it is a fact
    about the bytes, so it stays `static_confirmed`.
  - ▢ **`auxsecrets.ts` still has the exact defect just fixed**: a `SCAN_EXT` whitelist plus 512 KB UTF-8 reads,
    and it reports `filesScanned` without ever saying what it skipped. It should call `scanTreeForPem`.
  - ▢ **The scanner wants its own module.** `fsaudit.ts` importing `certs.js` is the wrong dependency arrow now
    that four providers want the same scan; `providers/pem-scan.ts` is the right home.
  - ▢ `fsaudit`'s `WALK_CAP = 5000` now *reports* its truncation but is unchanged, so a 6499-file rootfs is still
    partly unwalked; and the web has no view of the new `scan` coverage at all.
  - ▢ **`RSA TESTING KEY`** — Go's testdata convention for evading secret scanners — is classified `other` and not
    claimed (1 instance in the corpus, `AdGuardHome`). A deliberate under-claim worth revisiting.
- ✅ **gitleaks hits are normalised to `static_confirmed` / `high`, and 12 of them on one image are false**
  (fixed 2026-08-03, `0ceb136`) — impact **high**. On the BE3600: 7 hits on `dnscrypt-proxy.toml` are the upstream **public** minisign key
  (`RWQf6LRC…`), four of those on **commented-out lines**; two more are `public-resolvers.md` and
  `odoh-servers.md`, the published dnscrypt resolver directory; one is `hmac.lua`, a generic HMAC implementation
  with a parameter named `key`; two more (`sendsms`, `wg_client`) were independently triaged as FPs by this run's
  blind agent and by the 2026-07-22 pass. For a *Generic API Key* rule the property literally in the bytes is a
  high-entropy string, not an API key — promoting a heuristic to the bench's strongest proof state is the failure
  the ladder exists to prevent. Mirror image of the entry above: there the app loses a real key, here it asserts
  twelve that are not there. **The secret lane is the weakest part of the bench.**

  **Closed by making the classification rule-aware rather than by suppressing rows.** A rule whose match IS the
  artifact (a PEM private-key block, a prefixed/checksummed token) keeps `static_confirmed`/`high` and is **never**
  discounted by context — losing a real key to "it sits in documentation" is the worse failure of the two. A
  heuristic rule becomes a lead, with severity moved by signals measured from the report itself: commented-out
  line, documentation file, the identifier that named the value (`minisign_key` down, `private_key` up), example
  marker, source identifier. **Nothing was told what `RWQf6LRC…` is — the file says so.** All 12 demote (four
  land at `info`, and it turns out five sat on commented-out lines, not four); a real RSA key and a `ghp_` token
  planted for the test — including one deliberately placed in a `README.md` — stay `static_confirmed`/`high`.
  Fed the STORED result, which predates the context fields, it still demotes all 12: **a missing field reads as
  not-measured, never as a discount earned.** The same classification now also feeds `recordCredentials`, which
  was writing `severity: 'high'` for every match into the corpus-wide credential table — the one the cross-image
  layer reads to claim credential REUSE between devices, where an over-claim travels to conclusions about other
  images.
  **Follow-ups:** ▢ gitleaks-the-tool skips binaries entirely, so `libgnutls.so.30.37.1`'s two EC private-key
  blocks and `gl-sdk4-hw-info.ko`'s `BEGIN PRIVATE KEY` are invisible to THIS lane (the PEM scanner above now
  catches them, which is why the entry is not more urgent). ▢ `redactMatch` passes any match ≤24 chars through
  verbatim, so a genuine 20-char API key is stored in full in `evidence.match`. ▢ `FINDING_CAP = 500` truncates
  by filesystem-walk arrival order, which rule 4 forbids. ▢ The web mirror of `GitleaksFinding` lacks the new
  fields, so the UI cannot show the reasoning behind a demotion.
- ⚠ **The UEFI variable reader is one variable deep, and the test key it was built to find is in the other 56** —
  impact **high**, and it closes the *"`detectTestKey` is STILL unexercised"* item above. App on
  `OVMF_VARS_4M.snakeoil.fd`: `variableCount: 1 · variables: ["CustomMode"] · hasPK/hasKEK/hasDb/hasDbx: false ·
  testKey: null`. Two blind agents, independently, each wrote a 60-byte-record walker for the EDK2 authenticated
  store and each recovered **57 records, 31 live, zero decode failures**, with completeness proven (exactly 57
  `AA 55` pairs exist in the 540,672 bytes and all 57 are walked headers). Both measured chipsec at **1 of 57**,
  across 5 parsers × 4 offsets × 6 fwtypes; `chipsec_util uefi nvram` refuses to run offline. What the 56 hold:
  a self-signed `O = SnakeOil` CA, RSA-2048, valid 2020→**2120**, byte-identical in PK, KEK **and** db; a `dbx`
  whose only entry is `e3b0c442…b855`, the SHA-256 of the empty string; and an enrolment order showing the keys
  went in through the **unauthenticated** path. On the `.ms` sibling: Debian's PK byte-identical to KEK[0], db =
  Windows Production PCA 2011 + UEFI CA 2011, and **both of those CAs expired in June 2026**. The app's `note`
  is right and refuses to call the platform Secure-Boot-off — it is the extraction under it that is starved.
- ⚠ **The in-app agent's judgment nodes are starved of what the app already holds** — impact **high**. On the
  WR940N the `zero-day` node was handed `taint.sources: []`, `cgiHints: []`, `hasTaintSurface: false` and
  `priors.vulnerableComponents: []`, and concluded — correctly for that input — zero candidates. At that moment
  the ledger for the same image held **12 `binary-cmdexec-sink`, 37 `binary-pwnable-candidate` and 3
  `component-cve`, one of them `CVE-2020-8597` at critical**. The agent is not reasoning badly; it reasons over a
  scaffold far poorer than the workbench it is embedded in, and its empty answer is then stored beside a ledger
  that contradicts it.
- ⚠ **The Agents console answers "what came of it" with a process status** — impact **high**, found by looking at
  the page. The Runs table's second column is headed `colOutcome` — *"Qué salió de ella" / "What came of it"* —
  and `RunOutcome` (`pages/Agents.tsx:304`) always renders a badge built from `run.status`. For anything finished
  that string is `done` **by construction**, so every completed run reads the same. Scoped precisely:
  - **`scan` rows are fine.** Beside the badge they carry `workers(ran, total)`, the findings count, and an
    `incomplete(N)` badge whose `title` names the workers that did not run (`Agents.tsx:343-362`).
  - **`agent` rows are the defect.** The whole cell is `done` + a step count (`Agents.tsx:320-329`). Verified on
    the deployed page over this pass's 18 sessions: every row reads `done · 7 steps` or `done · 3 steps`. A
    session that mis-resolved the class and produced zero `zero-day` candidates and one that produced five are
    indistinguishable; so are the 11 that halted at `target-selection` for want of a rootfs — whose outcome is
    "there was nothing to analyse", not "done".
  **The file's own header states the rule it breaks**, lines 19-23: *"A row states an outcome, not a status.
  `done` says a process finished and says nothing about what was learned."* That prose describes the
  `summariseRun` treatment that exists for scans and was never written for agent rows.
  **And the machinery is already built and used elsewhere:** `routes/runs.ts` + `providers/run-summary.ts` turn a
  job row into an outcome from `proven | lead | empty | blocked | failed | running`, and `RunHistory.tsx` renders
  exactly that in the other panels. The console does not call `/runs`; it assembles its own rows from raw jobs
  (`Agents.tsx:88`, `status: j.status`). The fix is to give agent rows a real outcome — `haltReason`, budget
  consumed, whether the human gate fired, `zero-day` candidate count — or to route the whole table through
  `/runs`, and to stop putting a process status in a column that asks a different question.
- ▢ **The agent's `resolvedClass` is unconstrained free text and unreconciled with W0** — impact medium.
  Over 18 sessions: 15 right, **1 wrong** (Xiaomi 2023 `rtos` → `linux`, and it was the only `high` confidence
  among the wrong answers, with step 2 of the same transcript saying *"RTOS blob emulable under Renode"* two rows
  later and nothing reconciling them), and **2 off-vocabulary** — `embedded-uefi` for `uefi-bios`,
  `embedded-linux-router` for `embedded-linux` — semantically right, unusable by anything that routes on the
  class. W0 already computed the class deterministically before the session started. The fix is to hand the node
  that class and make disagreement a recorded event, not a better prompt.
- ✅ **Cross-reference credential hashes against the strings the image itself ships** (2026-08-03) —
  `providers/credmatch.ts` + `providers/descrypt.ts` + `POST/GET /images/:id/credmatch`, source `credmatch`.
  The cheap 90 % of the W3 "offline cracking" item that was filed as *"hashcat on `/etc/shadow`"*: no wordlist and
  no GPU, because the candidate set is the image's own printable strings and the salts are already in hand.
  A hit is `static_confirmed` (the plaintext maps to the stored hash — a fact about the bytes, never a device
  claim); a miss is a **bounded negative** stating how many candidates were tried, how they were derived and what
  the cap dropped; a scheme this deployment cannot compute is `blocked_by_platform` naming the scheme.
  **Measured on the real corpus**: **Tenda CP3** (`2b5fe786`) → `root` = `Td2N3ww1` in 1.3 s, from
  `usr/bin/force_upgrade` @0x20 via the `current_force_upgrade_pwd=` assignment; **WDR3600** (`398d50ef`) →
  `root` = `sohoadmin` in 39.5 s, from `usr/bin/vsftpd` @0x28930, 143,561 candidates; **WR940N** (`c42ab6f2`) →
  a bounded negative over 115,226 candidates.
  Three corrections to the entry this replaces, all found by running it:
  **(1) `sohoadmin` is NOT in the WR940N image.** `grep -ria sohoadmin` over the whole of `c42ab6f2` — raw image,
  every carved artefact, the rootfs — finds nothing. The string lives in `398d50ef` (WDR3600), which ships the
  **identical** `$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/` hash. The password of the WR940N really is `sohoadmin`; the
  image simply does not write it down, so the honest answer for that image is the bounded negative above.
  **(2) `openssl passwd -crypt` does not exist any more.** OpenSSL 3.0 removed it (`passwd: Unknown option:
  -crypt` on the container's 3.0.20), so DES — the dominant scheme in firmware of this vintage — is computed
  in-process by `descrypt.ts`, verified against glibc's `crypt(3)` over 14 vectors.
  **(3) `$5$`/`$6$` are computable after all**, including a `rounds=N$` cost passed through `-salt`, and both
  match glibc exactly. bcrypt, yescrypt and scrypt are the ones with no option.
- ▢ **credmatch harvests only the rootfs, and only that image.** Two gaps, both concrete:
  *Sibling partitions and the raw image are not candidate sources* — `auxsecrets.ts` exists because the Tenda's
  device-wide RSA key lives in `jffs2-root-0`, a partition `findRootfs` does not return, and the same blind spot
  applies here. *Cross-image pooling would settle the WR940N.* Its hash is byte-identical to the WDR3600's, and
  the plaintext is in the WDR3600 — a vendor that reuses one root password across a product line is the normal
  case, and the corpus already holds both images. It is deliberately not done: "the strings THIS image ships" is
  what makes a hit `static_confirmed`, and pooling would need a different, weaker claim ("a sibling image in this
  corpus ships the plaintext"), stated as such.
- ▢ **credmatch is not routed into the autonomous scan or the coverage banner.** `opacidad-plan.ts`'s
  `specsForClass` does not schedule it and `coverage.ts` does not count it, so W9 never asks the question and the
  per-image banner cannot say whether it was asked. It also has no web panel — the result is reachable only
  through the API. Impact medium: the provider is honest about its own coverage, and nothing else knows it exists.
- ▢ **bcrypt, yescrypt and scrypt are permanently `blocked_by_platform` here.** `openssl passwd` has never had an
  option for any of them, and nothing else in the image computes them. A modern rootfs using `$y$` therefore gets
  a "could not be tested" row rather than an answer. Closing it means either a second hasher in the toolchain or a
  pure implementation, and yescrypt's is not the ~250 lines DES was.
- ▢ **Kernel modules are counted, never disassembled** — impact **high**; the concrete instance behind
  `METHODOLOGY-GAPS.md` §4 #5. On the WDR3600 the app produced posture only (`kernel-age` critical, `/dev/kmem`
  compiled in, *"none of the 84 inspected modules carries an intree tag"*, *"8 of 9 kernel posture questions could
  not be answered"*); its sole mention of the module in question is a count inside `component-map`. The blind
  agent went in and found **KCodes NetUSB 1.02.66 on TCP 20005** (port read from `li v0,20005` in `tcpConnector`),
  with `SoftwareBus_dispatchNormalEPMsgOut` at `0x118f0` doing `addiu a0,v0,17` on a byte-swapped attacker length
  straight into `__kmalloc` with no range check — `len >= 0xFFFFFFEF` wraps to a 0–16 byte allocation and then
  `len` bytes are written. Unauthenticated kernel heap corruption under `GFP_ATOMIC`, the CVE-2021-45608 class.
  It also **declined CVE-2015-3036**, the obvious call for an Apr-2015 NetUSB, because `run_init_sbus` at
  `0xd338` carries the vendor's `sltiu v0,v0,63` bounds check. 84 modules inspected for a tag, none disassembled.
- ▢ **UEFI module rule coverage is 11 of 136, and the module that decides the answer is in the other 125** —
  impact medium. `fwhunt` on `OVMF_CODE_4M.secboot.fd` reports 11 matches of `BRLY-2022-028 (RsbStuffingCheck)`
  across `CpuHotplugSmm, CpuIo2Smm, FvbServicesSmm, PiSmmCore, PiSmmIpl, SmmAccess2Dxe, SmmAccessPei,
  SmmControl2Dxe, SmmFaultTolerantWriteDxe, SmmLockBox, VariableSmmRuntimeDxe` — eleven examined, eleven matched,
  a rate that is a property of which modules got examined. `PiSmmCpuDxeSmm`, the module that performs the RSM on
  SMI exit, is **not** among them, and the blind agent verified against the rule's own hex pattern that both of
  its `RSM` instructions are preceded by RSB stuffing — FirmwareBleed mitigated where it counts. The provider's
  own reason line already states the denominator honestly (*"102 module rule(s) over 11/136 carved module(s)"*);
  the number it reports is the problem, not the reporting. Do not suppress the rule — raise the coverage.
- ▢ **The cross-image corpus layer misses the only cross-image fact in this corpus** — impact medium, and it is
  the advertised differentiator. `Livebox6-4BD4` — a home network name — appears 4× in the Xiaomi 2018 raw NVRAM
  (with its PSK `4Ef5nARJdaZn` in the clear) and 4× inside the BeanView's compressed JFFS2
  (`devinfo/devlog/ezvizlog`, `log_BE8876253`). Two blind agents found it independently and neither could link
  it — only a cross-image view can. `/api/corpus/overview` returns `credentialReuse: []`. Not a bug, a modelling
  gap: `artifact_occurrence` (1999 rows) links **files by sha1** and the files differ; `credential_occurrence`
  (8 rows) links **credential hashes** and no provider emits an SSID as one. Worth closing because the fact
  itself is provenance — these two samples come from the same environment, which bears on using either as
  evidence.
- ▢ **Route guards still conflate "extraction never ran" with "extraction ran and found no rootfs"** — impact
  medium. On both Xiaomi eCos images extraction ran, succeeded and returned its diagnosis (*"A raw LZMA stream of
  973728 bytes, declaring 2175968 bytes uncompressed, was carved and never unpacked"*), and `sbom`, `gitleaks`,
  `fsaudit`, `compmap` and `services` then answered `HTTP 400 {"error":"Run extraction first — …"}`. Extraction is
  not what is missing; a rootfs is, and it is missing as a measured property. The same conflation iteration 17
  fixed in the web's section index, alive one layer down in the route guards.
- ✅ **The camera rootfs are not partial carves** (closes the ◐ above). The Tenda's rootfs really is 97 files: the
  vendor's own `mtdparts` declares nine partitions, five JFFS2, and the application lives in `/opt/app` (57 files,
  holding the 24 MB `Kylin` binary that IS the web/ONVIF/RTSP server), `/opt/custom` (6) and `/opt/sav` (18). The
  carve is complete; the entry stayed open for a week because nothing read the partition map.
- ✅ **The BE3600 gap has closed, and this is the run's biggest result in the app's favour.** §2 records this
  image as *"0 files extracted, 0 findings"*. Today the app extracts it and produces **686 findings**, including
  at `critical`/`static_confirmed` `Command injection: tor os.execute — params.enable → uci → shell as root` and
  `Config-restore bypass: tor reads a uci value into os.execute — uci import/restore sidesteps the RPC validator`,
  plus the same pair for `wg_client io.popen`. That is both halves of §7.1's headline, produced by the fixed
  pipeline — and **this run's blind agent missed it entirely**. The sink was confirmed present
  (`replace_country()` in `usr/lib/oui-httpd/rpc/tor`), so it is an agent miss, not a phantom.

## Out of scope (by design / hardware)
- — Weaponized exploitation (ROP / shellcode / PoC) — FirmLab proves reachability + drafts disclosure, no PoCs.
- — JTAG/SWD/SPI extraction, chip-off, side-channel/glitching, BLE/ZigBee/Wi-Fi/SDR — hardware lab / Phase-6 dongle.
