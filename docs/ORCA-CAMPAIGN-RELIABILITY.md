# Orca unattended campaigns: continuity and handoff

## Incident: 1–2 October 2026

The initial Codex → Antigravity handoff **succeeded** at 23:32:43Z: Run `run_ed63045bd51e`
changed owner and consumer generation from 1 to 2. The failure was subsequent unattended continuity.
At 00:47:22Z (02:47 Madrid), Antigravity ended its model turn with a status message. Its last mailbox
checks were non-blocking, and all 60 earlier background waits had completed. Nothing remained to wake it.
Worker completions at 00:49:07Z and 00:54:11Z stayed queued until the user prompted a resume at 07:22:17Z.

An independent Claude review verified the Antigravity transcript (located through Orca session search),
Run inbox/task history, Git reflog, daemon log and macOS power statistics. The daemon did not restart;
the host did not sleep or reboot (sleep count and kernel sleep time were zero). A Codex worker reached
its usage limit at 00:46:40Z and was replaced with Claude. That worker's limit did not explain the
coordinator's normal `DONE` turn. Antigravity quota in the gap was not measured.

Orca mailbox enqueue is durable; wake/nudge is best effort. Input acceptance likewise does not prove
execution or transfer of coordination. The outgoing coordinator had relinquished ownership correctly,
but no independent process owned recovery of an idle receiver. Possible loss of the wait-loop habit
in a compaction is a hypothesis; the actual ended turn and absent waits are verified.

The original eight-hour window elapsed without eight hours of continuous work. See
[the campaign record](OVERNIGHT-CAMPAIGN.md) for delivered changes. An elapsed deadline is not execution evidence.

## Required startup and handoff gates

1. Resolve the current Orca executable and load its version-matched guides. Create one durable Run with
   the actual deadline. Keep a local context file with the original user instruction, Run/owner IDs,
   exact ownership, pending Dispatches and questions, validation, priorities, and known capacity limits.
2. Start the external supervisor **before** leaving the session or relinquishing coordination. Verify its
   PID, journal and first observation against `run-show`. The model's own background wait is not the guard.
3. The coordinator keeps rolling `check --wait --timeout-ms 30000` calls outstanding while work remains.
   Process every Delivery, answer questions, settle/release workers and then ack; re-arm on empty timeout.
4. Before context or quota exhaustion, prepare a ready Claude/Antigravity successor with current context.
   Send the full handoff and have the receiver adopt the **same** Run from its own terminal. Verify the
   owner and increased generation through `run-show` before the sender becomes read-only. Acceptance alone
   is insufficient. Do not impersonate a receiver with a forged `--from`.
5. End at the original deadline or explicit cancellation. Report proven work, validation and gaps. Do not
   silently extend the window, claim unmeasured service exhaustion or count idle time as agent work.

## Incident: 2 October 2026 — stale native `working`

Run `run_ede578636b08`, Claude coordinator generation 3. At 17:12:28Z Claude ended its turn deliberately to prove
an idle → guard → resume roundtrip. The guard (PID 1769) never resumed it. Orca's native row for the pane kept
`state: working` with `updatedAt` frozen at 17:12:41Z, and `snapshotRun` skipped both the rendered read and the
`tui-idle` wait whenever the row said `working`. `ownerState` then fell to the freshness check, which reports a
row older than 180 s as `unknown` — forever, because nothing else was ever read. The rendered screen at the time
showed the finished turn (`Worked 20m22s`), an empty composer and the footer, and a `tui-idle` wait was satisfied:
the evidence existed and was never asked for. The root resumed Claude by hand at ~17:37Z. That is a manual
recovery: the Claude idle-resume roundtrip on this Run was not proven by it, and 17:12–17:37 is a recorded gap.

A contributing factor was Claude's own detached background inbox loop, which outlived the reasoning turn (the
footer showed `1 shell`). Coordinators keep their `check --wait` calls in the foreground of a turn; a detached
loop consumes nothing it should not, but it is not supervision either.

The fix: a `working` row older than the freshness bound (or with no timestamp) is **stale** and earns the same
rendered read and native idle wait as any other state. It becomes `idle` only on positive agreement — rendered
frame, empty composer, no draft, no selector, no quota, no visible turn in progress, AND a satisfied wait. Absence
of a spinner alone is not enough. A turn in progress matters here because Claude keeps an empty `❯` composer and
its normal footer on screen WHILE it works (captured: `✳ Clauding… (1m 27s · ↓ 6.9k tokens · …)`, no "esc to
interrupt"), so an empty prompt never proved idleness by itself. A fresh `working` row is still trusted outright and
causes no read. Tests: `skills/orca-campaign/scripts/watch.test.mjs` (stale-working cases; the working frame is a
real capture, the stale-idle frame is reconstructed from the operator's description and labelled as such).

**Acceptance (18:09–18:14Z, same Run).** The failed scenario was reproduced on purpose: Claude ended a turn with one
background shell (a placeholder `sleep`, polling nothing). Its native row again stayed `working` after the turn
(`stateStartedAt` 17:44:30Z, no `done`). The corrected guard (PID 76136) reported `working` until the row was more
than 180 s stale, then `idle` at 18:12:44Z from the rendered empty composer plus a satisfied `tui-idle` wait, sent
one resume at 18:13:45Z (request `520a0e0a-6a93-4512-a2de-61413157179d`, `turn_started`), and settled it
`confirmed` at 18:14:21Z after Claude's fresh tool and write execution. Earlier the same afternoon the guard had
reported `stale_native_working_turn_visible` while Claude really was working through long single tool calls — the
spinner, not the native row, kept it from calling that idle. Three earlier attempts were void, each woken by an Orca
message notification rather than the guard; the last by the coordinator's own message, because a message addressed
to the root's terminal is delivered to `run:<Run>`, which is the coordinator's inbox too. Send no Run message before
an idle test.

## Capacity policy, guarded worker launch and handoff reasons (2 October 2026)

User steering at 17:42Z, mid-campaign: successor coordinators use their own Orca workers for separable tasks; no
worker is launched on an exhausted model or service; a handoff happens only on observed capacity/context exhaustion
or inability to continue, never as routine rotation. The gen 2 → 3 handoff of this Run was a `forced_test` of the
continuity mechanism, not a quota event, so Antigravity is not blacklisted (its canary ran at 16:36Z).

A prompt cannot enforce an exclusion, so it is code: `skills/orca-campaign/scripts/policy.mjs` (a durable JSON
registry of provider/model blocks, recoveries and handoffs, with the rules in its header) and
`scripts/launch-worker.mjs`, installed as `orca-campaign-launch-worker`, which evaluates the registry and makes no
Orca call at all on a refusal. Both were written by an Antigravity worker dispatched from this Run (Task
`task_7564070c61c2`, Dispatch `ctx_fb8d509cd070`, 27 tests) and integrated by the coordinator, who added the refusal
of a launch naming no model while a model of its provider is blocked. The guard takes `--policy`: a missing or
invalid registry blocks execution, a quota screen on the rendered owner frame is recorded as a provider-wide block
(the owner of a hard stop cannot record its own exhaustion), and no standby on a refused provider is chosen.
Enforcement covers launches through the wrapper; raw `orca orchestration worker-start` is not intercepted.

Dispatching that worker exposed an Orca gap: `worker-start --agent antigravity` failed twice at `agent_readiness`
(timeout) while the pane showed a ready, empty composer, because `terminal wait --for tui-idle` never satisfies for
Antigravity CLI 1.2.14. The fallback was `task-create` plus `dispatch --inject` into the visibly ready terminal,
which keeps the Task/Dispatch provenance and `worker_done`, but leaves the lane unsupervised by design.

## Supervisor

`pnpm campaign:watch --help` exposes `scripts/orca-campaign-watch.mjs`. Its default is observation only.
`--execute` requires a non-empty trusted local context file. The journal is bound to the Run and fixed
deadline; execution holds a fixed per-OS-account Run lock, independent of TMPDIR, plus a journal lock.
The journal records the exact lock paths. Known legacy temporary lock locations are also held.

Example for a **new, authorized** campaign (replace the placeholders; do not reuse an expired deadline):

```bash
nohup node scripts/orca-campaign-watch.mjs \
  --run run_REPLACE --until 'REPLACE_WITH_FUTURE_ISO_DEADLINE' \
  --journal /tmp/firmlab-campaign-UNIQUE.json \
  --execute --context /absolute/path/current-handoff.md \
  --max-resumes 48 --keep-awake \
  > /tmp/firmlab-campaign-UNIQUE.log 2>&1 < /dev/null &
printf '%s\n' "$!" > /tmp/firmlab-campaign-UNIQUE.pid
```

Run from the repository root, with a working Node/Orca installation. Specify `--orca /absolute/path/to/cli`
when discovery would select the wrong host executable; discovery never falls through after a CLI error.
`--keep-awake` is macOS-only and uses a child `caffeinate -i -w <guard-pid>`; it changes no global power settings.
Remove that flag elsewhere. OS shutdown, logout, network loss and unavailable services cannot be repaired
by this process. Persistent launch services or account/model changes are not installed by this fix.

After launch, check the exact PID and journal. If it exited, inspect its log before leaving. To cancel,
signal only that verified supervisor PID. On a crash, the lock intentionally remains: inspect its
`owner.json`, prove that process is gone and no other supervisor owns the Run before manually removing
that exact lock. Do not remove a live lock or start a second guard to bypass uncertainty.

The guard resumes a positively idle, connected owner after an idle grace period. It rechecks owner,
generation, process incarnation and state immediately before submission. A stale Antigravity `done` row
can be confirmed by the current visible input prompt; unreadable screens and quota/permission selectors
block input. A working, interrupted or unverifiable owner receives no prompt. Fast completed turns can
be confirmed through their native state-transition timestamp even when `turn_started` telemetry is unsupported.

Resume intent is persisted **before** sending. An ambiguous/lost receipt never causes a second send.
An unobserved submission becomes visibly blocked after three minutes of proven idleness. Inspect the
original terminal and receipt; any transport replay must use the original request ID and the current Orca
guide. This tool offers no blind automatic resend. Resume frequency backs off and total sends are bounded
by `--max-resumes`; reaching the bound is a blocked state, not proof that every service ran out of capacity.

Optional `--standbys /absolute/path/standbys.json` contains explicit terminal handles, e.g. `["term_REPLACE"]`.
Reserve fresh standby terminals exclusively for this guard. Historical coordinator handles are conservatively
excluded because Orca Run history has no completed/live status. Only a **positively exited** owner triggers this fallback. A candidate must be connected, Claude/Antigravity,
ready with a readable input screen and no selector, and neither another Run's coordinator nor an active
worker. Incomplete fleet enumeration fails closed. A fallback prompt requests adoption; the guard waits
for observed execution/ownership and never declares ownership transferred from acceptance alone.
Unknown liveness and a quota menu require coordinator/operator intervention; prepare successors before exhaustion.

The guard does not consume the Run inbox, integrate branches, release workers, switch models, acquire credits,
or mutate firmware/corpus/database/deployment. It records safe status/receipt IDs and observation gaps, never
terminal contents, handoff text or provider capabilities. Keep the context file updated across handoffs;
ordinary resumes reference it, while a full fallback includes its current content reloaded each observation. A context larger than
80,000 UTF-8 bytes is refused rather than silently truncated or exceeding portable command limits.

## Verification

The guard regression suite runs with `pnpm test:campaign-watch` and is included in `pnpm test`. It covers stale
Antigravity idle state, Claude footer and short turns, unreadable screens, permission/quota selectors,
ownership races, observation gaps, lost receipts, cross-Run standbys, deadline, resume budget and a real
OS-process lock collision across separate journals followed by successful lock reuse.

A real Claude test on 2 October created isolated Run `run_6d7af9005a50` in a disposable test terminal.
A standalone Node guard reactivated its deliberately finished turn; the agent wrote only the temporary
`RESUMED` marker. Orca reported `input_accepted` and `turn_started`, and the guard observed execution,
refused another send with `--max-resumes 1`, then exited at 08:28:45.339Z. The test terminal was closed
only after a positive idle check. This tests recovery and deadline enforcement, not an eight-hour endurance run.

The same recovery was then tested with the original Antigravity terminal, preserving its session and files:
it created isolated Run `run_d61d99553495`, ended with `READY`, and the standalone guard submitted one
resume at 08:39:54.979Z. Orca correctly reported provider telemetry as unsupported; the guard retained the
pending intent until fresh native execution was observed at 08:40:01.049Z. Antigravity wrote only
`/tmp/firmlab-watch-antigravity-resumed.txt` (`RESUMED`). The guard observed return to idle, blocked a second
send at its configured budget, and exited with code 0 at 08:40:46.994Z (the deadline was 08:40:45.577Z;
a read already in progress accounted for the 1.4 s overrun, with no mutation after deadline).
No full eight-hour endurance test has been performed.

A forced-exit fallback was then tested against the closed standalone Claude owner (real Orca
`connected:false`, `exitCause.kind:operator_close`, no Dispatch row). The first trial was held by the
receiver asking whether the handoff text was an instruction; the guard did not answer its selector,
did not submit twice, and exited at deadline without claiming adoption. That test receiver was closed.
The prompt was clarified to direct execution of the already authorized bounded task.

In the final fresh trial, the guard sent one handoff, request `f4d6d78e-1906-4c65-9635-9da18e3da41a`.
The receiver executed `run-use` in its own terminal at 08:53:02Z: `run_6d7af9005a50` changed owner to
`term_0f3e977f-3cdc-4b5b-9dec-abfa2e9fd198`, generation **1 → 2**. Its receipt was saved and it wrote
only the temporary `ADOPTED` marker. The guard confirmed adoption, preserved the receipt ID in its
journal, blocked further input at budget 1, and exited with code 0 at 08:54:38.241Z. The receiver was
closed after a satisfied native idle wait. This tests actual receiver adoption, not only accepted input.

Final validation: `pnpm check`, `pnpm test` (4,120 tests: core 394, API 2,815, web 805, scripts 106),
`pnpm build`, `pnpm biome`, plus the focused 37-test guard suite.
The first full test attempt hit the pre-existing 20 ms HTTP cancellation/socket-arrival race; its isolated
rerun and subsequent full run passed. That independent race is explicitly deferred in `docs/BACKLOG.md`.
The first Claude auditor was retained by Orca's user-takeover protection; the final reviewer was released
with its archive preserved. Test terminals created here were closed; existing user terminals were preserved.

## Shared installation across projects

The maintained package now lives in `skills/orca-campaign/`. FirmLab's existing script is a compatibility
entry point to that same code. Install/update with `pnpm campaign:install`; the installer copies the package
to `~/.agents/skills/orca-campaign`, adds Codex/Claude discovery links and installs
`~/.local/bin/orca-campaign-watch`. The installed copy runs independently of this repository. It refuses
unmanaged destinations, edited managed files and conflicting commands; repeat installation is supported.
The stable lock lives under `~/.local/state/orca-campaign/locks/`; known legacy lock paths remain held.
Old guards using arbitrary custom TMPDIR values must be stopped before upgrading.

For Antigravity CLI, the installer prepares `~/.local/share/orca-campaign-antigravity`; validate and register
it with `agy plugin validate <path>` and `agy plugin install <path>`. This local plugin contains one skill,
with no hooks, agents, commands or MCP servers. It supplies discovery without changing models, accounts or
permission settings. A fresh Antigravity session reported the skill PRESENTE after registration (AUSENTE
before it). Orca's installed-skill inventory also reports Codex/Claude/common-agent discovery.

Use `$orca-campaign` in new sessions, or provide the installed SKILL.md path explicitly in a current session.
Each project must supply its own absolute project path, original user mandate, restrictions, validation and
handoff context. The generic supervisor does not impose FirmLab's firmware/database rules on unrelated work
or grant broader permissions. Each campaign still needs its own verified startup and fixed deadline.

Portability checks installed into a temporary profile with spaces/apostrophes, ran the installed command
and regression suite from another project directory, updated idempotently, and proved user edits and unrelated
commands remain intact. The actual user launcher also observed a live Orca Run from the isolated sample project
with no submitted prompt. No new unattended production campaign or always-running service was started.

The independent cross-project forward test additionally exposed and drove fixes for differing TMPDIR
lock namespaces, Codex/Claude mode footers, and malformed live context/standbys terminating the guard.
Regression evidence now includes two subprocesses with different TMPDIR values sharing one OS-account
Run lock, observer/executor journal exclusion, input repair while the same guard stays alive, and a
persisted stopped state on cancellation. Deadlines require explicit offsets. Native plugin copies are
re-registered after updates; installed common and native cached scripts must match the maintained source.

Shared-package final validation: 40 guard regressions, 2 installer/portability tests, and the full
`pnpm check`, `pnpm test` (4,125 tests), `pnpm build`, `pnpm biome` gates passed. The existing cancellation
socket-arrival race occurred on the first full attempt and the subsequent full run passed; it remains
tracked separately. Skill frontmatter validated, and source/common/Antigravity cached SKILL.md, watcher
and installer hashes matched. The independent forward-test reviewer settled successfully; Orca retained
its terminal under user-takeover protection, so no forced close was performed.
