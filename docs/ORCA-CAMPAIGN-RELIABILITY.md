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

## Supervisor

`pnpm campaign:watch --help` exposes `scripts/orca-campaign-watch.mjs`. Its default is observation only.
`--execute` requires a non-empty trusted local context file. The journal is bound to the Run and fixed
deadline; execution holds a per-Run OS lock even when two callers choose different journals.

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

The 37-test regression suite runs with `pnpm test:campaign-watch` and is included in `pnpm test`. It covers stale
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
