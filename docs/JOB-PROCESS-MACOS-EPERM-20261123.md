# `job-process.test.ts` maxBuffer / `kill EPERM` on macOS — 2026-11-23

During the 2026-11-08 release validation, the case `owned execFile compatibility > keeps original spawn, exit,
timeout and maxBuffer error codes` failed once inside `pnpm -r run test` with
`expected Error: kill EPERM { errno: -1 } … "code": "EPERM", "stdout": "1234"` instead of
`ERR_CHILD_PROCESS_STDIO_MAXBUFFER`. The isolated rerun passed all six cases. Evidence (local, read-only):
`~/.local/state/firmlab/release-20261108-142942/final-test.log` and `job-process-rerun.log`.

**Cause: proven.** On macOS a group SIGKILL that lands on an exited but unreaped leader is refused with EPERM,
and `job-process.ts` let that refusal replace the provider's error. **Fixed** by reading the OS state at the
refusal. Cleanup guarantees are unchanged.

## Environment

- macOS 27.2.1 (26B131), Darwin 27.2.0, `xnu-13432.41.4~25/RELEASE_ARM64_T8132`, Apple M4, 10 cores.
- Node `v26.13.1`, vitest 4.1.12, worktree base `da3d24f`.

## Kernel behaviour, measured

A scratch script spawned a detached child that exits at once and then blocked the event loop, so libuv could not
reap it. Two consecutive runs gave the same result:

| Probe while the leader is a zombie (`ps` stat `Z`) | Result |
| --- | --- |
| `process.kill(-pgid, 'SIGKILL')` | `EPERM` |
| `process.kill(-pgid, 0)` | `EPERM` |
| `process.kill(pid, 0)` | ok (POSIX: success for a zombie) |
| `process.kill(-pgid, 0)` after the reap | `ESRCH` |

This matches XNU's `killpg1`. The group walk filters out `SZOMB` members, and when nothing was signalled the
POSIX `kill(2)` path returns `EPERM`, not `ESRCH`. A group that holds only its dead leader therefore refuses
the group signal exactly like a group of processes this user may not signal. Linux signals its own zombies
successfully, so it does not produce this refusal. That claim comes from the kernel's design and was not
measured here, and it is consistent with the failure never being seen on the deployed Linux runtime.

## The race

`process.stdout.write("123456789")` writes and exits immediately. When the parent's event loop is slow to poll,
the stdout data and the SIGCHLD wakeup arrive in the same loop turn. libuv runs the stream read before it reaps,
so `append()` trips `maxBuffer` and calls `owner.terminate(child)` while the leader is still a zombie.
`JobCancellation.terminate` swallows only `ESRCH`, so the `EPERM` propagated, and `kill()` in `job-process.ts`
assigned it to `failure`, **overwriting** the `ERR_CHILD_PROCESS_STDIO_MAXBUFFER` that `append()` had set a line
earlier. Cleanup itself was correct throughout. The close handler re-signalled (`ESRCH`) and
`waitForProcessGroupExit` verified the group gone. The only defect was that the provider error was replaced by a
refusal that was not a denial.

## Reproduction attempts and rates

Natural reproduction on unmodified code:

| Attempt | Runs | Failures |
| --- | --- | --- |
| `vitest run job-process`, idle | 40 | 0 |
| `vitest run job-process`, 20 `yes > /dev/null` burners on 10 cores | 40 | 0 |
| full api suite (173 files, parallel), idle | 20 | 0 |
| full api suite under 20 burners | 10 | 0 |

The loops ran the test file 80 times and the full suite 30 times with no failure. The only natural occurrence
remains the one from 2026-11-08, in the full `pnpm -r run test` run with the web suite running alongside. CPU
pressure alone does not reliably open the window. The parent loop has to be late to poll, and a burner on another
core does not delay it.

Forced reproduction on unmodified code, against a scratch tsc build of `job-process.ts`. The run blocks the event
loop synchronously right after spawning, which is how a busy vitest worker behaves. Signals were logged and `ps`
was read only after a refusal:

| Loop held after spawn | Runs | `kill EPERM` replaced maxBuffer | Group at the refusal | `owner.cleanup()` |
| --- | --- | --- | --- | --- |
| 0 ms | 200 | 0 | — | ok |
| 5 ms | 100 | 0 | — | ok |
| 50 ms | 100 | 1 | leader only, `Z` | ok |
| 100 ms | 50 | 10 | leader only, `Z` | ok |
| 200 ms | 50 | 50 | leader only, `Z` | ok |

The rejected error was identical to the logged one: message `kill EPERM`, `errno -1`, `syscall kill`,
`stdout "1234"`. In each recorded trace the refusal was followed by `ESRCH` once the leader was reaped, and every
run's cleanup verified the group's exit.

## Change

`apps/api/src/group-signal-refusal.ts` (new, small):

- `psGroupMembers(text, group)` parses `ps -A -o pid=,pgid=,stat=`. A single row it cannot parse makes the whole
  listing `null`.
- `classifyGroupSignalRefusal(code, leader, members)` is pure. It returns `exited_unreaped` only when the code is
  `EPERM`, the listing is readable and non-empty, the leader is listed, and **every** member is a zombie. Any other
  input returns `denied`: a live member, an empty or unreadable listing, a missing leader, or another code.
- `groupSignalRefusal(error, leader)` reads the process table with `ps` (2 s timeout), only for EPERM and only
  off Linux and Windows. A failed read is `denied`.

`job-process.ts` routes both refusal sites in `kill()` (owned and unowned) through it. An `exited_unreaped`
refusal leaves the provider's own error in place. Every other refusal is recorded exactly as before.

Why the guarantees hold:

- **No capacity is released by this change.** `terminate` threw before marking the child killed, so the close
  handler in `JobCancellation.track` still re-signals and `waitForProcessGroupExit` still has to verify the group's
  exit before the slot is released. A failed verification is still recorded and still fails `cleanup()`.
- **EPERM is never swallowed by code alone.** The OS listing is read inside the same synchronous callback that
  signalled, so the event loop cannot reap the leader between the refusal and the read. The only change possible
  in that gap is another member exiting. That member was going to die anyway, and its death does not hide a
  survivor.
- **A real denial stays visible.** The new test `keeps a maxBuffer kill denial visible while the group is alive`
  injects EPERM while the child is alive and asserts that the rejection is that exact error. The existing timeout
  denial test covers the same case on the timer path.

Tests added to `job-process.test.ts`:

- the decision table for `classifyGroupSignalRefusal`;
- parsing and refusal of malformed listings in `psGroupMembers`;
- the forced zombie window, three attempts with the loop held for 300 ms. **On the original code it failed with
  the exact 2026-11-08 assertion**, and it passes with the fix;
- the live-group denial test above.

With the fix, the forced reproduction gave 100 of 100 runs keeping `ERR_CHILD_PROCESS_STDIO_MAXBUFFER` (50 at
200 ms and 50 at 100 ms), each with a verified cleanup. The test file then passed 30 of 30 runs under 20 burners.

## Not changed (scope): sibling instance

`execFileProcessGroup` (`exec-process-group.ts`) and `runIsolated` (`providers/isolate.ts`) call
`owner.requestTermination`, and `JobCancellation.requestTermination` pushes any non-`ESRCH` refusal into
`failures`. With the window forced (300 ms, 10 runs), `execFileProcessGroup` kept its maxBuffer error, but
`owner.cleanup()` rejected with `kill EPERM` every time, even though the group's exit had been verified. This
fails closed, because the slot is retained with a visible error, but the error is false. The fix belongs in
`job-cancellation.ts`, which is outside this task's file ownership. It can reuse `groupSignalRefusal`, and the
sibling module exists so that `job-cancellation.ts` can import it without a cycle through `job-process.ts`. That
change should be added to the backlog.
