---
name: orca-campaign
description: Supervise authorized unattended Orca project campaigns with an independent watchdog, fixed deadline, durable context and verified coordinator handoffs. Use for overnight or long autonomous sessions and recovering idle coordinators; ordinary one-off coding tasks need no watchdog.
---

# Orca campaign continuity

Use the bundled `scripts/watch.mjs` from any project. The installed command is `orca-campaign-watch`;
if it is outside PATH, run `node <this-skill-directory>/scripts/watch.mjs` directly. Requires Node 22+
and a working Orca runtime. Load the current `orca-cli` and, for supervised workers, `orchestration` guides.
Respect the actual user's authorization and the current project's AGENTS.md/handbook; this skill grants
no permission to deploy, use external services, modify data or change provider settings.

## Start an authorized unattended session

- Establish the user's objective, priorities and original fixed deadline; use the current project's
  working directory. Create/bind one Orca Run and verify its coordinator through `run-show`.
- Write a trusted local context file with the original mandate, absolute project/worktree path,
  Run/owner/generation, allowed and prohibited actions, file ownership, unsettled Dispatches/questions,
  integration state, validation commands, priorities and known capacity bounds. Update it atomically (write a temporary file, then rename it), and keep it current;
  an absent quota metric is unknown capacity. Do not reuse another project's context.
- Start the independent OS process before leaving or relinquishing coordination. For POSIX hosts:

```bash
nohup orca-campaign-watch \
  --run run_ACTUAL --until 'ACTUAL_FUTURE_ISO_DEADLINE' \
  --journal /absolute/path/unique-campaign.json \
  --execute --context /absolute/path/current-context.md \
  > /absolute/path/unique-campaign.log 2>&1 < /dev/null &
printf '%s\n' "$!" > /absolute/path/unique-campaign.pid
```

  Replace these values with the real Run, deadline and files; inspect `--help` for limits/options.
  On macOS, optional `--keep-awake` holds a process-bound sleep assertion, without changing power settings.
  Use `--orca <resolved-cli>` when needed; never silently fall back to a different Orca build.
- Verify the PID is alive and the journal has a successful first observation of the expected owner.
  A connected terminal alone or a prose status does not establish execution. Do not promise continuous
  operation while startup is blocked or unproven. Keep rolling `check --wait --timeout-ms 30000` calls
  outstanding while coordinating unfinished work, processing every Delivery before ack.

Folder projects do not require Git. If Orca registration is needed, use the current guide within the
user-authorized project scope; otherwise ask for the missing authorization. Without separate worktrees,
parallel writers need disjoint file ownership. Do not convert a local-folder task into a Git requirement.

## Handoff and stopping

Prepare a ready Claude/Antigravity successor before context/quota exhaustion. Full handoff is a direct
instruction to carry out the already authorized work: include current context and unchanged deadline,
have the receiver adopt the **same** Run from its own terminal, and verify owner plus increased generation
before the sender relinquishes editing. Never forge a receiver's `--from`. Acceptance proves input only.

The guard resumes only a positively idle owner with a readable empty input prompt. Optional `--standbys`
is a JSON array of explicitly reserved fresh terminal handles: automatic fallback requires a positively
exited owner, a ready Claude/Antigravity receiver, and no other Run/active-worker ownership. Historical
coordinator handles are conservatively excluded. It neither launches agents nor answers quota/permission
selectors; unknown liveness does not justify takeover. Coordinate preemptive handoff yourself while viable.

Each Run has a fixed OS-account lock at `~/.local/state/orca-campaign/locks/<Run>.lock`, independent
of terminal TMPDIR/HOME. Every writer also holds the journal lock; known legacy temporary lock paths
remain held for compatibility. The journal records the exact `locks` paths. Stop older guards using
arbitrary custom temporary directories before upgrading; unknown legacy paths cannot be enumerated safely.
A lost submission stays pending rather than producing a duplicate prompt. Observe the original terminal
and receipt before manual recovery; use the original Orca request ID for a transport replay, never a new send.
Check `reason`, `pending`, `lastSubmission` and `gaps` in the journal; blocked is not service exhaustion.
After SIGKILL, prove the lock's PID is gone and no guard still owns the Run before removing that exact lock.

Cancellation signals only the verified guard PID; it does not kill user terminals or workers. At the fixed
deadline finish the safe unit and report actual work/validation/gaps; elapsed time is not evidence of work.
The guard stops issuing calls at cancellation/deadline and releases its own lock/sleep assertion on normal exit.
OS shutdown, logout or unavailable services can still interrupt a session. Do not silently extend deadlines.

The supervisor reloads the context each observation and caps it at 80,000 UTF-8 bytes. Invalid context
or standbys block input while observation continues; repair the file and verify recovery. Check both PID
and fresh `checkedAt` periodically; a journal alone cannot prove a process is still alive. Cancellation
and unexpected errors record a stopped state on orderly exit. Use explicit UTC offsets in deadlines.
The supervisor recognizes captured Codex, Claude and Antigravity composers and bounds resumes with
backoff and `--max-resumes`, and never consumes the coordinator inbox or integrates/releases workers.
Observer mode is the default; only `--execute` submits prompts. Installation does not start a campaign
or install an always-running service. A new campaign requires its own verified startup.

## Install or update on another host

Run `node <skill-directory>/scripts/install.mjs`. It installs a self-contained copy under
`~/.agents/skills/orca-campaign`, Codex/Claude discovery links and `~/.local/bin/orca-campaign-watch`.
It refuses unmanaged destinations or user-edited files. Add `~/.local/bin` to the host's PATH only if
needed and authorized, or use the absolute launcher path. For Antigravity CLI, validate and register the
reported local plugin directory with `agy plugin validate <path>` then `agy plugin install <path>`;
this changes skill discovery only, not models/accounts/permissions. Reinstall/re-register after updates
if the provider caches plugin contents. Newly started sessions must discover the skill; a running session
can read this exact file explicitly. No campaign or always-running service is started by installation.
