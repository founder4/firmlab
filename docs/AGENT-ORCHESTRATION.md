# FirmLab multi-agent workflow with Orca

This is the operating playbook for supervised work by Codex, Claude, and Antigravity (Gemini models).
Repository rules live in `AGENTS.md`; architecture and validation details live in `CLAUDE.md`.

## Coordinator baseline review — 2026-10-31

Operator mandate: review the project, bring the working baseline up to date and prepare to resume development.
**Codex coordinates FirmLab inside Orca IDE**, including priorities, ownership, integration and final validation.
This instruction persists in `AGENTS.md`; it does not renew an expired unattended campaign or authorize deployment,
firmware acquisition, live corpus/database mutation or stored lane changes.

Observed state:

- Main workspace: `/Users/agfil/Proyectos/firmlab`, Orca ID
  `20bb4a22-e011-4a23-810f-3331b004eee8::/Users/agfil/Proyectos/firmlab`.
- After `git fetch origin`, `main` and `origin/main` both point to `b51c984` (0 ahead / 0 behind).
  The working tree has local changes; do not describe it as clean.
- Three pre-existing modified files are preserved: `Dockerfile.tools`, `scripts/deploy.sh`,
  `scripts/deploy-grype-refresh.test.mjs`. They came from the settled tools-hardening task
  `task_7bec8d300bbc` in `run_1f10ea3348fc`; no real build acceptance was claimed by that task.
- Orca 1.4.237 is reachable. The local inventory contains one workspace and this Codex terminal.
  This terminal has no bound Run. The latest historical Run `run_1f10ea3348fc` has ten completed tasks,
  nine released worker terminals and one user-owned retained terminal with unverifiable liveness.
  Preserve that retained ownership; no historical Run was adopted, reset or extended during this review.
- The running `firmlab` container is healthy, image `c03e9c7edc68…`, build `b79edd5`.
  The only commit between that build and HEAD is documentation. It publishes no host port;
  `firmlab-view` publishes `127.0.0.1:8899`. Health reports the trusted-proxy deployment mode.
  Authentication at the external proxy was not retested.

Local maintenance in this review:

- Updated security fixes in Fastify, Zod, Vitest, Vite and affected transitive dependencies, keeping the MCP SDK
  pin and the existing principal application/tooling major versions. The scoped `@fastify/static>glob` override
  is the exception: glob 14.0.2 brings the cancellation fix and patched minimatch 11. A real-plugin regression
  test covers nested JavaScript assets, `sendFile` HTML and missing assets using disposable files, both with
  wildcard routing (production default) and the glob-backed inventory route.
- `pnpm audit` initially reported 0 critical / 6 high / 16 moderate / 5 low; the updated lock reports zero.
  This is the npm dependency audit, not a new scan of the deployed Debian/tool image. The runtime residuals
  measured on 2026-10-22 remain historical evidence in `docs/BACKLOG.md`, not a current clean verdict.
- Corrected the deployment entry point to name the Debian 13 recipe divergence, and the roadmap's obsolete
  implication that disabling the agent also disables research. Operational priorities are in `docs/BACKLOG.md`.

Validation and limits: the updated dependency graph passes frozen install, typecheck, the full 4,760-test suite,
the two additional static-serving regression cases, the workspace build, and `pnpm biome` (0 errors/warnings
in the agent-surface audit). Host runtime is Node 26.12.1 / pnpm 11.23.0; CI targets Node 22. A disposable Docker
smoke with Node 22.23.4, `--network none`, the checkout mounted read-only and a fresh temporary data directory
starts the built API and verifies health, built HTML/JavaScript, SPA fallback (200) and absent API route (404).
This checks the updated application dependencies, not a fresh execution of every optional firmware tool.
During this baseline review no deployment, firmware fetch, live data mutation, flag change, commit or push was
performed. At that checkpoint the remote CI was historical: quality stopped
on the now-corrected Vitest audit, and YARA surveillance separately reports an unevaluated newer rules release.

Before dispatching future workers, verify current Orca authority and read the current version-matched guides.
Create or adopt a Run only for an actual supervised wave, with explicit tasks and ownership; do not infer live
authority from the older campaign/handoff documents or the IDs above.

## Roles

- **Coordinator:** owns decomposition, Orca lifecycle, integration, final validation, and the user report.
- **Implementer:** owns an explicit set of files and produces a tested change.
- **Researcher/reviewer:** reads broadly, writes no production files, and returns evidence and recommendations.

Use two implementers plus one reviewer as the normal ceiling. Start a larger wave only when file ownership and
acceptance checks are genuinely independent.

## Placement

- Use the current workspace for read-only research or one writer.
- Use an Orca `new-child` worktree for parallel implementation or any overlapping Git lifecycle.
- Use `new-top-level` only for independent work based on the repository default branch.
- Do not put two editing workers in the same checkout.

## Supervised run

The coordinator creates one durable Run, creates the complete independent wave before waiting, and processes
questions and settlements until every dispatch has an explicit outcome. Resolve the executable from
`ORCA_CLI_COMMAND`, then `orca-dev` in a declared dev session, otherwise `orca-ide` on Linux outside Orca,
or `orca` elsewhere. Load its version-matched `skills get orca-cli` and `skills get orchestration` guides.
Do not copy a different host's launcher, readiness workaround, model flag, or version assumption.

The sequence is `run-create`, then `worker-start --spec ... --agent codex|claude|antigravity` with explicit
placement and ownership. Omit model/effort flags unless authorized. Require the startup receipt to be ready;
accepted input alone does not prove a turn started. Recover failed startups using the current guide rather
than injecting through an unready TUI.

Keep rolling `orchestration check --wait --timeout-ms 30000` calls outstanding while the Run has unsettled
work; process the whole returned Delivery, answer questions and settle/release workers before acknowledging.
Re-arm even after an empty timeout. A final status message ends a model turn and is not a supervision loop.

## Unattended continuity and full handoff

Before promising an unattended campaign, use the shared `orca-campaign` skill (installed with
`pnpm campaign:install`) and follow [the continuity runbook](ORCA-CAMPAIGN-RELIABILITY.md).
Launch and verify the independent OS supervisor before the outgoing coordinator stops. Its fixed deadline,
Run identity and journal survive model-turn completion. Keep current handoff context on disk, including the
original mandate, ownership, unsettled tasks, decisions, validation and capacity observations.

A full handoff requires the receiver to adopt the **same** Run from its own terminal, and an observable
owner/generation change before the outgoing coordinator relinquishes work. Do not forge `--from` identities.
The sender receipt proves acceptance only; a durable mailbox enqueue provides best-effort attention, not
continuous execution. Prepare Claude/Antigravity successors before context or quota exhaustion; lack of a
quota metric is unknown capacity. The supervisor does not switch models or answer account/permission menus.

The supervisor reactivates an observed idle coordinator. Ordinary fallback requires a positively exited owner
and explicit, ready standby handles. With `--handoff-on-capacity-block --policy <registry> --standbys <reserves>`,
a rendered hard quota can instead retire the exact blocked PTY after persisting its provider block and proving a
ready different-provider receiver. Positive closure precedes the prompt; same-Run adoption precedes confirmation.
No receiver or ambiguous closure blocks the transition. Unknown liveness blocks mutations. At the deadline report actual executed
work and gaps rather than crediting the whole elapsed window. Never restart an expired campaign silently.

The supervisor screen-reads only the coordinator. A provider block is provider-wide (as the policy records it), so
after adopting a Run on a capacity handoff, read the rendered screen (`terminal read --screen`) of every active
worker on the blocked provider: such a worker stays `dispatched`/`live` with an empty inbox while it sits on the same
usage-limit screen. A final turn that ended there without `worker_done` is the positive proof `worker-stop` needs; a
screen that says it will continue or retry automatically is not an ended turn, so corroborate with
`worker-read --source auto` where a transcript exists. Do not answer the provider's model selector. Recover committed work from the worktree, review it as you would a settlement, and record
the Task's outcome; the 2026-10-06 instance is in [the continuity runbook](ORCA-CAMPAIGN-RELIABILITY.md).

## Task specification templates

### Implementation

```text
Target: <files/component>.
Change: <one concrete behavior or artifact to deliver>.
Constraints: preserve FirmLab proof-state, coverage, local-only, and persisted-data compatibility invariants;
do not touch <boundaries>.
Ownership: you may edit <exact paths>; other active workers own <paths>.
Acceptance: <focused test command and exact observable result>. Run relevant typecheck/lint. Report files changed,
tests run, residual risks, and send worker_done exactly once.
```

### Research or review

```text
Target: <question and relevant paths/commit>.
Change: no production edits; produce an evidence-backed review.
Constraints: distinguish defects, risks, and optional improvements; do not expand scope.
Ownership: read-only. The coordinator owns follow-up edits.
Acceptance: cite exact files/lines, reproduction or commands used, severity, and a concrete recommendation. Send
worker_done exactly once.
```

### Post-implementation review

```text
Target: review <branch/worktree/commit> against <task contract>.
Change: no edits; identify correctness, regression, security, compatibility, and missing-test findings.
Constraints: validate FirmLab invariants and inspect the diff plus surrounding code; do not accept based only on
the implementer's summary.
Ownership: read-only. Route fixes back to the named implementer.
Acceptance: return findings ordered by severity with file/line evidence, or explicitly state no findings and list
the checks performed. Send worker_done exactly once.
```

## Completion gate

An implementer result is input, not integration approval. The coordinator reviews the diff, routes any fixes,
integrates settled branches one at a time, and runs:

```bash
pnpm check && pnpm test && pnpm build && pnpm biome
```

For tool-backed, UI, corpus, or deployment work, add the corresponding real-system validation from `CLAUDE.md`.
Update `docs/BACKLOG.md` and the Orca workspace comment/status only when the evidence supports the transition.

Release or explicitly retain every settled Orca worker; do not leave lifecycle ownership ambiguous.
