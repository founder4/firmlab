# FirmLab multi-agent workflow with Orca

This is the operating playbook for supervised work by Codex, Claude, and Antigravity (Gemini models).
Repository rules live in `AGENTS.md`; architecture and validation details live in `CLAUDE.md`.

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

The supervisor reactivates an observed idle coordinator; its fallback is limited to a positively exited owner
and explicit, ready standby handles. Unknown liveness blocks mutations. At the deadline report actual executed
work and gaps rather than crediting the whole elapsed window. Never restart an expired campaign silently.

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
