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
questions and settlements until every dispatch has an explicit outcome. In this Linux installation the safe
external command is `orca-ide`; inside an Orca-managed terminal, use the executable Orca provides for that
session.

```bash
orca-ide status --json
orca-ide orchestration run-create --objective "<outcome for the user>" --json

orca-ide orchestration worker-start \
  --spec "<self-contained Codex task>" \
  --worktree new-child --name "<short-name>" --agent codex --setup run --json

orca-ide orchestration worker-start \
  --spec "<self-contained Claude task>" \
  --worktree new-child --name "<short-name>" --agent claude --setup run --json

# Antigravity 1.2.3 currently needs the low-level dispatch below; see the note after this block.

orca-ide orchestration check --wait \
  --types "worker_done,escalation,question" --timeout-ms 900000 --json
```

Orca 1.4.203 identifies Antigravity 1.2.3, but its supervised `worker-start` readiness probe does not yet
recognize the Antigravity TUI reliably. Use one managed terminal plus a normal durable task/dispatch instead of
retrying `worker-start`:

```bash
orca-ide orchestration task-create \
  --task-title "<short Antigravity task>" --spec "<self-contained read-only review>" --json
orca-ide terminal create --worktree active --title "<short-name>" --command "agy" --json
orca-ide orchestration dispatch --task <task-id> --to <terminal-handle> --inject --dry-run --json
orca-ide orchestration dispatch --task <task-id> --to <terminal-handle> --inject --json
```

Confirm with `terminal read` that the account and prompt are visible before the real injection. This dispatch is
tracked but unsupervised, so the coordinator must inspect terminal liveness directly and close it after settlement.
On this host, replace the generated preamble's bare `orca` commands with `orca-ide`; bare `orca` is the Linux
screen reader, not the Orca CLI.

Omit model and effort flags unless the user explicitly requested them. Orca should inherit each provider's
configured defaults.

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
