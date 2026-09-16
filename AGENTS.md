# FirmLab agent contract

These instructions apply to every coding agent working in this repository. Read `CLAUDE.md` before changing
code; despite its historical filename, it is the detailed project handbook for Codex, Claude, Antigravity
(Gemini models), and human contributors alike. A live Orca orchestration preamble is authoritative for the
current task and lifecycle.

## Mission and invariants

FirmLab is a local-first firmware analysis workbench. Preserve these invariants:

- Code, never a model, assigns proof states. Never upgrade evidence beyond what the executed provider proved.
- An empty finding list does not mean clean; report attempted and completed coverage and relevant bounds.
- A missing tool or unsupported platform is not a negative result. Degrade explicitly.
- Persisted provider output may come from an older build. Newly added result fields remain optional forever.
- Keep the dependency direction `web -> api -> core`; byte-only pure analysis belongs in `packages/core`.
- Keep the default deployment local-only. Do not widen listeners, egress, or approval scope incidentally.

## Working agreement

- Stay inside the assigned target and ownership boundary. Do not edit files owned by another active worker.
- Do not deploy, mutate the cross-image corpus/database, fetch firmware, or enable outbound research unless the
  task explicitly authorizes it.
- Preserve unrelated and pre-existing worktree changes. Never use destructive Git cleanup commands.
- Put decision/parsing logic in pure exported functions with tests; keep routes and store bindings thin.
- Build `@firmlab/core` before API or web work that consumes its `dist/` output.
- Add or update focused tests with every behavior change. Tool-backed behavior also needs real-container evidence
  when the task's acceptance contract requires it.
- Record newly discovered but deferred work in `docs/BACKLOG.md`; do not silently broaden the current task.
- Use conventional commits with lowercase subjects and no attribution trailers.

## Validation

Run the narrowest relevant tests while iterating. Before declaring a repository-wide change ready, run:

```bash
pnpm check
pnpm test
pnpm build
pnpm biome
```

Green fixtures do not prove a real external tool works. Follow the real-tool and UI validation recipes in
`CLAUDE.md` when the change crosses those boundaries.

## Orca coordination

- An ordinary agent works only on the user's current request; it does not invent orchestration lifecycle state.
- A dispatched worker follows the injected Orca Task/Dispatch contract, checks coordinator messages at natural
  checkpoints, and sends exactly one explicit `worker_done` result.
- Every dispatched task must state target, change, constraints, file ownership, and observable acceptance.
- Parallel edits require disjoint ownership or separate worktrees. Research/review workers should remain
  read-only unless explicitly assigned a follow-up implementation task.
- The coordinator integrates settled work one branch at a time and owns the final full validation pass.

The practical playbook and reusable task specifications live in `docs/AGENT-ORCHESTRATION.md`.
