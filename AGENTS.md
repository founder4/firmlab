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
- Keep the workbench's exposure local-only: listeners bind loopback (or sit behind the homelab's auth-gated
  proxy), and firmware bytes, secrets and keys never leave the machine. Do not widen listeners, the research
  allowlist, or approval scope incidentally.

## Network authorization (operator decision, 2026-10-04)

Outbound network use is habitually authorized, for FirmLab project work and for the product alike:

- **Agents** may use the network proactively when it helps the task — authoritative documentation, vendor and
  advisory feeds (NVD, OSV, KEV, vendor sites), dependency registries, and research. No per-task permission is
  needed for that.
- **The product's trusted research lane** (`FIRMLAB_RESEARCH`) is on by default. It reaches allowlisted
  intelligence hosts only, sends derived data only (component names/versions), and every run is declared and
  reconciled by the egress ledger. A stated `FIRMLAB_RESEARCH=0` or a stored Settings override turns it off, and
  a stated value always beats the default.

That standing permission does **not** cover, and must never be used to justify:

- exposing a listener (binding beyond loopback, publishing a port, removing the homelab's auth middlewares);
- transmitting raw firmware, extracted secrets, keys or credential material to any third party;
- enabling `FIRMLAB_HASH_LOOKUP` (sends hashes recovered from the firmware) or `FIRMLAB_CAPTURE` (active
  on-the-wire acquisition) — each stays a separate, attributable operator opt-in;
- giving an untrusted emulated guest or agent-executed binary direct egress (`FIRMLAB_EMU_ISOLATE` stays on by
  default; `providers/isolate.ts` network isolation is not to be loosened).

## Working agreement

- Stay inside the assigned target and ownership boundary. Do not edit files owned by another active worker.
- Do not deploy, mutate the cross-image corpus/database, fetch firmware, or change stored lane overrides unless
  the task explicitly authorizes it. Network access itself is authorized (see above); its boundaries are not
  relaxed by it.
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
