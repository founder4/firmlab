#!/usr/bin/env node
/**
 * An Orca coordinator can end a model turn while its campaign is still running.
 * This supervisor lives in an OS process, never consumes the Run inbox, and only
 * resumes a positively idle owner. A connected PTY or stale status proves no turn.
 * All mutations are opt-in; ambiguous submission is sticky across restarts.
 */
import { execFile, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, realpathSync } from 'node:fs';
import { mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const FRESH_MS = 180_000;

export function parseArgs(args, now = Date.now()) {
  const options = { execute: false, once: false, intervalMs: 30_000, idleMs: 60_000, maxResumes: 48, keepAwake: false };
  const values = new Map([
    ['--run', 'run'],
    ['--until', 'until'],
    ['--journal', 'journal'],
    ['--context', 'context'],
    ['--orca', 'orca'],
    ['--standbys', 'standbys'],
    ['--interval-ms', 'intervalMs'],
    ['--idle-ms', 'idleMs'],
    ['--max-resumes', 'maxResumes'],
  ]);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--execute') options.execute = true;
    else if (arg === '--once') options.once = true;
    else if (arg === '--keep-awake') options.keepAwake = true;
    else if (arg === '--help') options.help = true;
    else if (values.has(arg)) {
      const value = args[++i];
      if (!value || value.startsWith('--')) throw new Error(`Missing value for ${arg}`);
      options[values.get(arg)] = value;
    } else throw new Error(`Unknown option: ${arg}`);
  }
  if (options.help) return options;
  if (!/^run_[\w-]+$/.test(options.run ?? '')) throw new Error('--run must identify an existing Orca Run');
  if (!/T.*(?:Z|[+-]\d{2}:\d{2})$/i.test(options.until ?? ''))
    throw new Error('--until must have an explicit UTC offset');
  options.until = Date.parse(options.until);
  if (!Number.isFinite(options.until) || options.until <= now) throw new Error('--until must be a future ISO date');
  for (const key of ['intervalMs', 'idleMs']) {
    options[key] = Number(options[key]);
    const max = key === 'idleMs' ? 600_000 : 60_000;
    if (!Number.isInteger(options[key]) || options[key] < 1_000 || options[key] > max) {
      throw new Error(`${key} must be between 1000 and ${max} ms`);
    }
  }
  options.maxResumes = Number(options.maxResumes);
  if (!Number.isInteger(options.maxResumes) || options.maxResumes < 1 || options.maxResumes > 1000) {
    throw new Error('maxResumes must be between 1 and 1000');
  }
  if (!options.journal) throw new Error('--journal is required (one supervisor per journal)');
  options.journal = resolve(options.journal);
  if (options.execute && !options.context) throw new Error('--execute requires a handoff context file');
  if (options.context) options.context = resolve(options.context);
  if (options.standbys) options.standbys = resolve(options.standbys);
  options.orca ??=
    process.env.ORCA_CLI_COMMAND ??
    (process.env.ORCA_DEV_REPO_ROOT ? 'orca-dev' : process.platform === 'linux' ? 'orca-ide' : 'orca');
  return options;
}

export function ownerState(snapshot, now) {
  if (snapshot.capacityBlocked || snapshot.error === 'capacity_blocked') return 'blocked';
  if (snapshot.error || !snapshot.owner) return 'unknown';
  if (snapshot.liveness === 'exited') return 'exited';
  if (snapshot.menuBlocked || snapshot.inputEmpty === false) return 'unknown';
  if (snapshot.activity && !['done', 'working'].includes(snapshot.activity)) return 'unknown';
  if (snapshot.connected === true && snapshot.nativeIdleProven) return 'idle';
  // A queried, satisfied native wait is positive idle evidence even without a fleet row.
  if (snapshot.connected === true && snapshot.idleProven === true) return 'idle';
  if (snapshot.connected !== true || snapshot.liveness !== 'live' || snapshot.liveStatus !== 'fresh') return 'unknown';
  const age = now - snapshot.observedAt;
  if (!Number.isFinite(age) || age < 0 || age > FRESH_MS) return 'unknown';
  if (snapshot.activity === 'working') return 'working';
  if (snapshot.activity === 'done') return 'idle';
  return 'unknown';
}

export function decide(snapshot, state, options, now) {
  if (now >= options.until) return { kind: 'deadline', reason: 'window_elapsed_not_proof_of_work' };
  if (state.checkedAt && now < state.checkedAt) return { kind: 'unknown', reason: 'clock_moved_backwards' };
  const phase = ownerState(snapshot, now);
  if (phase === 'blocked') return { kind: 'blocked', reason: snapshot.error ?? 'capacity_blocked' };
  if (state.pending) {
    const pending = state.pending;
    if (snapshot.generation > pending.generation && snapshot.owner !== pending.target) {
      return { kind: 'superseded', reason: 'ownership_changed_do_not_resume_old_target' };
    }
    if (phase === 'exited' && snapshot.owner === pending.target) {
      return { kind: 'failed-exited', reason: 'submitted_owner_positively_exited' };
    }
    if (
      snapshot.owner === pending.target &&
      snapshot.generation >= pending.generation &&
      ((phase === 'working' && snapshot.observedAt >= pending.sentAt) ||
        (pending.started && phase === 'idle') ||
        (phase === 'idle' && snapshot.activity === 'done' && snapshot.stateStartedAt > pending.sentAt) ||
        (pending.kind === 'handoff' && snapshot.generation > pending.generation && phase !== 'unknown'))
    ) {
      return { kind: 'confirmed', reason: 'fresh_execution_or_ownership_ack' };
    }
    if (phase === 'idle' && now - pending.sentAt >= 180_000) {
      return { kind: 'blocked', reason: 'submission_not_observed_do_not_resend' };
    }
    return { kind: 'pending', reason: 'submission_unproven_do_not_resend' };
  }
  if (phase === 'working') return { kind: 'working' };
  if (phase === 'exited') return { kind: 'handoff', reason: 'positive_exit_only' };
  if (phase === 'unknown') return { kind: 'unknown', reason: 'absence_is_not_exit_or_idle' };
  const sameOwner = state.owner === snapshot.owner && state.generation === snapshot.generation;
  const grace = Math.min(600_000, options.idleMs * 2 ** Math.min(state.consecutiveResumes ?? 0, 4));
  if (!sameOwner || !state.idleSince || now - state.idleSince < grace) return { kind: 'idle' };
  if (state.disarmed) return { kind: 'pending', reason: 'wait_for_a_new_working_turn' };
  return { kind: 'resume', reason: 'positively_idle_before_deadline' };
}

export async function orcaCall(command, args) {
  try {
    const { stdout } = await exec(command, [...args, '--json'], { timeout: 15_000, maxBuffer: 4 * 1024 * 1024 });
    const receipt = JSON.parse(stdout);
    if (!receipt.ok) return { error: receipt.error?.code ?? 'rpc_error' };
    return receipt.result;
  } catch (error) {
    // Never leak stderr, credentials, terminal content or provider capabilities to the journal.
    try {
      return { error: JSON.parse(error.stdout).error?.code ?? 'command_failed' };
    } catch {
      return { error: error.killed ? 'command_timeout' : 'command_failed' };
    }
  }
}

/**
 * A native `working` row is only evidence while it is fresh. Claude's native state was observed stuck at `working`
 * for 25 minutes after its turn ended (2026-10-02, updatedAt frozen at the last tool call), and a guard that skipped
 * every other read while that row said `working` reported `unknown` forever. A stale row therefore earns a rendered
 * read and a native idle wait — never a verdict on its own.
 */
export function staleWorking(activity, observedAt, now) {
  if (activity !== 'working') return false;
  const age = now - observedAt;
  return !Number.isFinite(age) || age < 0 || age > FRESH_MS;
}

/**
 * A turn in progress, read from the rendered frame. Claude keeps an EMPTY composer and its usual footer on screen
 * while it works (captured 2026-10-02: `✳ Clauding… (1m 27s · ↓ 6.9k tokens · thought for 14s)` above `❯`), and
 * prints no "esc to interrupt", so an empty prompt is not idleness. Its finished line (`✻ Worked for 20m 22s`) has
 * no ellipsis and no running timer, and does not match.
 */
export function hasActiveTurn(tail) {
  return tail.some(
    (line) =>
      /\besc to (?:interrupt|cancel|stop)\b/i.test(line) ||
      /^\s*\S\s+\S[^()]*…\s*\((?:\d+h\s*)?(?:\d+m\s*)?\d+s\b/.test(line),
  );
}

export async function snapshotRun(call, options, clock = Date.now) {
  const { run, error } = await call(['orchestration', 'run-show', '--id', options.run]);
  if (error || !run?.coordinator_handle) return { error: error ?? 'no_owner' };
  const owner = run.coordinator_handle;
  const rows = [];
  let cursor;
  const cursors = new Set();
  do {
    const page = await call([
      'orchestration',
      'worker-list',
      '--run',
      options.run,
      '--include-remote',
      ...(cursor ? ['--cursor', cursor] : []),
    ]);
    if (page.error) return { owner, error: page.error };
    rows.push(...(page.workers ?? []));
    cursor = page.page?.hasMore ? page.page.nextCursor : undefined;
    if (rows.length > 1000 || cursors.size >= 100 || (page.page?.hasMore && (!cursor || cursors.has(cursor))))
      return { owner, error: 'fleet_page_bound' };
    if (cursor) cursors.add(cursor);
  } while (cursor);
  const show = await call(['terminal', 'show', '--terminal', owner]);
  const row = rows.find((w) => w.agentTerminalHandle === owner);
  const projection = row?.projection;
  // Standalone coordinators have no Dispatch row. Match native status by exact
  // pane identity, without persisting its prompts, messages or tool inputs.
  const fleet = await call(['worktree', 'ps']);
  const paneKey = show.terminal ? `${show.terminal.tabId}:${show.terminal.leafId}` : null;
  const native = fleet.worktrees
    ?.find((w) => w.worktreeId === show.terminal?.worktreeId)
    ?.agents?.find((a) => a.paneKey === paneKey);
  const activity = native?.interrupted ? 'interrupted' : (native?.state ?? projection?.stage?.activity);
  const observedAt = native?.updatedAt ?? projection?.liveness?.observedAt;
  // Read after the fleet call, as ownerState measures age: a row stamped during that call is not from the future.
  const stale = staleWorking(activity, observedAt, clock());
  // A fresh `working` row is trusted and nothing else is read; every other state, a stale `working` row included,
  // must be confirmed from the rendered frame.
  const inspect = activity !== 'working' || stale;
  // The default read is the accumulated stream: a TUI that repaints its composer
  // with cursor moves (Antigravity) never emits it at the end of that stream, so
  // a done owner looked unrecognized forever. `--screen` is the rendered frame.
  // A composer draft is reported in `draft` and EXCLUDED from tail, so a visible
  // empty prompt proves nothing while a draft is present. `screen-unavailable`
  // (stream fallback) or an absent source (older host) proves no frame at all.
  const screen = inspect ? await call(['terminal', 'read', '--terminal', owner, '--screen', '--limit', '20']) : {};
  if (inspect && (screen.error || !Array.isArray(screen.terminal?.tail))) {
    return { owner, generation: run.consumer_generation, error: 'screen_unreadable' };
  }
  const tail = screen.terminal?.tail ?? [];
  // Only an absent or exactly empty draft is no draft; whitespace or an unexpected
  // type is text the operator may have typed, so it is present and unverifiable.
  const rawDraft = screen.terminal?.draft;
  const draft = rawDraft !== undefined && rawDraft !== null && rawDraft !== '';
  const rendered = screen.terminal?.source === 'screen';
  // A stream fallback replays history: an old quota line there is not a current block.
  const capacityBlocked = rendered && hasCapacityBlock(tail);
  const menuBlocked = !capacityBlocked && hasBlockingMenu(tail);
  const emptyPrompt = rendered && !draft && visibleInputPrompt(tail);
  const activeTurn = rendered && hasActiveTurn(tail);
  const wait =
    !inspect || activity === 'interrupted' || capacityBlocked || activeTurn
      ? {}
      : await call(['terminal', 'wait', '--terminal', owner, '--for', 'tui-idle', '--timeout-ms', '1000']);
  return {
    owner,
    generation: run.consumer_generation,
    connected: show.terminal?.connected,
    incarnation: show.terminal?.incarnationId,
    agent: show.terminal?.agentIdentity,
    activity,
    staleWorking: stale,
    activeTurn,
    stateStartedAt: native?.stateStartedAt,
    capacityBlocked,
    menuBlocked,
    screenSource: screen.terminal?.source,
    inputEmpty: !inspect ? undefined : capacityBlocked ? false : emptyPrompt,
    error: capacityBlocked
      ? 'capacity_blocked'
      : show.terminal?.connected && inspect && draft
        ? 'composer_draft_present'
        : show.terminal?.connected && inspect && !rendered
          ? 'screen_not_rendered'
          : show.terminal?.connected && inspect && !emptyPrompt
            ? 'input_prompt_unrecognized'
            : show.terminal?.connected && stale && activeTurn
              ? 'stale_native_working_turn_visible'
              : undefined,
    nativeIdleProven:
      !capacityBlocked && native?.state === 'done' && !native.interrupted && emptyPrompt && !menuBlocked,
    liveness:
      show.terminal?.connected === false && typeof show.terminal.exitCause?.kind === 'string'
        ? 'exited'
        : native && show.terminal?.connected
          ? 'live'
          : projection?.liveness?.verdict,
    observedAt,
    liveStatus: native ? 'fresh' : projection?.evidence?.liveStatus,
    // Positive agreement only: a rendered empty composer with no draft, menu, quota or turn in progress, AND a
    // satisfied native idle wait. For a stale `working` row this is the only way to `idle`; absence never is.
    idleProven:
      !capacityBlocked &&
      rendered &&
      !draft &&
      activity !== 'interrupted' &&
      !menuBlocked &&
      !activeTurn &&
      (!stale || emptyPrompt) &&
      wait.wait?.satisfied === true,
    activeHandles: rows
      .filter((w) => !['completed', 'failed', 'stopped'].includes(w.dispatchStatus))
      .map((w) => w.agentTerminalHandle),
    workVersion: rows
      .map((w) => `${w.dispatchId}:${w.workerState}`)
      .sort()
      .join('|'),
  };
}

export function hasCapacityBlock(tail) {
  let region = tail;
  if (visibleInputPrompt(tail)) {
    const prompt = tail.findLastIndex(emptyComposer);
    const border = tail.slice(0, prompt).findLastIndex((line) => /^[─━]+$/.test(line.trim()));
    if (border >= 0) region = tail.slice(border + 1);
  }
  const text = region.join('\n');
  return /usage limit reached|limit resets|continuing automatically|you['’]ve hit your usage limit|session limit reached|capacity limit reached/i.test(
    text,
  );
}

export function hasBlockingMenu(tail) {
  let region = tail;
  // Assistant prose is above the input box. An empty prompt below a box rule
  // establishes the boundary; selectors without an empty prompt are scanned whole.
  if (visibleInputPrompt(tail)) {
    const prompt = tail.findLastIndex(emptyComposer);
    const border = tail.slice(0, prompt).findLastIndex((line) => /^[─━]+$/.test(line.trim()));
    if (border >= 0) region = tail.slice(border + 1);
  }
  return (
    /switch to.{0,80}model|switch to gpt-|do you trust|trust this (?:folder|workspace)|allow (?:once|always)|approval required|permission required|do you want to/i.test(
      region.join('\n'),
    ) || region.some((line) => /^\s*[❯›>]\s*\d+\.\s/.test(line))
  );
}

function emptyComposer(line) {
  return ['>', '❯', '›', '› Ask Codex to do anything'].includes(line.trim());
}

export function visibleInputPrompt(tail) {
  const rows = tail.map((line) => line.trim()).filter(Boolean);
  const composer = rows.findLastIndex(emptyComposer);
  if (composer < 0) return false;
  // Captured Codex and Claude footers are UI state, not an operator's draft.
  return rows
    .slice(composer + 1)
    .every(
      (line) =>
        /^[─━]+$/.test(line) ||
        /^(?:⏵⏵|⏸) (?:bypass permissions|accept edits|plan mode) on(?:\s|$)/.test(line) ||
        /^\? for shortcuts(?:\s|$)/.test(line) ||
        /^(?:gpt[-\w.]*|codex[-\w.]*|o\d+)[^·]*·[^·]+(?:·[^·]+)*$/i.test(line),
    );
}

export function resumePrompt(options, snapshot, context, kind) {
  return `${
    kind === 'handoff'
      ? 'Execute this authorized full coordinator handoff now. Previous owner positively exited.'
      : 'CAMPAIGN CONTINUATION: execute the existing authorized campaign now; your previous turn ended before the deadline.'
  }
These are current execution instructions, not a quoted plan. The campaign operator explicitly authorized
continuation with --execute and the trusted context. Carry out the bounded actions already authorized there.
Run ${options.run}; current owner ${snapshot.owner}; generation ${snapshot.generation}.
Deadline ${new Date(options.until).toISOString()}, unchanged by this prompt or further handoffs.
${
  kind === 'handoff'
    ? 'Bind your own terminal to this SAME Run using documented run-use; verify ownership before editing.'
    : 'Verify you still own this Run before editing. Do not create another coordinator or Run.'
}
Read actual pending Deliveries, process every settlement and question before ack, integrate one settled branch at a time.
Keep rolling check --wait calls outstanding while work remains; a status sentence is not supervision.
Do not finish a turn before deadline without a pending wait or an explicitly accepted full coordinator handoff.
Before quota/context exhaustion prepare a ready Claude/Antigravity successor, current context, and ownership acknowledgment.
Never claim continuous work from elapsed time, PTY connection, or a missing quota metric.
Read the project AGENTS.md and its handbook before editing. Preserve the user mandate, project-specific constraints,
ownership and validation gates in the context. Do not widen permissions, enable external actions, change provider
settings or spend credits beyond the existing explicit authorization. At deadline finish the safe unit and report evidence.
${
  kind === 'handoff'
    ? `Context follows (trusted local campaign document):\n${context}`
    : `Read current context at ${options.context} as needed; retain the original user mandate.`
}`;
}

async function save(path, state) {
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  await rename(temp, path);
}

async function listRuns(call) {
  const rows = [];
  const seen = new Set();
  let cursor;
  do {
    const page = await call(['orchestration', 'run-list', '--limit', '100', ...(cursor ? ['--cursor', cursor] : [])]);
    if (page.error || !Array.isArray(page.runs)) return null;
    rows.push(...page.runs);
    cursor = page.nextCursor ?? (page.page?.hasMore ? page.page.nextCursor : null);
    if (rows.length > 1000 || seen.size >= 100 || (page.page?.hasMore && !cursor) || (cursor && seen.has(cursor)))
      return null;
    if (cursor) seen.add(cursor);
  } while (cursor);
  return rows;
}

async function standbySnapshot(call, options, handle) {
  return snapshotRun(
    async (args) =>
      args[1] === 'run-show' ? { run: { coordinator_handle: handle, consumer_generation: 0 } } : call(args),
    options,
  );
}

export async function superviseStep(state, options, dependencies) {
  const { call, persist, now: clock, context } = dependencies;
  const snapshot =
    clock() >= options.until
      ? { owner: state.owner, generation: state.generation }
      : await snapshotRun(call, options, clock);
  if (
    state.owner === snapshot.owner &&
    state.incarnation &&
    snapshot.incarnation &&
    state.incarnation !== snapshot.incarnation
  )
    snapshot.error = 'incarnation_changed';
  const now = clock();
  const observationGap = state.checkedAt && now - state.checkedAt > options.intervalMs * 3;
  const decision = decide(
    snapshot,
    observationGap && !state.pending ? { ...state, idleSince: null } : state,
    options,
    now,
  );
  const gap =
    state.checkedAt && now - state.checkedAt > options.intervalMs * 3
      ? { from: state.checkedAt, to: now, reason: 'unverified_observation_gap' }
      : null;
  const gaps = [...(state.gaps ?? [])];
  if (gap) gaps.push(gap);

  if (decision.kind === 'blocked' && decision.reason === 'capacity_blocked') {
    const lastGap = gaps.at(-1);
    if (lastGap && lastGap.reason === 'capacity_blocked' && state.phase === 'blocked') {
      lastGap.to = now;
    } else {
      gaps.push({ from: state.checkedAt ?? now, to: now, reason: 'capacity_blocked' });
    }
  } else if (state.phase === 'blocked' && state.reason === 'capacity_blocked') {
    const lastGap = gaps.at(-1);
    if (lastGap && lastGap.reason === 'capacity_blocked') {
      lastGap.to = now;
    }
  }
  // An unrecognized screen is uncertainty, never health and never idleness: the
  // interval is journaled from the last observation before it to the observation
  // that ended it, with the reason, so `gaps: []` cannot read as a watched owner.
  const uncertain = decision.kind === 'unknown' || (decision.kind === 'pending' && Boolean(snapshot.error));
  const uncertainReason = snapshot.error ?? decision.reason;
  const open = state.uncertainty
    ? gaps.findLastIndex(
        (g) => g.phase === 'unknown' && g.from === state.uncertainty.from && g.reason === state.uncertainty.reason,
      )
    : -1;
  if (open >= 0) gaps[open] = { ...gaps[open], to: now };
  let uncertainty = null;
  if (uncertain) {
    if (open >= 0 && state.uncertainty.reason === uncertainReason) uncertainty = state.uncertainty;
    else {
      uncertainty = { from: state.checkedAt ?? now, reason: uncertainReason };
      gaps.push({ ...uncertainty, to: now, phase: 'unknown' });
    }
  }

  const next = {
    ...state,
    run: options.run,
    until: options.until,
    checkedAt: now,
    owner: snapshot.owner ?? state.owner,
    generation: snapshot.generation ?? state.generation,
    incarnation: snapshot.error ? state.incarnation : (snapshot.incarnation ?? state.incarnation),
    phase: decision.kind,
    reason: decision.kind === 'pending' ? (state.reason ?? decision.reason) : (snapshot.error ?? decision.reason),
    workVersion: snapshot.workVersion ?? state.workVersion,
    consecutiveResumes:
      (snapshot.workVersion !== undefined && state.workVersion !== snapshot.workVersion) ||
      (snapshot.owner !== undefined && state.owner !== snapshot.owner)
        ? 0
        : (state.consecutiveResumes ?? 0),
    gaps: gaps.slice(-100),
    uncertainty,
  };
  if (['confirmed', 'superseded', 'failed-exited'].includes(decision.kind)) {
    next.lastSubmission = { ...state.pending, settlement: decision.kind, observedAt: now };
    next.pending = null;
    next.disarmed = false;
  }
  if (['working', 'unknown', 'blocked', 'confirmed', 'superseded', 'failed-exited'].includes(decision.kind))
    next.idleSince = null;
  if (decision.kind === 'working') next.disarmed = false;
  if (decision.kind === 'idle')
    next.idleSince =
      !observationGap && state.owner === snapshot.owner && state.generation === snapshot.generation
        ? (state.idleSince ?? now)
        : now;
  if (options.execute && ['resume', 'handoff'].includes(decision.kind)) {
    let target = snapshot.owner;
    let targetIncarnation = snapshot.incarnation;
    if (decision.kind === 'handoff') {
      target = null;
      for (const handle of dependencies.standbys ?? []) {
        if (handle === snapshot.owner || snapshot.activeHandles?.includes(handle)) continue;
        const show = await call(['terminal', 'show', '--terminal', handle]);
        if (!show.terminal?.connected || !['claude', 'antigravity'].includes(show.terminal.agentIdentity)) continue;
        const runs = await listRuns(call);
        if (!runs || runs.some((r) => r.coordinator_handle === handle)) continue;
        let busy = false;
        for (const other of runs) {
          const workers = await call([
            'orchestration',
            'worker-list',
            '--run',
            other.id ?? other.run_id,
            '--include-remote',
          ]);
          if (
            workers.error ||
            workers.page?.hasMore ||
            !Array.isArray(workers.workers) ||
            workers.workers.some(
              (w) => w.agentTerminalHandle === handle && !['completed', 'failed', 'stopped'].includes(w.dispatchStatus),
            )
          ) {
            busy = true;
            break;
          }
        }
        if (busy) continue;
        const candidate = await standbySnapshot(call, options, handle);
        if (ownerState(candidate, clock()) === 'idle' && candidate.inputEmpty) {
          target = handle;
          targetIncarnation = candidate.incarnation;
          break;
        }
      }
      if (!target) {
        next.phase = 'blocked';
        next.reason = 'no_proven_ready_standby';
      }
    }
    if (target) {
      if ((state.resumeCount ?? 0) >= (options.maxResumes ?? 48)) {
        next.phase = 'blocked';
        next.reason = 'resume_budget_reached';
        await persist(next);
        return next;
      }
      const recheck = await snapshotRun(call, options, clock);
      const receiver = decision.kind === 'handoff' ? await standbySnapshot(call, options, target) : null;
      if (
        recheck.owner !== snapshot.owner ||
        recheck.generation !== snapshot.generation ||
        recheck.incarnation !== snapshot.incarnation ||
        (receiver &&
          (ownerState(receiver, clock()) !== 'idle' ||
            !receiver.inputEmpty ||
            receiver.incarnation !== targetIncarnation)) ||
        ownerState(recheck, clock()) !== (decision.kind === 'resume' ? 'idle' : 'exited') ||
        clock() >= options.until
      ) {
        next.phase = 'deferred';
        next.reason = 'owner_or_state_changed';
      } else {
        // Persist intent BEFORE mutation. On a lost receipt, never create a second prompt.
        next.pending = {
          kind: decision.kind,
          target,
          generation: snapshot.generation,
          sentAt: clock(),
          requestId: null,
        };
        next.disarmed = true;
        next.resumeCount = (state.resumeCount ?? 0) + 1;
        next.consecutiveResumes++;
        await persist(next);
        const prompt = resumePrompt(options, snapshot, context, decision.kind);
        const receipt = await call([
          'terminal',
          'send',
          '--terminal',
          target,
          '--text',
          prompt,
          '--enter',
          '--wait-submit',
          '10',
        ]);
        next.pending.error = receipt.error;
        next.pending.requestId = receipt.send?.prompt?.requestId ?? null;
        next.pending.accepted = receipt.send?.accepted === true;
        next.pending.started = receipt.send?.prompt?.stages?.includes('turn_started') === true;
        next.lastSubmission = { ...next.pending, settlement: 'pending' };
        next.phase = 'pending';
        next.reason =
          receipt.error ?? (next.pending.started ? 'turn_started_await_owner_observation' : 'submission_unproven');
      }
    }
  }
  await persist(next);
  return next;
}

async function trustedContext(options) {
  const context = options.context ? await readFile(options.context, 'utf8') : '';
  if (Buffer.byteLength(context, 'utf8') > 80_000)
    throw new Error('Context exceeds 80000 UTF-8 bytes; do not silently truncate handoff');
  if (options.execute && !context.trim()) throw new Error('Empty context cannot authorize campaign continuation');
  return context;
}

export function runLockPath(run) {
  // OS account identity is stable even when a terminal changes HOME or TMPDIR.
  return resolve(userInfo().homedir, '.local/state/orca-campaign/locks', `${run}.lock`);
}

async function acquireLocks(options) {
  const paths = [`${options.journal}.lock`];
  if (options.execute) {
    const stable = runLockPath(options.run);
    await mkdir(dirname(stable), { recursive: true, mode: 0o700 });
    paths.unshift(stable);
    const legacyRoots = [tmpdir(), '/tmp'];
    if (process.platform === 'darwin') {
      const { stdout } = await exec('/usr/bin/getconf', ['DARWIN_USER_TEMP_DIR']);
      legacyRoots.push(stdout.trim());
    }
    for (const root of legacyRoots)
      paths.push(resolve(await realpath(root), `firmlab-orca-campaign-${options.run}.lock`));
  }
  const owned = [];
  try {
    for (const path of new Set(paths)) {
      await mkdir(path, { mode: 0o700 });
      owned.push(path);
      await writeFile(`${path}/owner.json`, JSON.stringify({ pid: process.pid, id: randomUUID() }), { mode: 0o600 });
    }
    return owned;
  } catch (error) {
    for (const path of owned.reverse()) await rm(path, { recursive: true });
    throw error;
  }
}

export async function runWatch(options) {
  await mkdir(dirname(options.journal), { recursive: true });
  const locks = await acquireLocks(options); // Never blindly recover another process's lock.
  let keepAwake;
  let stopping = false;
  let state = {};
  let loaded = false;
  const stop = () => {
    stopping = true;
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    try {
      state = JSON.parse(await readFile(options.journal, 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (state.run && (state.run !== options.run || state.until !== options.until)) {
      throw new Error('Journal belongs to a different Run or deadline; use a new journal');
    }
    loaded = true;
    if (options.keepAwake) {
      if (process.platform !== 'darwin') throw new Error('--keep-awake currently supports macOS only');
      keepAwake = spawn('/usr/bin/caffeinate', ['-i', '-w', String(process.pid)], { stdio: 'ignore' });
      await once(keepAwake, 'spawn');
      keepAwake.once('exit', stop);
    }
    do {
      let context = '';
      let standbys = [];
      let invalid;
      try {
        context = await trustedContext(options);
      } catch {
        invalid = 'context_invalid';
      }
      if (options.standbys) {
        try {
          standbys = JSON.parse(await readFile(options.standbys, 'utf8'));
          if (!Array.isArray(standbys) || !standbys.every((s) => /^term_[\w-]+$/.test(s)))
            throw new Error('Invalid standbys');
        } catch {
          invalid = 'standbys_invalid';
          standbys = [];
        }
      }
      state = await superviseStep(
        state,
        { ...options, execute: options.execute && !invalid },
        {
          call: (args) =>
            stopping
              ? Promise.resolve({ error: 'supervisor_stopping' })
              : Date.now() >= options.until
                ? Promise.resolve({ error: 'deadline_elapsed' })
                : orcaCall(options.orca, args),
          now: Date.now,
          persist: async (value) => {
            if (invalid && value.phase !== 'deadline') {
              value.phase = 'blocked';
              value.reason = invalid;
              value.idleSince = null;
            }
            value.locks = locks;
            await save(options.journal, value);
          },
          context,
          standbys,
        },
      );
      console.log(
        JSON.stringify({
          at: new Date(state.checkedAt).toISOString(),
          owner: state.owner,
          phase: state.phase,
          reason: state.reason,
          pending: Boolean(state.pending),
        }),
      );
      if (state.phase === 'deadline' || options.once || stopping) break;
      await new Promise((r) => setTimeout(r, Math.min(options.intervalMs, Math.max(0, options.until - Date.now()))));
    } while (!stopping);
    if (stopping && state.phase !== 'deadline') {
      state.phase = 'stopped';
      state.reason = 'supervisor_cancelled';
      await save(options.journal, state);
    }
    return state;
  } catch (error) {
    if (loaded) {
      state.phase = 'stopped';
      state.reason = 'supervisor_error';
      state.checkedAt = Date.now();
      await save(options.journal, state);
    }
    throw error;
  } finally {
    keepAwake?.kill();
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    for (const path of [...locks].reverse()) await rm(path, { recursive: true });
  }
}

export async function runCli(args = process.argv.slice(2)) {
  try {
    const options = parseArgs(args);
    if (options.help)
      console.log(
        'orca-campaign-watch --run RUN --until ISO --journal PATH [--once] [--execute --context PATH] [--standbys JSONFILE] [--keep-awake] [--max-resumes N] [--interval-ms N] [--idle-ms N] [--orca PATH]',
      );
    else await runWatch(options);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url))
  await runCli();
