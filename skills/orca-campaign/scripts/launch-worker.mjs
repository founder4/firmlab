#!/usr/bin/env node
/**
 * Guarded wrapper around `orca orchestration worker-start`.
 *
 * Evaluates campaign capacity policy before launching an Orca worker process.
 * If capacity is blocked, unavailable, or the agent/provider is unknown, launch
 * is refused immediately with exit code 3, prints a single JSON status line
 * to stdout, and makes ZERO Orca calls.
 *
 * Forwarded worker-start arguments are checked to prevent security and policy bypasses:
 * - Direct or duplicate overrides of --agent or --model are strictly rejected.
 * - --terminal reuse across providers is rejected until verified lookup is supported.
 * - Explicit --capacity-domain is accounting metadata only and cannot bypass blocks.
 *
 * Exit status never reads success into a launch that did not report one. A worker-start killed by a signal
 * closes with code null, which `code ?? 0` used to turn into exit 0: a supervisor reading the status would
 * believe a worker had started when the launch was cut off mid-flight. A signal exits 128 + its number (the
 * shell convention, so `SIGTERM` reads 143), an unknown signal or a missing status exits 1, and a spawn error
 * (no orca executable) exits 1 with the reason on stderr.
 *
 * Enforcement limit:
 * This wrapper enforces capacity bounds at the invocation boundary. Direct, raw
 * invocations of `orca orchestration worker-start` outside this wrapper are not
 * intercepted; it does not claim to install a daemon-level or platform-wide kernel hook.
 */

import { spawn } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { constants } from 'node:os';
import { fileURLToPath } from 'node:url';
import { evaluateLaunch, parsePolicy, serializePolicy } from './policy.mjs';

/**
 * Maps a child's close (code, signal) to this process's exit status. Only an integer code passes through;
 * a signal is 128 + its number when known, and anything else is 1 — never 0.
 */
export function exitStatusFor(code, signal) {
  if (Number.isInteger(code)) return code;
  if (signal) {
    const number = typeof signal === 'number' ? signal : constants.signals[signal];
    return Number.isInteger(number) && number > 0 ? 128 + number : 1;
  }
  return 1;
}

/**
 * Loads and validates a campaign policy file.
 */
export async function loadPolicy(path) {
  try {
    const text = await readFile(path, 'utf8');
    const policy = parsePolicy(text);
    return { text, policy };
  } catch (err) {
    if (err.code === 'ENOENT') {
      return { error: 'policy_missing' };
    }
    return { error: 'policy_invalid', detail: err.message };
  }
}

/**
 * Durably saves a policy object using atomic write (temp file + rename, mode 0o600).
 */
export async function savePolicy(path, policy) {
  const temp = `${path}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(temp, serializePolicy(policy), { mode: 0o600 });
  await rename(temp, path);
}

/**
 * Parses CLI arguments for launch-worker.
 * Usage: node launch-worker.mjs --policy <path> --agent <id> [--model <id>] [--capacity-domain <d>] [--orca <exe>] -- <worker-start args...>
 */
export function parseArgs(args) {
  const options = {
    policy: null,
    agent: null,
    model: null,
    capacityDomain: null,
    orca: null,
    forward: [],
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
      return options;
    }
    if (arg === '--') {
      options.forward = args.slice(i + 1);
      break;
    }
    if (arg === '--policy') {
      options.policy = args[++i];
      if (!options.policy || options.policy.startsWith('--')) {
        throw new Error('Missing value for --policy');
      }
    } else if (arg === '--agent') {
      options.agent = args[++i];
      if (!options.agent || options.agent.startsWith('--')) {
        throw new Error('Missing value for --agent');
      }
    } else if (arg === '--model') {
      options.model = args[++i];
      if (!options.model || options.model.startsWith('--')) {
        throw new Error('Missing value for --model');
      }
    } else if (arg === '--capacity-domain') {
      options.capacityDomain = args[++i];
      if (!options.capacityDomain || options.capacityDomain.startsWith('--')) {
        throw new Error('Missing value for --capacity-domain');
      }
    } else if (arg === '--orca') {
      options.orca = args[++i];
      if (!options.orca || options.orca.startsWith('--')) {
        throw new Error('Missing value for --orca');
      }
    } else {
      options.forward.push(arg);
    }
  }

  if (!options.policy) {
    throw new Error('--policy is required');
  }
  if (!options.agent) {
    throw new Error('--agent is required');
  }

  options.orca ??=
    process.env.ORCA_CLI_COMMAND ??
    (process.env.ORCA_DEV_REPO_ROOT ? 'orca-dev' : process.platform === 'linux' ? 'orca-ide' : 'orca');

  return options;
}

/**
 * Testable core of launch-worker.
 *
 * @param {object} input - { policyText, agent, model, capacityDomain, forward, now }
 * @param {object} dependencies - { run }
 * @returns {Promise<{ launched: boolean, reason?: string, domain?: string, exitCode: number, stdout?: string, argv?: string[] }>}
 */
export async function launchWorker(
  { policyText, agent, model, capacityDomain, forward = [], now = Date.now() },
  { run } = {},
) {
  if (policyText === null || policyText === undefined) {
    return {
      launched: false,
      reason: 'policy_missing',
      domain: null,
      exitCode: 3,
    };
  }

  let policy;
  try {
    policy = parsePolicy(policyText);
  } catch {
    return {
      launched: false,
      reason: 'policy_invalid',
      domain: null,
      exitCode: 3,
    };
  }

  // Prevent forwarding bypasses: forwarded arguments must not override checked agent or model
  for (const arg of forward) {
    if (
      arg === '--agent' ||
      arg.startsWith('--agent=') ||
      arg === '-a' ||
      arg === '--model' ||
      arg.startsWith('--model=') ||
      arg === '-m'
    ) {
      return {
        launched: false,
        reason: 'conflicting_forwarded_args',
        domain: null,
        exitCode: 3,
      };
    }
    if (arg === '--terminal' || arg.startsWith('--terminal=') || arg === '-t') {
      return {
        launched: false,
        reason: 'terminal_reuse_disallowed',
        domain: null,
        exitCode: 3,
      };
    }
  }

  const evalResult = evaluateLaunch(policy, { agent, model, capacityDomain }, now);
  if (!evalResult.allowed) {
    return {
      launched: false,
      reason: evalResult.reason,
      domain: evalResult.domain,
      exitCode: 3,
    };
  }

  if (!run || typeof run !== 'function') {
    throw new Error('run function is required to execute worker-start');
  }

  const argv = ['orchestration', 'worker-start', '--agent', agent, ...(model ? ['--model', model] : []), ...forward];

  const result = await run(argv);
  const exitCode =
    typeof result === 'number'
      ? exitStatusFor(result, null)
      : exitStatusFor(result?.exitCode ?? result?.status ?? null, result?.signal ?? null);
  const stdout = typeof result === 'object' && result?.stdout != null ? result.stdout : '';
  const stderr = typeof result === 'object' && result?.stderr != null ? result.stderr : '';

  return {
    launched: true,
    exitCode,
    stdout,
    stderr,
    argv,
  };
}

export async function runCli(args = process.argv.slice(2)) {
  let options;
  try {
    options = parseArgs(args);
    if (options.help) {
      console.log(
        'Usage: node launch-worker.mjs --policy <path> --agent <id> [--model <id>] [--capacity-domain <d>] [--orca <exe>] -- <worker-start args...>',
      );
      return;
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
    return;
  }

  let policyText = null;
  try {
    policyText = await readFile(options.policy, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      policyText = null;
    } else {
      policyText = 'INVALID_FILE_CONTENT';
    }
  }

  const runner = (argv) => {
    return new Promise((resolve, reject) => {
      const cp = spawn(options.orca, argv, { stdio: 'inherit' });
      cp.on('error', reject);
      cp.on('close', (code, signal) => {
        resolve({ exitCode: code, signal });
      });
    });
  };

  let result;
  try {
    result = await launchWorker(
      {
        policyText,
        agent: options.agent,
        model: options.model,
        capacityDomain: options.capacityDomain,
        forward: options.forward,
        now: Date.now(),
      },
      { run: runner },
    );
  } catch (error) {
    console.error(`worker-start could not be run: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  if (!result.launched) {
    console.log(JSON.stringify({ launched: false, reason: result.reason, domain: result.domain }));
    process.exitCode = 3;
  } else {
    process.exitCode = result.exitCode;
  }
}

if (
  process.argv[1] &&
  existsSync(process.argv[1]) &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await runCli();
}
