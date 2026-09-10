#!/usr/bin/env node
/**
 * What `execFile` ACTUALLY throws, run through the classifier that reads it.
 *
 * `classifyProbeFailure` decides whether a tool is absent, slow or broken by reading `code`/`killed`/`signal` off
 * an error object. Its unit tests build those objects by hand, which is precisely how `parseGdbOutput` came to
 * infer "attached" from a line `gdb -batch` never prints: the fixture and the code were written from the same
 * assumption, so the suite was green and the runtime was wrong. This script removes the assumption — every case
 * below is a real child process, and the error is whatever Node hands back.
 *
 * The last case is the one the fix exists for: a tool that IS installed, probed with the 4 s default budget. If
 * it does not answer in time, the old `catch {}` reported it as `available: false` — indistinguishable from a
 * deployment that never had it, and every provider needing it then said `blocked_by_platform`.
 *
 *   node apps/api/scripts/probe-shapes.mjs          # after `pnpm --filter @firmlab/api build`
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { angrPython, classifyProbeFailure, detectTools, fwhuntPython } from '../dist/tools.js';

const execFileAsync = promisify(execFile);
const DEFAULT_PROBE_TIMEOUT_MS = 4000;

/** Run one probe for real and return what was thrown, never what we expected to be thrown. */
async function attempt(bin, args, timeout) {
  const started = Date.now();
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, { timeout });
    return { ok: true, ms: Date.now() - started, line: `${stdout}${stderr}`.split('\n')[0]?.trim().slice(0, 60) };
  } catch (err) {
    const e = /** @type {{ code?: unknown, killed?: unknown, signal?: unknown }} */ (err);
    return {
      ok: false,
      ms: Date.now() - started,
      shape: { code: e?.code, killed: e?.killed, signal: e?.signal },
      outcome: classifyProbeFailure(err),
    };
  }
}

/** A file that exists and cannot be executed — made here, never assumed to exist on this OS. */
function notExecutable() {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-probe-')), 'not-executable');
  fs.writeFileSync(p, 'this is data, not a program\n', { mode: 0o644 });
  return p;
}

const cases = [
  {
    name: 'binary not on PATH',
    bin: 'firmlab-no-such-tool-4a3f',
    args: ['--version'],
    timeout: DEFAULT_PROBE_TIMEOUT_MS,
    expect: 'missing',
  },
  {
    // An installed binary that simply outlives its budget. This is the shape the whole fix turns on.
    name: 'installed binary, budget too small',
    bin: 'sleep',
    args: ['5'],
    timeout: 200,
    expect: 'timeout',
  },
  {
    name: 'installed binary, non-zero exit',
    bin: 'sh',
    args: ['-c', 'echo refused >&2; exit 3'],
    timeout: DEFAULT_PROBE_TIMEOUT_MS,
    expect: 'error',
  },
  {
    // Present but not executable. The first draft of this case pointed at `/etc/hostname`, which does not exist on
    // macOS — so it measured ENOENT and read as a misclassification of a file that was simply absent. The file has
    // to be CREATED for the case to be about permissions at all; then Node reports EACCES and the classifier falls
    // through to `error`, which is right: the file is there.
    name: 'present but not executable',
    bin: notExecutable(),
    args: [],
    timeout: DEFAULT_PROBE_TIMEOUT_MS,
    expect: 'error',
  },
];

let failures = 0;
console.log('— synthetic-free shapes: every error below came out of a real child process —\n');
for (const c of cases) {
  const r = await attempt(c.bin, c.args, c.timeout);
  if (r.ok) {
    console.log(`✗ ${c.name}: expected a failure, the probe SUCCEEDED (${r.ms} ms) — this case proves nothing here`);
    failures++;
    continue;
  }
  const mark = r.outcome === c.expect ? '✓' : '✗';
  if (r.outcome !== c.expect) failures++;
  console.log(
    `${mark} ${c.name}: outcome=${r.outcome} expected=${c.expect} (${r.ms} ms) ` + `shape=${JSON.stringify(r.shape)}`,
  );
}

// The catalogue's two slowest probes, against the DEFAULT budget rather than their declared one. A tool that
// needs more than 4 s is not an absent tool, and this is the measurement that says which of the two it is.
console.log('\n— real catalogue probes, forced onto the 4 s default budget —\n');
const slow = [
  { id: 'angr', bin: angrPython(), args: ['-c', 'import angr; print(f"angr {angr.__version__}")'], declared: 20000 },
  {
    id: 'fwhunt',
    bin: fwhuntPython(),
    args: ['-c', 'import fwhunt_scan, rzpipe; print("fwhunt-scan ok")'],
    declared: 15000,
  },
];
for (const s of slow) {
  const forced = await attempt(s.bin, s.args, DEFAULT_PROBE_TIMEOUT_MS);
  if (forced.ok) {
    console.log(`· ${s.id} (${s.bin}): answered in ${forced.ms} ms under the 4 s default — "${forced.line}"`);
    continue;
  }
  if (forced.outcome === 'missing') {
    console.log(`· ${s.id} (${s.bin}): not installed here — nothing to measure, run this in the container`);
    continue;
  }
  const real = await attempt(s.bin, s.args, s.declared);
  if (forced.outcome === 'timeout' && real.ok) {
    // The defect, measured: installed, and the default budget calls it absent.
    console.log(
      [
        `! ${s.id} (${s.bin}): TIMEOUT under the 4 s default, and the tool answered in ${real.ms} ms with its`,
        `  declared ${s.declared} ms budget — "${real.line}".`,
        '  This is the case the fix exists for: before it, the row read available:false, exactly like a tool this',
        '  deployment never had, and every provider needing it reported blocked_by_platform.',
      ].join('\n'),
    );
    continue;
  }
  // `error` on these two means the INTERPRETER is on PATH and the import failed — the package is not in it. Worth
  // printing plainly, because it is not the same statement as "the tool is fine but slow".
  const atDeclared = real.ok
    ? `answers in ${real.ms} ms at ${s.declared} ms`
    : `still ${real.outcome} at ${s.declared} ms`;
  console.log(
    [
      `· ${s.id} (${s.bin}): outcome=${forced.outcome} at 4 s, ${atDeclared} — shape=${JSON.stringify(forced.shape)}`,
      '  For these two the probe is an import, so `error` means the interpreter ran and the package is absent',
      '  from it — not that the analysis tool is present and merely misbehaving.',
    ].join('\n'),
  );
}

// The branch nobody runs: the whole `probe → describe → i18n` path over the tools this box really has, in both
// languages. A classifier that is right and a gloss that is missing produce the same broken page, and an
// AVAILABLE tool must carry no outcome at all — the field says why a probe said no, and this one said yes.
console.log('\n— detectTools() over this deployment, both locales —\n');
for (const locale of ['en', 'es']) {
  const rows = await detectTools(locale === 'en', locale); // force once, then read the same cache in the other language
  const available = rows.filter((r) => r.available);
  const leaked = available.filter((r) => r.outcome !== undefined || r.outcomeReason !== undefined);
  const absent = rows.filter((r) => !r.available);
  const unglossed = absent.filter((r) => !r.outcome || !r.outcomeReason);
  console.log(`[${locale}] ${available.length}/${rows.length} available · ${absent.length} absent`);
  if (leaked.length > 0) {
    console.log(`  ✗ ${leaked.length} AVAILABLE tools carry an outcome: ${leaked.map((r) => r.id).join(', ')}`);
    failures++;
  }
  if (unglossed.length > 0) {
    console.log(`  ✗ ${unglossed.length} absent tools have no reason: ${unglossed.map((r) => r.id).join(', ')}`);
    failures++;
  }
  const byOutcome = {};
  for (const r of absent) {
    const key = r.outcome ?? 'none';
    byOutcome[key] = (byOutcome[key] ?? 0) + 1;
  }
  console.log(`  outcomes: ${JSON.stringify(byOutcome)}`);
  for (const r of absent.slice(0, 3)) console.log(`  · ${r.bin} → ${r.outcome}: ${r.outcomeReason}`);
  if (absent.length === 0) console.log('  (every tool answered — the absent path is unexercised on this box)');
}

console.log(`\n${failures === 0 ? 'all shapes classified as the tests claim' : `${failures} MISCLASSIFIED`}`);
process.exit(failures === 0 ? 0 : 1);
