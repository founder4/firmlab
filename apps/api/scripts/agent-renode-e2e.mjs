/**
 * End-to-end validation of the agent's RTOS/Renode path against a REAL Renode, driven by a mock LLM.
 *
 * Exercises the whole conscious-autonomy skeleton on a bare-metal image: node ① triage → deterministic preflight
 * → node ② target-selection (picks the rtos-renode rung) → the Phase-4 executor. Under full isolation this
 * auto-runs `runRenode` for real; otherwise it pauses and this driver approves. It then asserts the transcript:
 * the agent chose the RTOS rung, the executor dispatched it to RENODE (not the user-mode emulator — the
 * split-brain guard), the firmware actually booted, and the proof-state is honest (`confirmed_in_emulation`).
 *
 * Prereqs (see docker invocation in the repo's validation notes): a running API pointed at scripts/mock-llm.mjs
 * with FIRMLAB_AGENT=1, Renode installed, and a real RTOS ELF at FW_PATH. Env: API_BASE, FW_PATH.
 */
import fs from 'node:fs';

const API = process.env.API_BASE ?? 'http://127.0.0.1:8799';
const FW_PATH = process.env.FW_PATH ?? '/tmp/stm32f4.elf';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jsonOf = async (r) => {
  const t = await r.text();
  try {
    return JSON.parse(t);
  } catch {
    return t;
  }
};

let failures = 0;
const check = (cond, msg) => {
  console.log(`${cond ? '  ✓' : '  ✗ FAIL'} ${msg}`);
  if (!cond) failures += 1;
};
const done = () => {
  console.log(failures === 0 ? '\n✅ AGENT → RENODE E2E PASSED' : `\n❌ ${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
};

async function waitForApi() {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`${API}/health`)).ok) return true;
    } catch {}
    await sleep(500);
  }
  return false;
}

async function pollSession(sid, until, tries) {
  let s;
  for (let i = 0; i < tries; i++) {
    s = await jsonOf(await fetch(`${API}/api/agent/sessions/${sid}`));
    if (until.includes(s.session?.status)) break;
    await sleep(1000);
  }
  return s;
}

async function main() {
  console.log('Agent → Renode e2e (mock LLM, real Renode)');
  if (!(await waitForApi())) {
    console.error('API never became ready');
    process.exit(1);
  }

  // 1) Upload a real RTOS ELF — it must classify as rtos so the preflight offers the Renode rung.
  const form = new FormData();
  form.append('file', new Blob([fs.readFileSync(FW_PATH)], { type: 'application/octet-stream' }), 'firmware.elf');
  const up = await jsonOf(await fetch(`${API}/api/images`, { method: 'POST', body: form }));
  const id = up.image?.id;
  console.log('  uploaded', id, JSON.stringify(up.image?.identity));
  check(
    up.image?.identity?.firmwareClass === 'rtos',
    `image classified as rtos (got ${up.image?.identity?.firmwareClass})`,
  );

  // 2) Start an agent session (needs FIRMLAB_AGENT=1 + the mock LLM).
  const start = await jsonOf(
    await fetch(`${API}/api/images/${id}/agent/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ goal: 'boot the RTOS firmware and observe UART' }),
    }),
  );
  const sid = start.session?.id;
  check(!!sid, `agent session started (${sid})`);
  if (!sid) {
    console.error('  start response:', JSON.stringify(start));
    return done();
  }

  // 3) Drive it to a terminal state; approve if isolation wasn't full enough to auto-run.
  let s = await pollSession(sid, ['done', 'awaiting_approval', 'error', 'halted'], 90);
  if (s.session?.status === 'awaiting_approval') {
    console.log('  isolation not full → approving the proposed emulation');
    await fetch(`${API}/api/agent/sessions/${sid}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    s = await pollSession(sid, ['done', 'error', 'halted'], 60);
  }
  const steps = s.steps ?? [];
  console.log('  status:', s.session?.status, '| transcript:', steps.map((x) => `${x.node}:${x.status}`).join(' → '));

  // 4) Assert the transcript tells the honest RTOS→Renode story.
  const target = steps.find((x) => x.node === 'target-selection');
  const plan = target?.output?.emulationPlan ?? [];
  check(
    plan.some((p) => p.rung === 'rtos-renode'),
    'node ② selected the rtos-renode rung (clamped to the preflight ceiling)',
  );

  const emu = steps.find((x) => x.node === 'emulation');
  check(!!emu, 'an emulation step ran');
  check(
    emu?.input?.rung === 'rtos-renode',
    'executor dispatched the RTOS rung to Renode, not user-mode QEMU (split-brain guard)',
  );
  check(emu?.output?.booted === true, 'the firmware actually booted under Renode (real UART bytes)');
  check(emu?.output?.proofState === 'confirmed_in_emulation', 'proof-state is honest: confirmed_in_emulation');
  check(s.session?.status === 'done', 'session completed');
  if (emu?.output?.uartExcerpt) console.log('  UART:', JSON.stringify(String(emu.output.uartExcerpt).slice(0, 140)));

  done();
}

main().catch((e) => {
  console.error('driver error:', e);
  process.exit(1);
});
