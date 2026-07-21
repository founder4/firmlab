/**
 * Minimal OpenAI-compatible `/chat/completions` mock for driving the agent deterministically in tests — there is
 * no real LLM key in the dev/CI/container env, so the whole agent skeleton (orchestrator, governor, transcript,
 * rung clamping, human-approval gate, real emulation) is exercised against canned decisions instead.
 *
 * Point the API at it: FIRMLAB_LLM_PROVIDER=openai FIRMLAB_LLM_API_KEY=dummy FIRMLAB_LLM_MODEL=mock
 * FIRMLAB_LLM_BASE_URL=http://127.0.0.1:<port>  (default 8790).
 *
 * Routing is by a distinctive token in the prompt: the triage node's schema names `resolvedClass`, the
 * target-selection node's context names `maxRung`; anything else (the closing synthesis / copilot) gets free text.
 * The canned answers steer an RTOS image down the Renode rung. Override any answer via env (MOCK_TRIAGE_JSON,
 * MOCK_TARGET_JSON, MOCK_SYNTH_TEXT) to reuse this mock for other paths.
 */
import http from 'node:http';

const PORT = Number(process.env.MOCK_LLM_PORT ?? 8790);

const TRIAGE =
  process.env.MOCK_TRIAGE_JSON ??
  JSON.stringify({
    resolvedClass: 'rtos',
    classConfidence: 'high',
    shouldExtract: false,
    extractionCascade: [],
    attackSurface: ['UART console', 'firmware boot'],
    rationale: 'Bare-metal RTOS ELF — no Linux filesystem to extract; the whole image boots under Renode.',
  });

const TARGET =
  process.env.MOCK_TARGET_JSON ??
  JSON.stringify({
    targets: [
      {
        path: 'firmware.elf',
        rung: 'rtos-renode',
        priority: 'high',
        reason: 'RTOS image — boot the whole firmware under Renode and observe UART.',
      },
    ],
    rationale: 'One RTOS target: the firmware itself, at the rtos-renode rung.',
  });

const SYNTH =
  process.env.MOCK_SYNTH_TEXT ??
  'Closing synthesis: the RTOS firmware booted under Renode and produced UART output ' +
    '(confirmed_in_emulation — proves the sandbox, not the physical device). No zero-day candidate: a bare-metal ' +
    'image has no rootfs binary triage, so nothing was invented.';

function reply(res, content) {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(
    JSON.stringify({
      id: 'mock',
      object: 'chat.completion',
      model: 'mock',
      choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 20, completion_tokens: 40, total_tokens: 60 },
    }),
  );
}

const server = http.createServer((req, res) => {
  if (req.method !== 'POST' || !(req.url ?? '').includes('/chat/completions')) {
    res.writeHead(404);
    res.end('not found');
    return;
  }
  let body = '';
  req.on('data', (c) => {
    body += c;
  });
  req.on('end', () => {
    let prompt = '';
    try {
      const parsed = JSON.parse(body);
      prompt = (parsed.messages ?? [])
        .map((m) => (typeof m.content === 'string' ? m.content : JSON.stringify(m.content)))
        .join('\n');
    } catch {}
    if (prompt.includes('resolvedClass')) {
      console.log('[mock-llm] → triage');
      return reply(res, TRIAGE);
    }
    if (prompt.includes('maxRung')) {
      console.log('[mock-llm] → target-selection');
      return reply(res, TARGET);
    }
    console.log('[mock-llm] → synthesis/copilot');
    return reply(res, SYNTH);
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`[mock-llm] listening on http://127.0.0.1:${PORT}`));
