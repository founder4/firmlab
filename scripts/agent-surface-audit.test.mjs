import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { scanAgentSurface } from './agent-surface-audit.mjs';

const tempRoots = [];

function fixture(overrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-agent-surface-'));
  tempRoots.push(root);
  const files = {
    '.mcp.json': JSON.stringify({ mcpServers: { local: { command: 'node', args: ['server.js'], env: {} } } }),
    'AGENTS.md': 'Code, never a model\nempty finding list\nlocal-only',
    'CLAUDE.md': 'proof-state discipline\nWith every flag off: no network',
    'GEMINI.md': '@./AGENTS.md\n@./CLAUDE.md',
    'apps/api/src/mcp/server.ts':
      "new StdioServerTransport(); pathToFileURL(entryPoint).href === import.meta.url; 'firmlab_record_assertion'; z.object({}).strict()",
    'apps/api/src/mcp/client.ts': "name.toLowerCase() !== AUTHOR_KIND_HEADER; stamped[AUTHOR_KIND_HEADER] = 'agent'",
    'apps/api/src/copilot.ts': 'UNTRUSTED_EVIDENCE_SYSTEM_RULE serializeAgentPromptInput',
    'apps/api/src/agent/nodes.ts': 'UNTRUSTED_EVIDENCE_SYSTEM_RULE serializeAgentPromptInput',
    'apps/api/src/agent/zeroday.ts': 'UNTRUSTED_EVIDENCE_SYSTEM_RULE serializeAgentPromptInput',
    'apps/api/src/agent/intel.ts': 'UNTRUSTED_EVIDENCE_SYSTEM_RULE serializeAgentPromptInput',
    ...overrides,
  };
  for (const [file, content] of Object.entries(files)) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
  }
  return root;
}

test('the clean fixture scans every owned file and emits empty SARIF results', () => {
  const report = scanAgentSurface(fixture());
  assert.equal(report.filesScanned, report.expectedFiles);
  assert.deepEqual(report.findings, []);
  assert.equal(report.sarif.version, '2.1.0');
  assert.deepEqual(report.sarif.runs[0].results, []);
});

test('reports supply-chain, remote, secret, shell and hidden-text signals with locations', () => {
  const report = scanAgentSurface(
    fixture({
      '.mcp.json': JSON.stringify({
        mcpServers: {
          remote: { url: 'https://example.invalid/mcp' },
          floating: { command: 'npx', args: ['-y', '@scope/server@latest'] },
          shell: { command: 'bash', args: ['-c', 'server'], env: { API_KEY: 'literal-secret' } },
        },
      }),
      'GEMINI.md': '@./AGENTS.md\n@./CLAUDE.md\u202e',
    }),
  );
  const ids = new Set(report.findings.map((finding) => finding.ruleId));
  for (const id of [
    'mcp/remote-endpoint',
    'mcp/unpinned-npx-package',
    'mcp/shell-command',
    'mcp/literal-secret',
    'surface/hidden-unicode',
  ]) {
    assert.ok(ids.has(id), `expected ${id}`);
  }
  assert.ok(report.findings.every((finding) => finding.locations[0].physicalLocation.region.startLine >= 1));
});

test('the repository itself has no blocking agent-surface finding', () => {
  const report = scanAgentSurface(new URL('..', import.meta.url).pathname);
  assert.equal(report.filesScanned, report.expectedFiles);
  assert.deepEqual(
    report.findings.filter((finding) => finding.level === 'error'),
    [],
  );
});

test.after(() => {
  for (const root of tempRoots) fs.rmSync(root, { recursive: true, force: true });
});
