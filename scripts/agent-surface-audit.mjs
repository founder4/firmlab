#!/usr/bin/env node
/**
 * Deterministic, local-only audit of FirmLab's agent-facing configuration and trust boundaries.
 *
 * This is deliberately a small policy scanner rather than an oracle. It reads repository files, emits SARIF 2.1.0,
 * and makes no network request. Findings are review signals: warnings do not block the build; reproducible errors
 * can be enabled as a gate with --fail-on-error. A scanner that cannot open every owned file exits 2, never clean.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const RULES = {
  'surface/file-unreadable': ['error', 'An owned agent-surface file could not be read.'],
  'surface/hidden-unicode': ['warning', 'Hidden bidirectional or zero-width Unicode can conceal instructions.'],
  'mcp/invalid-config': ['error', '.mcp.json is not valid JSON with an mcpServers object.'],
  'mcp/remote-endpoint': ['error', 'Remote MCP endpoints widen the local-only trust boundary.'],
  'mcp/unpinned-npx-package': ['warning', 'An npx MCP package is not pinned to an immutable version.'],
  'mcp/shell-command': ['warning', 'A shell interpreter in MCP configuration can execute a composed command.'],
  'mcp/literal-secret': ['error', 'A credential-like MCP environment key contains a literal value.'],
  'instructions/missing-invariant': ['error', 'An agent entry point no longer imports or states a required invariant.'],
  'server/non-stdio-transport': ['error', 'The FirmLab MCP server must remain stdio-only.'],
  'server/import-side-effect': ['error', 'The MCP server no longer guards stdio startup behind direct execution.'],
  'server/assertion-schema-open': ['error', 'The assertion tool must reject unknown authority fields.'],
  'server/agent-author-header': ['error', 'The MCP transport must overwrite every case variant of author kind.'],
  'agent/missing-trust-boundary': ['error', 'A model-facing prompt no longer labels evidence as untrusted.'],
  'agent/model-controls-approval': ['error', 'A decision-node module mentions the pre-approval authority field.'],
};

const OWNED_FILES = [
  '.mcp.json',
  'AGENTS.md',
  'CLAUDE.md',
  'GEMINI.md',
  'apps/api/src/mcp/server.ts',
  'apps/api/src/mcp/client.ts',
  'apps/api/src/copilot.ts',
  'apps/api/src/agent/nodes.ts',
  'apps/api/src/agent/zeroday.ts',
  'apps/api/src/agent/intel.ts',
];

const PROMPT_FILES = [
  'apps/api/src/copilot.ts',
  'apps/api/src/agent/nodes.ts',
  'apps/api/src/agent/zeroday.ts',
  'apps/api/src/agent/intel.ts',
];

const lineOf = (text, offset) => text.slice(0, Math.max(0, offset)).split('\n').length;

function result(ruleId, file, message, text = '', offset = 0) {
  return {
    ruleId,
    level: RULES[ruleId][0],
    message: { text: message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: file.replaceAll(path.sep, '/') },
          region: { startLine: lineOf(text, offset) },
        },
      },
    ],
  };
}

function packageIsPinned(spec) {
  const at = spec.lastIndexOf('@');
  return at > 0 && !['', 'latest', 'next', '*'].includes(spec.slice(at + 1).toLowerCase());
}

function scanMcpConfig(text, findings) {
  let config;
  try {
    config = JSON.parse(text);
  } catch (error) {
    findings.push(result('mcp/invalid-config', '.mcp.json', `Invalid JSON: ${error.message}`, text));
    return;
  }
  if (!config?.mcpServers || typeof config.mcpServers !== 'object' || Array.isArray(config.mcpServers)) {
    findings.push(result('mcp/invalid-config', '.mcp.json', 'Expected an object at mcpServers.', text));
    return;
  }
  for (const [name, server] of Object.entries(config.mcpServers)) {
    if (!server || typeof server !== 'object' || Array.isArray(server)) continue;
    if (typeof server.url === 'string') {
      findings.push(
        result(
          'mcp/remote-endpoint',
          '.mcp.json',
          `MCP server ${name} uses URL transport (${server.url}); FirmLab defaults must remain local process transports.`,
          text,
          text.indexOf(server.url),
        ),
      );
    }
    const command = typeof server.command === 'string' ? path.basename(server.command).toLowerCase() : '';
    const args = Array.isArray(server.args) ? server.args.filter((arg) => typeof arg === 'string') : [];
    if (command === 'npx') {
      const spec = args.find((arg) => !arg.startsWith('-'));
      if (!spec || !packageIsPinned(spec)) {
        findings.push(
          result(
            'mcp/unpinned-npx-package',
            '.mcp.json',
            `MCP server ${name} resolves ${spec ?? '(no package found)'} at launch; pin an exact reviewed version.`,
            text,
            spec ? text.indexOf(spec) : 0,
          ),
        );
      }
    }
    if (['sh', 'bash', 'zsh', 'cmd', 'powershell', 'pwsh'].includes(command)) {
      findings.push(
        result(
          'mcp/shell-command',
          '.mcp.json',
          `MCP server ${name} launches through ${command}; use an argv-based executable directly.`,
          text,
          text.indexOf(server.command),
        ),
      );
    }
    for (const [key, value] of Object.entries(server.env ?? {})) {
      if (/(?:token|secret|password|api[_-]?key)/i.test(key) && typeof value === 'string' && value !== '') {
        findings.push(
          result(
            'mcp/literal-secret',
            '.mcp.json',
            `MCP server ${name} embeds a literal value for credential-like key ${key}.`,
            text,
            text.indexOf(key),
          ),
        );
      }
    }
  }
}

function requireAnchors(file, text, anchors, findings) {
  for (const anchor of anchors) {
    if (!text.includes(anchor)) {
      findings.push(
        result('instructions/missing-invariant', file, `${file} is missing required anchor: ${anchor}`, text),
      );
    }
  }
}

export function scanAgentSurface(root) {
  const findings = [];
  const contents = new Map();
  for (const file of OWNED_FILES) {
    try {
      contents.set(file, fs.readFileSync(path.join(root, file), 'utf8'));
    } catch (error) {
      findings.push(result('surface/file-unreadable', file, `${file} could not be read: ${error.message}`));
    }
  }

  for (const [file, text] of contents) {
    const match = /\u200B|\u200C|\u200D|\u202A|\u202B|\u202C|\u202D|\u202E|\u2066|\u2067|\u2068|\u2069/u.exec(text);
    if (match) {
      findings.push(
        result(
          'surface/hidden-unicode',
          file,
          `Hidden Unicode control U+${match[0].codePointAt(0).toString(16)}.`,
          text,
          match.index,
        ),
      );
    }
  }

  const mcp = contents.get('.mcp.json');
  if (mcp !== undefined) scanMcpConfig(mcp, findings);
  const agents = contents.get('AGENTS.md');
  if (agents !== undefined)
    requireAnchors('AGENTS.md', agents, ['Code, never a model', 'empty finding list', 'local-only'], findings);
  const claude = contents.get('CLAUDE.md');
  if (claude !== undefined)
    requireAnchors('CLAUDE.md', claude, ['proof-state discipline', 'With every flag off: no network'], findings);
  const gemini = contents.get('GEMINI.md');
  if (gemini !== undefined) requireAnchors('GEMINI.md', gemini, ['@./AGENTS.md', '@./CLAUDE.md'], findings);

  const server = contents.get('apps/api/src/mcp/server.ts');
  if (server !== undefined) {
    for (const forbidden of ['StreamableHTTPServerTransport', 'SSEServerTransport', '.listen(']) {
      const offset = server.indexOf(forbidden);
      if (offset >= 0) {
        findings.push(
          result(
            'server/non-stdio-transport',
            'apps/api/src/mcp/server.ts',
            `Forbidden MCP server transport/listener: ${forbidden}`,
            server,
            offset,
          ),
        );
      }
    }
    for (const anchor of ['new StdioServerTransport()', 'pathToFileURL(entryPoint).href === import.meta.url']) {
      if (!server.includes(anchor)) {
        findings.push(
          result(
            'server/import-side-effect',
            'apps/api/src/mcp/server.ts',
            `Missing direct-entry stdio anchor: ${anchor}`,
            server,
          ),
        );
      }
    }
    const assertion = server.match(/firmlab_record_assertion[\s\S]{0,6000}?\.strict\(\)/);
    if (!assertion) {
      findings.push(
        result(
          'server/assertion-schema-open',
          'apps/api/src/mcp/server.ts',
          'firmlab_record_assertion is not backed by a strict input object.',
          server,
        ),
      );
    }
  }

  const client = contents.get('apps/api/src/mcp/client.ts');
  if (client !== undefined) {
    for (const anchor of ['name.toLowerCase() !== AUTHOR_KIND_HEADER', "stamped[AUTHOR_KIND_HEADER] = 'agent'"]) {
      if (!client.includes(anchor)) {
        findings.push(
          result(
            'server/agent-author-header',
            'apps/api/src/mcp/client.ts',
            `Missing canonical agent-author header anchor: ${anchor}`,
            client,
          ),
        );
      }
    }
  }

  for (const file of PROMPT_FILES) {
    const text = contents.get(file);
    if (text === undefined) continue;
    for (const anchor of ['UNTRUSTED_EVIDENCE_SYSTEM_RULE', 'serializeAgentPromptInput']) {
      if (!text.includes(anchor)) {
        findings.push(result('agent/missing-trust-boundary', file, `${file} does not use ${anchor}.`, text));
      }
    }
    for (const authority of ['preapproveAll', 'FIRMLAB_AGENT_PREAPPROVE']) {
      const offset = text.indexOf(authority);
      if (offset >= 0) {
        findings.push(
          result(
            'agent/model-controls-approval',
            file,
            `${file} mentions approval authority ${authority}.`,
            text,
            offset,
          ),
        );
      }
    }
  }

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'firmlab-agent-surface-audit',
            informationUri: 'https://github.com/founder4/firmlab',
            rules: Object.entries(RULES).map(([id, [level, description]]) => ({
              id,
              shortDescription: { text: description },
              defaultConfiguration: { level },
            })),
          },
        },
        results: findings,
      },
    ],
  };
  return { filesScanned: contents.size, expectedFiles: OWNED_FILES.length, findings, sarif };
}

function main() {
  const args = process.argv.slice(2);
  const failOnError = args.includes('--fail-on-error');
  const sarifAt = args.indexOf('--sarif');
  const sarifTarget = sarifAt >= 0 ? args[sarifAt + 1] : null;
  if (sarifAt >= 0 && !sarifTarget) {
    console.error('[x] --sarif requires a path or - for stdout');
    process.exit(2);
  }
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const report = scanAgentSurface(root);
  if (report.filesScanned !== report.expectedFiles) {
    console.error(`[x] scanned ${report.filesScanned}/${report.expectedFiles} owned files; refusing a clean result.`);
    process.exit(2);
  }
  if (sarifTarget === '-') console.log(JSON.stringify(report.sarif, null, 2));
  else if (sarifTarget) fs.writeFileSync(path.resolve(root, sarifTarget), `${JSON.stringify(report.sarif, null, 2)}\n`);

  const errors = report.findings.filter((finding) => finding.level === 'error');
  const warnings = report.findings.filter((finding) => finding.level === 'warning');
  for (const finding of report.findings) {
    const where = finding.locations[0].physicalLocation;
    console.error(
      `[${finding.level}] ${finding.ruleId} ${where.artifactLocation.uri}:${where.region.startLine} — ${finding.message.text}`,
    );
  }
  console.error(
    `==> agent surface audit: ${report.filesScanned} files, ${errors.length} error(s), ${warnings.length} warning(s); local static signal, not an isolation proof`,
  );
  if (failOnError && errors.length > 0) process.exit(1);
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) main();
