import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import cassette from './__fixtures__/harmless-traversal.v1.json';
import type { FirmLabApiClient, JobView } from './client.js';
import { buildServer } from './server.js';

type JsonObject = Record<string, unknown>;

type ApiInteraction = {
  operation: 'get' | 'getWithStatus' | 'getOrNull' | 'job' | 'getText';
  arguments: unknown[];
  result: unknown;
};

type McpCall =
  | { kind: 'tool'; name: string; arguments: JsonObject }
  | { kind: 'resource'; uri: string }
  | { kind: 'prompt'; name: string; arguments: Record<string, string> };

class ReplayFirmLabClient implements FirmLabApiClient {
  readonly calls: { operation: ApiInteraction['operation']; arguments: unknown[] }[] = [];
  private cursor = 0;

  constructor(private readonly interactions: readonly ApiInteraction[]) {}

  private replay<T>(operation: ApiInteraction['operation'], args: unknown[]): T {
    const expected = this.interactions[this.cursor];
    this.calls.push({ operation, arguments: args });
    expect({ operation, arguments: args }, `API interaction ${this.cursor + 1}`).toEqual(
      expected && { operation: expected.operation, arguments: expected.arguments },
    );
    this.cursor += 1;
    return expected?.result as T;
  }

  assertExhausted(): void {
    expect(this.cursor).toBe(this.interactions.length);
  }

  async get<T>(path: string): Promise<T> {
    return this.replay<T>('get', [path]);
  }

  async getWithStatus<T>(path: string): Promise<{ ok: boolean; status: number; body: T }> {
    return this.replay<{ ok: boolean; status: number; body: T }>('getWithStatus', [path]);
  }

  async getOrNull<T>(path: string): Promise<T | null> {
    return this.replay<T | null>('getOrNull', [path]);
  }

  async job(jobId: string): Promise<JobView> {
    return this.replay<JobView>('job', [jobId]);
  }

  async getText(path: string): Promise<string> {
    return this.replay<string>('getText', [path]);
  }

  async post<T>(_path: string, _body?: unknown): Promise<T> {
    throw new Error('The harmless traversal must not POST to the FirmLab API');
  }

  async runJob(_startPath: string, _body: unknown, _timeoutMs: number, _pollMs?: number): Promise<JobView> {
    throw new Error('The harmless traversal must not start a FirmLab job');
  }

  async upload(_filename: string, _bytes: Buffer): Promise<{ id: string; filename: string }> {
    throw new Error('The harmless traversal must not upload an image');
  }
}

describe('FirmLab MCP client-visible contract', () => {
  const interactions = cassette.apiInteractions as ApiInteraction[];
  const traversal = cassette.mcpCalls as McpCall[];
  let api: ReplayFirmLabClient;
  let client: Client;
  let server: ReturnType<typeof buildServer>;

  beforeEach(async () => {
    api = new ReplayFirmLabClient(interactions);
    server = buildServer(api);
    client = new Client({ name: 'firmlab-contract-test', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  });

  afterEach(async () => {
    await client.close();
  });

  it('matches the reviewed v1 tools, resources, templates, and prompts snapshot', async () => {
    const [tools, resources, resourceTemplates, prompts] = await Promise.all([
      client.listTools(),
      client.listResources(),
      client.listResourceTemplates(),
      client.listPrompts(),
    ]);

    // This is intentionally an external snapshot: contract drift fails CI and requires a reviewer to inspect the
    // full client-visible diff before deliberately accepting it with Vitest's snapshot-update flag.
    expect({
      snapshotVersion: 1,
      server: client.getServerVersion(),
      capabilities: client.getServerCapabilities(),
      instructions: client.getInstructions(),
      tools: tools.tools.map(({ name, title, description, inputSchema, annotations }) => ({
        name,
        title,
        description,
        inputSchema,
        annotations,
      })),
      resources: resources.resources,
      resourceTemplates: resourceTemplates.resourceTemplates,
      prompts: prompts.prompts,
    }).toMatchSnapshot('client-visible contract v1');
  });

  it('replays a deterministic traversal of every harmless client call', async () => {
    const [tools, resources, resourceTemplates, prompts] = await Promise.all([
      client.listTools(),
      client.listResources(),
      client.listResourceTemplates(),
      client.listPrompts(),
    ]);
    const toolCalls = traversal.filter((call): call is Extract<McpCall, { kind: 'tool' }> => call.kind === 'tool');
    const resourceCalls = traversal.filter(
      (call): call is Extract<McpCall, { kind: 'resource' }> => call.kind === 'resource',
    );
    const promptCalls = traversal.filter(
      (call): call is Extract<McpCall, { kind: 'prompt' }> => call.kind === 'prompt',
    );

    expect(toolCalls.map(({ name }) => name)).toEqual(
      tools.tools.filter(({ annotations }) => annotations?.readOnlyHint).map(({ name }) => name),
    );
    expect(promptCalls.map(({ name }) => name)).toEqual(prompts.prompts.map(({ name }) => name));
    expect(resourceCalls).toHaveLength(resources.resources.length + resourceTemplates.resourceTemplates.length);
    expect(resourceCalls.map(({ uri }) => uri)).toEqual(
      expect.arrayContaining(resources.resources.map(({ uri }) => uri)),
    );

    const transcript: unknown[] = [];

    for (const call of traversal) {
      if (call.kind === 'tool') {
        const response = await client.callTool({ name: call.name, arguments: call.arguments });
        expect(response.isError).not.toBe(true);
        transcript.push({ request: call, response });
      } else if (call.kind === 'resource') {
        const response = await client.readResource({ uri: call.uri });
        expect(response.contents).not.toHaveLength(0);
        transcript.push({ request: call, response });
      } else {
        const response = await client.getPrompt({ name: call.name, arguments: call.arguments });
        expect(response.messages).not.toHaveLength(0);
        transcript.push({ request: call, response });
      }
    }

    api.assertExhausted();
    expect(api.calls).toEqual(interactions.map(({ operation, arguments: args }) => ({ operation, arguments: args })));
    expect({ cassetteVersion: cassette.version, transcript }).toMatchSnapshot('harmless traversal v1');
  });
});
