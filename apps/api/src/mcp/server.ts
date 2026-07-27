#!/usr/bin/env node
/**
 * FirmLab MCP server — the workbench as a toolchain any agent can drive.
 *
 * The app-vs-autonomous experiment (docs/AUTONOMOUS-WORKERS.md) measured two things: a fixed pipeline, and an
 * agent holding a raw toolchain. The fixed pipeline is reproducible and honest about what it did not do, but it
 * only ever runs the plan its class routes to. The raw-toolchain agent adapts, and confabulates — the pass-1
 * write-up asserted a "cleartext cloud pairing secret" that turned out to be a PUBLIC key. The third arrangement,
 * an agent driving the APP's providers, was never measured, and it is the interesting one: the agent chooses what
 * to ask, and every answer it gets is one FirmLab is willing to defend, carrying its proof state and the record of
 * what did not run. This server is that arrangement.
 *
 * It is deliberately thin. The providers are already clean seams behind an HTTP API that syncs findings under
 * idempotent sources and refuses what it cannot honestly do, so this is a façade over that API plus the one thing
 * the agent boundary genuinely needs and the HTTP API does not: results shaped so a model cannot read an absence
 * of analysis as an absence of problems (see mcp/format.ts, where that logic lives and is tested).
 *
 * Transport is stdio, so the agent owns the process lifetime. Two working configurations:
 *
 *   # against the deployed container (publishes no host port; the exec channel IS the transport)
 *   claude mcp add firmlab -- docker exec -i firmlab node /app/apps/api/dist/mcp/server.js
 *
 *   # against a local dev API
 *   FIRMLAB_API=http://127.0.0.1:8799 node apps/api/dist/mcp/server.js
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { type FirmLabClient, clientFromEnv } from './client.js';
import {
  HONESTY_INSTRUCTIONS,
  type McpCoverage,
  type McpFinding,
  coverageHeadline,
  findingsPayload,
  reachabilityPayload,
  scanPayload,
  toolError,
  toolResult,
} from './format.js';

/**
 * Providers an agent can run individually → the route that runs each. The agent-facing name describes the
 * question rather than mirroring the URL (`servicemap` is served at `/services`), so the enum stays readable in a
 * tool schema and the mapping stays in one place instead of leaking a URL quirk into the model's vocabulary.
 */
const WORKER_ROUTES = {
  fsaudit: 'fsaudit',
  sbom: 'sbom',
  certs: 'certs',
  compmap: 'compmap',
  servicemap: 'services',
  uboot: 'uboot',
  rtos: 'rtos',
  chipsec: 'chipsec',
  fcc: 'fcc',
} as const;

const WORKERS = Object.keys(WORKER_ROUTES) as [keyof typeof WORKER_ROUTES, ...(keyof typeof WORKER_ROUTES)[]];

/** Job budgets. Extraction and a full autonomous scan are minutes of real work, not seconds. */
const EXTRACT_TIMEOUT_MS = 10 * 60 * 1000;
const SCAN_TIMEOUT_MS = 25 * 60 * 1000;
const WORKER_TIMEOUT_MS = 5 * 60 * 1000;
const REACH_TIMEOUT_MS = 12 * 60 * 1000;

/** Read an image's coverage, or null — every findings-shaped result is bound to it. */
async function coverageOf(fl: FirmLabClient, imageId: string): Promise<McpCoverage | null> {
  return fl.getOrNull<McpCoverage>(`/api/images/${imageId}/coverage`);
}

/** A job that finished, errored, or ran out of the tool's budget — rendered so each reads as what it is. */
function jobPayload(job: { status: string; error: string | null; log: string; result: unknown; id: string }): unknown {
  if (job.status === 'error') {
    return { ok: false, jobId: job.id, error: job.error ?? 'job failed', log: job.log.slice(-4000) };
  }
  if (job.status !== 'done') {
    return {
      ok: false,
      stillRunning: true,
      jobId: job.id,
      status: job.status,
      note: 'The job is still running — this tool waited as long as it is allowed to. It has NOT failed and it has NOT finished; poll it with firmlab_job_status before drawing any conclusion.',
      log: job.log.slice(-4000),
    };
  }
  return { ok: true, jobId: job.id, result: job.result };
}

export function buildServer(fl: FirmLabClient): McpServer {
  const server = new McpServer(
    { name: 'firmlab', version: '0.1.0' },
    { instructions: HONESTY_INSTRUCTIONS, capabilities: { tools: {} } },
  );

  // === Read the bench ===

  server.registerTool(
    'firmlab_list_images',
    {
      title: 'List firmware images',
      description:
        'Every firmware image on the bench, with the device class and architecture FirmLab inferred for it. ' +
        'Start here: the class decides which analysis stages even apply to an image.',
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const { images } = await fl.get<{ images: Record<string, unknown>[] }>('/api/images');
      return toolResult({
        count: images.length,
        images: images.map((im) => ({
          id: im.id,
          filename: im.filename,
          size: im.size,
          status: im.status,
          firmwareClass: (im.identity as { firmwareClass?: string } | null)?.firmwareClass ?? 'unknown',
          arch: (im.identity as { arch?: string } | null)?.arch ?? 'unknown',
        })),
      });
    },
  );

  server.registerTool(
    'firmlab_coverage',
    {
      title: 'What has actually been examined',
      description:
        "The stages this image's device class routes to, which of them actually ran, and one sentence stating " +
        'what its finding count does and does not cover. Call this BEFORE characterising any result as clean, ' +
        'negative, or complete — it is the only thing that distinguishes "analyzed and nothing found" from ' +
        '"never analyzed", which are identical in a findings list and opposite as conclusions.',
      inputSchema: { imageId: z.string().describe('Image id from firmlab_list_images') },
      annotations: { readOnlyHint: true },
    },
    async ({ imageId }) => {
      const c = await coverageOf(fl, imageId);
      if (!c) return toolError(`No coverage for image ${imageId} — does it exist?`);
      return toolResult({
        headline: coverageHeadline(c),
        firmwareClass: c.firmwareClass,
        classRationale: c.classRationale,
        stagesExecuted: c.executed,
        stagesApplicable: c.applicable,
        findingCount: c.findingCount,
        stages: c.stages,
      });
    },
  );

  server.registerTool(
    'firmlab_findings',
    {
      title: 'The findings ledger (with its coverage caveat)',
      description:
        'Every finding recorded for an image, each carrying the PROOF STATE that bounds what it licenses you to ' +
        'claim. The result leads with a coverage verdict and the list of stages that produced no result — read ' +
        'those first. An empty list here is not a clean bill of health for the firmware.',
      inputSchema: {
        imageId: z.string().describe('Image id'),
        minSeverity: z
          .enum(['critical', 'high', 'medium', 'low', 'info'])
          .optional()
          .describe('Only findings at or above this severity'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ imageId, minSeverity }) => {
      const [{ findings }, coverage] = await Promise.all([
        fl.get<{ findings: McpFinding[] }>(`/api/images/${imageId}/findings`),
        coverageOf(fl, imageId),
      ]);
      const order = ['info', 'low', 'medium', 'high', 'critical'];
      const filtered = minSeverity
        ? findings.filter((f) => order.indexOf(f.severity) >= order.indexOf(minSeverity))
        : findings;
      return toolResult(findingsPayload(coverage, filtered));
    },
  );

  server.registerTool(
    'firmlab_list_binaries',
    {
      title: 'ELF inventory of the extracted rootfs',
      description:
        'Every ELF recovered from the image, with architecture and hardening flags (NX / stack canary / PIC) and ' +
        'notable imports. Needs a prior extraction. Use it to pick a target for firmlab_symbolic_reachability.',
      inputSchema: { imageId: z.string() },
      annotations: { readOnlyHint: true },
    },
    async ({ imageId }) => {
      const { binaries } = await fl.get<{ binaries: unknown[] }>(`/api/images/${imageId}/binaries`);
      return toolResult({
        count: binaries.length,
        note: binaries.length === 0 ? 'No binaries registered — run firmlab_extract first.' : undefined,
        binaries,
      });
    },
  );

  server.registerTool(
    'firmlab_capabilities',
    {
      title: 'What this deployment can actually do',
      description:
        'Which external tools are installed here, grouped by what they unlock. A question whose tool is absent ' +
        'cannot be answered by this deployment — that is a missing capability, never a negative result. Check ' +
        'here before concluding that an analysis "found nothing".',
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const { tools, groups } = await fl.get<{
        tools: { name: string; available: boolean; reason?: string; group: string }[];
        groups: Record<string, unknown>;
      }>('/api/tools');
      return toolResult({
        groups,
        absent: tools.filter((t) => !t.available).map((t) => ({ name: t.name, group: t.group, why: t.reason })),
        present: tools.filter((t) => t.available).map((t) => t.name),
      });
    },
  );

  // === Act on the bench ===

  server.registerTool(
    'firmlab_extract',
    {
      title: 'Recover the filesystem',
      description:
        'Carve the image and extract its root filesystem (recursive FIT→UBI→SquashFS when needed). Most analysis ' +
        'stages need this first. Degrades honestly: an image whose payload cannot be recovered says so, and a ' +
        'hollow/decoy image is reported as such rather than as an empty result.',
      inputSchema: { imageId: z.string() },
    },
    async ({ imageId }) => {
      const job = await fl.runJob(`/api/images/${imageId}/extract`, {}, EXTRACT_TIMEOUT_MS);
      return toolResult(jobPayload(job));
    },
  );

  server.registerTool(
    'firmlab_run_worker',
    {
      title: 'Run one analysis stage',
      description:
        'Run a single analysis provider against an image. Use when you want a specific question answered rather ' +
        'than the whole chain. Stages needing a filesystem require firmlab_extract first. Note that individually ' +
        'run stages do NOT count towards firmlab_coverage, which measures the autonomous scan.',
      inputSchema: {
        imageId: z.string(),
        worker: z
          .enum(WORKERS)
          .describe(
            'fsaudit = credentials/secrets audit · sbom = packages→CVEs · certs = embedded X.509 · compmap = ELF dependency graph · servicemap = boot-time network daemons · uboot = boot posture · rtos = bare-metal/RTOS · chipsec = UEFI Secure Boot/NVRAM · fcc = FCC-ID recon',
          ),
      },
    },
    async ({ imageId, worker }) => {
      const job = await fl.runJob(`/api/images/${imageId}/${WORKER_ROUTES[worker]}`, {}, WORKER_TIMEOUT_MS);
      return toolResult(jobPayload(job));
    },
  );

  server.registerTool(
    'firmlab_autonomous_scan',
    {
      title: 'Run the full class-routed worker chain',
      description:
        "Plan and run the whole analysis chain for this image's device class, re-planning as workers surface " +
        'leads, then compose an attack-path narrative. Minutes of real work. The result names the workers that ' +
        'did NOT complete and the honest gaps before it gives you the narrative — those bound everything the ' +
        'narrative says.',
      inputSchema: { imageId: z.string() },
    },
    async ({ imageId }) => {
      const job = await fl.runJob(`/api/images/${imageId}/opacidad`, {}, SCAN_TIMEOUT_MS);
      if (job.status !== 'done') return toolResult(jobPayload(job));
      return toolResult(scanPayload(job.result as Parameters<typeof scanPayload>[0]));
    },
  );

  server.registerTool(
    'firmlab_symbolic_reachability',
    {
      title: 'Ask angr whether a call site is reachable',
      description:
        "One checkable question per sink: is that call site reachable from the binary's entry point under " +
        'symbolic argv/stdin? A reached sink is a REACHABILITY claim — it does not establish an overflow or ' +
        'exploitability. A sink not reached inside the budget proves NOTHING about that sink. Leave sinks empty ' +
        "to derive them from the binary's own unbounded-copy imports, or name any symbols you care about " +
        '(e.g. system, memcpy). Needs a prior extraction.',
      inputSchema: {
        imageId: z.string(),
        binary: z.string().describe('Rootfs-relative path, e.g. usr/sbin/httpd'),
        sinks: z.array(z.string()).optional().describe('Function symbols; omit to derive from the binary'),
        budgetSeconds: z.number().min(15).max(600).optional().describe('Search budget per run (default 90)'),
      },
    },
    async ({ imageId, binary, sinks, budgetSeconds }) => {
      const job = await fl.runJob(
        `/api/images/${imageId}/symreach`,
        { binary, ...(sinks?.length ? { sinks } : {}), ...(budgetSeconds ? { budgetSeconds } : {}) },
        REACH_TIMEOUT_MS,
      );
      if (job.status !== 'done') return toolResult(jobPayload(job));
      return toolResult(reachabilityPayload(job.result as Parameters<typeof reachabilityPayload>[0]));
    },
  );

  server.registerTool(
    'firmlab_job_status',
    {
      title: 'Poll a job that outlived its tool call',
      description:
        'Status, log and result of a job started by another tool. A job that is still running has neither ' +
        'succeeded nor failed — do not conclude anything from it until it is done.',
      inputSchema: { jobId: z.string() },
      annotations: { readOnlyHint: true },
    },
    async ({ jobId }) => {
      const job = await fl.job(jobId);
      return toolResult(jobPayload(job));
    },
  );

  return server;
}

/** Entry point: stdio transport, so the agent owns the process lifetime. */
async function main(): Promise<void> {
  const server = buildServer(clientFromEnv());
  await server.connect(new StdioServerTransport());
}

// stdout is the MCP transport — a stray log there corrupts the protocol stream, so diagnostics go to stderr only.
main().catch((err) => {
  process.stderr.write(`firmlab-mcp: fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
