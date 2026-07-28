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
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { type FirmLabClient, clientFromEnv } from './client.js';
import {
  HONESTY_INSTRUCTIONS,
  type McpCoverage,
  type McpDirListing,
  type McpExtraction,
  type McpFileRead,
  type McpFinding,
  coverageHeadline,
  fileListingPayload,
  fileReadPayload,
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
    { instructions: HONESTY_INSTRUCTIONS, capabilities: { tools: {}, resources: {}, prompts: {} } },
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

  // === Open the evidence ===
  //
  // These two exist because the ledger was asking to be trusted. FirmLab carved 6497 files out of one corpus image
  // and served none of them, and docs/BACKLOG.md carries an entry that had to be withdrawn because it was written
  // from a FILENAME without opening the file — `private_key.pem`, which begins `-----BEGIN PUBLIC KEY-----`. An
  // agent reading a finding is one step further from the bytes than the operator who could not check them either.

  server.registerTool(
    'firmlab_list_files',
    {
      title: 'List a directory of the extracted filesystem',
      description:
        'Browse what extraction actually wrote to disk. The path is relative to the EXTRACTION ROOT, not to the ' +
        'rootfs, because several images carve into volumes without ever producing a rootfs and rooting here at the ' +
        'rootfs would show them an empty tree. Omit `path` for the top level. The result leads with the extraction ' +
        'verdict: an empty listing is not an empty filesystem, and the verdict says which of the several reasons ' +
        'applies. Symlinks are listed but never followed, and ones pointing out of the extraction are named ' +
        'separately — that a firmware ships `etc/passwd -> /dev/null` is a fact worth reporting, but its contents ' +
        'belong to the host and cannot be read.',
      inputSchema: {
        imageId: z.string(),
        path: z.string().optional().describe('Extraction-root-relative directory, e.g. squashfs-root/etc'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ imageId, path: dir }) => {
      const query = dir ? `?path=${encodeURIComponent(dir)}` : '';
      const { ok, body } = await fl.getWithStatus<{
        extraction: McpExtraction;
        listing: McpDirListing | null;
        error?: string;
        rule?: string;
      }>(`/api/images/${imageId}/files${query}`);
      if (!ok) return toolError(`${body.error ?? 'the path was refused'} (rule: ${body.rule ?? 'unknown'})`);
      return toolResult(fileListingPayload(body.extraction, body.listing));
    },
  );

  server.registerTool(
    'firmlab_read_file',
    {
      title: 'Read a bounded slice of an extracted file',
      description:
        'Open a file from the extraction and see its bytes. Text-vs-binary is decided FROM THE BYTES, never from ' +
        'the extension — a binary comes back as a hexdump whatever you ask for, and the result says which rule ' +
        'chose. The read is BOUNDED: the result always states the full size, the window served and how many bytes ' +
        'were not read, on each side. A window is not the file. Use it to CHECK evidence a finding cites rather ' +
        'than to infer content from a filename.',
      inputSchema: {
        imageId: z.string(),
        path: z.string().describe('Extraction-root-relative file, e.g. squashfs-root/etc/shadow'),
        offset: z.number().min(0).optional().describe('First byte to read (default 0)'),
        limit: z.number().min(1).optional().describe('Bytes to read (default 65536, ceiling 1048576)'),
        view: z.enum(['text', 'hex']).optional().describe('Preference only; binary bytes are always hexdumped'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ imageId, path: file, offset, limit, view }) => {
      const params = new URLSearchParams({ path: file });
      if (offset !== undefined) params.set('offset', String(offset));
      if (limit !== undefined) params.set('limit', String(limit));
      if (view !== undefined) params.set('view', view);
      const { ok, body } = await fl.getWithStatus<{
        extraction: McpExtraction;
        read: McpFileRead | null;
        error?: string;
        rule?: string;
        symlinkTarget?: string;
      }>(`/api/images/${imageId}/files/read?${params.toString()}`);
      if (!ok) {
        const target = body.symlinkTarget ? ` (symlink target: ${body.symlinkTarget})` : '';
        return toolError(`${body.error ?? 'the read was refused'}${target} (rule: ${body.rule ?? 'unknown'})`);
      }
      if (!body.read) {
        return toolResult({
          extractionVerdict: body.extraction.verdict,
          state: body.extraction.state,
          read: null,
          note: 'Nothing is on disk to read for this image. Read the extraction verdict — it is not the same claim as "the file is empty".',
        });
      }
      return toolResult(fileReadPayload(body.extraction, body.read));
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
    'firmlab_add_image',
    {
      title: 'Put a firmware image on the bench',
      description:
        'Ingest a firmware file so it can be analyzed. The path must be readable by the FirmLab SERVER, not by ' +
        'you — when the server runs inside the container and your file is on the host, copy it in first ' +
        '(`docker cp <file> firmlab:/tmp/`) and pass the container path. Analysis of identity/class happens at ' +
        'intake; everything else is a separate call.',
      inputSchema: {
        path: z.string().describe('Absolute path to the firmware file, as the FirmLab server sees it'),
      },
    },
    async ({ path: filePath }) => {
      let bytes: Buffer;
      try {
        bytes = await readFile(filePath);
      } catch (err) {
        const why = err instanceof Error ? err.message : String(err);
        return toolError(
          `Cannot read ${filePath} from the FirmLab server: ${why}. If the file is on your host and the server is in a container, \`docker cp\` it in first.`,
        );
      }
      const image = await fl.upload(basename(filePath), bytes);
      return toolResult({ ingested: true, ...image, next: 'Run firmlab_extract, then firmlab_autonomous_scan.' });
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

  // === Resources: document-shaped content the agent attaches as context rather than calls for ===

  server.registerResource(
    'proof-states',
    'firmlab://guide/proof-states',
    {
      title: 'How to read a FirmLab result',
      description: 'The proof-state ladder and the inferences that are always wrong here. Read before reporting.',
      mimeType: 'text/plain',
    },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'text/plain', text: HONESTY_INSTRUCTIONS }] }),
  );

  server.registerResource(
    'report',
    new ResourceTemplate('firmlab://images/{imageId}/report', { list: undefined }),
    {
      title: 'Analysis report (Markdown)',
      description: "FirmLab's own written report for an image — the findings with their evidence and proof states.",
      mimeType: 'text/markdown',
    },
    async (uri, { imageId }) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'text/markdown',
          text: await fl.getText(`/api/images/${imageId}/report`),
        },
      ],
    }),
  );

  server.registerResource(
    'disclosure',
    new ResourceTemplate('firmlab://images/{imageId}/disclosure', { list: undefined }),
    {
      title: 'Coordinated-disclosure draft (Markdown)',
      description:
        'A disclosure draft built from the ledger. A DRAFT: it must be reviewed against the proof states before ' +
        'anything is sent to a vendor, and it deliberately contains no exploit.',
      mimeType: 'text/markdown',
    },
    async (uri, { imageId }) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'text/markdown',
          text: await fl.getText(`/api/images/${imageId}/disclosure-report`),
        },
      ],
    }),
  );

  // === Prompts: the methodology, so the agent does not have to reinvent it each session ===

  server.registerPrompt(
    'triage_image',
    {
      title: 'Triage a firmware image honestly',
      description: 'Analyze one image end to end and report what was examined AND what was not.',
      argsSchema: { imageId: z.string() },
    },
    ({ imageId }) => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: [
              `Triage FirmLab image ${imageId}.`,
              '',
              "1. Read firmlab_coverage FIRST, so you know which stages this image's class even routes to.",
              '2. Run firmlab_extract, then firmlab_autonomous_scan.',
              '3. Read firmlab_findings and group by proof state, not by severity — a critical CVE at',
              '   needs_runtime_reproduction is a lead, and a static_confirmed medium is a fact.',
              '4. Report in two parts: what was established, and what was NOT examined (name the stages, and the',
              '   workers that degraded and why). If a stage could not run, say what would unlock it.',
              '',
              'Do not describe the image as clean or secure. The strongest honest claim available is "the stages',
              'that ran found nothing", and it is only worth writing next to the list of stages that did not run.',
            ].join('\n'),
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    'hunt_memory_safety',
    {
      title: 'Hunt memory-safety bugs and settle the leads',
      description: 'Turn the binary sweep’s candidates into reachability questions instead of leaving a maybe-list.',
      argsSchema: { imageId: z.string() },
    },
    ({ imageId }) => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: [
              `Hunt memory-safety issues in FirmLab image ${imageId}.`,
              '',
              'The binary sweep flags a precondition (unbounded copy + no canary), which is a lead, not a bug.',
              'Your job is to settle the promising ones rather than hand back the list:',
              '',
              '1. firmlab_extract, then firmlab_list_binaries. Prefer network-facing daemons and setuid binaries —',
              '   reachability of a sink in a binary nothing untrusted talks to is a much weaker result.',
              '2. For each chosen target, firmlab_symbolic_reachability. Omit sinks to derive them from the',
              '   binary, or name the ones you actually care about (system, memcpy, a vendor doSystem…).',
              '3. Report per sink. "reached" = the call site is on a live path from the entry point, with the input',
              '   that walks it — that is REACHABILITY, not an overflow and not exploitability. "not reached" is',
              '   NOT a negative result: the search is bounded, so say the question is unresolved and why.',
            ].join('\n'),
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    'compare_versions',
    {
      title: 'Compare two firmware versions',
      description: 'Read what changed between two images of the same device — the n-day framing.',
      argsSchema: { olderImageId: z.string(), newerImageId: z.string() },
    },
    ({ olderImageId, newerImageId }) => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: [
              `Compare FirmLab images ${olderImageId} (older) and ${newerImageId} (newer).`,
              '',
              '1. firmlab_coverage on BOTH first. If the two were examined to different depths, a difference in',
              '   their findings may be a difference in coverage rather than in the firmware — say so if it is.',
              '2. Ensure both are scanned, then diff the findings: what was fixed, what persists, what is new.',
              '3. A finding that disappeared is only "fixed" if the stage that would have found it actually ran on',
              '   the newer image. Check that before claiming a fix.',
            ].join('\n'),
          },
        },
      ],
    }),
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
