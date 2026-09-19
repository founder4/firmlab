/**
 * External-tool detection. The workbench is fully functional with none of these (the @firmlab/core engine
 * covers structure/entropy/strings/identity), but each detected tool unlocks a richer provider: binwalk for
 * format-aware carving, the extractors for real rootfs recovery, radare2/Ghidra for decompilation, syft/grype
 * for SBOM+CVEs, and the QEMU/Renode family for emulation. This module answers "what can this deployment do?"
 *
 * **Why `unlocks` is not on the spec below.** What a tool would let you ask is prose an operator reads on the
 * Capabilities page, recomputed on every request from the binaries actually on this box. It describes THIS
 * DEPLOYMENT, never a firmware image, and nothing about it is stored — so it is interface copy, it lives in
 * `i18n/` keyed by `ToolId`, and `detectTools` takes the locale as a parameter. The probe cache therefore holds
 * only what the probe LEARNED (present, version line), which is language-independent: one cache serves both.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { type Locale, messages } from './i18n/index.js';

const execFileAsync = promisify(execFile);

/**
 * The interpreter that owns angr. angr drags in z3/unicorn/pyvex/capstone, so the image installs it into its OWN
 * virtualenv rather than the system python3 that chipsec also uses — `FIRMLAB_ANGR_PYTHON` points at that venv's
 * interpreter. Falling back to `python3` keeps a plain host install (or a dev machine with angr on the system
 * python) working without configuration.
 */
export function angrPython(): string {
  return process.env.FIRMLAB_ANGR_PYTHON || 'python3';
}

/**
 * The interpreter that owns fwhunt-scan. Same isolation reasoning as angr: it pulls in `rzpipe` and drives a
 * separately-built rizin, and it must not share an interpreter with chipsec (which the UEFI path already uses on
 * the SAME images). Falling back to `python3` keeps a host install working without configuration.
 */
export function fwhuntPython(): string {
  return process.env.FIRMLAB_FWHUNT_PYTHON || 'python3';
}

/**
 * Where the FwHunt rule corpus lives. The rules are DATA, fetched from binarly-io/FwHunt, not something FirmLab
 * authors — that separation is the entire point (docs/BACKLOG.md: a hand-guessed GUID feed would be fabrication).
 */
export function fwhuntRulesDir(): string {
  return process.env.FIRMLAB_FWHUNT_RULES || '/opt/fwhunt-rules/rules';
}

/** Resolve a binary on PATH (executable), for tools whose --version probe is too slow/costly to run (e.g. a JVM). */
function resolveOnPath(bin: string): string | null {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    const p = path.join(dir, bin);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {}
  }
  return null;
}

export type ToolId =
  | 'binwalk'
  | 'qemu-system-mips'
  | 'mkfs.ext2'
  | 'unsquashfs'
  | 'sasquatch'
  | 'jefferson'
  | 'lzop'
  | 'ubireader_extract_files'
  | 'cpio'
  | 'radare2'
  | 'analyzeHeadless'
  | 'syft'
  | 'grype'
  | 'gitleaks'
  | 'qemu-mipsel-static'
  | 'qemu-mips-static'
  | 'qemu-arm-static'
  | 'qemu-aarch64-static'
  | 'qemu-system-mipsel'
  | 'qemu-system-arm'
  | 'qemu-system-aarch64'
  | 'renode'
  | 'chipsec'
  | 'angr'
  | 'fwhunt'
  | 'yara'
  | 'openssl'
  | 'gdb-multiarch';

interface ToolSpec {
  id: ToolId;
  /** Command probed on PATH. */
  bin: string;
  /** Args that make it exit quickly (version/help). */
  probe: string[];
  /** Feature group for the UI capabilities panel. */
  group: 'extract' | 'analyze' | 'sbom' | 'emulate' | 'secrets';
  /** Detect by PATH existence instead of executing — for tools whose probe is too slow (Ghidra's JVM startup > the
   *  probe timeout) or exits non-zero on --help. */
  detectByExistence?: boolean;
  /** Override the probe timeout. Only for a tool that is genuinely slow to answer (importing angr pulls in z3,
   *  unicorn and pyvex — seconds, not milliseconds) and would otherwise be misreported as absent. */
  timeoutMs?: number;
}

/**
 * The environment every external tool is invoked under, here and in `providers/sbom-db.ts`.
 *
 * Two of the binaries this module probes phone home on their own initiative. `syft` and `grype` both default to
 * `check-for-app-update: true` — a release poll on every invocation, including the `version` probe below — and
 * `grype` additionally defaults to `db.auto-update: true`, which downloads a multi-gigabyte vulnerability
 * database. None of it is gated by a FirmLab flag, so *"with every flag off: no network"* was false for any
 * deployment that had syft or grype installed, and the capability probe alone was enough to make it false.
 *
 * These variables are namespaced to those two tools, so spreading them over every probe costs nothing and means
 * a tool added later cannot reintroduce the hole by forgetting them. `GRYPE_DB_VALIDATE_AGE=false` is here
 * deliberately: grype REFUSES a database older than five days by default, and a provisioned, deliberately-pinned
 * database must be usable and reported as old, not rejected into silence.
 */
export const OFFLINE_ANCHORE_ENV: Readonly<Record<string, string>> = {
  GRYPE_DB_AUTO_UPDATE: 'false',
  GRYPE_DB_VALIDATE_AGE: 'false',
  GRYPE_CHECK_FOR_APP_UPDATE: 'false',
  SYFT_CHECK_FOR_APP_UPDATE: 'false',
};

/** Probe timeout for a tool that answers promptly. */
const DEFAULT_PROBE_TIMEOUT_MS = 4000;

const TOOLS: readonly ToolSpec[] = [
  { id: 'binwalk', bin: 'binwalk', probe: ['--help'], group: 'extract' },
  { id: 'unsquashfs', bin: 'unsquashfs', probe: ['-help'], group: 'extract' },
  { id: 'sasquatch', bin: 'sasquatch', probe: ['-help'], group: 'extract' },
  { id: 'jefferson', bin: 'jefferson', probe: ['--help'], group: 'extract' },
  { id: 'lzop', bin: 'lzop', probe: ['--version'], group: 'extract' },
  { id: 'ubireader_extract_files', bin: 'ubireader_extract_files', probe: ['--help'], group: 'extract' },
  { id: 'cpio', bin: 'cpio', probe: ['--version'], group: 'extract' },
  { id: 'radare2', bin: 'radare2', probe: ['-v'], group: 'analyze' },
  {
    id: 'analyzeHeadless',
    bin: 'analyzeHeadless',
    probe: ['-help'],
    group: 'analyze',
    // Ghidra's analyzeHeadless spins a JVM + Ghidra init on every call — far longer than the probe timeout, and
    // `-help` exits non-zero. Detect by existence so an installed Ghidra is reported (and thus usable), not "absent".
    detectByExistence: true,
  },
  { id: 'syft', bin: 'syft', probe: ['version'], group: 'sbom' },
  { id: 'grype', bin: 'grype', probe: ['version'], group: 'sbom' },
  { id: 'gitleaks', bin: 'gitleaks', probe: ['version'], group: 'secrets' },
  { id: 'qemu-mipsel-static', bin: 'qemu-mipsel-static', probe: ['-version'], group: 'emulate' },
  {
    // The user-mode twin of the qemu-system-mips entry below, and it is here for the same reason: handed a
    // big-endian binary, qemu-mipsel-static exits 255 with "Invalid ELF image for this architecture" before
    // executing an instruction. The `mips` arch is only ever produced from an ELF whose EI_DATA byte says
    // big-endian (structure.ts demotes the little-endian case to `mipsel`), so this is the emulator every
    // `mips` image needs, and it was never declared while the map pointed at the little-endian one.
    id: 'qemu-mips-static',
    bin: 'qemu-mips-static',
    probe: ['-version'],
    group: 'emulate',
  },
  { id: 'qemu-arm-static', bin: 'qemu-arm-static', probe: ['-version'], group: 'emulate' },
  { id: 'qemu-aarch64-static', bin: 'qemu-aarch64-static', probe: ['-version'], group: 'emulate' },
  {
    // Big-endian MIPS. Distinct from qemu-system-mipsel and NOT interchangeable: handed a big-endian kernel, the
    // little-endian emulator refuses with "The image has incorrect endianness" before executing anything.
    id: 'qemu-system-mips',
    bin: 'qemu-system-mips',
    probe: ['-version'],
    group: 'emulate',
  },
  { id: 'qemu-system-mipsel', bin: 'qemu-system-mipsel', probe: ['-version'], group: 'emulate' },
  { id: 'qemu-system-arm', bin: 'qemu-system-arm', probe: ['-version'], group: 'emulate' },
  // Shipped by the same Debian qemu-system-arm package as the 32-bit emulator above, and installed in the
  // deployed image the whole time — the arm64 full-system rung was refused with "no emulator in this
  // deployment" only because no map key named it.
  { id: 'qemu-system-aarch64', bin: 'qemu-system-aarch64', probe: ['-version'], group: 'emulate' },
  {
    // e2fsprogs' mke2fs, used with `-d` to populate a filesystem from a directory WITHOUT root — which is the
    // only reason the full-system rung can assemble its disk image inside an unprivileged container.
    id: 'mkfs.ext2',
    bin: 'mkfs.ext2',
    probe: ['-V'],
    group: 'emulate',
  },
  { id: 'renode', bin: 'renode', probe: ['--version'], group: 'emulate' },
  { id: 'chipsec', bin: 'chipsec_util', probe: ['--help'], group: 'analyze' },
  {
    id: 'angr',
    // angr is a Python library, not a command — the honest probe is "can this interpreter import it?", so the
    // reported bin is the interpreter and the version line is angr's own.
    bin: angrPython(),
    probe: ['-c', 'import angr; print("angr", angr.__version__)'],
    group: 'analyze',
    timeoutMs: 30000,
  },
  {
    // The rule engine for the embedded-Linux implant sweep. It is detected here; the RULES are not shipped with it
    // — `providers/yarascan.ts` reads the corpus from `FIRMLAB_YARA_RULES` and has an empty built-in on purpose,
    // so "yara is installed" and "this deployment can answer the question" are deliberately two different facts.
    id: 'yara',
    bin: 'yara',
    probe: ['--version'],
    group: 'analyze',
  },
  {
    // The hasher behind `providers/credmatch.ts`: `openssl passwd` reproduces a stored `$1$`/`$apr1$`/`$5$`/`$6$`
    // hash from a candidate plaintext and a salt. Presence here is deliberately NOT the same claim as "this
    // deployment can test every scheme" — `passwd` lost `-crypt` in OpenSSL 3.0, so which schemes a given build
    // actually computes is settled by a known-answer self-test in the provider, not by this probe.
    id: 'openssl',
    bin: 'openssl',
    probe: ['version'],
    group: 'secrets',
  },
  { id: 'gdb-multiarch', bin: 'gdb-multiarch', probe: ['--version'], group: 'emulate' },
  {
    id: 'fwhunt',
    // Like angr, a Python package rather than a command — probe by importing it, and report the interpreter.
    bin: fwhuntPython(),
    probe: ['-c', 'import fwhunt_scan, rzpipe; print("fwhunt-scan ok")'],
    group: 'analyze',
    timeoutMs: 15000,
  },
];

/** Every tool this build knows how to probe, in table order. Exported so a test can check nothing is unglossed. */
export const TOOL_IDS: readonly ToolId[] = TOOLS.map((t) => t.id);

export interface ToolStatus {
  id: ToolId;
  bin: string;
  available: boolean;
  version?: string;
  unlocks: string;
  group: ToolSpec['group'];
  /** Why the probe said no. Absent when the tool is available, or on a status built before this existed. */
  outcome?: ProbeOutcome;
  /** The localised sentence for `outcome`. Absent for the same reasons. */
  outcomeReason?: string;
  /**
   * The tool's DATA dependency, for the tools that have one. Absent means this tool needs no dataset — never
   * that its dataset is fine. Composed by the route, not by `probe`, for the reason `ToolDataset` gives.
   */
  dataset?: ToolDataset;
}

/**
 * Whether a tool that RUNS can actually answer, which is a second axis and not a worse value of `available`.
 *
 * grype is the case this exists for: `grype version` succeeds on a box with no vulnerability database, so the
 * probe reports `available: true` and the Capabilities table offers "CVE matching (N-day)" — a question the SBOM
 * lane is then going to refuse, by the policy in `providers/sbom-db.ts`. Measured on the deployed container on
 * 2026-09-19: 28 of 28 tools `available`, and `grype db status` reporting `database does not exist`.
 *
 * Folding this into `available: false` was the tempting fix and it is wrong twice over. It would claim the
 * deployment lacks grype, when grype is right there and every other grype-shaped question (`db status`, `db
 * import`) works; and it would send every provider gated on `isToolAvailable` to `blocked_by_platform`, which is
 * the "absent tool = absent answer" reading applied to a tool that is present. A missing dataset is a missing
 * ANSWER for one question, not a missing tool.
 *
 * It is deliberately NOT part of the probe cache. `detectTools` caches for the process lifetime because a binary
 * does not appear on PATH while the server runs — but a database very much does, since provisioning one is a
 * documented operator action, and a cached `ready: false` would keep denying it until someone restarted the API.
 */
export interface ToolDataset {
  /** Is the data this tool needs actually on disk? Read from the tool, never inferred from the binary. */
  ready: boolean;
  /** Localised: what is there and how old, or what is missing and how to supply it. */
  detail: string;
}

/**
 * How a probe failed, which is NOT one fact.
 *
 * `missing` is the deployment genuinely lacking a tool. `timeout` is a tool that is installed and did not answer
 * inside its probe budget — a JVM cold start, an `angr` import — and `error` is one that ran and refused. All three
 * used to collapse into `available: false`, which `/tools` aggregates into the capability counters and every
 * provider turns into `blocked_by_platform`: a slow tool was reported as a tool this deployment does not have.
 * That is the trap CLAUDE.md already names for the Ghidra and angr probes, made visible instead of guessed at.
 */
export type ProbeOutcome = 'missing' | 'timeout' | 'error';

/**
 * What a probe actually learned. No prose: this is what gets cached, and a cache holding a sentence in one language
 * would answer the second request in the wrong one.
 */
interface ProbeResult {
  id: ToolId;
  bin: string;
  available: boolean;
  version?: string;
  /** Present, but never asked which version — the binary was found on PATH and not executed. */
  presenceOnly?: boolean;
  group: ToolSpec['group'];
  /** Set only when `available` is false. No prose: the cache is language-neutral by design. */
  outcome?: ProbeOutcome;
}

/**
 * Classify what `execFile` threw. Pure and exported so a test reaches all three branches without a probe budget.
 *
 * Node reports a timeout by KILLING the child, so the error carries `killed: true` (and usually a signal) while
 * `code` is undefined; a missing binary is `ENOENT`; anything else — a non-zero exit above all — is a tool that
 * ran and refused. `unknown` in, never a throw out: a shape this does not recognise falls to `error`, which is the
 * conservative answer because it is the one that does not claim the tool is absent.
 */
export function classifyProbeFailure(err: unknown): ProbeOutcome {
  const e = err as { code?: unknown; killed?: unknown; signal?: unknown } | null | undefined;
  if (e?.code === 'ENOENT') return 'missing';
  if (e?.killed === true || (typeof e?.signal === 'string' && e.signal)) return 'timeout';
  return 'error';
}

let cache: ProbeResult[] | null = null;

async function probe(spec: ToolSpec): Promise<ProbeResult> {
  if (spec.detectByExistence) {
    const resolved = resolveOnPath(spec.bin);
    return {
      id: spec.id,
      bin: spec.bin,
      available: resolved !== null,
      ...(resolved ? { presenceOnly: true } : { outcome: 'missing' as const }),
      group: spec.group,
    };
  }
  try {
    const { stdout, stderr } = await execFileAsync(spec.bin, spec.probe, {
      timeout: spec.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS,
      env: { ...process.env, ...OFFLINE_ANCHORE_ENV },
    });
    const out = `${stdout}${stderr}`.split('\n')[0]?.trim().slice(0, 120) ?? '';
    return { id: spec.id, bin: spec.bin, available: true, version: out, group: spec.group };
  } catch (err) {
    return { id: spec.id, bin: spec.bin, available: false, outcome: classifyProbeFailure(err), group: spec.group };
  }
}

/**
 * Pure: dress a cached probe result in one language. Ids, binary names and the version line the tool printed are
 * identifiers and pass through untouched; only the gloss is localised.
 */
function describe(r: ProbeResult, locale: Locale): ToolStatus {
  const text = messages(locale).tools;
  return {
    id: r.id,
    bin: r.bin,
    available: r.available,
    ...(r.presenceOnly ? { version: text.installed } : r.version !== undefined ? { version: r.version } : {}),
    ...(r.outcome ? { outcome: r.outcome, outcomeReason: text.probeOutcome[r.outcome] } : {}),
    unlocks: text.unlocks[r.id],
    group: r.group,
  };
}

/**
 * Probe all tools once and cache the result for the process lifetime, then describe it in the requested language.
 * The locale defaults to English, so a caller that predates it — and a request with no `?lang` — is unaffected.
 */
export async function detectTools(force = false, locale: Locale = 'en'): Promise<ToolStatus[]> {
  if (!cache || force) cache = await Promise.all(TOOLS.map(probe));
  return cache.map((r) => describe(r, locale));
}

export async function isToolAvailable(id: ToolId): Promise<boolean> {
  const tools = await detectTools();
  return tools.find((t) => t.id === id)?.available ?? false;
}
