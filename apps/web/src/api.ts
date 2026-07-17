/**
 * Typed API client for the FirmLab backend. All calls are same-origin (dev proxies /api → :8799), so the
 * workbench never talks to a remote host.
 */
import type {
  EntropyProfile,
  FsNode,
  FsSummary,
  ImageIdentity,
  SignatureHit,
  StaticAnalysis,
  StringHit,
  StructureSegment,
} from '@firmlab/core';

export type {
  EntropyProfile,
  FsNode,
  FsSummary,
  ImageIdentity,
  SignatureHit,
  StaticAnalysis,
  StringHit,
  StructureSegment,
};

export interface ImageSummary {
  id: string;
  filename: string;
  size: number;
  sha256: string;
  uploadedAt: number;
  status: 'analyzing' | 'ready' | 'error';
  identity: ImageIdentity | null;
}

export interface ToolStatus {
  id: string;
  bin: string;
  available: boolean;
  version?: string;
  unlocks: string;
  group: 'extract' | 'analyze' | 'sbom' | 'emulate' | 'secrets';
}

export interface EmulationRecipe {
  id: string;
  mode: 'user-qemu' | 'system-qemu' | 'renode';
  title: string;
  description: string;
  requires: string[];
  runnable: boolean;
  command: string;
  rank: number;
  notes?: string;
}

export interface EmulationMenu {
  identity: ImageIdentity;
  rootfsReady: boolean;
  suggestedBinary: string | null;
  recipes: EmulationRecipe[];
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Negligible' | 'Unknown';

export interface SbomVuln {
  id: string;
  severity: Severity;
  packageName: string;
  packageVersion: string;
  fixedIn: string | null;
}

export interface SbomResult {
  available: boolean;
  reason?: string;
  target: string;
  packageCount: number;
  packages: { name: string; version: string; type: string }[];
  grypeAvailable: boolean;
  vulnerabilities: SbomVuln[];
  counts: Record<Severity, number>;
}

export interface DecompileResult {
  available: boolean;
  reason?: string;
  binary: string;
  info: {
    arch?: string;
    bits?: number;
    bintype?: string;
    os?: string;
    endian?: string;
    canary?: boolean;
    nx?: boolean;
    pic?: boolean;
  };
  functionCount: number;
  symbols: { name: string; type: string; addr: string }[];
  imports: { name: string; libname?: string }[];
  strings: { addr: string; value: string }[];
}

export interface GitleaksFinding {
  rule: string;
  description: string;
  file: string;
  line: number;
  match: string;
}

export interface GitleaksResult {
  available: boolean;
  reason?: string;
  target: string;
  findingCount: number;
  findings: GitleaksFinding[];
}

export interface IdentityChange {
  field: string;
  a: string;
  b: string;
}

export interface FirmwareDiffResult {
  a: { id: string; filename: string };
  b: { id: string; filename: string };
  identity: IdentityChange[];
  packages: {
    hasData: boolean;
    added: { name: string; version: string }[];
    removed: { name: string; version: string }[];
    changed: { name: string; a: string; b: string }[];
  };
  cves: {
    hasData: boolean;
    addedIds: string[];
    removedIds: string[];
    addedBySeverity: Record<Severity, number>;
  };
  files: {
    hasData: boolean;
    added: string[];
    removed: string[];
    changed: string[];
    counts: { added: number; removed: number; changed: number };
  };
}

export interface Job {
  id: string;
  imageId: string;
  kind: string;
  status: 'queued' | 'running' | 'done' | 'error';
  createdAt: number;
  updatedAt: number;
  params: unknown;
  log: string;
  result: unknown;
  error: string | null;
}

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}
async function post<T>(url: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method: 'POST' };
  if (body !== undefined) {
    init.headers = { 'content-type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(err.error ?? `${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export const api = {
  health: () => get<{ status: string; exposedToNetwork: boolean; trustedProxy?: boolean }>('/health'),
  listImages: () => get<{ images: ImageSummary[] }>('/api/images').then((r) => r.images),
  getImage: (id: string) => get<{ image: ImageSummary }>(`/api/images/${id}`).then((r) => r.image),
  deleteImage: (id: string) => fetch(`/api/images/${id}`, { method: 'DELETE' }).then(() => undefined),
  analysis: (id: string) => get<{ analysis: StaticAnalysis }>(`/api/images/${id}/analysis`).then((r) => r.analysis),
  entropy: (id: string) => get<{ size: number; entropy: EntropyProfile }>(`/api/images/${id}/entropy`),
  structure: (id: string) =>
    get<{ size: number; structure: StructureSegment[]; signatures: SignatureHit[] }>(`/api/images/${id}/structure`),
  secrets: (id: string) => get<{ secrets: StringHit[] }>(`/api/images/${id}/secrets`).then((r) => r.secrets),
  tools: () => get<{ tools: ToolStatus[]; groups: Record<string, { available: number; total: number }> }>('/api/tools'),
  emulation: (id: string) => get<EmulationMenu>(`/api/images/${id}/emulation`),
  emulate: (id: string, binary?: string) =>
    post<{ jobId: string }>(`/api/images/${id}/emulate`, binary ? { binary } : {}),
  extract: (id: string) => post<{ jobId: string }>(`/api/images/${id}/extract`),
  jobs: (id: string) => get<{ jobs: Job[] }>(`/api/images/${id}/jobs`).then((r) => r.jobs),
  job: (jobId: string) => get<{ job: Job }>(`/api/jobs/${jobId}`).then((r) => r.job),
  sbom: (id: string) => get<{ result: SbomResult | null }>(`/api/images/${id}/sbom`).then((r) => r.result),
  runSbom: (id: string) => post<{ jobId: string }>(`/api/images/${id}/sbom`),
  decompileResult: (id: string) =>
    get<{ result: DecompileResult | null }>(`/api/images/${id}/decompile`).then((r) => r.result),
  decompile: (id: string, binary: string) => post<{ jobId: string }>(`/api/images/${id}/decompile`, { binary }),
  gitleaks: (id: string) => get<{ result: GitleaksResult | null }>(`/api/images/${id}/gitleaks`).then((r) => r.result),
  runGitleaks: (id: string) => post<{ jobId: string }>(`/api/images/${id}/gitleaks`),
  diffResult: (id: string, against: string) =>
    get<{ result: FirmwareDiffResult | null }>(`/api/images/${id}/diff?against=${encodeURIComponent(against)}`).then(
      (r) => r.result,
    ),
  runDiff: (id: string, against: string) => post<{ jobId: string }>(`/api/images/${id}/diff`, { against }),

  async upload(file: File): Promise<ImageSummary> {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch('/api/images', { method: 'POST', body: form });
    if (!res.ok) {
      const err = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(err.error ?? `Upload failed: ${res.status}`);
    }
    return ((await res.json()) as { image: ImageSummary }).image;
  },
};

/** Shared signature-category → color map. Mirrors the CSS custom properties in theme.css. */
export const CATEGORY_COLORS: Record<string, string> = {
  filesystem: '#4db5ff',
  compression: '#f5b642',
  executable: '#7c5cff',
  bootloader: '#37d19a',
  kernel: '#ff9d5c',
  container: '#5cc8ff',
  crypto: '#ff5d6c',
  certificate: '#ff3b5b',
  image: '#b06cff',
  other: '#4a5468',
};

export function categoryColor(cat: string): string {
  return CATEGORY_COLORS[cat] ?? CATEGORY_COLORS.other ?? '#4a5468';
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function fmtHex(n: number): string {
  return `0x${n.toString(16)}`;
}
