/**
 * Thin HTTP client for the FirmLab API, used by the MCP server.
 *
 * The MCP surface deliberately talks to FirmLab over its own HTTP API rather than importing the providers
 * in-process. Two reasons, both load-bearing: the routes are where findings get synced under their idempotent
 * sources and where the honest guards live (rootfs required, target inside the rootfs, sink is a symbol name), so
 * importing the providers directly would mean reimplementing that and letting it drift; and the API process holds
 * the SQLite database open, so a second writer in another process is a lock conflict waiting to happen.
 *
 * It therefore works unchanged whether the agent runs the server inside the container (`docker exec -i`, the
 * default `127.0.0.1:8799`) or points it at another instance via `FIRMLAB_API`.
 */

export interface JobView {
  id: string;
  kind: string;
  status: 'queued' | 'running' | 'done' | 'error';
  log: string;
  result: unknown;
  error: string | null;
}

export class FirmLabClient {
  constructor(
    private readonly base: string,
    private readonly headers: Record<string, string> = {},
  ) {}

  private url(p: string): string {
    return `${this.base.replace(/\/+$/, '')}${p}`;
  }

  async get<T>(p: string): Promise<T> {
    const res = await fetch(this.url(p), { headers: this.headers });
    if (!res.ok) {
      // Same reasoning as `post` below: a refused GET carries the sentence naming what was refused and why, and
      // that sentence is the actionable part. The file browser's guard is the case that made this matter — "400
      // Bad Request" and "refused by the symlink rule: etc/passwd points at /dev/null, outside the extraction"
      // are the same status code and completely different answers.
      const detail = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(detail.error ?? `GET ${p} → ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as T;
  }

  /**
   * GET that hands back the parsed body WITH its status rather than throwing on a refusal.
   *
   * A refusal from the file routes is not a transport failure, it is an answer with structure — the rule that
   * refused, and the extraction verdict the caller still needs. Collapsing it into a thrown string loses both, so
   * the tools that need to render a refusal read it through here.
   */
  async getWithStatus<T>(p: string): Promise<{ ok: boolean; status: number; body: T }> {
    const res = await fetch(this.url(p), { headers: this.headers });
    const body = (await res.json().catch(() => ({}))) as T;
    return { ok: res.ok, status: res.status, body };
  }

  async post<T>(p: string, body?: unknown): Promise<T> {
    const res = await fetch(this.url(p), {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!res.ok) {
      // The routes answer a rejected request with a reason that names the mistake — surface it verbatim rather
      // than a bare status code, since that reason is usually the actionable part for the agent.
      const detail = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(detail.error ?? `POST ${p} → ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as T;
  }

  /** GET that yields null on a 404 rather than throwing — for optional reads like coverage. */
  async getOrNull<T>(p: string): Promise<T | null> {
    try {
      return await this.get<T>(p);
    } catch {
      return null;
    }
  }

  /**
   * Start a job and wait for it, bounded. MCP calls are request/response but FirmLab's heavy work is a job, so
   * this polls — and when the budget runs out it returns the UNFINISHED job rather than an error, so the agent
   * gets the job id and the log it has so far instead of losing the run it just started.
   */
  async runJob(startPath: string, body: unknown, timeoutMs: number, pollMs = 1500): Promise<JobView> {
    const { jobId } = await this.post<{ jobId: string }>(startPath, body);
    const deadline = Date.now() + timeoutMs;
    let job = await this.job(jobId);
    while (job.status !== 'done' && job.status !== 'error') {
      if (Date.now() >= deadline) return job;
      await new Promise((r) => setTimeout(r, pollMs));
      job = await this.job(jobId);
    }
    return job;
  }

  async job(jobId: string): Promise<JobView> {
    return (await this.get<{ job: JobView }>(`/api/jobs/${jobId}`)).job;
  }

  /** A raw text/markdown document (report, disclosure draft) rather than JSON. */
  async getText(p: string): Promise<string> {
    const res = await fetch(this.url(p), { headers: this.headers });
    if (!res.ok) throw new Error(`GET ${p} → ${res.status} ${res.statusText}`);
    return await res.text();
  }

  /**
   * Put a firmware image on the bench. The intake is multipart, so this builds the body from the file's bytes —
   * `FormData`/`Blob` are global on Node 22, so no multipart dependency is needed.
   */
  async upload(filename: string, bytes: Buffer): Promise<{ id: string; filename: string }> {
    const form = new FormData();
    form.append('file', new Blob([bytes]), filename);
    const res = await fetch(this.url('/api/images'), { method: 'POST', body: form, headers: this.headers });
    if (!res.ok) {
      const detail = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(detail.error ?? `upload → ${res.status} ${res.statusText}`);
    }
    return ((await res.json()) as { image: { id: string; filename: string } }).image;
  }
}

/**
 * Build the client from the environment. `FIRMLAB_MCP_HEADERS` carries a JSON object of extra headers for an
 * instance behind an auth proxy (the deployed FirmLab sits behind SSO); unset is the common in-container case.
 */
export function clientFromEnv(): FirmLabClient {
  const base = process.env.FIRMLAB_API?.trim() || 'http://127.0.0.1:8799';
  let headers: Record<string, string> = {};
  try {
    const raw = process.env.FIRMLAB_MCP_HEADERS?.trim();
    if (raw) headers = JSON.parse(raw) as Record<string, string>;
  } catch {
    // A malformed header blob must not silently become "no auth" on a gated instance — but it also must not stop
    // the server from starting, so it degrades to none and the first call fails loudly with the HTTP status.
  }
  return new FirmLabClient(base, headers);
}
