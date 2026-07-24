/**
 * Simulation menu — the emulation control surface. Shows the arch/class-aware ranked recipes (user-mode QEMU,
 * full-system QEMU, Renode), whether each is runnable in this deployment, and lets the user launch a user-mode
 * proof against the extracted rootfs, streaming the job log/result.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  type BinaryEntry,
  type ChipsecResult,
  type EmulationMenu,
  type EmulationRecipe,
  type Job,
  type RenodeResult,
  api,
} from '../api';
import { WebProbePanel } from './WebProbePanel';

const MODE_ICON: Record<string, string> = {
  'user-qemu': '▶',
  'chroot-qemu': '🧩',
  'system-qemu': '🖥',
  renode: '🔬',
  'uefi-chipsec': '🛡',
};

/** Recipes that take a rootfs binary argument (the others boot the whole image). */
const NEEDS_BINARY = new Set(['user-qemu', 'chroot-qemu']);

export function SimulationMenu({ imageId }: { imageId: string }): JSX.Element {
  const [menu, setMenu] = useState<EmulationMenu | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [binary, setBinary] = useState('');
  const [binaries, setBinaries] = useState<BinaryEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const poll = useRef<number | null>(null);

  // Continuity: the binaries discovered by Extraction feed the emulator's target selector — no retyping paths.
  useEffect(() => {
    api
      .binaries(imageId)
      .then(setBinaries)
      .catch(() => setBinaries([]));
  }, [imageId]);

  const load = useCallback(() => {
    api
      .emulation(imageId)
      .then(setMenu)
      .catch(() => setMenu(null));
  }, [imageId]);
  useEffect(load, [load]);

  useEffect(
    () => () => {
      if (poll.current) window.clearInterval(poll.current);
    },
    [],
  );

  const pollJob = useCallback((jobId: string, after?: () => void) => {
    poll.current = window.setInterval(async () => {
      const j = await api.job(jobId);
      setJob(j);
      if (j.status === 'done' || j.status === 'error') {
        if (poll.current) window.clearInterval(poll.current);
        setBusy(false);
        after?.();
      }
    }, 700);
  }, []);

  // Launch the deterministic mechanics for a recipe: user-mode qemu, chroot service, full-system boot, or a
  // real Renode RTOS boot — each through its own job endpoint, then stream the result.
  const runRecipe = useCallback(
    async (recipe: EmulationRecipe) => {
      setBusy(true);
      setError(null);
      setJob(null);
      try {
        let jobId: string;
        if (recipe.mode === 'user-qemu') ({ jobId } = await api.emulate(imageId, binary || undefined));
        else if (recipe.mode === 'chroot-qemu')
          ({ jobId } = await api.emulateSystem(imageId, 'chroot-service', binary || undefined));
        else if (recipe.mode === 'system-qemu') ({ jobId } = await api.emulateSystem(imageId, 'full-system'));
        else if (recipe.mode === 'uefi-chipsec') ({ jobId } = await api.runChipsec(imageId));
        else ({ jobId } = await api.runRenode(imageId));
        pollJob(jobId);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setBusy(false);
      }
    },
    [imageId, binary, pollJob],
  );

  const extractFirst = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const { jobId } = await api.extract(imageId);
      pollJob(jobId, load);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, load, pollJob]);

  if (!menu) return <div className="empty">Loading emulation plan…</div>;

  const result = job?.result as
    | ({ command?: string; stdout?: string; stderr?: string; timedOut?: boolean } & Partial<RenodeResult> &
        Partial<ChipsecResult>)
    | null;
  const isRenode = Boolean(result && 'booted' in result);
  const isChipsec = Boolean(result && 'moduleCount' in result);

  return (
    <div>
      {!menu.rootfsReady && (
        <div
          className="banner banner-warn"
          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
        >
          <span>User-mode emulation needs an extracted rootfs. Run extraction first (requires binwalk).</span>
          <button className="btn btn-sm" disabled={busy} onClick={extractFirst}>
            Extract now
          </button>
        </div>
      )}

      <div className="grid grid-2">
        {menu.recipes.map((r) => (
          <div
            key={r.id}
            className="panel"
            style={{ margin: 0, borderColor: r.runnable ? 'var(--border)' : 'var(--border-soft)' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <span style={{ fontSize: 16 }}>{MODE_ICON[r.mode]}</span>
              <strong style={{ fontSize: 13 }}>{r.title}</strong>
              <span style={{ marginLeft: 'auto' }} className={`badge ${r.runnable ? 'badge-ok' : ''}`}>
                {r.runnable ? 'runnable' : 'needs tools'}
              </span>
            </div>
            <div className="hint" style={{ marginBottom: 10 }}>
              {r.description}
            </div>
            <div
              className="mono"
              style={{
                fontSize: 11.5,
                background: 'var(--bg)',
                border: '1px solid var(--border-soft)',
                borderRadius: 6,
                padding: '8px 10px',
                color: 'var(--text-dim)',
                overflowX: 'auto',
                whiteSpace: 'nowrap',
              }}
            >
              $ {r.command}
            </div>
            {r.notes && (
              <div className="hint" style={{ marginTop: 8 }}>
                ℹ {r.notes}
              </div>
            )}
            {r.runnable && (
              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                {NEEDS_BINARY.has(r.mode) &&
                  (binaries.length > 0 ? (
                    <select
                      className="select mono"
                      aria-label="Target binary"
                      value={binary}
                      onChange={(e) => setBinary(e.target.value)}
                      style={{ flex: 1, fontSize: 12 }}
                    >
                      <option value="">
                        {menu.suggestedBinary ? `suggested: ${menu.suggestedBinary}` : 'Select a binary…'}
                      </option>
                      {binaries.map((b) => (
                        <option key={b.path} value={b.path}>
                          {b.path}
                          {b.arch ? ` · ${b.arch}` : ''}
                          {b.networkFacing ? ' · net' : ''}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      className="input mono"
                      placeholder={menu.suggestedBinary ?? 'run Extraction to list binaries'}
                      value={binary}
                      onChange={(e) => setBinary(e.target.value)}
                      style={{ flex: 1, fontSize: 12 }}
                    />
                  ))}
                <button
                  className="btn btn-primary btn-sm"
                  disabled={busy}
                  onClick={() => runRecipe(r)}
                  style={NEEDS_BINARY.has(r.mode) ? undefined : { marginLeft: 'auto' }}
                >
                  {busy ? (
                    <span className="spinner" />
                  ) : r.mode === 'renode' ? (
                    'Boot under Renode'
                  ) : r.mode === 'uefi-chipsec' ? (
                    'Decode & scan'
                  ) : (
                    'Run proof'
                  )}
                </button>
              </div>
            )}
          </div>
        ))}
      </div>

      {error && (
        <div className="banner banner-warn" style={{ marginTop: 16 }}>
          {error}
        </div>
      )}

      {job && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-title">
            Job {job.id}{' '}
            <span
              className={`badge ${job.status === 'done' ? 'badge-ok' : job.status === 'error' ? 'badge-high' : ''}`}
            >
              {job.status}
            </span>
          </div>
          {job.log && (
            <pre
              className="mono"
              style={{ fontSize: 11.5, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', margin: '8px 0' }}
            >
              {job.log}
            </pre>
          )}
          {isRenode && result && (
            <div style={{ marginTop: 8 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <span className={`badge ${result.booted ? 'badge-ok' : 'badge-medium'}`}>
                  {result.booted ? 'booted' : 'no UART output'}
                </span>
                <span className="badge">{result.proofState}</span>
                {result.platform && (
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                    {result.platform.split('/').pop()}
                  </span>
                )}
              </div>
              <div className="hint" style={{ marginTop: 6 }}>
                {result.reason}
              </div>
              {result.uartExcerpt && (
                <pre
                  className="mono"
                  style={{
                    fontSize: 11.5,
                    whiteSpace: 'pre-wrap',
                    background: 'var(--bg)',
                    padding: 10,
                    borderRadius: 6,
                    marginTop: 8,
                  }}
                >
                  {result.uartExcerpt}
                </pre>
              )}
            </div>
          )}
          {isChipsec && result && (
            <div style={{ marginTop: 8 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <span className={`badge ${result.moduleCount ? 'badge-ok' : 'badge-medium'}`}>
                  {result.moduleCount ? `${result.moduleCount} modules` : 'no UEFI volume'}
                </span>
                {Boolean(result.volumes) && <span className="badge">{result.volumes} FV</span>}
                <span className="badge">{result.proofState}</span>
              </div>
              <div className="hint" style={{ marginTop: 6 }}>
                {result.reason}
              </div>
              {result.byType && Object.keys(result.byType).length > 0 && (
                <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 6 }}>
                  {Object.entries(result.byType)
                    .sort((a, b) => b[1] - a[1])
                    .map(([t, n]) => `${t}: ${n}`)
                    .join('  ·  ')}
                </div>
              )}
              {result.secureBoot && (
                <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                  <span className="hint" style={{ fontSize: 11 }}>
                    Secure Boot:
                  </span>
                  <span
                    className={`badge ${result.secureBoot.secureBoot === 'enabled' ? 'badge-ok' : result.secureBoot.secureBoot === 'disabled' ? 'badge-high' : ''}`}
                  >
                    {result.secureBoot.secureBoot}
                  </span>
                  {result.secureBoot.setupMode !== 'unknown' && (
                    <span className={`badge ${result.secureBoot.setupMode === 'setup' ? 'badge-high' : ''}`}>
                      {result.secureBoot.setupMode} mode
                    </span>
                  )}
                  {result.secureBoot.testKey && (
                    <span className="badge badge-high">test key: {result.secureBoot.testKey}</span>
                  )}
                  <span className="hint mono" style={{ fontSize: 10.5 }}>
                    {result.secureBoot.variableCount} NVRAM var(s)
                  </span>
                </div>
              )}
              {result.findings && result.findings.length > 0 && (
                <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {result.findings.map((f) => (
                    <div
                      key={f.kind + f.title}
                      style={{
                        display: 'flex',
                        gap: 8,
                        alignItems: 'baseline',
                        background: 'var(--bg)',
                        border: '1px solid var(--border-soft)',
                        borderRadius: 6,
                        padding: '6px 10px',
                      }}
                    >
                      <span
                        className={`badge ${f.severity === 'critical' || f.severity === 'high' ? 'badge-high' : ''}`}
                      >
                        {f.severity}
                      </span>
                      <div>
                        <div style={{ fontSize: 12.5 }}>{f.title}</div>
                        <div className="hint" style={{ marginTop: 2 }}>
                          {f.rationale}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
          {result?.command && !isRenode && !isChipsec && (
            <>
              {result.timedOut && <div className="badge badge-medium">timed out (likely a long-running daemon)</div>}
              {result.stdout && (
                <pre
                  className="mono"
                  style={{
                    fontSize: 11.5,
                    whiteSpace: 'pre-wrap',
                    background: 'var(--bg)',
                    padding: 10,
                    borderRadius: 6,
                    marginTop: 8,
                  }}
                >
                  {result.stdout.slice(0, 4000)}
                </pre>
              )}
              {result.stderr && (
                <pre
                  className="mono"
                  style={{ fontSize: 11.5, whiteSpace: 'pre-wrap', color: 'var(--warn)', marginTop: 8 }}
                >
                  {result.stderr.slice(0, 2000)}
                </pre>
              )}
            </>
          )}
        </div>
      )}

      <WebProbePanel imageId={imageId} />
    </div>
  );
}
