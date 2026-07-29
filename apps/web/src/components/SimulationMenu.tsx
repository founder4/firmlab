/**
 * Simulation menu — the emulation control surface. Shows the arch/class-aware ranked recipes (user-mode QEMU,
 * full-system QEMU, Renode), whether each is runnable in this deployment, and lets the user launch a user-mode
 * proof against the extracted rootfs, streaming the job log/result.
 *
 * Two sentences carry the panel and live in the `simulation` namespace so they survive translation. A rung that
 * cannot run says WHY — the badge is not enough, because a rung with no button reads as "not applicable to this
 * firmware", which is a different and false claim, so `simulation.requires` names the tools this deployment would
 * have to install. And `simulation.sandboxCaveat`: a rung that boots proves the emulator accepted the image and
 * proves nothing whatsoever about the board.
 *
 * The recipe's own title, description, command and notes are composed by the API when it plans the run, and the
 * modes (`user-qemu`, `system-qemu`, `renode`, `uefi-chipsec`), tool names, job ids and proof states are
 * identifiers. None of them is translated here.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  type BinaryEntry,
  type BootDiagnosis,
  type ChipsecResult,
  type EgressObservation,
  type EmulationMenu,
  type EmulationRecipe,
  type Job,
  type RenodeResult,
  api,
} from '../api';
import { useMessages } from '../i18n';
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
  const t = useMessages();
  const [menu, setMenu] = useState<EmulationMenu | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  /** The last finished full-system run, so its egress survives a page reload. */
  const [stored, setStored] = useState<StoredEmulationResult | null>(null);
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

  /**
   * The last full-system run's egress, read from the LEDGER on mount.
   *
   * Without this the observation would exist only in the browser tab that launched the boot and vanish on reload
   * — which is the defect this project already closed once for twenty per-kind routes, reappearing in a new
   * panel. The run ledger is where a finished job lives, so that is where this reads it from; a live run below
   * still takes precedence, because it is the newer of the two.
   */
  useEffect(() => {
    let cancelled = false;
    api
      .runs(imageId, { kind: 'emulate' })
      .then(async (ledger) => {
        const last = ledger.runs.find((r) => r.status === 'done');
        if (!last) return null;
        const detail = await api.runDetail(imageId, last.jobId);
        return (detail.result ?? null) as StoredEmulationResult | null;
      })
      .then((r) => {
        // `unreachable` on its own is kept: a boot on which nothing answered often addressed nothing either, so
        // gating this on `egress` discarded the diagnosis for exactly the runs whose emptiness needs explaining.
        if (!cancelled) setStored(r?.egress || r?.unreachable ? r : null);
      })
      .catch(() => {
        if (!cancelled) setStored(null);
      });
    return () => {
      cancelled = true;
    };
  }, [imageId]);

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

  if (!menu) return <div className="empty">{t.simulation.loading}</div>;

  const result = job?.result as
    | ({ command?: string; stdout?: string; stderr?: string; timedOut?: boolean } & StoredEmulationResult &
        Partial<RenodeResult> &
        Partial<ChipsecResult>)
    | null;
  // A live run wins over the stored one — it is the newer of the two — and the stored one is what a reader who
  // simply opened this page sees.
  const egressShown = result?.egress || result?.unreachable ? result : stored;
  const isRenode = Boolean(result && 'booted' in result);
  const isChipsec = Boolean(result && 'moduleCount' in result);

  return (
    <div>
      {!menu.rootfsReady && (
        <div
          className="banner banner-warn"
          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
        >
          <span>{t.simulation.needsRootfs}</span>
          <button className="btn btn-sm" disabled={busy} onClick={extractFirst}>
            {t.simulation.extractNow}
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
                {r.runnable ? t.simulation.runnable : t.simulation.needsTools}
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
            {/* A rung with no button must not read as "not applicable to this firmware". The tool names are what
                would make it runnable, so they are named rather than left to the badge. */}
            {!r.runnable && r.requires.length > 0 && (
              <div className="hint" style={{ marginTop: 8 }}>
                {t.simulation.requires(r.requires.join(', '))}
              </div>
            )}
            {r.runnable && (
              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                {NEEDS_BINARY.has(r.mode) &&
                  (binaries.length > 0 ? (
                    <select
                      className="select mono"
                      aria-label={t.simulation.targetBinary}
                      value={binary}
                      onChange={(e) => setBinary(e.target.value)}
                      style={{ flex: 1, fontSize: 12 }}
                    >
                      <option value="">
                        {menu.suggestedBinary
                          ? t.simulation.suggested(menu.suggestedBinary)
                          : t.simulation.selectBinary}
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
                      placeholder={menu.suggestedBinary ?? t.simulation.binaryPlaceholder}
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
                    t.simulation.bootRenode
                  ) : r.mode === 'uefi-chipsec' ? (
                    t.simulation.decodeScan
                  ) : (
                    t.simulation.runProof
                  )}
                </button>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* The ceiling of everything above, stated where the buttons are rather than only in a finding's proof state. */}
      <div className="hint" style={{ marginTop: 12 }}>
        {t.simulation.sandboxCaveat}
      </div>

      {error && (
        <div className="banner banner-warn" style={{ marginTop: 16 }}>
          {error}
        </div>
      )}

      {job && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-title">
            {t.simulation.job(job.id)}{' '}
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
                  {result.booted ? t.simulation.booted : t.simulation.noUart}
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
                  {result.moduleCount ? t.simulation.moduleCount(result.moduleCount) : t.simulation.noUefiVolume}
                </span>
                {Boolean(result.volumes) && (
                  <span className="badge">{t.simulation.volumeCount(result.volumes ?? 0)}</span>
                )}
                <span className="badge">{result.proofState}</span>
              </div>
              <div className="hint" style={{ marginTop: 6 }}>
                {result.reason}
              </div>
              {result.byType && Object.keys(result.byType).length > 0 && (
                <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 6 }}>
                  {Object.entries(result.byType)
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, n]) => `${type}: ${n}`)
                    .join('  ·  ')}
                </div>
              )}
              {result.secureBoot && (
                <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                  <span className="hint" style={{ fontSize: 11 }}>
                    {t.simulation.secureBoot}
                  </span>
                  <span
                    className={`badge ${result.secureBoot.secureBoot === 'enabled' ? 'badge-ok' : result.secureBoot.secureBoot === 'disabled' ? 'badge-high' : ''}`}
                  >
                    {result.secureBoot.secureBoot}
                  </span>
                  {result.secureBoot.setupMode !== 'unknown' && (
                    <span className={`badge ${result.secureBoot.setupMode === 'setup' ? 'badge-high' : ''}`}>
                      {t.simulation.setupMode(result.secureBoot.setupMode)}
                    </span>
                  )}
                  {result.secureBoot.testKey && (
                    <span className="badge badge-high">{t.simulation.testKey(result.secureBoot.testKey)}</span>
                  )}
                  <span className="hint mono" style={{ fontSize: 10.5 }}>
                    {t.simulation.nvramVars(result.secureBoot.variableCount)}
                  </span>
                </div>
              )}
              {/* The provider's own sentence, beside the badge rather than buried in `reason` above: `unknown` is
                  the state this decode could not read, and next to a badge that says nothing else it reads as a
                  measurement. Composed by `interpretSecureBoot`, printed as written. */}
              {result.secureBoot?.note && (
                <div className="hint" style={{ marginTop: 4 }}>
                  {result.secureBoot.note}
                </div>
              )}
              {/* And when there is no posture at all. Three different situations reached this spot as the same
                  blank space, which reads as "this image has no variable store" — the one thing none of them says. */}
              {!result.secureBoot && result.nvramStoreNote && (
                <div style={{ marginTop: 8 }}>
                  <div className="hint" style={{ fontSize: 11 }}>
                    {t.simulation.secureBoot}
                  </div>
                  <div className="hint" style={{ marginTop: 2 }}>
                    {result.nvramStoreNote}
                  </div>
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
                        {/* The finding's own words, as the provider recorded them — never re-worded here. */}
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
          {/* Above the raw console on purpose: this is the one part of a full-system run that says something
              about the FIRMWARE's intent rather than about the emulator, and it must not be buried under 4 KB
              of boot log. Rendered from the stored result, so an older run simply has none and shows nothing. */}
          {result?.command && !isRenode && !isChipsec && (
            <>
              {result.timedOut && <div className="badge badge-medium">{t.simulation.timedOut}</div>}
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

      {/* Its own panel, OUTSIDE the running-job block: the observation is a property of the image, and a reader
          who simply opened this page has to see it without having launched the boot themselves. `egressShown`
          prefers a live run over the stored one. */}
      {(egressShown?.egress || egressShown?.unreachable) && (
        <div className="panel" style={{ marginTop: 16 }}>
          {/* Above the egress, because "nothing answered, and here is why" is the first thing a reader of an
              empty result needs — and the sentence names what to go and fix. */}
          {egressShown.unreachable && (
            <div style={{ marginBottom: egressShown.egress ? 14 : 0 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <strong style={{ fontSize: 13 }}>{t.simulation.unreachableTitle}</strong>
                <span className="badge badge-medium mono" style={{ fontSize: 10 }}>
                  {egressShown.unreachable.cause}
                </span>
              </div>
              <div className="hint" style={{ marginTop: 6 }}>
                {egressShown.unreachable.summary}
              </div>
              {egressShown.unreachable.evidence.length > 0 && (
                <div className="hint mono" style={{ marginTop: 4, fontSize: 11.5 }}>
                  {egressShown.unreachable.evidence.join(' · ')}
                </div>
              )}
              {/* The daemons themselves. The summary above leads with ONE — the most informative death — and
                  says how many others there were; this is where the others actually are. "never started" and
                  "started and took SIGSEGV" are the two facts the whole module exists to separate, so a daemon
                  that started and did NOT exit is listed too, as the running one it is. */}
              <DaemonList diagnosis={egressShown.unreachable} />
            </div>
          )}
          {egressShown.egress && <EgressPanel egress={egressShown.egress} isolated={egressShown.isolated === true} />}
        </div>
      )}

      <WebProbePanel imageId={imageId} />
    </div>
  );
}

/**
 * Which network daemons the boot trace saw, and what became of each.
 *
 * `boot-diagnose` collects both lists and the panel read neither, so a boot on which two daemons died reported
 * one of them and a boot on which one started and survived looked, in this panel, exactly like a boot on which
 * none ever did. The exit code is printed beside the signal name because 139 means nothing on its own and
 * SIGSEGV means everything.
 */
function DaemonList({ diagnosis }: { diagnosis: BootDiagnosis }): JSX.Element | null {
  const t = useMessages();
  const d = t.simulation.daemons;
  const exitedNames = new Set(diagnosis.daemonsExited.map((x) => x.binary));
  const stillRunning = diagnosis.daemonsStarted.filter((n) => !exitedNames.has(n));
  if (diagnosis.daemonsStarted.length === 0) {
    // Not the same as "they all died": nothing that looks like a network daemon was ever executed.
    return (
      <div className="hint" style={{ marginTop: 6 }}>
        {d.noneStarted}
      </div>
    );
  }
  return (
    <div style={{ marginTop: 8 }}>
      <div className="eyebrow" style={{ marginBottom: 4 }}>
        {d.heading}
      </div>
      {diagnosis.daemonsExited.map((x) => (
        <div key={`${x.binary}-${x.pid}`} style={{ fontSize: 12.5, marginBottom: 2 }}>
          <span className="mono">{x.binary}</span>{' '}
          <span className="badge badge-crit" title={d.exitedTitle}>
            {x.signal === null ? d.exited(x.code) : d.crashed(SIGNAL_NAME[x.signal] ?? `signal ${x.signal}`, x.code)}
          </span>{' '}
          {x.lastOpen && (
            <span className="hint mono" style={{ fontSize: 11.5 }}>
              {d.lastOpen} {x.lastOpen}
            </span>
          )}
        </div>
      ))}
      {stillRunning.map((n) => (
        <div key={n} style={{ fontSize: 12.5, marginBottom: 2 }}>
          <span className="mono">{n}</span>{' '}
          <span className="badge badge-ok" title={d.runningTitle}>
            {d.running}
          </span>
        </div>
      ))}
    </div>
  );
}

/**
 * How many destination rows the panel prints. The parser keeps up to 200; printing all of them made one boot's
 * page 8582 px tall. Sorted by frame count upstream, so this cuts the least-addressed and says so — a cut by
 * arrival order would make the visible SET an artifact of capture order.
 */
const MAX_ROWS = 40;

/** Signal numbers the firmadyne trace produces, named. The NUMBER stays beside the name — it is what was traced. */
const SIGNAL_NAME: Record<number, string> = { 4: 'SIGILL', 6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE', 11: 'SIGSEGV' };

/**
 * The half of a full-system result this panel reads. Every field optional and permanently so: a run stored
 * before the observation existed carries none of them, and a required field would make this type assert
 * something about a persisted row it cannot know.
 */
interface StoredEmulationResult {
  egress?: EgressObservation;
  isolated?: boolean;
  unreachable?: BootDiagnosis;
}

/**
 * What the booted firmware ADDRESSED, and whether this run let it get there.
 *
 * Two things it refuses to say. It never reports a destination as *contacted*: under isolation nothing was
 * reached by construction, and without isolation a SYN into a black hole is indistinguishable from a completed
 * handshake on the sending side. And the addresses, ports and hostnames render exactly as they were on the wire —
 * they are measurements, not chrome, and the only translated words here are the ones around them.
 *
 * The `outbound open` state is styled as a warning rather than as a neutral fact, because it is the state in
 * which a firmware under analysis could reach the internet from the operator's machine.
 */
function EgressPanel({ egress, isolated }: { egress: EgressObservation; isolated: boolean }): JSX.Element {
  const t = useMessages();
  const s = t.simulation;
  const external = egress.attempts.filter((a) => a.scope === 'external');
  const other = egress.attempts.filter((a) => a.scope !== 'external');

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <strong style={{ fontSize: 13 }}>{s.egressTitle}</strong>
        <span className={`badge ${isolated ? 'badge-ok' : 'badge-high'}`}>
          {isolated ? s.egressBlocked : s.egressOpen}
        </span>
      </div>
      {/* Both standing sentences point at a list — "nothing below was reached", "could reach these" — so a boot
          that addressed nothing outside the emulator printed a promise of destinations above empty space, and
          the isolated one claimed "this is what the firmware asked for" about a firmware that asked for nothing.
          Switched on the EXTERNAL count, not on the whole list: a row for the sandbox's own resolver is not
          something the firmware could reach "from this machine" either. */}
      <div className="hint" style={{ marginTop: 6 }}>
        {external.length === 0
          ? isolated
            ? s.egressIsolatedEmpty
            : s.egressOpenEmpty
          : isolated
            ? s.egressIsolatedNote
            : s.egressOpenWarning}
      </div>
      {/* The bound on the whole list, and it is a measured one — see the locale comment. */}
      <div className="hint" style={{ marginTop: 4 }}>
        {s.egressOneBoot}
      </div>

      {egress.problem && (
        <div className="hint" style={{ marginTop: 6 }}>
          {egress.problem}
        </div>
      )}

      {egress.dnsQueries.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div className="eyebrow" style={{ marginBottom: 4 }}>
            {s.egressNames}
          </div>
          {egress.dnsQueries.map((q) => (
            <div key={`${q.name}@${q.server}`} style={{ fontSize: 12.5, marginBottom: 2 }}>
              <span className="mono">{q.name}</span>{' '}
              <span className="hint">
                — {s.egressAskedOf(q.server)} · {s.egressFrames(q.frames)}
              </span>
            </div>
          ))}
        </div>
      )}
      {egress.dnsTruncated > 0 && (
        <div className="hint" style={{ marginTop: 6 }}>
          {s.egressTruncatedNames(egress.dnsTruncated)}
        </div>
      )}
      {(egress.queriesDropped ?? 0) > 0 && (
        <div className="hint" style={{ marginTop: 4 }}>
          {s.egressQueriesDropped(egress.queriesDropped ?? 0)}
        </div>
      )}

      {external.length + other.length === 0 ? (
        <div className="hint" style={{ marginTop: 10 }}>
          {s.egressNone}
        </div>
      ) : (
        <div style={{ marginTop: 10 }}>
          <div className="eyebrow" style={{ marginBottom: 4 }}>
            {s.egressDestinations}
          </div>
          {/* External first and always shown; the rest follow, because a firmware asking the emulator's own
              resolver is context for the list above rather than noise to hide. Bounded on screen — the parser's
              cap is 200 and one boot printed 150 rows, which made the page eight thousand pixels tall and buried
              the two that mattered. The cut is by frame count, never by arrival, and it says what it cut. */}
          {[...external, ...other].slice(0, MAX_ROWS).map((a) => (
            <div
              key={`${a.protocol}-${a.address}-${a.port ?? ''}`}
              style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 12.5, marginBottom: 2 }}
            >
              <span className="mono" style={{ minWidth: 0 }}>
                {a.address}
                {a.port === undefined ? '' : `:${a.port}`}
              </span>
              <span className="badge" style={{ fontSize: 10 }}>
                {a.protocol}
              </span>
              <span className={a.scope === 'external' ? '' : 'hint'} style={{ fontSize: 11.5 }}>
                {s.egressScope[a.scope]}
              </span>
              <span className="hint" style={{ fontSize: 11.5 }}>
                {s.egressFrames(a.frames)}
              </span>
            </div>
          ))}
          {external.length + other.length > MAX_ROWS && (
            <div className="hint" style={{ marginTop: 4 }}>
              {s.egressMore(MAX_ROWS, external.length + other.length)}
            </div>
          )}
          {(egress.attemptsDropped ?? 0) > 0 && (
            <div className="hint" style={{ marginTop: 4 }}>
              {s.egressDropped(egress.attemptsDropped ?? 0)}
            </div>
          )}
        </div>
      )}
      {/* Under the list on purpose: it is the sentence that stops a reader counting the bench's own probes as
          the firmware's intent, and it belongs where those rows used to be. */}
      {(egress.answeredFrames ?? 0) > 0 && (
        <div className="hint" style={{ marginTop: 8 }}>
          {s.egressAnswered(egress.answeredFrames ?? 0)}
        </div>
      )}
      {(egress.undecidedFrames ?? 0) > 0 && (
        <div className="hint" style={{ marginTop: 4 }}>
          {s.egressUndecided(egress.undecidedFrames ?? 0)}
        </div>
      )}
    </div>
  );
}
