import { Fragment, useCallback, useEffect, useRef, useState } from 'react';
import {
  type CapturabilityPlan,
  type CaptureBackend,
  type CaptureDevice,
  type CaptureFlow,
  type CaptureSession,
  type CaptureStatus,
  type LearningSurface,
  api,
} from '../api';

function ceilingClass(c: string | null | undefined): string {
  if (c === 'captured_plaintext' || c === 'captured_encrypted') return 'badge-ok';
  if (c === 'blocked_by_pinning' || c === 'blocked_needs_hardware') return 'badge-high';
  return 'badge-medium';
}

/** The capturability ladder for a target: the honest ceiling, the ranked strategies, and what would unlock more. */
function PreflightCard({ plan }: { plan: CapturabilityPlan }): JSX.Element {
  return (
    <div style={{ padding: '4px 2px' }}>
      <div style={{ marginBottom: 6 }}>
        Ceiling: <span className={`badge ${ceilingClass(plan.ceiling)} mono`}>{plan.ceiling}</span>{' '}
        <span className="hint">{plan.reason}</span>
      </div>
      <table className="data">
        <tbody>
          {plan.strategies.map((s) => (
            <tr key={s.transport}>
              <td style={{ width: 24 }}>
                <span className={`badge ${s.viable ? 'badge-ok' : ''}`}>{s.viable ? '●' : '○'}</span>
              </td>
              <td className="mono" style={{ width: 110 }}>
                {s.transport}
                {s.positioning ? ` · ${s.positioning}` : ''}
              </td>
              <td className="hint">{s.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {plan.unlockHint && (
        <div className="hint" style={{ marginTop: 6 }}>
          ↑ {plan.unlockHint}
          {/pin|frida/i.test(plan.unlockHint) && (
            <>
              {' '}
              <a href="/api/capture/frida-unpin">download Frida unpin →</a>
            </>
          )}
        </div>
      )}
    </div>
  );
}

const ROLE_LABEL: Record<string, string> = {
  positioning: 'Positioning',
  interception: 'Interception',
  radio: 'Radio',
  physical: 'Physical',
};

function confidenceClass(c: string | null): string {
  if (c === 'high') return 'badge-ok';
  if (c === 'medium') return 'badge-medium';
  return 'badge';
}

function fmtWhen(ms: number): string {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

/**
 * The Capture section (Phase 6.0–6.3). Shows what this deployment could capture (auto-detected backends + the
 * honest transport ceiling), runs a passive LAN discovery sweep to build the device inventory (the radar), gives a
 * per-target capturability preflight (the ranked strategy ladder + the honest acquisition ceiling + a Frida unpin
 * download when pinned), and arms an on-path proxy to intercept a target's OTA — scoring the flows for firmware and
 * ingesting a carved blob into the workbench. Gated by FIRMLAB_CAPTURE + a per-action operator acknowledgement.
 */
export function Capture(): JSX.Element {
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [backends, setBackends] = useState<CaptureBackend[]>([]);
  const [transports, setTransports] = useState<string[]>([]);
  const [devices, setDevices] = useState<CaptureDevice[]>([]);
  const [ack, setAck] = useState(false);
  const [subnet, setSubnet] = useState('');
  const [scanning, setScanning] = useState(false);
  const [session, setSession] = useState<CaptureSession | null>(null);
  const [scanned, setScanned] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  // 6.1 interception session state.
  const [capSession, setCapSession] = useState<CaptureSession | null>(null);
  const [capFlows, setCapFlows] = useState<CaptureFlow[]>([]);
  const [capReason, setCapReason] = useState<string | null>(null);
  const [capCeiling, setCapCeiling] = useState<string | null>(null);
  const [ingested, setIngested] = useState<Record<string, string>>({});
  const capPollRef = useRef<number | null>(null);

  // 6.3 capturability preflight, per device.
  const [preflight, setPreflight] = useState<Record<string, CapturabilityPlan>>({});

  // 6.6 learning surface (OTA timeline + per-vendor priors + CDN graph).
  const [learning, setLearning] = useState<LearningSurface | null>(null);

  const runPreflight = useCallback(async (deviceId: string) => {
    const plan = await api.capturePreflight(deviceId).catch(() => null);
    if (plan) setPreflight((m) => ({ ...m, [deviceId]: plan }));
  }, []);

  useEffect(() => {
    api
      .captureStatus()
      .then(setStatus)
      .catch(() => setStatus({ enabled: false }));
    api
      .captureBackends()
      .then((v) => {
        setBackends(v.backends);
        setTransports(v.transports);
      })
      .catch(() => undefined);
    api
      .captureDevices()
      .then(setDevices)
      .catch(() => setDevices([]));
    api
      .captureFamilies()
      .then(setLearning)
      .catch(() => setLearning(null));
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
      if (capPollRef.current) window.clearInterval(capPollRef.current);
    };
  }, []);

  const armCapture = useCallback(
    async (device: CaptureDevice) => {
      setCapReason(null);
      setCapFlows([]);
      setIngested({});
      try {
        const r = await api.startCaptureSession(device.id, ack);
        setCapReason(r.reason);
        if (capPollRef.current) window.clearInterval(capPollRef.current);
        capPollRef.current = window.setInterval(async () => {
          const v = await api.captureSession(r.sessionId).catch(() => null);
          if (!v) return;
          setCapSession(v.session);
          setCapFlows(v.flows);
          setCapCeiling(v.ceiling);
          if (v.session.status === 'ingested' || v.session.status === 'torn_down' || v.session.status === 'error') {
            if (capPollRef.current) window.clearInterval(capPollRef.current);
          }
        }, 1000);
        const v = await api.captureSession(r.sessionId).catch(() => null);
        if (v) {
          setCapSession(v.session);
          setCapFlows(v.flows);
          setCapCeiling(v.ceiling);
        }
      } catch (e) {
        setCapReason(e instanceof Error ? e.message : String(e));
      }
    },
    [ack],
  );

  const ingest = useCallback(
    async (flowId: string) => {
      if (!capSession) return;
      try {
        const r = await api.ingestCaptureFlow(capSession.id, flowId);
        setIngested((m) => ({ ...m, [flowId]: r.imageId }));
        const v = await api.captureSession(capSession.id).catch(() => null);
        if (v) setCapSession(v.session);
      } catch (e) {
        setCapReason(e instanceof Error ? e.message : String(e));
      }
    },
    [capSession],
  );

  const stopCapture = useCallback(async () => {
    if (!capSession) return;
    if (capPollRef.current) window.clearInterval(capPollRef.current);
    await api.teardownCapture(capSession.id).catch(() => undefined);
    const v = await api.captureSession(capSession.id).catch(() => null);
    if (v) setCapSession(v.session);
  }, [capSession]);

  const runScan = useCallback(async () => {
    setErr(null);
    setScanning(true);
    try {
      const { scanId } = await api.runCaptureDiscover(subnet.trim() || null, ack);
      pollRef.current = window.setInterval(async () => {
        const v = await api.captureScan(scanId).catch(() => null);
        if (!v) return;
        setSession(v.session);
        setDevices(v.devices);
        if (v.session.status === 'done' || v.session.status === 'error') {
          if (pollRef.current) window.clearInterval(pollRef.current);
          setScanning(false);
          setScanned(true);
          if (v.session.status === 'error') setErr(v.session.error ?? 'Discovery failed');
        }
      }, 900);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setScanning(false);
    }
  }, [subnet, ack]);

  const enabled = status?.enabled === true;

  return (
    <div>
      {enabled ? (
        <div className="banner banner-info">
          The <strong>capture lane</strong> acquires firmware from a live device — intercept an OTA update, carve the
          blob from the traffic, and ingest it into the workbench. This is FirmLab's second network-touching lane.
          <strong> Discover</strong> devices below, then <strong>Capture</strong> arms an on-path proxy for one target:
          trigger its OTA, and FirmLab scores the flows for firmware and offers the carved blob for one-click ingest.
        </div>
      ) : (
        <div className="banner banner-warn">
          The capture lane is <strong>off</strong>. Set <span className="mono">FIRMLAB_CAPTURE=1</span> to enable it
          (its own flag, like <span className="mono">FIRMLAB_RESEARCH</span>). Detection below still runs — it's
          read-only — but arming a scan is disabled until the lane is on. On Docker, discovery also needs{' '}
          <span className="mono">--network host</span>.
        </div>
      )}

      <div className="panel">
        <div className="panel-title">Capture backends</div>
        <div className="panel-sub">
          How this deployment could get on-path and what it could read. Plug hardware → a backend lights up. Capture
          ceiling right now:{' '}
          {transports.length ? (
            transports.map((t) => (
              <span key={t} className="badge badge-accent mono" style={{ marginRight: 4 }}>
                {t}
              </span>
            ))
          ) : (
            <span className="badge">nothing capturable yet</span>
          )}
        </div>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 30 }} />
                <th style={{ width: 130 }}>Backend</th>
                <th style={{ width: 110 }}>Role</th>
                <th>What it unlocks / what's needed</th>
              </tr>
            </thead>
            <tbody>
              {backends.map((b) => (
                <tr key={b.id}>
                  <td>
                    <span className={`badge ${b.available ? 'badge-ok' : ''}`}>{b.available ? '●' : '○'}</span>
                  </td>
                  <td className="mono">{b.id}</td>
                  <td className="hint">{ROLE_LABEL[b.role] ?? b.role}</td>
                  <td>
                    <div>{b.available ? b.unlocks : <span className="hint">{b.unlocks}</span>}</div>
                    <div className="hint" style={{ marginTop: 2 }}>
                      {b.reason}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel-title">Discover devices</div>
        <div className="panel-sub">
          A passive host sweep (arp-scan / nmap) builds the inventory below. Nothing is intercepted — discovery only
          enumerates who is on the wire.
        </div>

        <label
          style={{ display: 'flex', gap: 8, alignItems: 'flex-start', margin: '10px 0', maxWidth: 640 }}
          htmlFor="capture-ack"
        >
          <input id="capture-ack" type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span className="hint">I confirm these are devices/networks I own or am authorized to test.</span>
        </label>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            className="select"
            placeholder={status?.defaultSubnet ?? 'subnet (e.g. 192.168.1.0/24) — blank = auto-detect'}
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            style={{ minWidth: 320, fontFamily: 'var(--mono)', fontSize: 12.5 }}
            aria-label="Subnet to scan"
          />
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={!enabled || !ack || scanning}
            onClick={runScan}
          >
            {scanning ? 'Scanning…' : 'Scan network'}
          </button>
        </div>

        {err && (
          <div className="banner banner-warn" style={{ marginTop: 12 }}>
            {err}
          </div>
        )}
        {session && (
          <pre className="mono" style={{ marginTop: 12, fontSize: 11.5, whiteSpace: 'pre-wrap' }}>
            {session.transcript.trim()}
          </pre>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">Device radar</div>
        <div className="panel-sub">
          {devices.length} device(s) in the inventory. Type guesses are heuristic (phrased as questions), never
          asserted.
        </div>
        {devices.length === 0 ? (
          <div className="empty">
            <div className="empty-title">{scanned ? 'Scan complete — no devices responded' : 'No scan yet'}</div>
            <div className="empty-body">
              {scanned
                ? 'The sweep ran but nothing answered. On Docker, discovery needs --network host; also confirm arp-scan or nmap is installed.'
                : 'Arm a discovery scan above to build the LAN inventory.'}
            </div>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th style={{ width: 150 }}>MAC</th>
                  <th style={{ width: 130 }}>IP</th>
                  <th>Vendor</th>
                  <th>Type guess</th>
                  <th>mDNS</th>
                  <th style={{ width: 90 }}>Seen</th>
                  <th style={{ width: 90 }} />
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <Fragment key={d.id}>
                    <tr>
                      <td className="mono">{d.mac}</td>
                      <td className="mono hint">{d.ip ?? '—'}</td>
                      <td>{d.ouiVendor ?? <span className="hint">unknown</span>}</td>
                      <td>
                        {d.typeGuess ? (
                          <span className={`badge ${confidenceClass(d.typeConfidence)}`}>
                            {d.typeGuess} · {d.typeConfidence}
                          </span>
                        ) : (
                          <span className="hint">—</span>
                        )}
                      </td>
                      <td className="hint mono" style={{ fontSize: 11 }}>
                        {d.mdnsIdentity ?? '—'}
                      </td>
                      <td className="hint">{fmtWhen(d.lastSeen)}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <button type="button" className="btn btn-sm btn-ghost" onClick={() => runPreflight(d.id)}>
                          Preflight
                        </button>{' '}
                        <button
                          type="button"
                          className="btn btn-sm btn-ghost"
                          disabled={!enabled || !ack}
                          title={ack ? 'Arm an OTA capture for this device' : 'Acknowledge authorization first'}
                          onClick={() => armCapture(d)}
                        >
                          Capture
                        </button>
                      </td>
                    </tr>
                    {preflight[d.id] && (
                      <tr>
                        <td colSpan={7} style={{ background: 'var(--bg-inset)' }}>
                          <PreflightCard plan={preflight[d.id] as CapturabilityPlan} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {capSession && (
        <div className="panel">
          <div className="panel-title">Capture session</div>
          <div className="panel-sub">
            Target {capSession.targetDeviceId ?? '—'} · status{' '}
            <span className={`badge ${capSession.status === 'ingested' ? 'badge-ok' : 'badge-accent'}`}>
              {capSession.status}
            </span>
            {capCeiling && (
              <>
                {' '}
                · ceiling <span className={`badge ${ceilingClass(capCeiling)} mono`}>{capCeiling}</span>
              </>
            )}
            . Trigger the device's OTA now; firmware-looking flows are highlighted and can be ingested.
          </div>
          {capCeiling === 'blocked_by_pinning' && (
            <div className="banner banner-warn">
              The device pins TLS — the OTA can't be decrypted through the proxy. Run the bundled unpin script on a
              rooted phone: <a href="/api/capture/frida-unpin">download Frida unpin →</a>
            </div>
          )}
          {capReason && (
            <div className={`banner ${capSession.status === 'error' ? 'banner-warn' : 'banner-info'}`}>{capReason}</div>
          )}
          <div style={{ display: 'flex', gap: 8, margin: '8px 0' }}>
            <button type="button" className="btn btn-sm btn-ghost" onClick={stopCapture}>
              Stop &amp; teardown
            </button>
          </div>
          {capFlows.length === 0 ? (
            <div className="hint">No flows yet — waiting for traffic through the proxy.</div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th style={{ width: 70 }}>Score</th>
                    <th>URL</th>
                    <th style={{ width: 130 }}>Type</th>
                    <th style={{ width: 90 }}>Size</th>
                    <th style={{ width: 120 }} />
                  </tr>
                </thead>
                <tbody>
                  {capFlows.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <span
                          className={`badge ${f.carved ? 'badge-crit' : f.firmwareScore >= 30 ? 'badge-medium' : ''}`}
                        >
                          {f.firmwareScore}
                        </span>
                      </td>
                      <td className="mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>
                        {f.url ?? '—'}
                      </td>
                      <td className="hint mono" style={{ fontSize: 11 }}>
                        {f.contentType ?? '—'}
                      </td>
                      <td className="hint mono">{(f.size / 1024).toFixed(0)} KB</td>
                      <td>
                        {ingested[f.id] ? (
                          <a className="badge badge-ok" href={`#/image/${ingested[f.id]}`}>
                            ingested →
                          </a>
                        ) : f.carved ? (
                          <button type="button" className="btn btn-primary btn-sm" onClick={() => ingest(f.id)}>
                            Ingest
                          </button>
                        ) : (
                          <span className="hint">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      <div className="panel">
        <div className="panel-title">OTA learning</div>
        <div className="panel-sub">
          What the corpus has learned across captured versions — a per-family OTA timeline, how each vendor ships, and
          which CDN serves whom. Capture the same device twice to unlock a cross-version diff.
        </div>
        {!learning || learning.families.length === 0 ? (
          <div className="empty">
            <div className="empty-title">No captured versions yet</div>
            <div className="empty-body">Ingest a capture (above) — its provenance seeds the OTA timeline here.</div>
          </div>
        ) : (
          <>
            {learning.vendorPriors.length > 0 && (
              <div className="hint" style={{ marginBottom: 10 }}>
                Vendor priors:{' '}
                {learning.vendorPriors.map((p) => (
                  <span key={p.vendor} style={{ marginRight: 10 }}>
                    <strong>{p.vendor}</strong> ships <span className="badge mono">{p.ships}</span>
                    {p.cdns.length ? ` from ${p.cdns.join(', ')}` : ''} ({p.captureCount})
                  </span>
                ))}
              </div>
            )}
            {learning.families.map((fam) => (
              <div key={fam.key} style={{ marginBottom: 14 }}>
                <div className="eyebrow">
                  {fam.key} · {fam.captures.length} version(s) · {fam.transports.join(', ') || '—'}
                </div>
                <div className="table-wrap">
                  <table className="data">
                    <tbody>
                      {fam.captures.map((c, i) => (
                        <tr key={c.imageId}>
                          <td className="mono" style={{ width: 160 }}>
                            {c.filename}
                          </td>
                          <td className="hint mono">{c.firmwareClass ?? '—'}</td>
                          <td className="hint mono">{c.transport ?? '—'}</td>
                          <td className="hint mono">{(c.size / 1024).toFixed(0)} KB</td>
                          <td style={{ width: 130 }}>
                            <a className="badge" href={`#/image/${c.imageId}`}>
                              open →
                            </a>{' '}
                            {i > 0 && (
                              <a className="badge badge-accent" href={`#/image/${c.imageId}/diff`}>
                                diff prev
                              </a>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
