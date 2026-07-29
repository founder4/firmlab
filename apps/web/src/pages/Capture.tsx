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
import { type Messages, useLocale, useMessages } from '../i18n';

function ceilingClass(c: string | null | undefined): string {
  if (c === 'captured_plaintext' || c === 'captured_encrypted') return 'badge-ok';
  if (c === 'blocked_by_pinning' || c === 'blocked_needs_hardware') return 'badge-high';
  return 'badge-medium';
}

/**
 * The capturability ladder for a target: the honest ceiling, the ranked strategies, and what would unlock more.
 *
 * The ceiling itself (`captured_plaintext`, `blocked_by_pinning`…) is an identifier the API returns, and each
 * strategy's reason is the preflight's own sentence — both render verbatim. Only the label in front is localised.
 */
function PreflightCard({ plan }: { plan: CapturabilityPlan }): JSX.Element {
  const t = useMessages();
  return (
    <div style={{ padding: '4px 2px' }}>
      <div style={{ marginBottom: 6 }}>
        {t.capture.preflight.ceiling} <span className={`badge ${ceilingClass(plan.ceiling)} mono`}>{plan.ceiling}</span>{' '}
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
              <a href="/api/capture/frida-unpin">{t.capture.preflight.unpin}</a>
            </>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * A backend's role is an API value; only its gloss is localised, and an unrecognised role falls through to the raw
 * value rather than to a blank cell — a backend this build has never seen still has to name itself.
 */
const ROLES = ['positioning', 'interception', 'radio', 'physical'] as const;
const isRole = (r: string): r is (typeof ROLES)[number] => (ROLES as readonly string[]).includes(r);

function confidenceClass(c: string | null): string {
  if (c === 'high') return 'badge-ok';
  if (c === 'medium') return 'badge-medium';
  return 'badge';
}

/** Not a component, so the catalogue is handed in: each language spells its own elapsed-time phrase. */
function fmtWhen(ms: number, t: Messages): string {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return t.capture.radar.seconds(s);
  if (s < 3600) return t.capture.radar.minutes(Math.round(s / 60));
  return t.capture.radar.hours(Math.round(s / 3600));
}

/**
 * The Capture section (Phase 6.0–6.3). Shows what this deployment could capture (auto-detected backends + the
 * honest transport ceiling), runs a passive LAN discovery sweep to build the device inventory (the radar), gives a
 * per-target capturability preflight (the ranked strategy ladder + the honest acquisition ceiling + a Frida unpin
 * download when pinned), and arms an on-path proxy to intercept a target's OTA — scoring the flows for firmware and
 * ingesting a carved blob into the workbench. Gated by FIRMLAB_CAPTURE + a per-action operator acknowledgement.
 *
 * Every sentence on this page comes from the `capture` catalogue, and the two lane banners are assembled from
 * fragments rather than held as one string. That is deliberate: the env var, the Docker flag and the emphasised
 * verbs stay OUTSIDE the translated text, so a translation can restate the sentence but cannot quietly alter what
 * the operator has to type — or which word the banner leans on.
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

  const t = useMessages();
  const locale = useLocale();

  const runPreflight = useCallback(async (deviceId: string) => {
    const plan = await api.capturePreflight(deviceId).catch(() => null);
    if (plan) setPreflight((m) => ({ ...m, [deviceId]: plan }));
  }, []);

  /**
   * The backend table is asked for again when the language changes, and it is its OWN effect for a reason: the
   * mount effect below owns the polling intervals and tears them down on cleanup, so folding the locale into its
   * dependency list would kill a running discovery sweep every time somebody flipped the switch.
   */
  useEffect(() => {
    api
      .captureBackends(locale)
      .then((v) => {
        setBackends(v.backends);
        setTransports(v.transports);
      })
      .catch(() => undefined);
  }, [locale]);

  useEffect(() => {
    api
      .captureStatus()
      .then(setStatus)
      .catch(() => setStatus({ enabled: false }));
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
          // The session's own error text when it has one; the generic sentence only when it does not.
          if (v.session.status === 'error') setErr(v.session.error ?? t.capture.discover.failed);
        }
      }, 900);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setScanning(false);
    }
  }, [subnet, ack, t]);

  const enabled = status?.enabled === true;

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">{t.capture.eyebrow}</div>
        <h1 className="page-title">{t.capture.title}</h1>
        <div className="page-desc">{t.capture.desc}</div>
      </div>

      {enabled ? (
        <div className="banner banner-info">
          <strong>{t.capture.laneOn.discover}</strong> {t.capture.laneOn.mid}{' '}
          <strong>{t.capture.laneOn.capture}</strong> {t.capture.laneOn.tail}
        </div>
      ) : (
        // The env var and the Docker flag are what the operator has to type: they sit beside the sentence, never
        // inside it, so no translation can quietly bend one.
        <div className="banner banner-warn">
          {t.capture.laneOff.lead} <strong>{t.capture.laneOff.word}</strong>. {t.capture.laneOff.set}{' '}
          <span className="mono">FIRMLAB_CAPTURE=1</span> {t.capture.laneOff.enable}{' '}
          <span className="mono">FIRMLAB_RESEARCH</span>). {t.capture.laneOff.detection} {t.capture.laneOff.docker}{' '}
          <span className="mono">--network host</span>.
        </div>
      )}

      <div className="panel">
        <div className="panel-title">{t.capture.backends.title}</div>
        <div className="panel-sub">
          {t.capture.backends.sub}{' '}
          {transports.length ? (
            transports.map((transport) => (
              <span key={transport} className="badge badge-accent mono" style={{ marginRight: 4 }}>
                {transport}
              </span>
            ))
          ) : (
            <span className="badge">{t.capture.backends.none}</span>
          )}
        </div>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 30 }} />
                <th style={{ width: 130 }}>{t.capture.backends.colBackend}</th>
                <th style={{ width: 110 }}>{t.capture.backends.colRole}</th>
                <th>{t.capture.backends.colUnlocks}</th>
              </tr>
            </thead>
            <tbody>
              {backends.map((b) => (
                <tr key={b.id}>
                  <td>
                    <span className={`badge ${b.available ? 'badge-ok' : ''}`}>{b.available ? '●' : '○'}</span>
                  </td>
                  <td className="mono">{b.id}</td>
                  <td className="hint">{isRole(b.role) ? t.capture.roles[b.role] : b.role}</td>
                  {/* `unlocks` is composed by the API in the locale this page asked for — it describes the
                      deployment and is recomputed on every read. `reason` is what THIS box answered when probed
                      (the dongle it found, the capability it lacks), so it is printed exactly as it arrived. */}
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
        <div className="panel-title">{t.capture.discover.title}</div>
        <div className="panel-sub">{t.capture.discover.sub}</div>

        <label
          style={{ display: 'flex', gap: 8, alignItems: 'flex-start', margin: '10px 0', maxWidth: 640 }}
          htmlFor="capture-ack"
        >
          <input id="capture-ack" type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span className="hint">{t.capture.discover.ack}</span>
        </label>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            className="select"
            placeholder={status?.defaultSubnet ?? t.capture.discover.subnetPlaceholder}
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            style={{ minWidth: 320, fontFamily: 'var(--mono)', fontSize: 12.5 }}
            aria-label={t.capture.discover.subnetLabel}
          />
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={!enabled || !ack || scanning}
            onClick={runScan}
          >
            {scanning ? t.capture.discover.scanning : t.capture.discover.scan}
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
        <div className="panel-title">{t.capture.radar.title}</div>
        <div className="panel-sub">{t.capture.radar.sub(devices.length)}</div>
        {devices.length === 0 ? (
          <div className="empty">
            {/* A sweep that ran and found nothing is not the same as no sweep, and the two say so separately. */}
            <div className="empty-title">{scanned ? t.capture.radar.scannedTitle : t.capture.radar.noScanTitle}</div>
            <div className="empty-body">{scanned ? t.capture.radar.scannedBody : t.capture.radar.noScanBody}</div>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                {/* MAC, IP and mDNS are protocol names — the same in every language. */}
                <tr>
                  <th style={{ width: 150 }}>MAC</th>
                  <th style={{ width: 130 }}>IP</th>
                  <th>{t.capture.radar.colVendor}</th>
                  <th>{t.capture.radar.colGuess}</th>
                  <th>mDNS</th>
                  <th style={{ width: 90 }}>{t.capture.radar.colSeen}</th>
                  <th style={{ width: 90 }} />
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <Fragment key={d.id}>
                    <tr>
                      <td className="mono">{d.mac}</td>
                      <td className="mono hint">{d.ip ?? '—'}</td>
                      <td>{d.ouiVendor ?? <span className="hint">{t.common.unknown}</span>}</td>
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
                      <td className="hint">{fmtWhen(d.lastSeen, t)}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <button type="button" className="btn btn-sm btn-ghost" onClick={() => runPreflight(d.id)}>
                          {t.capture.radar.preflight}
                        </button>{' '}
                        <button
                          type="button"
                          className="btn btn-sm btn-ghost"
                          disabled={!enabled || !ack}
                          title={ack ? t.capture.radar.captureReady : t.capture.radar.captureBlocked}
                          onClick={() => armCapture(d)}
                        >
                          {t.capture.radar.capture}
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
          <div className="panel-title">{t.capture.session.title}</div>
          <div className="panel-sub">
            {t.capture.session.target} {capSession.targetDeviceId ?? '—'} · {t.capture.session.status}{' '}
            <span className={`badge ${capSession.status === 'ingested' ? 'badge-ok' : 'badge-accent'}`}>
              {capSession.status}
            </span>
            {capCeiling && (
              <>
                {' '}
                · {t.capture.session.ceiling}{' '}
                <span className={`badge ${ceilingClass(capCeiling)} mono`}>{capCeiling}</span>
              </>
            )}
            . {t.capture.session.trigger}
          </div>
          {capCeiling === 'blocked_by_pinning' && (
            <div className="banner banner-warn">
              {t.capture.session.pinned} <a href="/api/capture/frida-unpin">{t.capture.preflight.unpin}</a>
            </div>
          )}
          {capReason && (
            <div className={`banner ${capSession.status === 'error' ? 'banner-warn' : 'banner-info'}`}>{capReason}</div>
          )}
          <div style={{ display: 'flex', gap: 8, margin: '8px 0' }}>
            <button type="button" className="btn btn-sm btn-ghost" onClick={stopCapture}>
              {t.capture.session.stop}
            </button>
          </div>
          {capFlows.length === 0 ? (
            <div className="hint">{t.capture.session.noFlows}</div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th style={{ width: 70 }}>{t.capture.session.colScore}</th>
                    <th>URL</th>
                    <th style={{ width: 130 }}>{t.capture.session.colType}</th>
                    <th style={{ width: 90 }}>{t.capture.session.colSize}</th>
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
                            {t.capture.session.ingested}
                          </a>
                        ) : f.carved ? (
                          <button type="button" className="btn btn-primary btn-sm" onClick={() => ingest(f.id)}>
                            {t.capture.session.ingest}
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
        <div className="panel-title">{t.capture.learning.title}</div>
        <div className="panel-sub">{t.capture.learning.sub}</div>
        {!learning || learning.families.length === 0 ? (
          <div className="empty">
            <div className="empty-title">{t.capture.learning.emptyTitle}</div>
            <div className="empty-body">{t.capture.learning.emptyBody}</div>
          </div>
        ) : (
          <>
            {learning.vendorPriors.length > 0 && (
              <div className="hint" style={{ marginBottom: 10 }}>
                {t.capture.learning.priors}{' '}
                {learning.vendorPriors.map((p) => (
                  <span key={p.vendor} style={{ marginRight: 10 }}>
                    {/* The vendor name, its shipping posture and the CDN hosts are observations, not prose. */}
                    <strong>{p.vendor}</strong> {t.capture.learning.ships} <span className="badge mono">{p.ships}</span>
                    {p.cdns.length ? ` ${t.capture.learning.fromCdns(p.cdns.join(', '))}` : ''} ({p.captureCount})
                  </span>
                ))}
              </div>
            )}
            {learning.families.map((fam) => (
              <div key={fam.key} style={{ marginBottom: 14 }}>
                <div className="eyebrow">
                  {fam.key} · {t.capture.learning.versions(fam.captures.length)} · {fam.transports.join(', ') || '—'}
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
                              {t.capture.learning.open}
                            </a>{' '}
                            {i > 0 && (
                              <a className="badge badge-accent" href={`#/image/${c.imageId}/diff`}>
                                {t.capture.learning.diffPrev}
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
