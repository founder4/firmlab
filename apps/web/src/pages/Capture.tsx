import { useCallback, useEffect, useRef, useState } from 'react';
import { type CaptureBackend, type CaptureDevice, type CaptureSession, type CaptureStatus, api } from '../api';

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
 * The Capture section (Phase 6.0). Shows what this deployment could capture (auto-detected backends + the honest
 * transport ceiling) and runs a passive LAN discovery sweep to build the device inventory (the radar). No
 * interception here — that lands in 6.1. Gated by FIRMLAB_CAPTURE + a per-scan operator acknowledgement.
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
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

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
          blob from the traffic, and ingest it into the workbench. This is FirmLab's second network-touching lane. Phase
          6.0 covers <strong>discovery</strong> (a passive LAN sweep) and reports what each device could be captured
          over; interception itself lands in 6.1.
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
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id}>
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
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
