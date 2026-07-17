import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  type DecompileResult,
  type FsNode,
  type FsSummary,
  type ImageSummary,
  type Job,
  type SbomResult,
  type Severity,
  type StaticAnalysis,
  api,
  fmtBytes,
  fmtHex,
} from '../api';
import { EntropyChart } from '../components/EntropyChart';
import { FilesystemTree } from '../components/FilesystemTree';
import { SimulationMenu } from '../components/SimulationMenu';
import { StructureMap } from '../components/StructureMap';

type TabId = 'overview' | 'structure' | 'entropy' | 'filesystem' | 'secrets' | 'sbom' | 'binaries' | 'simulate';

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'structure', label: 'Structure' },
  { id: 'entropy', label: 'Entropy' },
  { id: 'filesystem', label: 'Filesystem' },
  { id: 'secrets', label: 'Secrets' },
  { id: 'sbom', label: 'SBOM & CVEs' },
  { id: 'binaries', label: 'Binaries' },
  { id: 'simulate', label: 'Simulation' },
];

/** Tabs that operate on the extracted rootfs / tools rather than the cached static analysis. */
const NO_ANALYSIS_TABS = new Set<TabId>(['filesystem', 'sbom', 'binaries', 'simulate']);

export function ImageDetail(): JSX.Element {
  const { id = '' } = useParams();
  const [image, setImage] = useState<ImageSummary | null>(null);
  const [analysis, setAnalysis] = useState<StaticAnalysis | null>(null);
  const [tab, setTab] = useState<TabId>('overview');

  useEffect(() => {
    api
      .getImage(id)
      .then(setImage)
      .catch(() => setImage(null));
    api
      .analysis(id)
      .then(setAnalysis)
      .catch(() => setAnalysis(null));
  }, [id]);

  if (!image) return <div className="empty">Loading image…</div>;

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Link to="/" className="hint">
          ← Dashboard
        </Link>
        <h2 className="mono" style={{ margin: '6px 0 2px', fontSize: 20 }}>
          {image.filename}
        </h2>
        <div className="hint mono">
          {image.sha256.slice(0, 32)}… · {fmtBytes(image.size)}
        </div>
      </div>

      <div className="tabs">
        {TABS.map((t) => (
          <div key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
          </div>
        ))}
      </div>

      {tab === 'overview' && <Overview image={image} analysis={analysis} />}
      {tab === 'structure' && analysis && <StructurePanel analysis={analysis} />}
      {tab === 'entropy' && analysis && <EntropyPanel analysis={analysis} />}
      {tab === 'filesystem' && <FilesystemPanel imageId={id} />}
      {tab === 'secrets' && analysis && <SecretsPanel analysis={analysis} />}
      {tab === 'sbom' && <SbomPanel imageId={id} />}
      {tab === 'binaries' && <BinariesPanel imageId={id} />}
      {tab === 'simulate' && <SimulationMenu imageId={id} />}
      {!analysis && !NO_ANALYSIS_TABS.has(tab) && <div className="empty">No analysis available.</div>}
    </div>
  );
}

function Overview({ image, analysis }: { image: ImageSummary; analysis: StaticAnalysis | null }): JSX.Element {
  const id = image.identity;
  return (
    <div>
      <div className="grid grid-3" style={{ marginBottom: 18 }}>
        <Stat label="Class" value={id?.firmwareClass ?? '—'} />
        <Stat label="Architecture" value={`${id?.arch ?? '—'} / ${id?.endianness ?? '—'}`} mono />
        <Stat label="Filesystems" value={id?.filesystems.join(', ') || '—'} mono />
        <Stat label="Bootloader" value={id?.bootloader ?? '—'} />
        <Stat label="Signatures" value={String(analysis?.signatures.length ?? 0)} />
        <Stat label="Secrets" value={String(analysis?.secrets.length ?? 0)} />
      </div>
      {analysis && (
        <div className="panel">
          <div className="panel-title">Entropy signal</div>
          <div className="grid grid-3">
            <Stat label="Mean H" value={analysis.entropy.mean.toFixed(2)} mono />
            <Stat label="Likely encrypted" value={analysis.entropy.likelyEncrypted ? 'yes' : 'no'} />
            <Stat label="Likely compressed" value={analysis.entropy.likelyCompressed ? 'yes' : 'no'} />
          </div>
        </div>
      )}
    </div>
  );
}

function StructurePanel({ analysis }: { analysis: StaticAnalysis }): JSX.Element {
  return (
    <div className="panel">
      <div className="panel-title">Structure map</div>
      <div className="panel-sub">Signature-carved layout across the image ({analysis.structure.length} segments)</div>
      <StructureMap segments={analysis.structure} size={analysis.size} />
    </div>
  );
}

function EntropyPanel({ analysis }: { analysis: StaticAnalysis }): JSX.Element {
  return (
    <div className="panel">
      <div className="panel-title">Entropy profile</div>
      <div className="panel-sub">Shannon entropy across the image — high bands are compressed or encrypted</div>
      <EntropyChart entropy={analysis.entropy} size={analysis.size} />
      {analysis.entropy.highEntropyRegions.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 16 }}>
          <table className="data">
            <thead>
              <tr>
                <th>High-entropy region</th>
                <th>Mean H</th>
                <th>Size</th>
              </tr>
            </thead>
            <tbody>
              {analysis.entropy.highEntropyRegions.slice(0, 20).map((r, i) => (
                <tr key={i}>
                  <td className="mono">
                    {fmtHex(r.start)} – {fmtHex(r.end)}
                  </td>
                  <td className="mono">{r.meanEntropy.toFixed(2)}</td>
                  <td className="mono">{fmtBytes(r.end - r.start)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function SecretsPanel({ analysis }: { analysis: StaticAnalysis }): JSX.Element {
  if (analysis.secrets.length === 0)
    return <div className="empty">No secret-like strings detected in the raw image.</div>;
  return (
    <div className="panel">
      <div className="panel-title">Secrets & credentials</div>
      <div className="panel-sub">Heuristic matches in the raw image (values shown are pre-extraction)</div>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Kind</th>
              <th>Offset</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {analysis.secrets.map((s, i) => (
              <tr key={i}>
                <td>
                  <span className={`badge badge-${s.severity}`}>{s.severity}</span>
                </td>
                <td>{s.secretKind}</td>
                <td className="mono">{fmtHex(s.offset)}</td>
                <td
                  className="mono"
                  style={{ maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                >
                  {s.value}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FilesystemPanel({ imageId }: { imageId: string }): JSX.Element {
  const [tree, setTree] = useState<FsNode | null>(null);
  const [summary, setSummary] = useState<FsSummary | null>(null);
  const [status, setStatus] = useState<'none' | 'running' | 'done' | 'error'>('none');
  const [log, setLog] = useState('');

  const loadLatest = useCallback(async () => {
    const jobs = await api.jobs(imageId);
    const extract = jobs.find((j) => j.kind === 'extract' && j.status === 'done');
    if (extract) {
      const r = extract.result as { tree?: FsNode; summary?: FsSummary; extractor?: string } | null;
      if (r?.tree) {
        setTree(r.tree);
        setSummary(r.summary ?? null);
        setStatus('done');
      } else {
        setStatus('error');
        setLog(extract.log ?? 'Extraction produced no rootfs (binwalk unavailable or no filesystem found).');
      }
    }
  }, [imageId]);
  useEffect(() => {
    loadLatest();
  }, [loadLatest]);

  const runExtract = useCallback(async () => {
    setStatus('running');
    setLog('');
    const { jobId } = await api.extract(imageId);
    const timer = window.setInterval(async () => {
      const j = await api.job(jobId);
      setLog(j.log);
      if (j.status === 'done' || j.status === 'error') {
        window.clearInterval(timer);
        loadLatest();
        if (j.status === 'error') setStatus('error');
      }
    }, 800);
  }, [imageId, loadLatest]);

  if (tree) {
    return (
      <div>
        {summary && (
          <div className="grid grid-3" style={{ marginBottom: 16 }}>
            <Stat label="Files" value={String(summary.totalFiles)} />
            <Stat label="Directories" value={String(summary.totalDirs)} />
            <Stat label="setuid binaries" value={String(summary.setuidBinaries.length)} />
          </div>
        )}
        <div className="panel">
          <div className="panel-title">Root filesystem</div>
          <FilesystemTree root={tree} />
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-title">Filesystem extraction</div>
      <div className="panel-sub">Carve the image with binwalk and model the recovered rootfs.</div>
      <button className="btn btn-primary" disabled={status === 'running'} onClick={runExtract}>
        {status === 'running' ? (
          <>
            <span className="spinner" /> Extracting…
          </>
        ) : (
          'Run extraction'
        )}
      </button>
      {log && (
        <pre
          className="mono"
          style={{ fontSize: 11.5, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', marginTop: 14 }}
        >
          {log}
        </pre>
      )}
    </div>
  );
}

/** Poll a job to completion, streaming its log into `onLog`; resolves with the finished job. */
function pollJob(jobId: string, onLog: (log: string) => void): Promise<Job> {
  return new Promise((resolve, reject) => {
    const timer = window.setInterval(async () => {
      try {
        const j = await api.job(jobId);
        onLog(j.log);
        if (j.status === 'done' || j.status === 'error') {
          window.clearInterval(timer);
          resolve(j);
        }
      } catch (err) {
        window.clearInterval(timer);
        reject(err);
      }
    }, 900);
  });
}

const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];
const SEVERITY_BADGE: Record<Severity, string> = {
  Critical: 'badge-crit',
  High: 'badge-high',
  Medium: 'badge-medium',
  Low: 'badge-low',
  Negligible: 'badge-info',
  Unknown: 'badge-info',
};

function SbomPanel({ imageId }: { imageId: string }): JSX.Element {
  const [result, setResult] = useState<SbomResult | null>(null);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState('');
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    api
      .sbom(imageId)
      .then(setResult)
      .catch(() => setResult(null))
      .finally(() => setLoaded(true));
  }, [imageId]);

  const run = useCallback(async () => {
    setRunning(true);
    setLog('');
    try {
      const { jobId } = await api.runSbom(imageId);
      const job = await pollJob(jobId, setLog);
      if (job.status === 'done') setResult(job.result as SbomResult);
    } catch (err) {
      setLog(String(err instanceof Error ? err.message : err));
    } finally {
      setRunning(false);
    }
  }, [imageId]);

  if (!loaded) return <div className="empty">Loading…</div>;

  return (
    <div>
      <div className="panel">
        <div className="panel-title">Software Bill of Materials + CVEs</div>
        <div className="panel-sub">syft inventories the extracted rootfs; grype matches known (N-day) CVEs.</div>
        <button className="btn btn-primary" disabled={running} onClick={run}>
          {running ? (
            <>
              <span className="spinner" /> Scanning…
            </>
          ) : result ? (
            'Re-scan'
          ) : (
            'Generate SBOM & scan CVEs'
          )}
        </button>
        {result && !result.available && (
          <div className="banner banner-warn" style={{ marginTop: 14 }}>
            {result.reason ?? 'SBOM unavailable — run extraction first, or install syft.'}
          </div>
        )}
        {log && (
          <pre
            className="mono"
            style={{ fontSize: 11.5, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', marginTop: 14 }}
          >
            {log}
          </pre>
        )}
      </div>

      {result?.available && (
        <>
          <div className="grid grid-3" style={{ marginBottom: 18 }}>
            <Stat label="Packages" value={String(result.packageCount)} />
            <Stat label="Vulnerabilities" value={String(result.vulnerabilities.length)} />
            <Stat label="Critical / High" value={`${result.counts.Critical} / ${result.counts.High}`} mono />
          </div>

          {!result.grypeAvailable && (
            <div className="banner banner-info">grype not present — SBOM generated, but CVE matching was skipped.</div>
          )}

          {result.vulnerabilities.length > 0 && (
            <div className="panel">
              <div className="panel-title">
                CVEs
                <span className="legend" style={{ marginLeft: 'auto' }}>
                  {SEVERITY_ORDER.filter((s) => result.counts[s] > 0).map((s) => (
                    <span key={s} className={`badge ${SEVERITY_BADGE[s]}`}>
                      {s} {result.counts[s]}
                    </span>
                  ))}
                </span>
              </div>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>CVE</th>
                      <th>Package</th>
                      <th>Version</th>
                      <th>Fixed in</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.vulnerabilities.slice(0, 300).map((v, i) => (
                      <tr key={`${v.id}-${v.packageName}-${i}`}>
                        <td>
                          <span className={`badge ${SEVERITY_BADGE[v.severity]}`}>{v.severity}</span>
                        </td>
                        <td className="mono">{v.id}</td>
                        <td>{v.packageName}</td>
                        <td className="mono">{v.packageVersion}</td>
                        <td className="mono">{v.fixedIn ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {result.packages.length > 0 && (
            <div className="panel">
              <div className="panel-title">Packages ({result.packageCount})</div>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Version</th>
                      <th>Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.packages.slice(0, 300).map((p, i) => (
                      <tr key={`${p.name}-${i}`}>
                        <td>{p.name}</td>
                        <td className="mono">{p.version}</td>
                        <td className="hint">{p.type}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function BinariesPanel({ imageId }: { imageId: string }): JSX.Element {
  const [result, setResult] = useState<DecompileResult | null>(null);
  const [binary, setBinary] = useState('');
  const [rootfsReady, setRootfsReady] = useState<boolean | null>(null);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState('');

  useEffect(() => {
    api
      .decompileResult(imageId)
      .then((r) => {
        setResult(r);
        if (r?.binary) setBinary(r.binary);
      })
      .catch(() => setResult(null));
    api
      .emulation(imageId)
      .then((m) => {
        setRootfsReady(m.rootfsReady);
        setBinary((b) => b || m.suggestedBinary || '');
      })
      .catch(() => setRootfsReady(false));
  }, [imageId]);

  const run = useCallback(async () => {
    if (!binary.trim()) return;
    setRunning(true);
    setLog('');
    try {
      const { jobId } = await api.decompile(imageId, binary.trim());
      const job = await pollJob(jobId, setLog);
      if (job.status === 'done') setResult(job.result as DecompileResult);
    } catch (err) {
      setLog(String(err instanceof Error ? err.message : err));
    } finally {
      setRunning(false);
    }
  }, [imageId, binary]);

  const info = result?.info;

  return (
    <div>
      <div className="panel">
        <div className="panel-title">Binary triage (radare2)</div>
        <div className="panel-sub">
          Static triage of a binary from the extracted rootfs: headers, imports, symbols, strings.
        </div>
        {rootfsReady === false && (
          <div className="banner banner-warn" style={{ marginBottom: 14 }}>
            No extracted rootfs yet — run extraction on the Filesystem tab first.
          </div>
        )}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            className="input mono"
            placeholder="rootfs-relative path, e.g. bin/busybox"
            value={binary}
            onChange={(e) => setBinary(e.target.value)}
            style={{ flex: '1 1 240px', minWidth: 0 }}
          />
          <button className="btn btn-primary" disabled={running || !binary.trim()} onClick={run}>
            {running ? (
              <>
                <span className="spinner" /> Triaging…
              </>
            ) : (
              'Triage binary'
            )}
          </button>
        </div>
        {result && !result.available && (
          <div className="banner banner-warn" style={{ marginTop: 14 }}>
            {result.reason ?? 'Triage unavailable — check the path, or install radare2.'}
          </div>
        )}
        {log && (
          <pre
            className="mono"
            style={{ fontSize: 11.5, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', marginTop: 14 }}
          >
            {log}
          </pre>
        )}
      </div>

      {result?.available && info && (
        <>
          <div className="panel">
            <div className="panel-title mono">{result.binary}</div>
            <div className="legend" style={{ marginTop: 6 }}>
              {info.arch && (
                <span className="badge badge-info">
                  {info.arch}
                  {info.bits ? `/${info.bits}` : ''}
                </span>
              )}
              {info.bintype && <span className="badge badge-info">{info.bintype}</span>}
              {info.endian && <span className="badge badge-info">{info.endian}</span>}
              {info.os && <span className="badge badge-info">{info.os}</span>}
              <span className={`badge ${info.nx ? 'badge-ok' : 'badge-medium'}`}>NX {info.nx ? 'on' : 'off'}</span>
              <span className={`badge ${info.canary ? 'badge-ok' : 'badge-medium'}`}>
                canary {info.canary ? 'on' : 'off'}
              </span>
              <span className="badge badge-info">PIC {info.pic ? 'yes' : 'no'}</span>
              <span className="badge badge-info">{result.functionCount} funcs</span>
            </div>
          </div>

          <div className="grid grid-2">
            <TriageTable title={`Imports (${result.imports.length})`} head={['Symbol', 'Library']}>
              {result.imports.slice(0, 300).map((im, i) => (
                <tr key={`${im.name}-${i}`}>
                  <td className="mono">{im.name}</td>
                  <td className="hint">{im.libname ?? '—'}</td>
                </tr>
              ))}
            </TriageTable>
            <TriageTable title={`Symbols (${result.symbols.length})`} head={['Name', 'Type']}>
              {result.symbols.slice(0, 300).map((s, i) => (
                <tr key={`${s.name}-${i}`}>
                  <td className="mono">{s.name}</td>
                  <td className="hint">{s.type}</td>
                </tr>
              ))}
            </TriageTable>
          </div>

          {result.strings.length > 0 && (
            <div className="panel">
              <div className="panel-title">Strings ({result.strings.length})</div>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.strings.slice(0, 300).map((s, i) => (
                      <tr key={`${s.addr}-${i}`}>
                        <td className="mono">{s.addr}</td>
                        <td className="mono">{s.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function TriageTable({
  title,
  head,
  children,
}: {
  title: string;
  head: [string, string];
  children: ReactNode;
}): JSX.Element {
  return (
    <div className="panel">
      <div className="panel-title">{title}</div>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>{head[0]}</th>
              <th>{head[1]}</th>
            </tr>
          </thead>
          <tbody>{children}</tbody>
        </table>
      </div>
    </div>
  );
}

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }): JSX.Element {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${mono ? 'mono' : ''}`}>{value}</div>
    </div>
  );
}
