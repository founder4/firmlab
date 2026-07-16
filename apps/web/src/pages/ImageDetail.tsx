import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { type FsNode, type FsSummary, type ImageSummary, type StaticAnalysis, api, fmtBytes, fmtHex } from '../api';
import { EntropyChart } from '../components/EntropyChart';
import { FilesystemTree } from '../components/FilesystemTree';
import { SimulationMenu } from '../components/SimulationMenu';
import { StructureMap } from '../components/StructureMap';

type TabId = 'overview' | 'structure' | 'entropy' | 'filesystem' | 'secrets' | 'simulate';

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'structure', label: 'Structure' },
  { id: 'entropy', label: 'Entropy' },
  { id: 'filesystem', label: 'Filesystem' },
  { id: 'secrets', label: 'Secrets' },
  { id: 'simulate', label: 'Simulation' },
];

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
      {tab === 'simulate' && <SimulationMenu imageId={id} />}
      {!analysis && tab !== 'filesystem' && tab !== 'simulate' && <div className="empty">No analysis available.</div>}
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
        <table className="data" style={{ marginTop: 16 }}>
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

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }): JSX.Element {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${mono ? 'mono' : ''}`}>{value}</div>
    </div>
  );
}
