import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  type AgentConfig,
  type AgentSession,
  type AgentStatus,
  type AgentStep,
  type BinaryEntry,
  type CopilotResult,
  type CorpusRefs,
  type DecompileResult,
  type Finding,
  type FirmwareDiffResult,
  type FsNode,
  type FsSummary,
  type GhidraResult,
  type GitleaksResult,
  type ImageSummary,
  type Job,
  type ProofState,
  type ResearchResult,
  type ResearchStatus,
  type RuntimeCapabilities,
  type SbomResult,
  type Severity,
  type StaticAnalysis,
  api,
  fmtBytes,
  fmtHex,
} from '../api';
import { AnalysisActionsPanel } from '../components/AnalysisActionsPanel';
import { EntropyChart } from '../components/EntropyChart';
import { FilesystemTree } from '../components/FilesystemTree';
import { FuzzPanel } from '../components/FuzzPanel';
import { OpacidadPanel } from '../components/OpacidadPanel';
import { PresetsPanel } from '../components/PresetsPanel';
import { ReportBuilder } from '../components/ReportBuilder';
import { SbomGraph } from '../components/SbomGraph';
import { SignalCanvas } from '../components/SignalCanvas';
import { SimulationMenu } from '../components/SimulationMenu';
import { StepTimeline } from '../components/StepTimeline';
import { StructureMap } from '../components/StructureMap';
import { toast } from '../toast';

type TabId =
  | 'dossier'
  | 'overview'
  | 'structure'
  | 'entropy'
  | 'filesystem'
  | 'secrets'
  | 'bootloader'
  | 'sbom'
  | 'binaries'
  | 'findings'
  | 'diff'
  | 'simulate'
  | 'opacidad'
  | 'agent';

/** Sections that operate on the extracted rootfs / tools rather than the cached static analysis. */
const NO_ANALYSIS_TABS = new Set<TabId>([
  'dossier',
  'filesystem',
  'secrets',
  'bootloader',
  'sbom',
  'binaries',
  'findings',
  'diff',
  'simulate',
  'opacidad',
  'agent',
]);

/** URL section → internal panel id. The step timeline drives these; `overview` is the composite dossier. */
const SECTION_TITLES: Record<TabId, string> = {
  dossier: 'General',
  overview: 'General',
  structure: 'Structure',
  entropy: 'Entropy',
  filesystem: 'Extraction',
  secrets: 'Secrets',
  bootloader: 'Bootloader',
  sbom: 'SBOM & CVEs',
  binaries: 'Binaries',
  findings: 'Findings & report',
  diff: 'Diff',
  simulate: 'Emulation',
  opacidad: 'Autonomous scan',
  agent: 'Agent',
};

function resolveSection(section: string | undefined): TabId {
  if (!section || section === 'overview') return 'dossier';
  return section in SECTION_TITLES ? (section as TabId) : 'dossier';
}

export function ImageDetail(): JSX.Element {
  const { id = '', section } = useParams();
  const [image, setImage] = useState<ImageSummary | null>(null);
  const [analysis, setAnalysis] = useState<StaticAnalysis | null>(null);
  const tab = resolveSection(section);

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

  if (!image) {
    return (
      <div style={{ display: 'grid', gap: 12 }}>
        <div className="skeleton" style={{ height: 60 }} />
        <div className="skeleton" style={{ height: 220 }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="eyebrow">Firmware · {image.identity?.arch ?? 'unknown arch'}</div>
          <h1 className="page-title">{SECTION_TITLES[tab]}</h1>
          <div className="hint mono" style={{ wordBreak: 'break-all' }}>
            {image.sha256.slice(0, 24)}… · {fmtBytes(image.size)}
          </div>
        </div>
        <a className="btn btn-sm" href={`/api/images/${id}/report`} download>
          <span aria-hidden="true">⭳</span> Report
        </a>
        <a
          className="btn btn-sm"
          href={`/api/images/${id}/disclosure-report`}
          download
          title="Coordinated-disclosure draft (Markdown) — review before sending"
        >
          <span aria-hidden="true">⭳</span> Disclosure
        </a>
      </div>

      <StepTimeline imageId={id} active={tab} ready={image.status === 'ready'} />

      {tab === 'dossier' && <DossierPanel image={image} />}
      {tab === 'structure' && analysis && <StructurePanel analysis={analysis} />}
      {tab === 'entropy' && analysis && <EntropyPanel analysis={analysis} />}
      {/* Extraction: the carved rootfs and what it exposes — files + secrets in one place. */}
      {tab === 'filesystem' && (
        <>
          <FilesystemPanel imageId={id} />
          <SecretsPanel analysis={analysis} imageId={id} />
        </>
      )}
      {tab === 'secrets' && <SecretsPanel analysis={analysis} imageId={id} />}
      {/* Bootloader: the deep static config/boot providers (u-boot env, /etc audit, certs, services…). */}
      {tab === 'bootloader' && <AnalysisActionsPanel imageId={id} />}
      {tab === 'sbom' && <SbomPanel imageId={id} />}
      {tab === 'binaries' && <BinariesPanel imageId={id} />}
      {/* Emulation: dynamic reproduction only — the deep static providers moved to Bootloader. */}
      {tab === 'simulate' && (
        <>
          <SimulationMenu imageId={id} />
          <FuzzPanel imageId={id} />
          <PresetsPanel imageId={id} />
        </>
      )}
      {tab === 'findings' && <ReportBuilder imageId={id} image={image} analysis={analysis} />}
      {tab === 'diff' && <DiffPanel imageId={id} />}
      {tab === 'opacidad' && <OpacidadPanel imageId={id} />}
      {tab === 'agent' && <AgentPanel imageId={id} />}
      {!analysis && !NO_ANALYSIS_TABS.has(tab) && (
        <div className="empty">
          <div className="empty-mark">0x—</div>
          <div className="empty-title">No static analysis</div>
          <div className="empty-body">
            This image hasn’t been analyzed yet, or analysis failed. Re-upload it from the Dashboard.
          </div>
        </div>
      )}
    </div>
  );
}

// === Dossier: the single view that builds up everything known about an image, honestly. ===

const PROOF_STATE_META: Record<ProofState, { label: string; color: string }> = {
  confirmed_full_system: { label: 'confirmed (full-system)', color: 'var(--ok, #4caf7d)' },
  confirmed_in_emulation: { label: 'confirmed (emulated)', color: 'var(--ok, #4caf7d)' },
  static_confirmed: { label: 'static-confirmed', color: 'var(--info, #4db5ff)' },
  needs_runtime_reproduction: { label: 'needs reproduction', color: 'var(--sev-medium, #e6b45c)' },
  blocked_by_platform: { label: 'blocked (platform)', color: 'var(--text-dim)' },
  blocked_by_security: { label: 'blocked (control)', color: 'var(--text-dim)' },
  false_positive: { label: 'false positive', color: 'var(--text-dim)' },
};

function ProofStateBadge({ state }: { state: ProofState }): JSX.Element {
  const m = PROOF_STATE_META[state];
  return (
    <span
      className="mono"
      style={{ color: m.color, border: `1px solid ${m.color}`, borderRadius: 4, padding: '1px 6px', fontSize: 10.5 }}
    >
      {m.label}
    </span>
  );
}

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--sev-critical, #e0524f)',
  high: 'var(--sev-high, #e06c4f)',
  medium: 'var(--sev-medium, #e6b45c)',
  low: 'var(--text-dim)',
  info: 'var(--text-dim)',
};

/** One row of the coverage strip: says whether an analysis stage ran, so the dossier never fakes completeness. */
function CoverageItem({ label, done, detail }: { label: string; done: boolean; detail?: string }): JSX.Element {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5 }}>
      <span style={{ color: done ? 'var(--ok, #4caf7d)' : 'var(--text-dim)' }}>{done ? '✓' : '○'}</span>
      <span style={{ color: done ? 'var(--text)' : 'var(--text-dim)' }}>{label}</span>
      {detail && <span className="hint mono">{detail}</span>}
    </div>
  );
}

/** One corpus cross-reference line: a recurring item + links to the other images it appears in. */
function CorpusRefRow({
  icon,
  label,
  images,
}: {
  icon: string;
  label: string;
  images: { id: string; filename: string }[];
}): JSX.Element {
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'baseline' }}>
      <span>{icon}</span>
      <span>{label}</span>
      {images.map((img) => (
        <Link key={img.id} to={`/image/${img.id}`} className="mono" style={{ fontSize: 11.5 }}>
          {img.filename}
        </Link>
      ))}
    </div>
  );
}

function DossierPanel({ image }: { image: ImageSummary }): JSX.Element {
  const id = image.id;
  const [findings, setFindings] = useState<Finding[]>([]);
  const [binaries, setBinaries] = useState<BinaryEntry[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [caps, setCaps] = useState<RuntimeCapabilities | null>(null);
  const [refs, setRefs] = useState<CorpusRefs | null>(null);
  const [agent, setAgent] = useState<AgentStatus | null>(null);
  const [copilot, setCopilot] = useState<CopilotResult | null>(null);
  const [copilotRunning, setCopilotRunning] = useState(false);
  const [copilotLog, setCopilotLog] = useState('');

  const runCopilot = useCallback(async () => {
    setCopilotRunning(true);
    setCopilotLog('');
    try {
      const { jobId } = await api.runCopilot(id);
      const job = await pollJob(jobId, setCopilotLog);
      if (job.status === 'done') setCopilot(job.result as CopilotResult);
    } catch (err) {
      toast.error(err);
    } finally {
      setCopilotRunning(false);
    }
  }, [id]);

  useEffect(() => {
    api
      .findings(id)
      .then(setFindings)
      .catch(() => setFindings([]));
    api
      .agentStatus()
      .then(setAgent)
      .catch(() => setAgent(null));
    api
      .copilotResult(id)
      .then(setCopilot)
      .catch(() => setCopilot(null));
    api
      .binaries(id)
      .then(setBinaries)
      .catch(() => setBinaries([]));
    api
      .jobs(id)
      .then(setJobs)
      .catch(() => setJobs([]));
    api
      .emulation(id)
      .then((m) => setCaps(m.capabilities))
      .catch(() => setCaps(null));
    api
      .corpusRefs(id)
      .then(setRefs)
      .catch(() => setRefs(null));
  }, [id]);

  const refCount = refs ? refs.credentials.length + refs.components.length + refs.artifacts.length : 0;

  const ranKind = (kind: string): boolean => jobs.some((j) => j.kind === kind && j.status === 'done');
  const triagedBinaries = binaries.filter((b) => b.triaged).length;

  const idn = image.identity;
  const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedFindings = [...findings].sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));

  return (
    <div>
      {/* The signal tape — the image read as signal along its byte axis; every panel below is a lens over it. */}
      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">Signal tape</div>
            <div className="panel-sub">
              Entropy trace over the structure carve, findings pinned to their offset. Scrub to read any byte range.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
            <span className="badge badge-accent">{idn?.firmwareClass ?? 'unknown'}</span>
            <span className="badge mono">
              {idn?.arch ?? '—'}/{idn?.endianness ?? '—'}
            </span>
            {(idn?.filesystems ?? []).map((fs) => (
              <span key={fs} className="badge mono">
                {fs}
              </span>
            ))}
          </div>
        </div>
        <SignalCanvas imageId={id} size={image.size} findings={findings} />
      </div>

      <div className="grid grid-3" style={{ margin: '16px 0' }}>
        <Stat label="Binaries" value={`${binaries.length} (${triagedBinaries} triaged)`} />
        <Stat label="Findings" value={String(findings.length)} />
        <Stat label="Runtime strategy" value={caps?.strategy ?? '—'} mono />
      </div>

      {agent?.enabled && (
        <div className="panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <div className="panel-title" style={{ margin: 0 }}>
              Copilot analysis
            </div>
            <span className="badge" title="LLM backing the copilot">
              {agent.provider} · {agent.model}
            </span>
            <div style={{ flex: 1 }} />
            <button type="button" className="btn btn-sm btn-primary" disabled={copilotRunning} onClick={runCopilot}>
              {copilotRunning ? (
                <>
                  <span className="spinner" /> Analyzing…
                </>
              ) : copilot ? (
                'Re-run'
              ) : (
                'Analyze'
              )}
            </button>
          </div>
          <div className="panel-sub">
            Interpretation over the cited findings — priors and proof-states, not new truth. The copilot runs nothing
            and invents nothing.
          </div>
          {copilotLog && !copilot && (
            <pre className="mono" style={{ fontSize: 11.5, color: 'var(--text-dim)', marginTop: 10 }}>
              {copilotLog}
            </pre>
          )}
          {copilot && (
            <div
              style={{ marginTop: 12, whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.5 }}
              className="copilot-output"
            >
              {copilot.text}
            </div>
          )}
        </div>
      )}

      <ResearchPanel imageId={id} />

      <div className="panel">
        <div className="panel-title">Coverage</div>
        <div className="panel-sub">What has run so far — the dossier never implies completeness it doesn't have.</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px 24px', marginTop: 10 }}>
          <CoverageItem label="Static analysis" done={image.status === 'ready'} />
          <CoverageItem label="Extraction" done={ranKind('extract')} />
          <CoverageItem label="SBOM & CVEs" done={ranKind('sbom')} />
          <CoverageItem label="Deep secrets (gitleaks)" done={ranKind('gitleaks')} />
          <CoverageItem
            label="Binary triage"
            done={triagedBinaries > 0}
            detail={binaries.length ? `${triagedBinaries}/${binaries.length}` : ''}
          />
          <CoverageItem label="Emulation" done={ranKind('emulate')} />
        </div>
        {caps && (
          <div className="hint" style={{ marginTop: 12 }}>
            Runtime preflight: <strong>{caps.strategy}</strong> — {caps.reason} (proof ceiling:{' '}
            <span className="mono">{caps.proofCeiling}</span>)
          </div>
        )}
      </div>

      {refCount > 0 && refs && (
        <div className="panel">
          <div className="panel-title">Corpus cross-references ({refCount})</div>
          <div className="panel-sub">
            Things in this image the corpus has seen elsewhere — priors worth checking, not conclusions.
          </div>
          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12.5 }}>
            {refs.credentials.map((c) => (
              <CorpusRefRow
                key={`c-${c.hash}`}
                icon="🔑"
                label={`${c.kind ?? 'credential'} — also in`}
                images={c.otherImages}
              />
            ))}
            {refs.components.map((c) => (
              <CorpusRefRow
                key={`p-${c.name}-${c.version}`}
                icon="📦"
                label={`${c.name} ${c.version}${c.cveCount > 0 ? ` (${c.cveCount} CVE)` : ''} — also in`}
                images={c.otherImages}
              />
            ))}
            {refs.artifacts.map((a) => (
              <CorpusRefRow key={`a-${a.sha1}`} icon="⚙" label={`${a.path} — same binary in`} images={a.otherImages} />
            ))}
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-title">Findings ({findings.length})</div>
        <div className="panel-sub">
          Each carries an explicit proof state — not just what was found, but how much it is proven.
        </div>
        {sortedFindings.length === 0 ? (
          <div className="hint">No findings yet. Run extraction, SBOM and the deep scans to populate the ledger.</div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Sev</th>
                  <th>Finding</th>
                  <th>Source</th>
                  <th>Proof state</th>
                </tr>
              </thead>
              <tbody>
                {sortedFindings.slice(0, 300).map((f) => (
                  <tr key={f.id}>
                    <td>
                      <span style={{ color: SEV_COLOR[f.severity] ?? 'var(--text-dim)' }}>●</span>
                    </td>
                    <td style={{ fontSize: 12.5 }}>{f.title}</td>
                    <td className="mono hint" style={{ fontSize: 11 }}>
                      {f.source}
                    </td>
                    <td>
                      <ProofStateBadge state={f.proofState} />
                    </td>
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

function SecretsPanel({ analysis, imageId }: { analysis: StaticAnalysis | null; imageId: string }): JSX.Element {
  const secrets = analysis?.secrets ?? [];
  return (
    <div>
      <div className="panel">
        <div className="panel-title">Secrets & credentials</div>
        <div className="panel-sub">Heuristic matches in the raw image (values shown are pre-extraction)</div>
        {secrets.length === 0 ? (
          <div className="hint">No secret-like strings detected in the raw image.</div>
        ) : (
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
                {secrets.map((s, i) => (
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
        )}
      </div>
      <GitleaksSection imageId={imageId} />
    </div>
  );
}

function GitleaksSection({ imageId }: { imageId: string }): JSX.Element {
  const [result, setResult] = useState<GitleaksResult | null>(null);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState('');

  useEffect(() => {
    api
      .gitleaks(imageId)
      .then(setResult)
      .catch(() => setResult(null));
  }, [imageId]);

  const run = useCallback(async () => {
    setRunning(true);
    setLog('');
    try {
      const { jobId } = await api.runGitleaks(imageId);
      const job = await pollJob(jobId, setLog);
      if (job.status === 'done') setResult(job.result as GitleaksResult);
    } catch (err) {
      setLog(String(err instanceof Error ? err.message : err));
    } finally {
      setRunning(false);
    }
  }, [imageId]);

  return (
    <div className="panel">
      <div className="panel-title">Deep secret scan (gitleaks)</div>
      <div className="panel-sub">Scans the extracted rootfs for keys, tokens, and credentials in files.</div>
      <button className="btn btn-primary" disabled={running} onClick={run}>
        {running ? (
          <>
            <span className="spinner" /> Scanning…
          </>
        ) : result?.available ? (
          'Re-scan rootfs'
        ) : (
          'Scan rootfs'
        )}
      </button>
      {result && !result.available && (
        <div className="banner banner-warn" style={{ marginTop: 14 }}>
          {result.reason ?? 'gitleaks unavailable — run extraction first, or install gitleaks.'}
        </div>
      )}
      {result?.available && (
        <div style={{ marginTop: 14 }}>
          <div className="hint" style={{ marginBottom: 10 }}>
            {result.findingCount} finding{result.findingCount === 1 ? '' : 's'} in the rootfs.
          </div>
          {result.findings.length > 0 && (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Match</th>
                  </tr>
                </thead>
                <tbody>
                  {result.findings.slice(0, 300).map((f, i) => (
                    <tr key={`${f.file}-${f.line}-${i}`}>
                      <td>{f.rule}</td>
                      <td className="mono">{f.file}</td>
                      <td className="mono">{f.line}</td>
                      <td className="mono">{f.match}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
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
          if (j.status === 'error') toast.error(j.error ?? 'Job failed');
          resolve(j);
        }
      } catch (err) {
        window.clearInterval(timer);
        toast.error(err);
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

          {result.packages.length > 0 && (
            <div className="panel">
              <div className="panel-head" style={{ marginBottom: 4 }}>
                <div>
                  <div className="panel-title">Component graph</div>
                  <div className="panel-sub">
                    The rootfs and its components, grouped by ecosystem around the ring and coloured by the worst CVE
                    affecting each. Hover a node for its version and CVEs.
                  </div>
                </div>
              </div>
              <SbomGraph sbom={result} />
            </div>
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

/** Compact NX / stack-canary / PIC indicators. 1 = present (good), 0 = missing (weak), null = unknown. */
function HardeningBadges({
  nx,
  canary,
  pic,
}: { nx: number | null; canary: number | null; pic: number | null }): JSX.Element {
  const chip = (label: string, v: number | null): JSX.Element => {
    const color = v === 1 ? 'var(--ok, #4caf7d)' : v === 0 ? 'var(--sev-high, #e06c4f)' : 'var(--text-dim)';
    return (
      <span key={label} style={{ color, marginRight: 6 }}>
        {v === 1 ? '✓' : v === 0 ? '✗' : '?'}
        {label}
      </span>
    );
  };
  return (
    <>
      {chip('NX', nx)}
      {chip('CAN', canary)}
      {chip('PIC', pic)}
    </>
  );
}

function BinariesPanel({ imageId }: { imageId: string }): JSX.Element {
  const [result, setResult] = useState<DecompileResult | null>(null);
  const [binary, setBinary] = useState('');
  const [rootfsReady, setRootfsReady] = useState<boolean | null>(null);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState('');
  const [binaries, setBinaries] = useState<BinaryEntry[]>([]);

  const refreshBinaries = useCallback(() => {
    api
      .binaries(imageId)
      .then(setBinaries)
      .catch(() => setBinaries([]));
  }, [imageId]);

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
    refreshBinaries();
  }, [imageId, refreshBinaries]);

  const run = useCallback(async () => {
    if (!binary.trim()) return;
    setRunning(true);
    setLog('');
    try {
      const { jobId } = await api.decompile(imageId, binary.trim());
      const job = await pollJob(jobId, setLog);
      if (job.status === 'done') {
        setResult(job.result as DecompileResult);
        refreshBinaries();
      }
    } catch (err) {
      setLog(String(err instanceof Error ? err.message : err));
    } finally {
      setRunning(false);
    }
  }, [imageId, binary, refreshBinaries]);

  const info = result?.info;

  return (
    <div>
      {binaries.length > 0 && (
        <div className="panel">
          <div className="panel-title">Binaries ({binaries.length})</div>
          <div className="panel-sub">
            Every ELF from the extracted rootfs, with architecture from its header. Select one to triage it.
          </div>
          <div className="table-wrap" style={{ marginTop: 12 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Arch</th>
                  <th>Hardening</th>
                  <th>Notable imports</th>
                  <th>Net</th>
                </tr>
              </thead>
              <tbody>
                {binaries.map((b) => (
                  <tr
                    key={b.path}
                    onClick={() => setBinary(b.path)}
                    style={{ cursor: 'pointer', background: b.path === binary ? 'var(--surface-2)' : undefined }}
                  >
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {b.path}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {b.arch ?? '—'}
                      {b.bits ? ` ${b.bits}` : ''}
                      {b.endianness ? ` ${b.endianness === 'big' ? 'BE' : 'LE'}` : ''}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {b.triaged ? <HardeningBadges nx={b.nx} canary={b.canary} pic={b.pic} /> : '—'}
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--sev-high, #e6a15c)' }}>
                      {b.importsSummary ?? ''}
                    </td>
                    <td>{b.networkFacing ? '🌐' : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
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

      <GhidraDecompile imageId={imageId} binary={binary} />
    </div>
  );
}

function GhidraDecompile({ imageId, binary }: { imageId: string; binary: string }): JSX.Element {
  const [result, setResult] = useState<GhidraResult | null>(null);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState('');
  const [open, setOpen] = useState<number | null>(null);

  useEffect(() => {
    api
      .ghidraResult(imageId)
      .then(setResult)
      .catch(() => setResult(null));
  }, [imageId]);

  const run = useCallback(async () => {
    if (!binary.trim()) return;
    setRunning(true);
    setLog('');
    try {
      const { jobId } = await api.ghidra(imageId, binary.trim());
      const job = await pollJob(jobId, setLog);
      if (job.status === 'done') setResult(job.result as GhidraResult);
    } catch (err) {
      setLog(String(err instanceof Error ? err.message : err));
    } finally {
      setRunning(false);
    }
  }, [imageId, binary]);

  return (
    <div className="panel">
      <div className="panel-title">Decompilation (Ghidra)</div>
      <div className="panel-sub">Full pseudocode via Ghidra headless — needs the optional Ghidra image layer.</div>
      <button className="btn" disabled={running || !binary.trim()} onClick={run}>
        {running ? (
          <>
            <span className="spinner" /> Decompiling…
          </>
        ) : (
          'Decompile with Ghidra'
        )}
      </button>
      {result && !result.available && (
        <div className="banner banner-info" style={{ marginTop: 14 }}>
          {result.reason ?? 'Ghidra not installed — build the image with the optional Ghidra layer.'}
        </div>
      )}
      {result?.available && (
        <div style={{ marginTop: 12 }}>
          <div className="hint" style={{ marginBottom: 8 }}>
            {result.functionCount} functions decompiled from {result.binary}.
          </div>
          {result.functions.map((fn, i) => (
            <div key={`${fn.name}-${i}`} style={{ marginBottom: 6 }}>
              <button
                type="button"
                className="btn btn-sm mono"
                style={{ width: '100%', textAlign: 'left' }}
                onClick={() => setOpen(open === i ? null : i)}
              >
                {open === i ? '▾' : '▸'} {fn.signature || fn.name}
              </button>
              {open === i && (
                <pre
                  className="mono"
                  style={{ fontSize: 11.5, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', margin: '4px 0 0' }}
                >
                  {fn.pseudocode}
                </pre>
              )}
            </div>
          ))}
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

function DiffPanel({ imageId }: { imageId: string }): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
  const [against, setAgainst] = useState('');
  const [result, setResult] = useState<FirmwareDiffResult | null>(null);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState('');

  useEffect(() => {
    api
      .listImages()
      .then((all) => setImages(all.filter((im) => im.id !== imageId)))
      .catch(() => setImages([]));
  }, [imageId]);

  // Load any previously computed diff when the target changes.
  useEffect(() => {
    setResult(null);
    if (!against) return;
    api
      .diffResult(imageId, against)
      .then(setResult)
      .catch(() => setResult(null));
  }, [imageId, against]);

  const run = useCallback(async () => {
    if (!against) return;
    setRunning(true);
    setLog('');
    try {
      const { jobId } = await api.runDiff(imageId, against);
      const job = await pollJob(jobId, setLog);
      if (job.status === 'done') setResult(job.result as FirmwareDiffResult);
    } catch (err) {
      setLog(String(err instanceof Error ? err.message : err));
    } finally {
      setRunning(false);
    }
  }, [imageId, against]);

  return (
    <div>
      <div className="panel">
        <div className="panel-title">Compare firmware</div>
        <div className="panel-sub">
          Diff identity, packages/CVEs (needs SBOM on both), and rootfs files (needs extraction).
        </div>
        {images.length === 0 ? (
          <div className="hint">Upload a second image to compare against.</div>
        ) : (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <select
              className="input"
              value={against}
              onChange={(e) => setAgainst(e.target.value)}
              style={{ flex: '1 1 240px', minWidth: 0 }}
            >
              <option value="">Select an image to compare against…</option>
              {images.map((im) => (
                <option key={im.id} value={im.id}>
                  {im.filename}
                </option>
              ))}
            </select>
            <button className="btn btn-primary" disabled={running || !against} onClick={run}>
              {running ? (
                <>
                  <span className="spinner" /> Comparing…
                </>
              ) : (
                'Compare'
              )}
            </button>
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

      {result && (
        <>
          <div className="panel">
            <div className="panel-title">Identity</div>
            {result.identity.length === 0 ? (
              <div className="hint">No identity differences.</div>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>Field</th>
                      <th className="mono">{result.a.filename}</th>
                      <th className="mono">{result.b.filename}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.identity.map((c) => (
                      <tr key={c.field}>
                        <td>{c.field}</td>
                        <td className="mono">{c.a || '—'}</td>
                        <td className="mono">{c.b || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-title">Packages</div>
            {!result.packages.hasData ? (
              <div className="hint">Run SBOM on both images to diff packages.</div>
            ) : (
              <>
                <div className="grid grid-3" style={{ marginBottom: 12 }}>
                  <Stat label="Added" value={String(result.packages.added.length)} />
                  <Stat label="Removed" value={String(result.packages.removed.length)} />
                  <Stat label="Version-changed" value={String(result.packages.changed.length)} />
                </div>
                {result.packages.changed.length > 0 && (
                  <div className="table-wrap">
                    <table className="data">
                      <thead>
                        <tr>
                          <th>Package</th>
                          <th>{result.a.filename}</th>
                          <th>{result.b.filename}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.packages.changed.slice(0, 300).map((c) => (
                          <tr key={c.name}>
                            <td>{c.name}</td>
                            <td className="mono">{c.a}</td>
                            <td className="mono">{c.b}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>

          <div className="panel">
            <div className="panel-title">CVEs</div>
            {!result.cves.hasData ? (
              <div className="hint">Run SBOM on both images to diff CVEs.</div>
            ) : (
              <>
                <div className="legend" style={{ marginBottom: 10 }}>
                  <span className="badge badge-ok">+{result.cves.addedIds.length} added</span>
                  <span className="badge badge-info">−{result.cves.removedIds.length} removed</span>
                  {SEVERITY_ORDER.filter((s) => result.cves.addedBySeverity[s] > 0).map((s) => (
                    <span key={s} className={`badge ${SEVERITY_BADGE[s]}`}>
                      +{result.cves.addedBySeverity[s]} {s}
                    </span>
                  ))}
                </div>
                <div className="hint mono" style={{ wordBreak: 'break-word' }}>
                  {result.cves.addedIds.slice(0, 60).join(', ') || 'No newly-introduced CVEs.'}
                </div>
              </>
            )}
          </div>

          <div className="panel">
            <div className="panel-title">Root filesystem</div>
            {!result.files.hasData ? (
              <div className="hint">Run extraction on both images to diff files.</div>
            ) : (
              <div className="grid grid-3">
                <Stat label="Added" value={String(result.files.counts.added)} />
                <Stat label="Removed" value={String(result.files.counts.removed)} />
                <Stat label="Changed (size)" value={String(result.files.counts.changed)} />
              </div>
            )}
          </div>
        </>
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

// === External intelligence (Phase 5): OSINT + published-vuln correlation, the only network-touching surface. ===

function ResearchPanel({ imageId }: { imageId: string }): JSX.Element | null {
  const [status, setStatus] = useState<ResearchStatus | null>(null);
  const [result, setResult] = useState<ResearchResult | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    api
      .researchStatus()
      .then(setStatus)
      .catch(() => setStatus({ enabled: false }));
    api
      .researchResult(imageId)
      .then(setResult)
      .catch(() => setResult(null));
  }, [imageId]);

  const run = useCallback(async () => {
    setRunning(true);
    try {
      const { jobId } = await api.runResearch(imageId);
      const job = await pollJob(jobId, () => undefined);
      if (job.status === 'done') setResult(job.result as ResearchResult);
    } catch (err) {
      toast.error(err);
    } finally {
      setRunning(false);
    }
  }, [imageId]);

  if (!status) return null;

  if (!status.enabled) {
    return (
      <div className="panel" style={{ borderStyle: 'dashed' }}>
        <div className="panel-title">
          External intelligence <span className="badge">off</span>
        </div>
        <div className="panel-sub" style={{ margin: 0 }}>
          The only feature that leaves this machine. Enable with <span className="mono">FIRMLAB_RESEARCH=1</span> to
          correlate the SBOM against public advisories (OSV) and draft responsible-disclosure notes. Off by default —
          FirmLab stays local-only.
        </div>
      </div>
    );
  }

  const osv = result?.osv;
  const nvd = result?.nvd;
  const kev = result?.kev;
  return (
    <div className="panel">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <div className="panel-title" style={{ margin: 0 }}>
          External intelligence
        </div>
        <span className="prov prov-heuristic" title="Correlated from public sources; reachability unverified">
          public sources
        </span>
        <div style={{ flex: 1 }} />
        <button type="button" className="btn btn-sm btn-primary" disabled={running} onClick={run}>
          {running ? (
            <>
              <span className="spinner" /> Researching…
            </>
          ) : result ? (
            'Re-run'
          ) : (
            'Run research'
          )}
        </button>
      </div>
      <div className="panel-sub">
        Sends only component names + versions to the vuln databases (OSV, NVD); downloads the CISA KEV catalog to flag
        known-exploited CVEs locally. Never firmware bytes, secrets, or keys. A published advisory for a present
        component is a lead, not a confirmed bug (reachability is decided per-image).
      </div>

      {result && osv && (
        <div style={{ marginTop: 4 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
            <span className="badge" title="OSV: ecosystem-mapped SBOM components queried">
              OSV {osv.queried} queried
            </span>
            <span className="badge badge-high">{osv.totalAdvisories} OSV advisories</span>
            {nvd && (nvd.queried > 0 || nvd.totalAdvisories > 0) && (
              <span className="badge" title="NVD: keyword search for components OSV could not map">
                NVD {nvd.queried} queried · {nvd.totalAdvisories} advisories
              </span>
            )}
            {kev?.checked && (
              <span
                className={`badge ${kev.matches.length > 0 ? 'badge-high' : 'badge-ok'}`}
                title="CISA Known Exploited Vulnerabilities — exploited in the wild"
              >
                KEV {kev.matches.length} known-exploited
              </span>
            )}
            {result.provenance.vendors.slice(0, 4).map((v) => (
              <span key={v} className="badge badge-accent" title="Provenance hint (vendor)">
                {v}
              </span>
            ))}
          </div>

          {kev?.checked && kev.matches.length > 0 && (
            <div
              style={{
                marginBottom: 12,
                border: '1px solid var(--border)',
                borderRadius: 8,
                padding: '10px 12px',
                background: 'var(--bg)',
              }}
            >
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                ⚠ Known-exploited in the wild (CISA KEV) · reachability here still unverified
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                {kev.matches.slice(0, 10).map((m) => (
                  <div key={m.cveID} style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${m.cveID}`}
                      target="_blank"
                      rel="noreferrer"
                      className="badge badge-high mono"
                    >
                      {m.cveID}
                    </a>
                    <span className="mono hint">
                      {m.vendorProject} {m.product}
                    </span>
                    {m.knownRansomware === 'Known' && (
                      <span className="badge badge-high" title="Used in known ransomware campaigns">
                        ransomware
                      </span>
                    )}
                    <span className="hint" title={m.shortDescription}>
                      added {m.dateAdded}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {osv.components.length > 0 && (
            <div className="table-wrap" style={{ marginBottom: 12 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>Advisories (reachability unverified)</th>
                  </tr>
                </thead>
                <tbody>
                  {osv.components.slice(0, 12).map((c) => (
                    <tr key={`${c.name}@${c.version}`}>
                      <td className="mono">
                        {c.name} {c.version}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                          {c.advisories.slice(0, 8).map((a) => {
                            const label = a.aliases.find((x) => x.startsWith('CVE-')) ?? a.id;
                            const href = a.references[0];
                            return href ? (
                              <a
                                key={a.id}
                                href={href}
                                target="_blank"
                                rel="noreferrer"
                                className="badge mono"
                                title={a.summary}
                              >
                                {label}
                              </a>
                            ) : (
                              <span key={a.id} className="badge mono" title={a.summary}>
                                {label}
                              </span>
                            );
                          })}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {nvd && nvd.components.length > 0 && (
            <div className="table-wrap" style={{ marginBottom: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                NVD · keyword matches for components OSV couldn't map (reachability unverified)
              </div>
              <table className="data">
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>CVEs (NVD keyword)</th>
                  </tr>
                </thead>
                <tbody>
                  {nvd.components.slice(0, 12).map((c) => (
                    <tr key={`nvd-${c.name}@${c.version}`}>
                      <td className="mono">
                        {c.name} {c.version}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                          {c.advisories.slice(0, 8).map((a) => {
                            const href = a.references[0] ?? `https://nvd.nist.gov/vuln/detail/${a.id}`;
                            const sev = a.severity ? ` · ${a.severity}` : '';
                            return (
                              <a
                                key={a.id}
                                href={href}
                                target="_blank"
                                rel="noreferrer"
                                className="badge mono"
                                title={`${a.summary}${sev}`}
                              >
                                {a.id}
                              </a>
                            );
                          })}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.keyMaterial.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                Key material · embedded keys are effectively public
              </div>
              {result.keyMaterial.map((k) => (
                <div
                  key={k.kind + k.redacted}
                  style={{
                    display: 'flex',
                    gap: 8,
                    alignItems: 'baseline',
                    fontSize: 12.5,
                    marginBottom: 3,
                    flexWrap: 'wrap',
                  }}
                >
                  <span className="badge">{k.kind}</span>
                  <span className="mono hint">{k.redacted}</span>
                  {k.effectivelyPublic && (
                    <span className="badge badge-high" title="Extractable from any device running this firmware">
                      effectively public
                    </span>
                  )}
                  {(k.sharedInImages ?? 0) > 0 && (
                    <span className="badge badge-medium">reused in {k.sharedInImages} other image(s)</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {result.securityContacts.some((c) => c.checked) && (
            <div style={{ marginBottom: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                Responsible disclosure · security.txt
              </div>
              {result.securityContacts.map((c) => (
                <div key={c.domain} style={{ fontSize: 12.5, marginBottom: 3 }}>
                  <span className="mono">{c.domain}</span>{' '}
                  {c.found ? (
                    c.contact.map((x) => (
                      <span key={x} className="badge badge-ok" style={{ marginRight: 4 }}>
                        {x}
                      </span>
                    ))
                  ) : (
                    <span className="hint">{c.reason ?? 'no security.txt'}</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {result.synthesis && (
            <>
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                Brief · {result.synthesis.provider} · {result.synthesis.model}
              </div>
              <div style={{ whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.5 }}>{result.synthesis.text}</div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// === Agent: the conscious-autonomy session view — what the agent chose at each node, and why (Phase 3). ===

const SESSION_META: Record<AgentSession['status'], { label: string; color: string }> = {
  running: { label: 'running', color: 'var(--info, #4db5ff)' },
  awaiting_approval: { label: 'awaiting approval', color: 'var(--sev-medium, #e6b45c)' },
  done: { label: 'done', color: 'var(--ok, #4caf7d)' },
  error: { label: 'error', color: 'var(--sev-critical, #e0524f)' },
  halted: { label: 'halted (governor)', color: 'var(--text-dim)' },
};

const NODE_LABEL: Record<string, string> = {
  triage: '① Triage',
  extraction: 'Extraction (deterministic)',
  preflight: 'Preflight (deterministic)',
  'target-selection': '② Target selection',
  emulation: 'Emulation',
  error: 'Error',
};

/** The emulation plan the target-selection node produced, read from the latest such step. */
function emulationPlanOf(steps: AgentStep[]): { binary: string; rung: string }[] {
  const step = [...steps].reverse().find((s) => s.node === 'target-selection' && s.output);
  const out = step?.output as { emulationPlan?: { binary: string; rung: string }[] } | undefined;
  return out?.emulationPlan ?? [];
}

function StepCard({ step }: { step: AgentStep }): JSX.Element {
  const out = step.output as Record<string, unknown> | null;
  const highlights: ReactNode[] = [];
  if (step.node === 'triage' && out) {
    highlights.push(
      <div key="h">
        class <b>{String(out.resolvedClass)}</b> ({String(out.classConfidence)}) · extract:{' '}
        <b>{out.shouldExtract ? 'yes' : 'no'}</b>
        {Array.isArray(out.extractionCascade) && out.extractionCascade.length > 0 && (
          <> · cascade {(out.extractionCascade as string[]).join(' → ')}</>
        )}
      </div>,
    );
    if (Array.isArray(out.attackSurface) && out.attackSurface.length > 0)
      highlights.push(<div key="a">attack surface: {(out.attackSurface as string[]).join(', ')}</div>);
  } else if (step.node === 'preflight' && out) {
    highlights.push(
      <div key="p">
        strategy <b>{String(out.strategy)}</b> · ceiling <b>{String(out.proofCeiling)}</b>
      </div>,
    );
  } else if (step.node === 'extraction' && out) {
    highlights.push(
      <div key="e">
        {out.rootfs ? '✓ rootfs' : '○ no rootfs'} · {String(out.extractor ?? '—')} · arch{' '}
        {String(out.detectedArch ?? '—')} · {String(out.files ?? '?')} files
      </div>,
    );
  } else if (step.node === 'target-selection' && out) {
    const targets = (out.targets as { path: string; rung: string; priority: string; reason: string }[]) ?? [];
    highlights.push(
      <div key="t" style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {targets.map((t) => (
          <div key={t.path} className="mono" style={{ fontSize: 12 }}>
            <span style={{ color: 'var(--text)' }}>{t.path}</span> <span className="badge">{t.rung}</span>{' '}
            <span className="hint">{t.priority}</span> — {t.reason}
          </div>
        ))}
        {targets.length === 0 && <span className="hint">no targets selected</span>}
      </div>,
    );
  } else if (step.node === 'emulation' && out) {
    highlights.push(
      <div key="m">
        ran <b>{out.ran ? 'yes' : 'no'}</b> · exit {String(out.exitCode ?? '—')} · proof-state{' '}
        {typeof out.proofState === 'string' && (PROOF_STATE_META as Record<string, unknown>)[out.proofState] ? (
          <ProofStateBadge state={out.proofState as ProofState} />
        ) : (
          <b>{String(out.proofState)}</b>
        )}
      </div>,
    );
  }

  const dot =
    step.status === 'ok'
      ? 'var(--ok, #4caf7d)'
      : step.status === 'error'
        ? 'var(--sev-critical, #e0524f)'
        : 'var(--text-dim)';
  return (
    <div className="panel" style={{ marginTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ color: dot }}>●</span>
        <b>{NODE_LABEL[step.node] ?? step.node}</b>
        {step.model && <span className="badge">{step.model}</span>}
        {step.inputTokens + step.outputTokens > 0 && (
          <span className="hint mono">{step.inputTokens + step.outputTokens} tok</span>
        )}
      </div>
      <div
        style={{ marginTop: 6, fontSize: 12.5, color: 'var(--text)', display: 'flex', flexDirection: 'column', gap: 4 }}
      >
        {highlights}
      </div>
      {step.rationale && (
        <div style={{ marginTop: 6, fontSize: 12.5, fontStyle: 'italic', color: 'var(--text-dim)' }}>
          {step.rationale}
        </div>
      )}
      {(step.input != null || step.output != null) && (
        <details style={{ marginTop: 6 }}>
          <summary className="hint" style={{ cursor: 'pointer' }}>
            audit: inputs & decision
          </summary>
          <pre className="mono" style={{ fontSize: 10.5, color: 'var(--text-dim)', overflowX: 'auto' }}>
            {JSON.stringify({ input: step.input, output: step.output }, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}

function BudgetGauge({ session }: { session: AgentSession }): JSX.Element {
  const b = session.budget;
  const c = session.consumed;
  const row = (label: string, used: string, cap: string) => (
    <div style={{ display: 'flex', gap: 6, fontSize: 12 }}>
      <span className="hint" style={{ minWidth: 56 }}>
        {label}
      </span>
      <span className="mono">
        {used} / {cap}
      </span>
    </div>
  );
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 24px', marginTop: 8 }}>
      {row('steps', String(c.steps), String(b.maxSteps))}
      {row('tokens', String(c.inputTokens + c.outputTokens), String(b.maxTokens))}
      {row('cost', `$${c.usd.toFixed(4)}`, b.maxUsd > 0 ? `$${b.maxUsd}` : '∞')}
      {row('time', `${Math.round(c.elapsedMs / 1000)}s`, `${Math.round(b.maxWallMs / 1000)}s`)}
    </div>
  );
}

function AgentPanel({ imageId }: { imageId: string }): JSX.Element {
  const [config, setConfig] = useState<AgentConfig | null>(null);
  const [session, setSession] = useState<AgentSession | null>(null);
  const [steps, setSteps] = useState<AgentStep[]>([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const view = await api.agentSession(imageId);
    setSession(view.session);
    setSteps(view.steps);
    return view.session;
  }, [imageId]);

  useEffect(() => {
    api
      .agentConfig()
      .then(setConfig)
      .catch(() => setConfig({ enabled: false }));
    load().catch(() => undefined);
  }, [load]);

  // Poll while a session is actively running (not while awaiting approval or terminal).
  useEffect(() => {
    if (session?.status !== 'running') return;
    const timer = window.setInterval(() => {
      load().catch(() => undefined);
    }, 1200);
    return () => window.clearInterval(timer);
  }, [session?.status, load]);

  const start = useCallback(async () => {
    setBusy(true);
    try {
      await api.startAgentSession(imageId);
      await load();
    } catch (err) {
      toast.error(err);
    } finally {
      setBusy(false);
    }
  }, [imageId, load]);

  const approve = useCallback(
    async (binary: string) => {
      if (!session) return;
      setBusy(true);
      try {
        const view = await api.approveEmulation(session.id, binary);
        setSession(view.session);
        setSteps(view.steps);
      } catch (err) {
        toast.error(err);
      } finally {
        setBusy(false);
      }
    },
    [session],
  );

  const decline = useCallback(async () => {
    if (!session) return;
    setBusy(true);
    try {
      const view = await api.declineEmulation(session.id);
      setSession(view.session);
      setSteps(view.steps);
    } catch (err) {
      toast.error(err);
    } finally {
      setBusy(false);
    }
  }, [session]);

  if (config && !config.enabled) {
    return (
      <div className="panel">
        <div className="panel-title">Agent — conscious autonomy</div>
        <div className="panel-sub">
          Disabled. Set <span className="mono">FIRMLAB_AGENT=1</span> and an LLM API key to enable the decision nodes.
          With the flag off, FirmLab stays local-only, deterministic, no-network, no-cost.
        </div>
      </div>
    );
  }

  const running = session?.status === 'running';
  const awaiting = session?.status === 'awaiting_approval';
  const plan = emulationPlanOf(steps);

  return (
    <div>
      <div className="panel">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div className="panel-title" style={{ margin: 0 }}>
            Agent session
          </div>
          {config?.model && (
            <span className="badge">
              {config.provider} · {config.model}
            </span>
          )}
          {session && (
            <span className="mono" style={{ color: SESSION_META[session.status].color, fontSize: 12 }}>
              {SESSION_META[session.status].label}
            </span>
          )}
          <div style={{ flex: 1 }} />
          <button type="button" className="btn btn-sm btn-primary" disabled={busy || running} onClick={start}>
            {running ? (
              <>
                <span className="spinner" /> Running…
              </>
            ) : session ? (
              'New session'
            ) : (
              'Start session'
            )}
          </button>
        </div>
        <div className="panel-sub">
          The agent reasons within a deterministic skeleton: it chooses branches (triage ①, target selection ②) and
          interprets — every mechanical step is deterministic, and emulation waits for your approval. A governor caps
          the run.
        </div>
        {session && <BudgetGauge session={session} />}
        {session?.haltReason && (
          <div style={{ marginTop: 8, fontSize: 12.5, color: 'var(--sev-medium, #e6b45c)' }}>
            ⚠ {session.haltReason}
          </div>
        )}
      </div>

      {awaiting && plan.length > 0 && (
        <div className="panel" style={{ borderColor: 'var(--sev-medium, #e6b45c)' }}>
          <div className="panel-title">Approval required — proposed emulation</div>
          <div className="panel-sub">
            The agent proposes running these under emulation. Emulation proves the sandbox, not the device; nothing runs
            without your approval.
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
            {plan.map((p) => (
              <div key={p.binary} style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span className="mono">{p.binary}</span>
                <span className="badge">{p.rung}</span>
                <div style={{ flex: 1 }} />
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  disabled={busy}
                  onClick={() => approve(p.binary)}
                >
                  Approve & run
                </button>
              </div>
            ))}
            <div>
              <button type="button" className="btn btn-sm" disabled={busy} onClick={decline}>
                Decline all
              </button>
            </div>
          </div>
        </div>
      )}

      {steps.length === 0 && !session && (
        <div className="empty">No agent session yet. Start one to have the agent triage and select targets.</div>
      )}
      {steps.map((s) => (
        <StepCard key={s.seq} step={s} />
      ))}
    </div>
  );
}
