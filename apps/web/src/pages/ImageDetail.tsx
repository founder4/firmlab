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
  type Finding,
  type FindingProvenance,
  type FirmwareDiffResult,
  type FsNode,
  type FsSummary,
  type GitleaksResult,
  type ImageSummary,
  type Job,
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
import { CapabilityResults } from '../components/CapabilityResults';
import { ComponentMap } from '../components/ComponentMap';
import { CoverageBanner } from '../components/CoverageBanner';
import { EntropyChart } from '../components/EntropyChart';
import { FileBrowser } from '../components/FileBrowser';
import { FileSearch } from '../components/FileSearch';
import { FilesystemTree } from '../components/FilesystemTree';
import { FindingsLedger, PROOF_STATE_META } from '../components/FindingsLedger';
import { FuzzPanel } from '../components/FuzzPanel';
import { HardwareInterfaces } from '../components/HardwareInterfaces';
import { OpacidadPanel } from '../components/OpacidadPanel';
import { OperatorPanel } from '../components/OperatorPanel';
import { PresetsPanel } from '../components/PresetsPanel';
import { ReportBuilder } from '../components/ReportBuilder';
import { RunHistory } from '../components/RunHistory';
import { SbomGraph } from '../components/SbomGraph';
import { SectionIndex } from '../components/SectionIndex';
import { SignalCanvas } from '../components/SignalCanvas';
import { SimulationMenu } from '../components/SimulationMenu';
import { StepTimeline } from '../components/StepTimeline';
import { StructureMap } from '../components/StructureMap';
import { SymReachPanel } from '../components/SymReachPanel';
import { TestBench } from '../components/TestBench';
import { UpdatePathPanel } from '../components/UpdatePathPanel';
import { type Messages, messages, useLocale, useMessages } from '../i18n';
import { Markdown } from '../markdown';
import { toast } from '../toast';

/**
 * The URL sections this screen serves, as ROUTE segments — English forever, because a translated URL breaks every
 * saved link and every screenshot in the docs.
 *
 * `satisfies` pins the list to the shared `sections` catalogue: an id added here that the catalogue cannot label is
 * a compile error, and the label itself is read from `t.sections` at render time. This file used to carry its own
 * `SECTION_TITLES` map beside the catalogue's, which is two lists of the same thing and one commit away from
 * disagreeing.
 */
const SECTION_IDS = [
  'dossier',
  'overview',
  'structure',
  'entropy',
  'filesystem',
  'files',
  'secrets',
  'hardware',
  'bootloader',
  'sbom',
  'compmap',
  'deepscans',
  'binaries',
  'testbench',
  'findings',
  'operator',
  'diff',
  'simulate',
  'opacidad',
  'agent',
] as const satisfies readonly (keyof Messages['sections'])[];

type TabId = (typeof SECTION_IDS)[number];

const SECTION_SET: ReadonlySet<string> = new Set<string>(SECTION_IDS);

/** Sections that operate on the extracted rootfs / tools rather than the cached static analysis. */
const NO_ANALYSIS_TABS = new Set<TabId>([
  'dossier',
  'deepscans',
  'filesystem',
  'files',
  'secrets',
  'hardware',
  'bootloader',
  'sbom',
  'compmap',
  'binaries',
  'testbench',
  'findings',
  'operator',
  'diff',
  'simulate',
  'opacidad',
  'agent',
]);

function resolveSection(section: string | undefined): TabId {
  if (!section || section === 'overview') return 'dossier';
  return SECTION_SET.has(section) ? (section as TabId) : 'dossier';
}

/**
 * A proof state as this screen states it: the CODE verbatim, then its gloss.
 *
 * The code is an identifier — it crosses the API and lands in SQLite, and rendering `confirmado_en_emulación`
 * anywhere would invent a value the workbench does not use. What is localised is the sentence beside it, and that
 * sentence is the load-bearing part: `confirmed_in_emulation` proves the sandbox and never the physical device,
 * `blocked_by_*` means the question WAS asked and could not be answered. Both come from the shared `proofState`
 * namespace rather than being restated here, so this screen and the findings ledger cannot word them differently.
 */
function ProofStateChip({ state }: { state: FindingProvenance }): JSX.Element {
  const t = useMessages();
  const color = PROOF_STATE_META[state].color;
  return (
    <span
      title={t.proofState.meaning[state]}
      style={{ display: 'inline-flex', gap: 6, alignItems: 'baseline', flexWrap: 'wrap' }}
    >
      <span
        className="mono"
        style={{ color, border: `1px solid ${color}`, borderRadius: 4, padding: '1px 6px', fontSize: 10.5 }}
      >
        {state}
      </span>
      <span className="hint">{t.proofState.label[state]}</span>
    </span>
  );
}

export function ImageDetail(): JSX.Element {
  const { id = '', section } = useParams();
  const t = useMessages();
  // The export follows the language the workbench is being read in. The API's resolver is total — an unknown value
  // falls back to English — so the parameter is safe to append unconditionally.
  const locale = useLocale();
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
          <div className="eyebrow">
            {t.imageDetail.header.eyebrow(image.identity?.arch ?? t.imageDetail.header.unknownArch)}
          </div>
          <h1 className="page-title">{t.sections[tab]}</h1>
          <div className="hint mono" style={{ wordBreak: 'break-all' }}>
            {image.sha256.slice(0, 24)}… · {fmtBytes(image.size)}
          </div>
        </div>
        {/* `download` carries no value on purpose: the server's content-disposition names the file with the locale
            suffix, so the two languages of one report do not overwrite each other. Hardcoding a name breaks that. */}
        <a className="btn btn-sm" href={`/api/images/${id}/report?lang=${locale}`} download>
          <span aria-hidden="true">⭳</span> {t.imageDetail.header.report}
        </a>
        <a
          className="btn btn-sm"
          href={`/api/images/${id}/disclosure-report?lang=${locale}`}
          download
          title={t.imageDetail.header.disclosureTitle}
        >
          <span aria-hidden="true">⭳</span> {t.imageDetail.header.disclosure}
        </a>
      </div>

      <StepTimeline imageId={id} active={tab} ready={image.status === 'ready'} />

      {tab === 'dossier' && <DossierPanel image={image} sectionIds={SECTION_IDS} />}
      {tab === 'structure' && analysis && <StructurePanel analysis={analysis} />}
      {tab === 'entropy' && analysis && <EntropyPanel analysis={analysis} />}
      {/* Extraction: the carved rootfs and what it exposes — files + secrets in one place. */}
      {tab === 'filesystem' && (
        <>
          <FilesystemPanel imageId={id} />
          <SecretsPanel analysis={analysis} imageId={id} />
        </>
      )}
      {/* File browser: the surface that lets a finding's evidence be checked instead of trusted. */}
      {tab === 'files' && (
        <>
          <FileBrowser imageId={id} />
          {/* The other direction: the browser answers "what does this file say", this answers "which file says this". */}
          <FileSearch imageId={id} />
        </>
      )}
      {tab === 'secrets' && <SecretsPanel analysis={analysis} imageId={id} />}
      {/* What the firmware declares about the physical ways in. Reads stored results; connects to nothing. */}
      {tab === 'hardware' && <HardwareInterfaces imageId={id} />}
      {/* Bootloader: the deep static config/boot providers (u-boot env, /etc audit, certs, services…). */}
      {tab === 'bootloader' && (
        <>
          <AnalysisActionsPanel imageId={id} />
          {/* The update-path provider is launched from the panel above and its result had nowhere to be read: the
              findings landed in the ledger, the updaters and the source chain that credited them did not. */}
          <UpdatePathPanel imageId={id} />
        </>
      )}
      {tab === 'sbom' && <SbomPanel imageId={id} />}
      {/* The other half of "what is this made of": the SBOM's packages, and here what links against what. */}
      {tab === 'compmap' && <ComponentMap imageId={id} />}
      {tab === 'deepscans' && <CapabilityResults imageId={id} />}
      {/* The test bench is organised by TARGET: every question asked of a binary, and every run it produced.
          `binaries` still routes here so older links keep working. */}
      {(tab === 'testbench' || tab === 'binaries') && (
        <>
          <TestBench imageId={id} />
          <SymReachPanel imageId={id} binary="" onBinary={() => undefined} />
        </>
      )}
      {/* Emulation recipes answer a different question: how this IMAGE can be booted at all. */}
      {tab === 'simulate' && (
        <>
          <SimulationMenu imageId={id} />
          <FuzzPanel imageId={id} />
          <PresetsPanel imageId={id} />
        </>
      )}
      {/* Coverage first: a findings list is unreadable until you know which stages produced it. */}
      {tab === 'findings' && (
        <>
          <CoverageBanner imageId={id} />
          {/* Not a pipeline stage, so deliberately not in the StepTimeline — reached from here, where a reader is
              already looking at what the bench measured and may need to record what it cannot. */}
          <div className="hint" style={{ margin: '-8px 0 12px' }}>
            {t.imageDetail.findingsTab.operatorPrompt}{' '}
            <Link className="btn btn-sm btn-ghost" to={`/image/${id}/operator`}>
              {t.sections.operator}
            </Link>
          </div>
          <ReportBuilder imageId={id} image={image} analysis={analysis} />
        </>
      )}
      {/* The one section where a person writes a row. Deliberately its own section, not a corner of Findings. */}
      {tab === 'operator' && <OperatorPanel imageId={id} />}
      {tab === 'diff' && <DiffPanel imageId={id} />}
      {tab === 'opacidad' && <OpacidadPanel imageId={id} />}
      {tab === 'agent' && <AgentPanel imageId={id} />}
      {!analysis && !NO_ANALYSIS_TABS.has(tab) && (
        <div className="empty">
          <div className="empty-mark">0x—</div>
          <div className="empty-title">{t.imageDetail.emptyAnalysis.title}</div>
          <div className="empty-body">{t.imageDetail.emptyAnalysis.body(t.nav.dashboard)}</div>
        </div>
      )}
    </div>
  );
}

// === Dossier: the single view that builds up everything known about an image, honestly. ===

/* The proof-state badge, the severity palette and the ledger table itself live in `FindingsLedger`: the dispute
   annotation needs all three, and they belong beside the one table that shows measured and asserted rows together. */

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

function DossierPanel({ image, sectionIds }: { image: ImageSummary; sectionIds: readonly string[] }): JSX.Element {
  const id = image.id;
  const t = useMessages();
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
  // The two facts the section index needs, and the only two: did extraction complete, and did it yield a rootfs.
  // Read from the job's own result rather than inferred, so "ran and found none" cannot be mistaken for "not run".
  const extractJob = jobs.find((j) => j.kind === 'extract' && j.status === 'done');
  const extraction = {
    ran: extractJob !== undefined,
    rootfs: Boolean((extractJob?.result as { rootfsPath?: string | null } | null | undefined)?.rootfsPath),
  };
  const triagedBinaries = binaries.filter((b) => b.triaged).length;

  const idn = image.identity;

  return (
    <div>
      {/* The signal tape — the image read as signal along its byte axis; every panel below is a lens over it. */}
      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">{t.imageDetail.dossier.signalTitle}</div>
            <div className="panel-sub">{t.imageDetail.dossier.signalSub}</div>
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
            {/* The class is an identifier the API decided; only the "we do not know" fallback is prose. */}
            <span className="badge badge-accent">{idn?.firmwareClass ?? t.common.unknown}</span>
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
        <Stat
          label={t.imageDetail.dossier.statBinaries}
          value={t.imageDetail.dossier.statBinariesValue(binaries.length, triagedBinaries)}
        />
        <Stat label={t.imageDetail.dossier.statFindings} value={String(findings.length)} />
        <Stat label={t.imageDetail.dossier.statStrategy} value={caps?.strategy ?? '—'} mono />
      </div>

      {agent?.enabled && (
        <div className="panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <div className="panel-title" style={{ margin: 0 }}>
              {t.imageDetail.dossier.copilotTitle}
            </div>
            <span className="badge" title={t.imageDetail.dossier.copilotModelTitle}>
              {agent.provider} · {agent.model}
            </span>
            <div style={{ flex: 1 }} />
            <button type="button" className="btn btn-sm btn-primary" disabled={copilotRunning} onClick={runCopilot}>
              {copilotRunning ? (
                <>
                  <span className="spinner" /> {t.imageDetail.dossier.copilotAnalyzing}
                </>
              ) : copilot ? (
                t.imageDetail.dossier.copilotRerun
              ) : (
                t.imageDetail.dossier.copilotAnalyze
              )}
            </button>
          </div>
          <div className="panel-sub">{t.imageDetail.dossier.copilotSub}</div>
          {copilotLog && !copilot && (
            <pre className="mono" style={{ fontSize: 11.5, color: 'var(--text-dim)', marginTop: 10 }}>
              {copilotLog}
            </pre>
          )}
          {copilot && <Markdown text={copilot.text} className="copilot-output" />}
        </div>
      )}

      <ResearchPanel imageId={id} />

      <div className="panel">
        <div className="panel-title">{t.imageDetail.dossier.coverageTitle}</div>
        <div className="panel-sub">{t.imageDetail.dossier.coverageSub}</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px 24px', marginTop: 10 }}>
          <CoverageItem label={t.imageDetail.dossier.stageStatic} done={image.status === 'ready'} />
          <CoverageItem label={t.imageDetail.dossier.stageExtract} done={ranKind('extract')} />
          <CoverageItem label={t.imageDetail.dossier.stageSbom} done={ranKind('sbom')} />
          <CoverageItem label={t.imageDetail.dossier.stageSecrets} done={ranKind('gitleaks')} />
          <CoverageItem
            label={t.imageDetail.dossier.stageTriage}
            done={triagedBinaries > 0}
            detail={binaries.length ? `${triagedBinaries}/${binaries.length}` : ''}
          />
          <CoverageItem label={t.imageDetail.dossier.stageEmulation} done={ranKind('emulate')} />
        </div>
        {caps && (
          <>
            <div className="hint" style={{ marginTop: 12 }}>
              {t.imageDetail.dossier.preflight}: <strong>{caps.strategy}</strong> — {caps.reason}
            </div>
            {/* A ceiling, not a result: the highest rung this deployment could reach for this image. */}
            <div className="hint" style={{ marginTop: 4, display: 'flex', gap: 6, alignItems: 'baseline' }}>
              {t.imageDetail.dossier.proofCeiling}: <ProofStateChip state={caps.proofCeiling} />
            </div>
          </>
        )}
      </div>

      {refCount > 0 && refs && (
        <div className="panel">
          <div className="panel-title">{t.imageDetail.dossier.corpusTitle(refCount)}</div>
          <div className="panel-sub">{t.imageDetail.dossier.corpusSub}</div>
          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12.5 }}>
            {refs.credentials.map((c) => (
              <CorpusRefRow
                key={`c-${c.hash}`}
                icon="🔑"
                label={t.imageDetail.dossier.corpusCredential(c.kind ?? t.imageDetail.dossier.corpusCredentialFallback)}
                images={c.otherImages}
              />
            ))}
            {refs.components.map((c) => (
              <CorpusRefRow
                key={`p-${c.name}-${c.version}`}
                icon="📦"
                label={t.imageDetail.dossier.corpusComponent(c.name, c.version, c.cveCount)}
                images={c.otherImages}
              />
            ))}
            {refs.artifacts.map((a) => (
              <CorpusRefRow
                key={`a-${a.sha1}`}
                icon="⚙"
                label={t.imageDetail.dossier.corpusArtifact(a.path)}
                images={a.otherImages}
              />
            ))}
          </div>
        </div>
      )}

      {/* Measured rows and the assertions about them, in one table — including the contest an operator recorded
          against a computed row, annotated onto it without touching what code decided. */}
      <FindingsLedger findings={findings} />

      {/* Every section, reachable. Ten of them had no link anywhere in the app and the shell's own hint pointed at a
          timeline that cannot reach them. */}
      <div className="panel" style={{ marginTop: 16 }}>
        <SectionIndex imageId={image.id} sections={sectionIds} extraction={extraction} />
      </div>
    </div>
  );
}

function StructurePanel({ analysis }: { analysis: StaticAnalysis }): JSX.Element {
  const t = useMessages();
  return (
    <div className="panel">
      <div className="panel-title">{t.imageDetail.structure.title}</div>
      <div className="panel-sub">{t.imageDetail.structure.sub(analysis.structure.length)}</div>
      <StructureMap segments={analysis.structure} size={analysis.size} />
    </div>
  );
}

function EntropyPanel({ analysis }: { analysis: StaticAnalysis }): JSX.Element {
  const t = useMessages();
  return (
    <div className="panel">
      <div className="panel-title">{t.imageDetail.entropy.title}</div>
      <div className="panel-sub">{t.imageDetail.entropy.sub}</div>
      <EntropyChart entropy={analysis.entropy} size={analysis.size} />
      {analysis.entropy.highEntropyRegions.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 16 }}>
          <table className="data">
            <thead>
              <tr>
                <th>{t.imageDetail.entropy.colRegion}</th>
                <th>{t.imageDetail.entropy.colMeanH}</th>
                <th>{t.imageDetail.entropy.colSize}</th>
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
  const t = useMessages();
  const secrets = analysis?.secrets ?? [];
  return (
    <div>
      <div className="panel">
        <div className="panel-title">{t.imageDetail.secrets.title}</div>
        <div className="panel-sub">{t.imageDetail.secrets.sub}</div>
        {secrets.length === 0 ? (
          <div className="hint">{t.imageDetail.secrets.empty}</div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>{t.imageDetail.secrets.colSeverity}</th>
                  <th>{t.imageDetail.secrets.colKind}</th>
                  <th>{t.imageDetail.secrets.colOffset}</th>
                  <th>{t.imageDetail.secrets.colValue}</th>
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
  const t = useMessages();
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
      <div className="panel-title">{t.imageDetail.gitleaks.title}</div>
      <div className="panel-sub">{t.imageDetail.gitleaks.sub}</div>
      <button className="btn btn-primary" disabled={running} onClick={run}>
        {running ? (
          <>
            <span className="spinner" /> {t.imageDetail.gitleaks.scanning}
          </>
        ) : result?.available ? (
          t.imageDetail.gitleaks.rescan
        ) : (
          t.imageDetail.gitleaks.scan
        )}
      </button>
      {result && !result.available && (
        // The provider's own reason wins: it knows whether the tool is missing or the rootfs is. Ours is the floor.
        <div className="banner banner-warn" style={{ marginTop: 14 }}>
          {result.reason ?? t.imageDetail.gitleaks.unavailable}
        </div>
      )}
      {result?.available && (
        <div style={{ marginTop: 14 }}>
          <div className="hint" style={{ marginBottom: 10 }}>
            {t.imageDetail.gitleaks.count(result.findingCount)}
          </div>
          {result.findings.length > 0 && (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>{t.imageDetail.gitleaks.colRule}</th>
                    <th>{t.imageDetail.gitleaks.colFile}</th>
                    <th>{t.imageDetail.gitleaks.colLine}</th>
                    <th>{t.imageDetail.gitleaks.colMatch}</th>
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
  const t = useMessages();
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
        setLog(extract.log ?? t.imageDetail.filesystem.noRootfs);
      }
    }
  }, [imageId, t]);
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
            <Stat label={t.imageDetail.filesystem.statFiles} value={String(summary.totalFiles)} />
            <Stat label={t.imageDetail.filesystem.statDirs} value={String(summary.totalDirs)} />
            <Stat label={t.imageDetail.filesystem.statSetuid} value={String(summary.setuidBinaries.length)} />
          </div>
        )}
        <div className="panel">
          <div className="panel-title">{t.imageDetail.filesystem.rootfsTitle}</div>
          <FilesystemTree root={tree} />
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-title">{t.imageDetail.filesystem.title}</div>
      <div className="panel-sub">{t.imageDetail.filesystem.sub}</div>
      <button className="btn btn-primary" disabled={status === 'running'} onClick={runExtract}>
        {status === 'running' ? (
          <>
            <span className="spinner" /> {t.imageDetail.filesystem.extracting}
          </>
        ) : (
          t.imageDetail.filesystem.run
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
          // Outside React: `messages()` is the module-scope reader, so a toast fired from a timer is still localised.
          if (j.status === 'error') toast.error(j.error ?? messages().imageDetail.job.failed);
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
  const t = useMessages();
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

  if (!loaded) return <div className="empty">{t.common.loading}</div>;

  return (
    <div>
      <div className="panel">
        <div className="panel-title">{t.imageDetail.sbom.title}</div>
        <div className="panel-sub">{t.imageDetail.sbom.sub}</div>
        <button className="btn btn-primary" disabled={running} onClick={run}>
          {running ? (
            <>
              <span className="spinner" /> {t.imageDetail.sbom.scanning}
            </>
          ) : result ? (
            t.imageDetail.sbom.rescan
          ) : (
            t.imageDetail.sbom.generate
          )}
        </button>
        {result && !result.available && (
          <div className="banner banner-warn" style={{ marginTop: 14 }}>
            {result.reason ?? t.imageDetail.sbom.unavailable}
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
            <Stat label={t.imageDetail.sbom.statPackages} value={String(result.packageCount)} />
            <Stat label={t.imageDetail.sbom.statVulns} value={String(result.vulnerabilities.length)} />
            <Stat
              label={t.imageDetail.sbom.statCritHigh}
              value={`${result.counts.Critical} / ${result.counts.High}`}
              mono
            />
          </div>

          {/* Absence of the matcher is not absence of CVEs — the banner has to say which of the two happened. */}
          {!result.grypeAvailable && <div className="banner banner-info">{t.imageDetail.sbom.grypeMissing}</div>}

          {result.packages.length > 0 && (
            <div className="panel">
              <div className="panel-head" style={{ marginBottom: 4 }}>
                <div>
                  <div className="panel-title">{t.imageDetail.sbom.graphTitle}</div>
                  <div className="panel-sub">{t.imageDetail.sbom.graphSub}</div>
                </div>
              </div>
              <SbomGraph sbom={result} />
            </div>
          )}

          {result.vulnerabilities.length > 0 && (
            <div className="panel">
              <div className="panel-title">
                {t.imageDetail.sbom.cvesTitle}
                <span className="legend" style={{ marginLeft: 'auto' }}>
                  {/* grype's severity names are its own vocabulary and travel with the data — rendered verbatim. */}
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
                      <th>{t.imageDetail.sbom.colSeverity}</th>
                      {/* The acronym IS the identifier in the cell below it; there is nothing to translate. */}
                      <th>CVE</th>
                      <th>{t.imageDetail.sbom.colPackage}</th>
                      <th>{t.imageDetail.sbom.colVersion}</th>
                      <th>{t.imageDetail.sbom.colFixedIn}</th>
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
              <div className="panel-title">{t.imageDetail.sbom.packagesTitle(result.packageCount)}</div>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>{t.imageDetail.sbom.colName}</th>
                      <th>{t.imageDetail.sbom.colVersion}</th>
                      <th>{t.imageDetail.sbom.colType}</th>
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
      <RunHistory imageId={imageId} kinds={['sbom']} label={t.imageDetail.sbom.runLabel} />
    </div>
  );
}

function DiffPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
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
        <div className="panel-title">{t.imageDetail.diff.title}</div>
        <div className="panel-sub">{t.imageDetail.diff.sub}</div>
        {images.length === 0 ? (
          <div className="hint">{t.imageDetail.diff.needSecond}</div>
        ) : (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <select
              className="input"
              value={against}
              onChange={(e) => setAgainst(e.target.value)}
              style={{ flex: '1 1 240px', minWidth: 0 }}
            >
              <option value="">{t.imageDetail.diff.selectPlaceholder}</option>
              {images.map((im) => (
                <option key={im.id} value={im.id}>
                  {im.filename}
                </option>
              ))}
            </select>
            <button className="btn btn-primary" disabled={running || !against} onClick={run}>
              {running ? (
                <>
                  <span className="spinner" /> {t.imageDetail.diff.comparing}
                </>
              ) : (
                t.imageDetail.diff.compare
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
            <div className="panel-title">{t.imageDetail.diff.identityTitle}</div>
            {result.identity.length === 0 ? (
              <div className="hint">{t.imageDetail.diff.identityNone}</div>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>{t.imageDetail.diff.colField}</th>
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
            <div className="panel-title">{t.imageDetail.diff.packagesTitle}</div>
            {!result.packages.hasData ? (
              <div className="hint">{t.imageDetail.diff.packagesNeedSbom}</div>
            ) : (
              <>
                <div className="grid grid-3" style={{ marginBottom: 12 }}>
                  <Stat label={t.imageDetail.diff.statAdded} value={String(result.packages.added.length)} />
                  <Stat label={t.imageDetail.diff.statRemoved} value={String(result.packages.removed.length)} />
                  <Stat label={t.imageDetail.diff.statVersionChanged} value={String(result.packages.changed.length)} />
                </div>
                {result.packages.changed.length > 0 && (
                  <div className="table-wrap">
                    <table className="data">
                      <thead>
                        <tr>
                          <th>{t.imageDetail.diff.colPackage}</th>
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
            <div className="panel-title">{t.imageDetail.diff.cvesTitle}</div>
            {!result.cves.hasData ? (
              <div className="hint">{t.imageDetail.diff.cvesNeedSbom}</div>
            ) : (
              <>
                <div className="legend" style={{ marginBottom: 10 }}>
                  <span className="badge badge-ok">{t.imageDetail.diff.added(result.cves.addedIds.length)}</span>
                  <span className="badge badge-info">{t.imageDetail.diff.removed(result.cves.removedIds.length)}</span>
                  {SEVERITY_ORDER.filter((s) => result.cves.addedBySeverity[s] > 0).map((s) => (
                    <span key={s} className={`badge ${SEVERITY_BADGE[s]}`}>
                      {t.imageDetail.diff.bySeverity(result.cves.addedBySeverity[s], s)}
                    </span>
                  ))}
                </div>
                {/* "None added" is a statement about these two images, never about either one's exposure. */}
                <div className="hint mono" style={{ wordBreak: 'break-word' }}>
                  {result.cves.addedIds.slice(0, 60).join(', ') || t.imageDetail.diff.noNewCves}
                </div>
              </>
            )}
          </div>

          <div className="panel">
            <div className="panel-title">{t.imageDetail.diff.filesTitle}</div>
            {!result.files.hasData ? (
              <div className="hint">{t.imageDetail.diff.filesNeedExtract}</div>
            ) : (
              <div className="grid grid-3">
                <Stat label={t.imageDetail.diff.statAdded} value={String(result.files.counts.added)} />
                <Stat label={t.imageDetail.diff.statRemoved} value={String(result.files.counts.removed)} />
                <Stat label={t.imageDetail.diff.statFilesChanged} value={String(result.files.counts.changed)} />
              </div>
            )}
          </div>
        </>
      )}
      <RunHistory imageId={imageId} kinds={['diff']} label={t.imageDetail.diff.runLabel} />
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
  const t = useMessages();
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
          {t.imageDetail.research.offTitle} <span className="badge">{t.imageDetail.research.offBadge}</span>
        </div>
        {/* The env var is a literal and is spliced between two halves of the sentence, so each language keeps its
            own word order around it. */}
        <div className="panel-sub" style={{ margin: 0 }}>
          {t.imageDetail.research.offBodyBefore}
          <span className="mono">FIRMLAB_RESEARCH=1</span>
          {t.imageDetail.research.offBodyAfter}
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
          {t.imageDetail.research.title}
        </div>
        <span className="prov prov-heuristic" title={t.imageDetail.research.sourceTitle}>
          {t.imageDetail.research.sourceBadge}
        </span>
        <div style={{ flex: 1 }} />
        <button type="button" className="btn btn-sm btn-primary" disabled={running} onClick={run}>
          {running ? (
            <>
              <span className="spinner" /> {t.imageDetail.research.researching}
            </>
          ) : result ? (
            t.imageDetail.research.rerun
          ) : (
            t.imageDetail.research.run
          )}
        </button>
      </div>
      {/* What leaves the machine, and that an advisory is a lead — both have to survive translation intact. */}
      <div className="panel-sub">{t.imageDetail.research.sub}</div>

      {result && osv && (
        <div style={{ marginTop: 4 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
            <span className="badge" title={t.imageDetail.research.osvBadgeTitle}>
              {t.imageDetail.research.osvBadge(osv.queried)}
            </span>
            <span className="badge badge-high">{t.imageDetail.research.osvAdvisories(osv.totalAdvisories)}</span>
            {nvd && (nvd.queried > 0 || nvd.totalAdvisories > 0) && (
              <span
                className="badge"
                title={
                  // A result stored before this split does not know how it asked, and saying nothing beats
                  // rendering "undefined asked by CPE version match".
                  nvd.askedByCpe === undefined
                    ? t.imageDetail.research.nvdTitleUnknown
                    : t.imageDetail.research.nvdTitle(nvd.askedByCpe, nvd.askedByKeyword ?? 0)
                }
              >
                {t.imageDetail.research.nvdBadge(nvd.queried, nvd.totalAdvisories)}
              </span>
            )}
            {/* Checked or not, the badge is ALWAYS here. It used to be conditional on `kev.checked`, so a KEV
                lookup that did not happen made the whole block vanish — and a missing block is indistinguishable
                from a clean one. `kev.reason` is the provider's own sentence for why it did not run. */}
            {kev?.checked ? (
              <span
                className={`badge ${kev.matches.length > 0 ? 'badge-high' : 'badge-ok'}`}
                title={t.imageDetail.research.kevBadgeTitle(kev.catalogSize ?? 0)}
              >
                {t.imageDetail.research.kevBadge(kev.matches.length)}
              </span>
            ) : (
              <span className="badge badge-medium" title={kev?.reason ?? t.imageDetail.research.kevNotCheckedTitle}>
                {t.imageDetail.research.kevNotChecked}
              </span>
            )}
            {result.provenance.vendors.slice(0, 4).map((v) => (
              <span key={v} className="badge badge-accent" title={t.imageDetail.research.vendorTitle}>
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
                {t.imageDetail.research.kevHeading}
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
                      <span className="badge badge-high" title={t.imageDetail.research.ransomwareTitle}>
                        {t.imageDetail.research.ransomware}
                      </span>
                    )}
                    <span className="hint" title={m.shortDescription}>
                      {t.imageDetail.research.kevAdded(m.dateAdded)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* The denominators, under the badges they qualify. Both lanes count what they never asked about and
              neither number reached the screen, so "0 advisories" read as "there are none" when it meant "none
              among the ones we asked". `> 0` rather than truthy: a 0 here is genuinely "nothing was skipped". */}
          {(osv.skipped > 0 || (nvd?.notQueried ?? 0) > 0) && (
            <div style={{ marginBottom: 10 }}>
              {osv.skipped > 0 && <div className="note">{t.imageDetail.research.osvSkipped(osv.skipped)}</div>}
              {(nvd?.notQueried ?? 0) > 0 && (
                <div className="note" style={{ marginTop: 6 }}>
                  {t.imageDetail.research.nvdNotQueried(nvd?.notQueried ?? 0)}
                </div>
              )}
            </div>
          )}

          {osv.components.length > 0 && (
            <div className="table-wrap" style={{ marginBottom: 12 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>{t.imageDetail.research.colComponent}</th>
                    <th>{t.imageDetail.research.colAdvisories}</th>
                  </tr>
                </thead>
                <tbody>
                  {osv.components.slice(0, COMPONENT_ROWS).map((c) => (
                    <tr key={`${c.name}@${c.version}`}>
                      <td className="mono">
                        {c.name} {c.version}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                          {c.advisories.slice(0, ADVISORY_ROWS).map((a) => {
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
                          {/* The NVD table beside this one has said "N of M shown" since it was written; this one
                              stopped at eight and said nothing, so the same truncation read as a complete list on
                              one table and as a bound on the other. */}
                          {c.advisories.length > ADVISORY_ROWS && (
                            <span
                              className="badge"
                              title={t.imageDetail.research.shownOfTitle(
                                ADVISORY_ROWS,
                                c.advisories.length,
                                c.name,
                                c.version,
                              )}
                            >
                              {t.imageDetail.research.shownOf(ADVISORY_ROWS, c.advisories.length)}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {osv.components.length > COMPONENT_ROWS && (
                <div className="note" style={{ marginTop: 6 }}>
                  {t.imageDetail.research.componentsShown(COMPONENT_ROWS, osv.components.length)}
                </div>
              )}
            </div>
          )}

          {nvd && nvd.components.length > 0 && (
            <div className="table-wrap" style={{ marginBottom: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                {t.imageDetail.research.nvdHeading}
              </div>
              {/* The provider's own rule text, as it recorded it. */}
              {nvd.notQueriedRule && (
                <div className="note" style={{ marginBottom: 8 }}>
                  {nvd.notQueriedRule}
                </div>
              )}
              {(nvd.uncheckedIdentities ?? []).map((u) => (
                <div className="note" style={{ marginBottom: 8 }} key={`nvd-alt-${u.name}@${u.version}`}>
                  {t.imageDetail.research.uncheckedBefore(u.name, u.version)}
                  <span className="mono">{u.identities.join(', ')}</span>
                  {t.imageDetail.research.uncheckedAfter}
                </div>
              ))}
              <table className="data">
                <thead>
                  <tr>
                    <th>{t.imageDetail.research.colComponent}</th>
                    <th>{t.imageDetail.research.colAskedBy}</th>
                    <th>{t.imageDetail.research.colCves}</th>
                  </tr>
                </thead>
                <tbody>
                  {nvd.components.slice(0, COMPONENT_ROWS).map((c) => (
                    <tr key={`nvd-${c.name}@${c.version}`}>
                      <td className="mono">
                        {c.name} {c.version}
                      </td>
                      <td>
                        {/* Three states, not two. A row stored before `matchedBy` existed does not know how it
                            was asked, and defaulting the unknown to "keyword" would assert the weaker question
                            was used — a claim about provenance made from a missing field. */}
                        <span
                          className={`badge ${c.matchedBy === 'cpe' ? 'badge-ok' : ''}`}
                          title={
                            c.matchedBy === 'cpe'
                              ? t.imageDetail.research.askedCpeTitle
                              : c.matchedBy === 'keyword'
                                ? t.imageDetail.research.askedKeywordTitle
                                : t.imageDetail.research.askedUnknownTitle
                          }
                        >
                          {c.matchedBy === 'cpe'
                            ? t.imageDetail.research.askedCpe
                            : c.matchedBy === 'keyword'
                              ? t.imageDetail.research.askedKeyword
                              : t.imageDetail.research.askedUnknown}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', alignItems: 'center' }}>
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
                          {/* The table shows at most 8; NVD may hold more than were even fetched. Stating both
                              keeps a truncated row from reading as the complete set. */}
                          {(() => {
                            const total = c.totalMatching ?? c.advisories.length;
                            const shown = Math.min(8, c.advisories.length);
                            return total > shown ? (
                              <span
                                className="badge"
                                title={t.imageDetail.research.shownOfTitle(shown, total, c.name, c.version)}
                              >
                                {t.imageDetail.research.shownOf(shown, total)}
                              </span>
                            ) : null;
                          })()}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {nvd.components.length > COMPONENT_ROWS && (
                <div className="note" style={{ marginTop: 6 }}>
                  {t.imageDetail.research.componentsShown(COMPONENT_ROWS, nvd.components.length)}
                </div>
              )}
            </div>
          )}

          {/* The egress ledger — what this lane put on the wire and what it never does. `research/egress.ts`
              builds it on every run and nothing rendered it: the privacy claim that justifies the only
              internet-touching flag in the product was readable in JSON and nowhere else. */}
          {result.egress && (result.egress.destinations.length > 0 || result.egress.neverSent.length > 0) && (
            <ResearchEgress egress={result.egress} />
          )}

          {result.keyMaterial.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                {t.imageDetail.research.keyHeading}
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
                    <span className="badge badge-high" title={t.imageDetail.research.effectivelyPublicTitle}>
                      {t.imageDetail.research.effectivelyPublic}
                    </span>
                  )}
                  {(k.sharedInImages ?? 0) > 0 && (
                    <span className="badge badge-medium">{t.imageDetail.research.reusedIn(k.sharedInImages ?? 0)}</span>
                  )}
                </div>
              ))}
            </div>
          )}

          <HashLookupBlock lookup={result.hashLookup} />

          {result.securityContacts.some((c) => c.checked) && (
            <div style={{ marginBottom: 12 }}>
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                {t.imageDetail.research.contactsHeading}
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
                    <span className="hint">{c.reason ?? t.imageDetail.research.noSecurityTxt}</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {result.synthesis && (
            <>
              <div className="eyebrow" style={{ marginBottom: 6 }}>
                {t.imageDetail.research.brief(result.synthesis.provider, result.synthesis.model)}
              </div>
              {/* The brief is Markdown the model wrote — headings, citation links, tables. Rendered, never as
                  HTML: see the note at the top of `markdown.tsx` for why that distinction is load-bearing on a
                  lane whose input came off the internet. */}
              <Markdown text={result.synthesis.text} />
            </>
          )}
        </div>
      )}
      <RunHistory imageId={imageId} kinds={['research']} label={t.imageDetail.research.runLabel} />
    </div>
  );
}

/**
 * What the online hash lookup asked, and — the part that matters — what it deliberately did not.
 *
 * The whole block was invisible: `providers/hashlookup.ts` distinguishes SIX outcomes and `apps/web` had no
 * reader for any of them, so a password hash that was never sent rendered exactly like one that was checked and
 * came back clean. On the highest-stakes finding class in the workbench, that is the worst version of the
 * mistake this project exists to prevent.
 *
 * Two distinctions are load-bearing and neither may be flattened:
 *
 *  - **`skipped_salted` is not `miss`.** A salted crypt hash is never sent, because a miss on one would prove
 *    nothing about the password's strength. Rendering both as "not found" would turn a refusal to ask into a
 *    negative answer.
 *  - **The lane being off is not an empty result.** With `FIRMLAB_HASH_LOOKUP` unset nothing is asked at all,
 *    and the provider's own `reason` says so — printed here rather than showing an empty list.
 */
/** How many components and how many advisories each table prints. Both used to be bare `12` / `8` inline. */
const COMPONENT_ROWS = 12;
const ADVISORY_ROWS = 8;

/**
 * What this lookup put on the wire, and what it never does.
 *
 * `research/egress.ts` builds this ledger on every run, and it is the reason an operator can turn on the only
 * internet-touching flag in the product: it names each destination, what is sent there, and the ceiling on how
 * many questions. It had no reader — the claim existed in JSON and nowhere a person would look.
 *
 * The `sends` strings and the `neverSent` list are the provider's own words and render as written; a host with a
 * count of 0 is a one-way download (the KEV catalog comes in, nothing about the firmware goes out) and says so
 * rather than printing "at most 0", which reads like a bound rather than a direction.
 */
function ResearchEgress({ egress }: { egress: ResearchResult['egress'] }): JSX.Element {
  const t = useMessages();
  const r = t.imageDetail.research;
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="eyebrow" style={{ marginBottom: 6 }}>
        {r.egressHeading}
      </div>
      {egress.destinations.map((d) => (
        <div key={d.host} style={{ fontSize: 12.5, marginBottom: 4 }}>
          <span className="mono">{d.host}</span>{' '}
          <span className="badge" style={{ fontSize: 10 }}>
            {d.count > 0 ? r.egressAtMost(d.count) : r.egressNothing}
          </span>
          <div className="hint" style={{ marginTop: 1 }}>
            {d.sends}
          </div>
        </div>
      ))}
      {egress.neverSent.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div className="hint" style={{ fontSize: 11.5 }}>
            {r.neverSentHeading}
          </div>
          <ul className="hint" style={{ margin: '2px 0 0', paddingLeft: 18, fontSize: 11.5 }}>
            {egress.neverSent.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function HashLookupBlock({ lookup }: { lookup: ResearchResult['hashLookup'] }): JSX.Element | null {
  const t = useMessages();
  const h = t.imageDetail.research.hash;
  if (!lookup) return null;

  // The lane is off, or it ran and had nothing to ask. Both are stated; neither is silence.
  if (!lookup.enabled || lookup.entries.length === 0) {
    return (
      <div style={{ marginBottom: 12 }}>
        <div className="eyebrow" style={{ marginBottom: 4 }}>
          {h.heading}
        </div>
        <div className="hint" style={{ maxWidth: '72ch' }}>
          {/* The provider's own sentence, as it recorded it. */}
          {lookup.reason || (lookup.enabled ? h.noneToAsk : h.disabled)}
        </div>
      </div>
    );
  }

  return (
    <div style={{ marginBottom: 12 }}>
      <div className="eyebrow" style={{ marginBottom: 4 }}>
        {h.heading}
      </div>
      <div className="hint" style={{ maxWidth: '72ch', marginBottom: 6 }}>
        {lookup.reason}
      </div>
      {lookup.entries.map((e) => (
        <div
          key={`${e.source}:${e.account}`}
          style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap', fontSize: 12.5, marginBottom: 3 }}
        >
          {/* Account, source and scheme are what the provider read out of the firmware — verbatim. */}
          <span className="mono">{e.account}</span>
          <span className="hint mono" style={{ fontSize: 11 }}>
            {e.source} · {e.scheme}
          </span>
          <span className={`badge ${HASH_OUTCOME_CLASS[e.outcome] ?? ''}`} title={h.outcomeMeaning[e.outcome]}>
            {h.outcome[e.outcome]}
          </span>
          {/* Recovered AND locally verified against the hash. Masked by the provider; never widened here. */}
          {e.passwordMasked && <span className="mono">{e.passwordMasked}</span>}
          {e.manualLookupUrl && (
            <a href={e.manualLookupUrl} target="_blank" rel="noreferrer" className="hint" style={{ fontSize: 11.5 }}>
              {h.manual}
            </a>
          )}
        </div>
      ))}
      {/* The sentence a list of six labels cannot carry on its own. */}
      <div className="hint" style={{ marginTop: 6, maxWidth: '72ch' }}>
        {h.saltedNote}
      </div>
    </div>
  );
}

/**
 * Outcome colour. `resolved` is the only one that earns a severity: a recovered, locally verified password is a
 * credential. `miss` is deliberately NEUTRAL rather than green — it means the lookup found nothing, which is not
 * evidence the password is strong.
 */
const HASH_OUTCOME_CLASS: Record<string, string> = {
  resolved: 'badge-crit',
  unverified: 'badge-medium',
  miss: '',
  skipped_salted: '',
  skipped_cap: 'badge-medium',
  skipped_other: '',
};

// === Agent: the conscious-autonomy session view — what the agent chose at each node, and why (Phase 3). ===

/**
 * Session-status colour only. The status CODES are what the API stores, so they stay the keys; the label a reader
 * sees comes from `t.imageDetail.agent.sessionStatus`, keyed by the same code.
 */
const SESSION_COLOR: Record<AgentSession['status'], string> = {
  running: 'var(--info, #4db5ff)',
  awaiting_approval: 'var(--sev-medium, #e6b45c)',
  done: 'var(--ok, #4caf7d)',
  error: 'var(--sev-critical, #e0524f)',
  halted: 'var(--text-dim)',
};

/** The emulation plan the target-selection node produced, read from the latest such step. */
function emulationPlanOf(steps: AgentStep[]): { binary: string; rung: string }[] {
  const step = [...steps].reverse().find((s) => s.node === 'target-selection' && s.output);
  const out = step?.output as { emulationPlan?: { binary: string; rung: string }[] } | undefined;
  return out?.emulationPlan ?? [];
}

function StepCard({ step }: { step: AgentStep }): JSX.Element {
  const t = useMessages();
  const a = t.imageDetail.agent;
  // The transcript's node ids are open-ended strings from the API; an unknown one renders as its own id.
  const nodeLabels: Record<string, string> = a.node;
  const out = step.output as Record<string, unknown> | null;
  const highlights: ReactNode[] = [];
  if (step.node === 'triage' && out) {
    highlights.push(
      <div key="h">
        {a.triageClass} <b>{String(out.resolvedClass)}</b> ({String(out.classConfidence)}) · {a.triageExtract}{' '}
        <b>{out.shouldExtract ? t.common.yes : t.common.no}</b>
        {Array.isArray(out.extractionCascade) && out.extractionCascade.length > 0 && (
          <> · {a.cascade((out.extractionCascade as string[]).join(' → '))}</>
        )}
      </div>,
    );
    if (Array.isArray(out.attackSurface) && out.attackSurface.length > 0)
      highlights.push(<div key="a">{a.attackSurface((out.attackSurface as string[]).join(', '))}</div>);
  } else if (step.node === 'preflight' && out) {
    highlights.push(
      <div key="p">
        {a.strategy} <b>{String(out.strategy)}</b> · {a.ceiling} <b>{String(out.proofCeiling)}</b>
      </div>,
    );
  } else if (step.node === 'extraction' && out) {
    highlights.push(
      <div key="e">
        {out.rootfs ? a.rootfsYes : a.rootfsNo} · {String(out.extractor ?? '—')} · {a.arch}{' '}
        {String(out.detectedArch ?? '—')} · {a.files(String(out.files ?? '?'))}
      </div>,
    );
  } else if (step.node === 'target-selection' && out) {
    const targets = (out.targets as { path: string; rung: string; priority: string; reason: string }[]) ?? [];
    highlights.push(
      <div key="t" style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {/* Path, rung, priority and reason are what the node recorded — printed as recorded. */}
        {targets.map((target) => (
          <div key={target.path} className="mono" style={{ fontSize: 12 }}>
            <span style={{ color: 'var(--text)' }}>{target.path}</span> <span className="badge">{target.rung}</span>{' '}
            <span className="hint">{target.priority}</span> — {target.reason}
          </div>
        ))}
        {targets.length === 0 && <span className="hint">{a.noTargets}</span>}
      </div>,
    );
  } else if (step.node === 'emulation' && out) {
    highlights.push(
      <div key="m">
        {a.ran} <b>{out.ran ? t.common.yes : t.common.no}</b> · {a.exit} {String(out.exitCode ?? '—')} · {a.proofState}{' '}
        {typeof out.proofState === 'string' && (PROOF_STATE_META as Record<string, unknown>)[out.proofState] ? (
          <ProofStateChip state={out.proofState as FindingProvenance} />
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
        <b>{nodeLabels[step.node] ?? step.node}</b>
        {step.model && <span className="badge">{step.model}</span>}
        {step.inputTokens + step.outputTokens > 0 && (
          <span className="hint mono">{a.tokens(step.inputTokens + step.outputTokens)}</span>
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
            {a.audit}
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
  const t = useMessages();
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
      {row(t.imageDetail.agent.budgetSteps, String(c.steps), String(b.maxSteps))}
      {row(t.imageDetail.agent.budgetTokens, String(c.inputTokens + c.outputTokens), String(b.maxTokens))}
      {row(t.imageDetail.agent.budgetCost, `$${c.usd.toFixed(4)}`, b.maxUsd > 0 ? `$${b.maxUsd}` : '∞')}
      {row(t.imageDetail.agent.budgetTime, `${Math.round(c.elapsedMs / 1000)}s`, `${Math.round(b.maxWallMs / 1000)}s`)}
    </div>
  );
}

export function AgentPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const a = t.imageDetail.agent;
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
        <div className="panel-title">{a.disabledTitle}</div>
        <div className="panel-sub">
          {a.disabledBefore}
          <span className="mono">FIRMLAB_AGENT=1</span>
          {a.disabledAfter}
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
            {a.sessionTitle}
          </div>
          {config?.model && (
            <span className="badge">
              {config.provider} · {config.model}
            </span>
          )}
          {session && (
            <span className="mono" style={{ color: SESSION_COLOR[session.status], fontSize: 12 }}>
              {a.sessionStatus[session.status]}
            </span>
          )}
          <div style={{ flex: 1 }} />
          <button type="button" className="btn btn-sm btn-primary" disabled={busy || running} onClick={start}>
            {running ? (
              <>
                <span className="spinner" /> {a.running}
              </>
            ) : session ? (
              a.newSession
            ) : (
              a.startSession
            )}
          </button>
        </div>
        <div className="panel-sub">{a.sub}</div>
        {session && <BudgetGauge session={session} />}
        {session?.haltReason && (
          <div style={{ marginTop: 8, fontSize: 12.5, color: 'var(--sev-medium, #e6b45c)' }}>
            ⚠ {session.haltReason}
          </div>
        )}
      </div>

      {awaiting && plan.length > 0 && (
        <div className="panel" style={{ borderColor: 'var(--sev-medium, #e6b45c)' }}>
          <div className="panel-title">{a.approvalTitle}</div>
          {/* Emulation proves the sandbox, never the physical device — and nothing runs unapproved. */}
          <div className="panel-sub">{a.approvalSub}</div>
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
                  {a.approve}
                </button>
              </div>
            ))}
            <div>
              <button type="button" className="btn btn-sm" disabled={busy} onClick={decline}>
                {a.declineAll}
              </button>
            </div>
          </div>
        </div>
      )}

      {steps.length === 0 && !session && <div className="empty">{a.noSession}</div>}
      {steps.map((s) => (
        <StepCard key={s.seq} step={s} />
      ))}
    </div>
  );
}
