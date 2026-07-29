/**
 * Technique coverage checklist — an in-app map of firmware/IoT pentest techniques (OWASP FSTM stages + ISTG
 * categories + class-specific deep analysis) against what FirmLab actually does. Each item carries a status:
 * done (a provider/agent does it), partial (manual or half-covered), planned (a real gap we intend to build), or
 * out-of-scope (hardware/radio/weaponization that a software workbench shouldn't claim). Kept in sync with
 * docs/METHODOLOGY-GAPS.md. Curated data (the workbench's capability design, not per-deployment tool detection).
 *
 * **What stays here and what moved to the catalogue.** The table below is structure only — an id, a status, the
 * order they are read in, and the pointer into this repository that backs the row. Every word a reader is asked to
 * trust (the technique's name, the area heading, the four status words and the notes that are sentences) lives in
 * the `techniques` namespace, because this screen is a claim about the workbench and a translation that overstates
 * it is the workbench lying about itself. The ids are typed off the catalogue, so a row added here without wording
 * there is a compile error rather than a blank cell.
 *
 * **The methodology's own names are not prose.** `OWASP FSTM`, `ISTG` and the stage numbers in the headings are the
 * published names of an external standard, and the point of this screen is that it can be laid beside the published
 * methodology and lined up row for row — so they render verbatim in every language, exactly like the tool names in
 * the technique titles and the `providers/…` pointers in the note column.
 *
 * **Why a row carries either a `ref` or a `note`.** The note column is two different things wearing one column.
 * `providers/report` and `core/mcu + renode` are pointers into this repository: identifiers, `mono`, and identical
 * in every language, so they belong beside the data. `defensive by design` and `proves reachability` are sentences
 * and belong in the catalogue. The split is a type, not a convention, and the catalogue-integrity test enforces the
 * same rule from the other side by refusing a Spanish string identical to its English source.
 *
 * `out-of-scope` is the status this screen exists to state, and the one a careless rendering would lose. It is a
 * deliberate boundary — weaponised exploitation, chip-off, radio work are refused by design — and it must read as
 * neither a finished item nor a gap someone forgot. That is why it keeps a badge and a symbol of its own instead of
 * being left blank, and why its summary label is spelled out where the row's is short.
 */
import { type Messages, useMessages } from '../i18n';

type CovStatus = 'done' | 'partial' | 'planned' | 'out-of-scope';

/** All three ids come from the catalogue, so the checklist cannot name an area, a technique or a note that has no
 * wording behind it. */
type AreaId = keyof Messages['techniques']['areas'];
type TechniqueId = keyof Messages['techniques']['items'];
type NoteId = keyof Messages['techniques']['notes'];

interface TechniqueBase {
  id: TechniqueId;
  status: CovStatus;
}

/** The note is a pointer into this repository — an identifier, verbatim in every language, never translated. */
interface RefTechnique extends TechniqueBase {
  ref: string;
}

/** The note is a sentence, so it comes from the catalogue and each language writes its own. */
interface NotedTechnique extends TechniqueBase {
  note: NoteId;
}

type Technique = RefTechnique | NotedTechnique;

interface CovGroup {
  area: AreaId;
  items: Technique[];
}

const COVERAGE: CovGroup[] = [
  {
    area: 'recon',
    items: [
      { id: 'provenance', status: 'done', ref: 'providers/provenance' },
      { id: 'osint', status: 'done', note: 'osint' },
      { id: 'securityTxt', status: 'done', ref: 'providers/securitytxt' },
      { id: 'fccId', status: 'done', ref: 'providers/fcc' },
      { id: 'upload', status: 'done', note: 'upload' },
      { id: 'lanDiscovery', status: 'done', note: 'lanDiscovery' },
      { id: 'otaIntercept', status: 'partial', note: 'otaIntercept' },
    ],
  },
  {
    area: 'static',
    items: [
      { id: 'identity', status: 'done', ref: '@firmlab/core' },
      { id: 'extraction', status: 'done', ref: 'providers/extract' },
      { id: 'secrets', status: 'done', ref: 'core + gitleaks' },
      { id: 'sbom', status: 'done', ref: 'providers/sbom + research' },
      { id: 'hardening', status: 'done', ref: 'radare2 checksec' },
      { id: 'decompile', status: 'done', ref: 'providers/decompile + zeroday' },
      { id: 'fsaudit', status: 'done', ref: 'providers/fsaudit' },
      { id: 'certs', status: 'done', ref: 'providers/certs (X.509)' },
      { id: 'compmap', status: 'done', ref: 'providers/compmap' },
      { id: 'uboot', status: 'done', ref: 'providers/uboot' },
    ],
  },
  {
    area: 'emulation',
    items: [
      { id: 'qemuUser', status: 'done', ref: 'providers/emulate' },
      { id: 'chroot', status: 'done', ref: 'providers/emulate-system' },
      { id: 'fullSystem', status: 'done', ref: 'providers/emulate-system' },
      { id: 'renode', status: 'done', ref: 'providers/renode' },
      { id: 'chipsec', status: 'done', ref: 'providers/chipsec' },
      { id: 'servicemap', status: 'done', ref: 'providers/servicemap' },
      { id: 'presets', status: 'done', ref: 'routes/presets + PresetsPanel' },
      { id: 'interactiveShell', status: 'planned', note: 'interactiveShell' },
    ],
  },
  {
    area: 'dynamic',
    items: [
      { id: 'fuzzing', status: 'done', ref: 'providers/fuzz' },
      { id: 'isolation', status: 'done', ref: 'providers/isolate' },
      { id: 'webprobe', status: 'done', ref: 'providers/webprobe' },
      { id: 'webAuthBypass', status: 'planned', note: 'webAuthBypass' },
      { id: 'interactiveGdb', status: 'planned', note: 'interactiveGdb' },
      // Built and reachable: `providers/symreach.ts`, `routes/symreach.ts` and `SymReachPanel`. Announced as
      // `planned` since the day it shipped — this matrix is the only place the workbench states what it can do,
      // and under-claiming here is the same defect as over-claiming, pointed the other way.
      { id: 'symreach', status: 'done', note: 'symreach' },
      { id: 'crossBinary', status: 'planned', note: 'crossBinary' },
      { id: 'cmplog', status: 'planned', note: 'cmplog' },
    ],
  },
  {
    area: 'comparison',
    items: [
      { id: 'treeDiff', status: 'done', ref: 'providers/diff' },
      // Built: `providers/funcdiff.ts` + `funcdiff-run.ts` + `routes/diff.ts`. It has no PANEL, which is a
      // separate and recorded gap — but the technique is implemented and the route answers.
      { id: 'functionDiff', status: 'done', note: 'functionDiff' },
      { id: 'kernelModuleCve', status: 'planned', note: 'kernelModuleCve' },
    ],
  },
  {
    area: 'uefi',
    items: [
      { id: 'efiInventory', status: 'done', ref: 'chipsec' },
      { id: 'bootkitLead', status: 'done', note: 'bootkitLead' },
      { id: 'iocFeed', status: 'done', note: 'iocFeed' },
      { id: 'secureBoot', status: 'done', note: 'secureBoot' },
      // Built: `providers/fwhunt.ts`, served by `routes/chipsec.ts`, with the rule corpus pinned in the image.
      { id: 'fwhunt', status: 'done', note: 'fwhunt' },
      { id: 'logofail', status: 'planned', note: 'logofail' },
    ],
  },
  {
    area: 'rtos',
    items: [
      { id: 'mcuFingerprint', status: 'done', ref: 'core/mcu + renode' },
      { id: 'bootLiveness', status: 'done', ref: 'renode' },
      { id: 'vectorTable', status: 'done', ref: 'providers/rtos' },
      { id: 'mmioFuzzing', status: 'planned', note: 'mmioFuzzing' },
    ],
  },
  {
    area: 'reporting',
    items: [
      { id: 'htmlReport', status: 'done', ref: 'providers/report' },
      { id: 'disclosureDraft', status: 'done', ref: 'providers/disclosure' },
      { id: 'intelBrief', status: 'done', ref: 'agent/intel' },
      { id: 'pdfExport', status: 'planned', note: 'pdfExport' },
    ],
  },
  {
    area: 'hardware',
    items: [
      { id: 'uartBridge', status: 'planned', note: 'uartBridge' },
      { id: 'jtag', status: 'out-of-scope', note: 'jtag' },
      { id: 'bleDfu', status: 'partial', note: 'bleDfu' },
      { id: 'zigbeeOta', status: 'partial', note: 'zigbeeOta' },
      { id: 'wifiSdr', status: 'out-of-scope', note: 'wifiSdr' },
      { id: 'sideChannel', status: 'out-of-scope', note: 'sideChannel' },
      { id: 'weaponization', status: 'out-of-scope', note: 'weaponization' },
    ],
  },
];

/** Presentation only — the label itself comes from the catalogue, because it is prose and it is translated. */
const STATUS_META: Record<CovStatus, { badge: string; symbol: string }> = {
  done: { badge: 'badge-ok', symbol: '✓' },
  partial: { badge: 'badge-medium', symbol: '◐' },
  planned: { badge: 'badge-accent', symbol: '▢' },
  'out-of-scope': { badge: '', symbol: '—' },
};

export function TechniqueCoverage(): JSX.Element {
  const t = useMessages();
  const all = COVERAGE.flatMap((g) => g.items);
  const count = (s: CovStatus): number => all.filter((x) => x.status === s).length;

  return (
    <div className="panel" style={{ marginTop: 20 }}>
      <div className="panel-title">{t.techniques.title}</div>
      <div className="panel-sub">
        {t.techniques.sub.beforeDoc} <span className="mono">docs/METHODOLOGY-GAPS.md</span> {t.techniques.sub.afterDoc}
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '4px 0 16px' }}>
        <span className="badge badge-ok">{t.techniques.summary.done(count('done'))}</span>
        <span className="badge badge-medium">{t.techniques.summary.partial(count('partial'))}</span>
        <span className="badge badge-accent">{t.techniques.summary.planned(count('planned'))}</span>
        <span className="badge">{t.techniques.summary.outOfScope(count('out-of-scope'))}</span>
      </div>

      {COVERAGE.map((group) => (
        <div key={group.area} style={{ marginBottom: 18 }}>
          <div className="nav-section" style={{ margin: '0 0 8px' }}>
            {t.techniques.areas[group.area]}
          </div>
          <table className="data">
            <tbody>
              {group.items.map((item) => {
                const meta = STATUS_META[item.status];
                const note = 'ref' in item ? item.ref : t.techniques.notes[item.note];
                return (
                  <tr key={item.id} style={item.status === 'out-of-scope' ? { opacity: 0.62 } : undefined}>
                    <td style={{ width: 92 }}>
                      <span className={`badge ${meta.badge}`}>
                        {meta.symbol} {t.techniques.status[item.status]}
                      </span>
                    </td>
                    <td>{t.techniques.items[item.id].name}</td>
                    <td className="hint mono" style={{ width: 190 }}>
                      {note}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}
