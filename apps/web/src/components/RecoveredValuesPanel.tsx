import { useCallback, useEffect, useMemo, useState } from 'react';
import { type StaticAnalysis, api, fmtBytes, fmtHex } from '../api';
import type { FsAuditResultView, GitleaksFinding, GitleaksResult, Job, NvramResultView } from '../api';
import { copyToClipboard } from '../clipboard';
import { messages, useMessages } from '../i18n';
import { toast } from '../toast';

type ValueSource = 'raw' | 'rootfs' | 'nvram';
type ValueCategory = 'credential' | 'key-material' | 'configuration';

interface RecoveredValue {
  id: string;
  source: ValueSource;
  category: ValueCategory;
  kind: string;
  value: string;
  location: string;
  severity?: string;
  context?: string;
  legacyRedaction?: boolean;
}

const CREDENTIAL_KEY = /(pass(word|wd)?|passwd|secret|token|api.?key|auth|login|user(name)?|psk|wpa|wep|pin)/i;
const KEY_MATERIAL = /(private.?key|public.?key|cert|pem|shadow|hash|fingerprint|ssh|tls)/i;

function nvramCategory(key: string): ValueCategory {
  if (CREDENTIAL_KEY.test(key)) return 'credential';
  if (KEY_MATERIAL.test(key)) return 'key-material';
  return 'configuration';
}

function gitleaksCategory(finding: GitleaksFinding): ValueCategory {
  return KEY_MATERIAL.test(`${finding.rule} ${finding.description}`) ? 'key-material' : 'credential';
}

function pollJob(jobId: string, onLog: (log: string) => void): Promise<Job> {
  return new Promise((resolve, reject) => {
    const timer = window.setInterval(async () => {
      try {
        const job = await api.job(jobId);
        onLog(job.log);
        if (job.status === 'done' || job.status === 'error') {
          window.clearInterval(timer);
          if (job.status === 'error') toast.error(job.error ?? messages().imageDetail.job.failed);
          resolve(job);
        }
      } catch (error) {
        window.clearInterval(timer);
        toast.error(error);
        reject(error);
      }
    }, 900);
  });
}

async function copyValue(value: string): Promise<void> {
  try {
    await copyToClipboard(value);
    toast.success(messages().common.copied);
  } catch (error) {
    toast.error(error);
  }
}

/** A single evidence-first inventory across raw bytes, extracted files, and recovered NVRAM stores. */
export function RecoveredValuesPanel({
  analysis,
  imageId,
}: {
  analysis: StaticAnalysis | null;
  imageId: string;
}): JSX.Element {
  const t = useMessages();
  const [gitleaks, setGitleaks] = useState<GitleaksResult | null>(null);
  const [nvram, setNvram] = useState<NvramResultView | null>(null);
  const [fsaudit, setFsAudit] = useState<FsAuditResultView | null>(null);
  const [running, setRunning] = useState(false);
  const [auditRunning, setAuditRunning] = useState(false);
  const [log, setLog] = useState('');
  const [query, setQuery] = useState('');
  const [source, setSource] = useState<ValueSource | 'all'>('all');

  const load = useCallback(() => {
    api
      .gitleaks(imageId)
      .then(setGitleaks)
      .catch(() => setGitleaks(null));
    api
      .nvramResult(imageId)
      .then(setNvram)
      .catch(() => setNvram(null));
    api
      .fsauditResult(imageId)
      .then(setFsAudit)
      .catch(() => setFsAudit(null));
  }, [imageId]);

  useEffect(load, [load]);

  const runGitleaks = useCallback(async () => {
    setRunning(true);
    setLog('');
    try {
      const { jobId } = await api.runGitleaks(imageId);
      const job = await pollJob(jobId, setLog);
      if (job.status === 'done') setGitleaks(job.result as GitleaksResult);
    } catch (error) {
      setLog(String(error instanceof Error ? error.message : error));
    } finally {
      setRunning(false);
    }
  }, [imageId]);

  const runFsAudit = useCallback(async () => {
    setAuditRunning(true);
    setLog('');
    try {
      const { jobId } = await api.runAnalysis(imageId, 'fsaudit');
      const job = await pollJob(jobId, setLog);
      if (job.status === 'done') setFsAudit(job.result as FsAuditResultView);
    } catch (error) {
      setLog(String(error instanceof Error ? error.message : error));
    } finally {
      setAuditRunning(false);
    }
  }, [imageId]);

  const values = useMemo<RecoveredValue[]>(() => {
    const recovered: RecoveredValue[] = [];
    for (const [index, hit] of (analysis?.secrets ?? []).entries()) {
      const kind = hit.secretKind ?? 'secret-like string';
      recovered.push({
        id: `raw-${hit.offset}-${index}`,
        source: 'raw',
        category: KEY_MATERIAL.test(kind) ? 'key-material' : 'credential',
        kind,
        value: hit.value,
        location: fmtHex(hit.offset),
        ...(hit.severity ? { severity: hit.severity } : {}),
      });
    }
    for (const [index, finding] of (gitleaks?.findings ?? []).entries()) {
      recovered.push({
        id: `rootfs-${finding.file}-${finding.line}-${index}`,
        source: 'rootfs',
        category: gitleaksCategory(finding),
        kind: finding.rule,
        value: finding.value ?? finding.match,
        location: `${finding.file}:${finding.line}`,
        ...((finding.lineText ?? finding.context) ? { context: finding.lineText ?? finding.context } : {}),
        legacyRedaction: finding.value === undefined,
      });
    }
    for (const [index, entry] of (fsaudit?.recoveredValues ?? []).entries()) {
      recovered.push({
        id: `fsaudit-${entry.path}-${entry.offset ?? index}-${index}`,
        source: 'rootfs',
        category: entry.kind === 'empty-password' ? 'credential' : 'key-material',
        kind: entry.account ? `${entry.kind} · ${entry.account}` : (entry.label ?? entry.kind),
        value: entry.value,
        location: `${entry.path}${entry.offset !== undefined ? ` @ ${fmtHex(entry.offset)}` : ''}`,
      });
    }
    for (const [storeIndex, store] of (nvram?.stores ?? []).entries()) {
      for (const [recordIndex, record] of (store.records ?? []).entries()) {
        recovered.push({
          id: `nvram-${storeIndex}-${record.offset}-${recordIndex}`,
          source: 'nvram',
          category: nvramCategory(record.key),
          kind: record.key,
          value: record.value,
          location: `${fmtHex(store.offset ?? 0)} / ${fmtHex(record.offset)}`,
          ...(store.confidence ? { context: store.confidence } : {}),
        });
      }
    }
    return recovered;
  }, [analysis?.secrets, fsaudit?.recoveredValues, gitleaks?.findings, nvram?.stores]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return values.filter((item) => {
      if (source !== 'all' && item.source !== source) return false;
      if (!needle) return true;
      return [item.kind, item.value, item.location, item.context, item.category]
        .filter(Boolean)
        .some((part) => String(part).toLowerCase().includes(needle));
    });
  }, [query, source, values]);

  const scan = analysis?.secretScan;
  const rawSecrets = analysis?.secrets ?? [];
  const partial = Boolean(scan && scan.scannedBytes < scan.totalBytes);
  const listCapped = Boolean(scan && scan.matched > rawSecrets.length);
  const count = (kind: ValueSource): number => values.filter((item) => item.source === kind).length;

  return (
    <div className="panel recovered-values-panel">
      <div className="recovered-values-head">
        <div>
          <div className="panel-title">{t.imageDetail.secrets.title}</div>
          <div className="panel-sub">{t.imageDetail.secrets.sub}</div>
        </div>
        <div className="recovered-value-actions">
          <button className="btn" disabled={auditRunning} onClick={runFsAudit}>
            {auditRunning ? (
              <>
                <span className="spinner" /> {t.imageDetail.secrets.auditing}
              </>
            ) : fsaudit?.available ? (
              t.imageDetail.secrets.reaudit
            ) : (
              t.imageDetail.secrets.audit
            )}
          </button>
          <button className="btn btn-primary" disabled={running} onClick={runGitleaks}>
            {running ? (
              <>
                <span className="spinner" /> {t.imageDetail.gitleaks.scanning}
              </>
            ) : gitleaks?.available ? (
              t.imageDetail.gitleaks.rescan
            ) : (
              t.imageDetail.gitleaks.scan
            )}
          </button>
        </div>
      </div>

      <div className="banner banner-warn recovered-values-warning">{t.imageDetail.secrets.sensitive}</div>

      <div className="recovered-value-stats" aria-label={t.imageDetail.secrets.inventory}>
        <button
          type="button"
          className={`recovered-stat${source === 'all' ? ' is-active' : ''}`}
          onClick={() => setSource('all')}
        >
          <strong>{values.length}</strong>
          <span>{t.imageDetail.secrets.allSources}</span>
        </button>
        <button
          type="button"
          className={`recovered-stat${source === 'raw' ? ' is-active' : ''}`}
          onClick={() => setSource('raw')}
        >
          <strong>{count('raw')}</strong>
          <span>{t.imageDetail.secrets.rawSource}</span>
        </button>
        <button
          type="button"
          className={`recovered-stat${source === 'rootfs' ? ' is-active' : ''}`}
          onClick={() => setSource('rootfs')}
        >
          <strong>{count('rootfs')}</strong>
          <span>{t.imageDetail.secrets.rootfsSource}</span>
        </button>
        <button
          type="button"
          className={`recovered-stat${source === 'nvram' ? ' is-active' : ''}`}
          onClick={() => setSource('nvram')}
        >
          <strong>{count('nvram')}</strong>
          <span>{t.imageDetail.secrets.nvramSource}</span>
        </button>
      </div>

      <div className="recovered-toolbar">
        <label className="ledger-search">
          <span className="sr-only">{t.imageDetail.secrets.search}</span>
          <input
            className="input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t.imageDetail.secrets.search}
          />
        </label>
        <span className="hint">{t.imageDetail.secrets.showing(filtered.length, values.length)}</span>
      </div>

      {partial && scan ? (
        <div className="banner banner-warn">
          <div style={{ maxWidth: '72ch' }}>
            {t.imageDetail.secrets.partial(
              ((scan.scannedBytes / scan.totalBytes) * 100).toFixed(1),
              fmtBytes(scan.scannedBytes),
              fmtBytes(scan.totalBytes),
            )}
          </div>
        </div>
      ) : null}
      {listCapped && scan ? (
        <div className="hint recovered-bound">{t.imageDetail.secrets.listCapped(rawSecrets.length, scan.matched)}</div>
      ) : null}
      {gitleaks && !gitleaks.available ? (
        <div className="banner banner-warn">{gitleaks.reason ?? t.imageDetail.gitleaks.unavailable}</div>
      ) : null}
      {gitleaks?.available && gitleaks.total !== undefined && gitleaks.total > gitleaks.findings.length ? (
        <div className="hint recovered-bound">
          {t.imageDetail.gitleaks.countCapped(gitleaks.findings.length, gitleaks.total)}
        </div>
      ) : null}
      {nvram?.reason ? <div className="hint recovered-bound">NVRAM: {nvram.reason}</div> : null}

      {values.length === 0 ? (
        <div className="recovered-empty">{t.imageDetail.secrets.empty}</div>
      ) : filtered.length === 0 ? (
        <div className="recovered-empty">{t.imageDetail.secrets.noResults}</div>
      ) : (
        <div className="recovered-value-list">
          {filtered.map((item) => (
            <article className="recovered-value" key={item.id}>
              <div className="recovered-value-meta">
                <span className={`badge badge-${item.severity ?? 'info'}`}>{item.kind}</span>
                <span className="mono">
                  {t.imageDetail.secrets.sourceLabel[item.source]} · {item.location}
                </span>
                <span>{t.imageDetail.secrets.category[item.category]}</span>
              </div>
              <div className="recovered-value-body">
                <pre className="mono">{item.value || t.imageDetail.secrets.emptyValue}</pre>
                <button type="button" className="btn btn-sm" onClick={() => void copyValue(item.value)}>
                  {t.common.copy}
                </button>
              </div>
              {item.context ? <div className="recovered-value-context mono">{item.context}</div> : null}
              {item.legacyRedaction ? <div className="hint">{t.imageDetail.secrets.legacyRedaction}</div> : null}
            </article>
          ))}
        </div>
      )}
      {log ? <pre className="mono recovered-log">{log}</pre> : null}
    </div>
  );
}
