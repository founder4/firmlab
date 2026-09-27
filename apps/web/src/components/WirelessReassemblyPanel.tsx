import { useCallback, useState } from 'react';
import { Link } from 'react-router-dom';
import { type BleDfuResult, type CaptureDevice, type ReassemblyCompleteness, type ZigbeeOtaResult, api } from '../api';
import { parseCapturePayload, uint8ToBase64 } from '../capture-reassembly';
import { useMessages } from '../i18n';

export interface WirelessReassemblyPanelProps {
  captureEnabled: boolean;
  devices?: CaptureDevice[] | undefined;
  initialSessionId?: string | undefined;
}

type WirelessTab = 'ble' | 'zigbee';

interface ReassemblyResultState {
  tab: WirelessTab;
  flowId?: string | undefined;
  firmwareScore?: number | undefined;
  carved?: boolean | undefined;
  size?: number | undefined;
  chunkCount?: number | undefined;
  blockCount?: number | undefined;
  completeness?: ReassemblyCompleteness | undefined;
  zigbeeMeta?:
    | {
        manufacturerCode: number;
        imageType: number;
        fileVersion: number;
      }
    | undefined;
  imageId?: string | undefined;
  error?: string | undefined;
}

export function WirelessReassemblyPanel({
  captureEnabled,
  devices = [],
  initialSessionId = '',
}: WirelessReassemblyPanelProps): JSX.Element {
  const t = useMessages();
  const [tab, setTab] = useState<WirelessTab>('ble');
  const [ack, setAck] = useState(false);
  const [deviceId, setDeviceId] = useState('');
  const [sessionId, setSessionId] = useState(initialSessionId);
  const [filename, setFilename] = useState('');
  const [autoIngest, setAutoIngest] = useState(true);

  // File state
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [initPacketFile, setInitPacketFile] = useState<File | null>(null);

  // Execution state
  const [creatingSession, setCreatingSession] = useState(false);
  const [inFlight, setInFlight] = useState(false);
  const [ingesting, setIngesting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [sessionSuccess, setSessionSuccess] = useState<string | null>(null);

  // Result state
  const [result, setResult] = useState<ReassemblyResultState | null>(null);

  const switchTab = useCallback((nextTab: WirelessTab) => {
    setTab(nextTab);
    setFormError(null);
    setResult(null);
    setSelectedFiles([]);
    setInitPacketFile(null);
  }, []);

  const handleCreateSession = useCallback(async () => {
    setFormError(null);
    setSessionSuccess(null);
    if (!captureEnabled) {
      setFormError(t.capture.wireless.disabledWarning);
      return;
    }
    if (!ack) {
      setFormError(t.capture.wireless.ackRequired);
      return;
    }

    setCreatingSession(true);
    try {
      const dev = deviceId.trim() || null;
      let newId = '';
      if (tab === 'ble') {
        const res = await api.createBleCaptureSession(dev, ack);
        newId = res.sessionId;
      } else {
        const res = await api.createZigbeeCaptureSession(dev, ack);
        newId = res.sessionId;
      }
      setSessionId(newId);
      setSessionSuccess(newId);
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreatingSession(false);
    }
  }, [captureEnabled, ack, deviceId, tab, t]);

  const handleSubmit = useCallback(async () => {
    setFormError(null);
    setResult(null);

    if (!captureEnabled) {
      setFormError(t.capture.wireless.disabledWarning);
      return;
    }
    if (!ack) {
      setFormError(t.capture.wireless.ackRequired);
      return;
    }
    const curSessionId = sessionId.trim();
    if (!curSessionId) {
      setFormError(t.capture.wireless.sessionRequired);
      return;
    }
    if (selectedFiles.length === 0) {
      setFormError(t.capture.wireless.filesRequired);
      return;
    }

    setInFlight(true);
    try {
      // 1. Read files and decode into base64 items (transport only, no analysis)
      const allBase64: string[] = [];
      const allSeqs: number[] = [];
      let parsedName: string | undefined;
      let initPacketB64: string | undefined;

      // Sort files naturally by name
      const files = [...selectedFiles].sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }),
      );

      for (const file of files) {
        if (file.name.endsWith('.json') || file.name.endsWith('.txt') || file.name.endsWith('.hex')) {
          const text = await file.text();
          const parsed = parseCapturePayload(text, file.name);
          if (parsed.error) throw new Error(parsed.error);
          allBase64.push(...parsed.base64Items);
          if (parsed.sequences) allSeqs.push(...parsed.sequences);
          if (parsed.initPacketBase64 && !initPacketB64) initPacketB64 = parsed.initPacketBase64;
          if (parsed.name && !parsedName) parsedName = parsed.name;
        } else {
          // Binary chunk or container
          const buffer = await file.arrayBuffer();
          const u8 = new Uint8Array(buffer);
          allBase64.push(uint8ToBase64(u8));
          if (!parsedName) parsedName = file.name;
        }
      }

      // If separate init packet was uploaded for BLE
      if (tab === 'ble' && initPacketFile) {
        const initBuf = await initPacketFile.arrayBuffer();
        initPacketB64 = uint8ToBase64(new Uint8Array(initBuf));
      }

      if (allBase64.length === 0) {
        throw new Error(t.capture.wireless.filesRequired);
      }

      const finalName = filename.trim() || parsedName || (tab === 'ble' ? 'ble-dfu.bin' : 'zigbee-ota.bin');

      // 2. Stage through the backend API route — the backend computes completeness
      let stageRes: BleDfuResult | ZigbeeOtaResult;
      const seqsParam = allSeqs.length > 0 ? allSeqs : undefined;
      if (tab === 'ble') {
        stageRes = await api.stageBleDfu(curSessionId, allBase64, finalName, initPacketB64, seqsParam);
      } else {
        stageRes = await api.stageZigbeeOta(curSessionId, allBase64, finalName, seqsParam);
      }

      const completeness = stageRes.completeness;
      // Complete if backend confirms completeness; if server is older (completeness omitted), fallback to carved
      const isComplete = completeness ? completeness.status === 'complete' : stageRes.carved;

      // 3. Ingest ONLY if complete and autoIngest requested
      let imageId: string | undefined;
      if (isComplete && autoIngest && stageRes.carved && stageRes.flowId) {
        try {
          const ingestRes = await api.ingestCaptureFlow(curSessionId, stageRes.flowId);
          imageId = ingestRes.imageId;
        } catch (ingestErr) {
          setFormError(ingestErr instanceof Error ? ingestErr.message : String(ingestErr));
        }
      }

      setResult({
        tab,
        flowId: stageRes.flowId,
        firmwareScore: stageRes.firmwareScore,
        carved: stageRes.carved,
        size: stageRes.size,
        chunkCount: tab === 'ble' ? allBase64.length : undefined,
        blockCount: tab === 'zigbee' ? allBase64.length : undefined,
        completeness,
        zigbeeMeta:
          tab === 'zigbee' && 'manufacturerCode' in stageRes
            ? {
                manufacturerCode: stageRes.manufacturerCode,
                imageType: stageRes.imageType,
                fileVersion: stageRes.fileVersion,
              }
            : undefined,
        imageId,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('FIRMLAB_CAPTURE') || msg.includes('Capture disabled')) {
        setFormError(t.capture.wireless.disabledWarning);
      } else {
        setFormError(msg);
      }
      setResult({
        tab,
        error: msg,
      });
    } finally {
      setInFlight(false);
    }
  }, [captureEnabled, ack, sessionId, selectedFiles, tab, initPacketFile, filename, autoIngest, t]);

  const handleManualIngest = useCallback(async () => {
    if (!result?.flowId || !sessionId.trim()) return;
    setIngesting(true);
    try {
      const res = await api.ingestCaptureFlow(sessionId.trim(), result.flowId);
      setResult((prev) => (prev ? { ...prev, imageId: res.imageId } : null));
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e));
    } finally {
      setIngesting(false);
    }
  }, [result?.flowId, sessionId]);

  const completeness = result?.completeness;
  const isComplete = completeness ? completeness.status === 'complete' : (result?.carved ?? false);
  const isIncomplete = completeness ? completeness.status === 'incomplete' : !result?.carved && !result?.error;
  const isUnknown = completeness ? completeness.status === 'unknown' : false;
  const isLegacy = Boolean(result && !completeness && !result.error);
  const hasError = Boolean(result?.error);

  return (
    <div className="panel" data-testid="wireless-reassembly-panel">
      <div className="panel-title">{t.capture.wireless.panelTitle}</div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {t.capture.wireless.panelSub}
      </div>

      {/* Flag FIRMLAB_CAPTURE disabled banner */}
      {!captureEnabled && (
        <div
          className="banner banner-warn"
          role="alert"
          style={{ marginTop: 12 }}
          data-testid="capture-disabled-banner"
        >
          {t.capture.wireless.disabledWarning}
        </div>
      )}

      {/* Tabs: BLE DFU / Zigbee OTA */}
      <div className="tabs" style={{ marginTop: 16, marginBottom: 16 }} role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'ble'}
          className={`tab-btn ${tab === 'ble' ? 'active' : ''}`}
          onClick={() => switchTab('ble')}
        >
          {t.capture.wireless.tabBle}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'zigbee'}
          className={`tab-btn ${tab === 'zigbee' ? 'active' : ''}`}
          onClick={() => switchTab('zigbee')}
        >
          {t.capture.wireless.tabZigbee}
        </button>
      </div>

      {/* Form area */}
      <div style={{ display: 'grid', gap: 14, maxWidth: 640 }}>
        {/* Operator Acknowledgement */}
        <label
          htmlFor="wireless-ack"
          style={{
            display: 'flex',
            gap: 8,
            alignItems: 'flex-start',
            cursor: 'pointer',
            padding: '8px 10px',
            background: 'var(--panel-sub)',
            borderRadius: 4,
          }}
        >
          <input
            id="wireless-ack"
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
            style={{ marginTop: 3 }}
            aria-label={t.capture.wireless.ack}
          />
          <span style={{ fontSize: 13, lineHeight: 1.4 }}>{t.capture.wireless.ack}</span>
        </label>

        {/* Target device selector (optional) */}
        <div>
          <label htmlFor="wireless-device-select" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
            {t.capture.wireless.targetDevice}
          </label>
          <select
            id="wireless-device-select"
            className="select"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            style={{ maxWidth: 420 }}
            aria-label={t.capture.wireless.targetDevice}
          >
            <option value="">{t.capture.wireless.deviceSelectPlaceholder}</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.id} — {d.ouiVendor || d.mac} {d.ip ? `(${d.ip})` : ''}
              </option>
            ))}
          </select>
        </div>

        {/* Session ID input & Create button */}
        <div>
          <label htmlFor="wireless-session-id" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
            {t.capture.wireless.sessionIdLabel}
          </label>
          <div style={{ display: 'flex', gap: 8, maxWidth: 480 }}>
            <input
              id="wireless-session-id"
              type="text"
              className="select mono"
              placeholder={t.capture.wireless.sessionIdPlaceholder}
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              style={{ flex: 1 }}
              aria-label={t.capture.wireless.sessionIdLabel}
            />
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={!captureEnabled || !ack || creatingSession}
              onClick={handleCreateSession}
              aria-busy={creatingSession}
            >
              {creatingSession ? t.capture.wireless.creatingSession : t.capture.wireless.createSession}
            </button>
          </div>
          {sessionSuccess && (
            <div className="hint" style={{ marginTop: 4, color: 'var(--green)' }}>
              {t.capture.wireless.sessionCreated(sessionSuccess)}
            </div>
          )}
        </div>

        {/* Output firmware name */}
        <div>
          <label htmlFor="wireless-filename" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
            {t.capture.wireless.filenameLabel}
          </label>
          <input
            id="wireless-filename"
            type="text"
            className="select mono"
            placeholder={tab === 'ble' ? 'ble-dfu.bin' : 'zigbee-ota.bin'}
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            style={{ maxWidth: 420 }}
            aria-label={t.capture.wireless.filenameLabel}
          />
        </div>

        {/* Capture files upload */}
        <div>
          <label htmlFor="wireless-files" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
            {t.capture.wireless.filesLabel}
          </label>
          <input
            id="wireless-files"
            type="file"
            multiple
            className="select"
            style={{ maxWidth: 420, fontSize: 12 }}
            aria-label={t.capture.wireless.filesLabel}
            onChange={(e) => {
              if (e.target.files) {
                setSelectedFiles(Array.from(e.target.files));
              }
            }}
          />
          <div className="hint" style={{ marginTop: 4, fontSize: 11 }}>
            {tab === 'ble' ? t.capture.wireless.filesHintBle : t.capture.wireless.filesHintZigbee}
          </div>
        </div>

        {/* BLE Init Packet (optional) */}
        {tab === 'ble' && (
          <div>
            <label htmlFor="wireless-init-packet" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
              {t.capture.wireless.initPacketLabel}
            </label>
            <input
              id="wireless-init-packet"
              type="file"
              accept=".dat,.bin"
              className="select"
              style={{ maxWidth: 420, fontSize: 12 }}
              aria-label={t.capture.wireless.initPacketLabel}
              onChange={(e) => {
                if (e.target.files?.[0]) {
                  setInitPacketFile(e.target.files[0]);
                } else {
                  setInitPacketFile(null);
                }
              }}
            />
            <div className="hint" style={{ marginTop: 4, fontSize: 11 }}>
              {t.capture.wireless.initPacketHint}
            </div>
          </div>
        )}

        {/* Auto Ingest Checkbox */}
        <label htmlFor="wireless-auto-ingest" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            id="wireless-auto-ingest"
            type="checkbox"
            checked={autoIngest}
            onChange={(e) => setAutoIngest(e.target.checked)}
          />
          <span className="hint">{t.capture.wireless.autoIngest}</span>
        </label>

        {/* Error message */}
        {formError && (
          <div className="banner banner-warn" role="alert" data-testid="form-error">
            {formError}
          </div>
        )}

        {/* Action button */}
        <div>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={!captureEnabled || inFlight}
            onClick={handleSubmit}
            aria-busy={inFlight}
          >
            {inFlight
              ? t.capture.wireless.processing
              : tab === 'ble'
                ? t.capture.wireless.submitBle
                : t.capture.wireless.submitZigbee}
          </button>
        </div>
      </div>

      {/* Results / Status Area */}
      {result && (
        <div
          style={{ marginTop: 20, borderTop: '1px solid var(--border)', paddingTop: 16 }}
          data-testid="reassembly-results"
        >
          <div className="eyebrow" style={{ marginBottom: 6 }}>
            {t.capture.wireless.resultsTitle}
          </div>

          {/* Status Verdict Banner */}
          {hasError ? (
            <div className="banner banner-warn" style={{ marginBottom: 12 }}>
              <span className="badge badge-high" style={{ marginRight: 8 }}>
                {t.capture.wireless.statusError}
              </span>
              <span>{result.error}</span>
            </div>
          ) : isIncomplete ? (
            <div className="banner banner-warn" style={{ marginBottom: 12 }} data-testid="incomplete-banner">
              <span className="badge badge-high" style={{ marginRight: 8 }}>
                {t.capture.wireless.statusIncomplete}
              </span>
              <span>{completeness?.reason ?? t.capture.wireless.statusIncomplete}</span>
            </div>
          ) : isUnknown ? (
            <div className="banner banner-warn" style={{ marginBottom: 12 }} data-testid="unknown-banner">
              <span className="badge badge-high" style={{ marginRight: 8 }}>
                {t.capture.wireless.statusUnknown}
              </span>
              <span>{completeness?.reason ?? t.capture.wireless.statusUnknown}</span>
            </div>
          ) : isLegacy ? (
            <div className="banner banner-info" style={{ marginBottom: 12 }} data-testid="legacy-banner">
              <span className="badge badge-info" style={{ marginRight: 8 }}>
                {t.capture.wireless.statusLegacy}
              </span>
              <span>{t.capture.wireless.statusLegacy}</span>
            </div>
          ) : (
            <div className="banner banner-info" style={{ marginBottom: 12 }} data-testid="complete-banner">
              <span className="badge badge-ok" style={{ marginRight: 8 }}>
                {t.capture.wireless.statusComplete}
              </span>
              {result.firmwareScore !== undefined && <span>{t.capture.wireless.flowStaged(result.firmwareScore)}</span>}
            </div>
          )}

          {/* Inspection Metrics Table */}
          {!hasError && (
            <div className="table-wrap" style={{ marginBottom: 14 }}>
              <table className="data">
                <tbody>
                  <tr>
                    <td style={{ width: 220 }}>{t.capture.wireless.reconstructedBytes}</td>
                    <td className="mono">
                      <strong>{(result.size ?? 0).toLocaleString()} bytes</strong>{' '}
                      <span className="hint">
                        ({((result.size ?? 0) / 1024).toFixed(1)} KB) ·{' '}
                        {tab === 'ble' && result.chunkCount !== undefined
                          ? t.capture.wireless.chunksCount(result.chunkCount)
                          : tab === 'zigbee' && result.blockCount !== undefined
                            ? t.capture.wireless.blocksCount(result.blockCount)
                            : ''}
                      </span>
                    </td>
                  </tr>

                  <tr>
                    <td>{t.capture.wireless.expectedBytes}</td>
                    <td className="mono">
                      {completeness?.expectedBytes !== null && completeness?.expectedBytes !== undefined ? (
                        <>
                          {completeness.expectedBytes.toLocaleString()} bytes{' '}
                          <span className="hint">({(completeness.expectedBytes / 1024).toFixed(1)} KB)</span>
                        </>
                      ) : (
                        <span className="hint">{t.capture.wireless.expectedUnknown}</span>
                      )}
                    </td>
                  </tr>

                  <tr>
                    <td>{t.capture.wireless.missingGaps}</td>
                    <td>
                      {completeness?.missingBytes && completeness.missingBytes > 0 ? (
                        <span className="badge badge-high mono">
                          {t.capture.wireless.missingBytesCount(
                            completeness.missingBytes,
                            completeness.expectedBytes ?? result.size ?? 0,
                          )}
                        </span>
                      ) : completeness?.missingSequences && completeness.missingSequences.length > 0 ? (
                        <span className="badge badge-high mono">
                          {t.capture.wireless.missingChunksNamed(completeness.missingSequences.join(', '))}
                        </span>
                      ) : isComplete ? (
                        <span className="badge badge-ok">{t.capture.wireless.noGaps}</span>
                      ) : (
                        <span className="hint">{completeness?.reason ?? t.capture.wireless.expectedUnknown}</span>
                      )}
                    </td>
                  </tr>

                  <tr>
                    <td>{t.capture.wireless.integrity}</td>
                    <td>
                      {tab === 'zigbee' && result.zigbeeMeta ? (
                        <span className="badge badge-ok mono">
                          {t.capture.wireless.integrityValidZigbee(
                            `0x${result.zigbeeMeta.manufacturerCode.toString(16).padStart(4, '0')}`,
                            `0x${result.zigbeeMeta.imageType.toString(16).padStart(4, '0')}`,
                            `v${result.zigbeeMeta.fileVersion}`,
                          )}
                        </span>
                      ) : tab === 'ble' && isComplete && completeness?.expectedBytes ? (
                        <span className="badge badge-ok mono">
                          {t.capture.wireless.integrityValidBle(`${completeness.expectedBytes.toLocaleString()} bytes`)}
                        </span>
                      ) : (
                        <span className="hint">{t.capture.wireless.integrityNone}</span>
                      )}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {/* Workbench Ingest & Image Link — ONLY if flow is staged and complete */}
          {result.flowId && isComplete && result.carved && (
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 10 }}>
              {result.imageId ? (
                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }} data-testid="ingested-link-container">
                  <span className="badge badge-ok">{t.capture.wireless.imageIngested(result.imageId)}</span>
                  <Link
                    to={`/image/${result.imageId}/overview`}
                    className="btn btn-primary btn-sm"
                    data-testid="image-overview-link"
                  >
                    {t.capture.wireless.openOverview}
                  </Link>
                </div>
              ) : (
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={ingesting}
                  onClick={handleManualIngest}
                >
                  {ingesting ? t.capture.wireless.ingesting : t.capture.wireless.ingestButton}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
