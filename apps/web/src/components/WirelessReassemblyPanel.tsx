import { useCallback, useState } from 'react';
import { Link } from 'react-router-dom';
import { type CaptureDevice, api } from '../api';
import {
  type BleReassemblyInspection,
  type ZigbeeReassemblyInspection,
  inspectBleReassembly,
  inspectZigbeeReassembly,
  parseCapturePayload,
  uint8ToBase64,
} from '../capture-reassembly';
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
  imageId?: string | undefined;
  bleInspection?: BleReassemblyInspection | undefined;
  zigbeeInspection?: ZigbeeReassemblyInspection | undefined;
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
      // 1. Read files and parse into chunks / blocks
      const allChunksOrBlocks: Uint8Array[] = [];
      const allBase64: string[] = [];
      const collectedMissingSeqs: number[] = [];
      let parsedName: string | undefined;
      let parsedInitPacket: Uint8Array | undefined;
      let parsedExpectedSize: number | undefined;

      // Sort files naturally by name
      const files = [...selectedFiles].sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }),
      );

      for (const file of files) {
        if (file.name.endsWith('.json') || file.name.endsWith('.txt') || file.name.endsWith('.hex')) {
          const text = await file.text();
          const parsed = parseCapturePayload(text, file.name);
          if (parsed.error) throw new Error(parsed.error);
          allChunksOrBlocks.push(...parsed.chunksOrBlocks);
          allBase64.push(...parsed.base64Items);
          if (parsed.missingSeqs.length > 0) collectedMissingSeqs.push(...parsed.missingSeqs);
          if (parsed.name && !parsedName) parsedName = parsed.name;
          if (parsed.initPacket && !parsedInitPacket) parsedInitPacket = parsed.initPacket;
          if (parsed.expectedSize !== undefined && parsedExpectedSize === undefined) {
            parsedExpectedSize = parsed.expectedSize;
          }
        } else {
          // Binary chunk or container
          const buffer = await file.arrayBuffer();
          const u8 = new Uint8Array(buffer);
          allChunksOrBlocks.push(u8);
          allBase64.push(uint8ToBase64(u8));
          if (!parsedName) parsedName = file.name;
        }
      }

      // If separate init packet was uploaded for BLE
      if (tab === 'ble' && initPacketFile) {
        const initBuf = await initPacketFile.arrayBuffer();
        parsedInitPacket = new Uint8Array(initBuf);
      }

      if (allBase64.length === 0) {
        throw new Error(t.capture.wireless.filesRequired);
      }

      const finalName = filename.trim() || parsedName || (tab === 'ble' ? 'ble-dfu.bin' : 'zigbee-ota.bin');

      // 2. Perform client-side inspection
      let bleInspection: BleReassemblyInspection | undefined;
      let zigbeeInspection: ZigbeeReassemblyInspection | undefined;
      let isComplete = false;

      if (tab === 'ble') {
        bleInspection = inspectBleReassembly(
          allChunksOrBlocks,
          parsedInitPacket,
          parsedExpectedSize,
          collectedMissingSeqs,
        );
        isComplete = bleInspection.isComplete;
      } else {
        zigbeeInspection = inspectZigbeeReassembly(allChunksOrBlocks, collectedMissingSeqs);
        isComplete = zigbeeInspection.isComplete;
      }

      // 3. Stage the reassembly through the API route
      let flowId: string | undefined;
      let firmwareScore: number | undefined;

      if (tab === 'ble') {
        const stageRes = await api.stageBleDfu(curSessionId, allBase64, finalName);
        flowId = stageRes.flowId;
        firmwareScore = stageRes.firmwareScore;
      } else {
        const stageRes = await api.stageZigbeeOta(curSessionId, allBase64, finalName);
        flowId = stageRes.flowId;
        firmwareScore = stageRes.firmwareScore;
      }

      // 4. Ingest if complete and autoIngest requested
      let imageId: string | undefined;
      if (isComplete && autoIngest && flowId) {
        try {
          const ingestRes = await api.ingestCaptureFlow(curSessionId, flowId);
          imageId = ingestRes.imageId;
        } catch (ingestErr) {
          // Non-fatal for reassembly result, but captured
          setFormError(ingestErr instanceof Error ? ingestErr.message : String(ingestErr));
        }
      }

      setResult({
        tab,
        flowId,
        firmwareScore,
        imageId,
        bleInspection,
        zigbeeInspection,
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

  const currentInspection = tab === 'ble' ? result?.bleInspection : result?.zigbeeInspection;
  const isComplete = currentInspection?.isComplete ?? false;
  const hasError = Boolean(result?.error);

  return (
    <div className="panel" data-testid="wireless-reassembly-panel">
      <div className="panel-title">{t.capture.wireless.panelTitle}</div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {t.capture.wireless.panelSub}
      </div>

      {!captureEnabled && (
        <div className="banner banner-warn" style={{ marginTop: 12 }} data-testid="capture-disabled-banner">
          {t.capture.wireless.disabledWarning}
        </div>
      )}

      <div className="tabs" role="tablist" style={{ marginTop: 16 }}>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'ble'}
          className={`tab ${tab === 'ble' ? 'active' : ''}`}
          onClick={() => switchTab('ble')}
        >
          {t.capture.wireless.tabBle}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'zigbee'}
          className={`tab ${tab === 'zigbee' ? 'active' : ''}`}
          onClick={() => switchTab('zigbee')}
        >
          {t.capture.wireless.tabZigbee}
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {/* Operator Acknowledgement */}
        <label htmlFor="wireless-ack" style={{ display: 'flex', gap: 8, alignItems: 'flex-start', maxWidth: 640 }}>
          <input id="wireless-ack" type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span className="hint">{t.capture.wireless.ack}</span>
        </label>

        {/* Target Device & Session Creation */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
          <div>
            <label htmlFor="wireless-target-device" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
              {t.capture.wireless.targetDevice}
            </label>
            {devices.length > 0 ? (
              <select
                id="wireless-target-device"
                className="select"
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                style={{ width: '100%' }}
                aria-label={t.capture.wireless.deviceIdLabel}
              >
                <option value="">{t.capture.wireless.deviceSelectPlaceholder}</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.mac} {d.ouiVendor ? `(${d.ouiVendor})` : ''} {d.ip ? `· ${d.ip}` : ''}
                  </option>
                ))}
              </select>
            ) : (
              <input
                id="wireless-target-device"
                className="select"
                placeholder={t.capture.wireless.deviceSelectPlaceholder}
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                style={{ width: '100%', fontFamily: 'var(--mono)', fontSize: 12 }}
                aria-label={t.capture.wireless.deviceIdLabel}
              />
            )}
          </div>

          <div>
            <label htmlFor="wireless-session-id" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
              {t.capture.wireless.sessionIdLabel}
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                id="wireless-session-id"
                className="select"
                placeholder={t.capture.wireless.sessionIdPlaceholder}
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
                style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 12 }}
                aria-label={t.capture.wireless.sessionIdLabel}
              />
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                disabled={!captureEnabled || !ack || creatingSession}
                onClick={handleCreateSession}
              >
                {creatingSession ? t.capture.wireless.creatingSession : t.capture.wireless.createSession}
              </button>
            </div>
            {sessionSuccess && (
              <div className="hint" style={{ marginTop: 4, color: 'var(--ok)' }}>
                {t.capture.wireless.sessionCreated(sessionSuccess)}
              </div>
            )}
          </div>
        </div>

        {/* Filename and Files */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
          <div>
            <label htmlFor="wireless-filename" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
              {t.capture.wireless.filenameLabel}
            </label>
            <input
              id="wireless-filename"
              className="select"
              placeholder={tab === 'ble' ? 'ble-dfu.bin' : 'zigbee-ota.bin'}
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              style={{ width: '100%', fontFamily: 'var(--mono)', fontSize: 12 }}
              aria-label={t.capture.wireless.filenameLabel}
            />
          </div>

          <div>
            <label htmlFor="wireless-files" style={{ display: 'block', marginBottom: 4, fontSize: 12 }}>
              {t.capture.wireless.filesLabel}
            </label>
            <input
              id="wireless-files"
              type="file"
              multiple
              className="select"
              style={{ width: '100%', fontSize: 12 }}
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
          ) : !isComplete ? (
            <div className="banner banner-warn" style={{ marginBottom: 12 }} data-testid="incomplete-banner">
              <span className="badge badge-high" style={{ marginRight: 8 }}>
                {t.capture.wireless.statusIncomplete}
              </span>
              <span>
                {currentInspection?.details.length
                  ? currentInspection.details.join(' · ')
                  : t.capture.wireless.statusIncomplete}
              </span>
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
          {currentInspection && (
            <div className="table-wrap" style={{ marginBottom: 14 }}>
              <table className="data">
                <tbody>
                  <tr>
                    <td style={{ width: 220 }}>{t.capture.wireless.reconstructedBytes}</td>
                    <td className="mono">
                      <strong>{currentInspection.reconstructedBytes.toLocaleString()} bytes</strong>{' '}
                      <span className="hint">
                        ({(currentInspection.reconstructedBytes / 1024).toFixed(1)} KB) ·{' '}
                        {tab === 'ble' && result?.bleInspection
                          ? t.capture.wireless.chunksCount(result.bleInspection.chunkCount)
                          : tab === 'zigbee' && result?.zigbeeInspection
                            ? t.capture.wireless.blocksCount(result.zigbeeInspection.blockCount)
                            : ''}
                      </span>
                    </td>
                  </tr>

                  {tab === 'ble' &&
                    result?.bleInspection?.expectedSize !== null &&
                    result?.bleInspection?.expectedSize !== undefined && (
                      <tr>
                        <td>{t.capture.wireless.expectedBytes}</td>
                        <td className="mono">
                          {result.bleInspection.expectedSize.toLocaleString()} bytes{' '}
                          <span className="hint">({(result.bleInspection.expectedSize / 1024).toFixed(1)} KB)</span>
                        </td>
                      </tr>
                    )}

                  {tab === 'zigbee' &&
                    result?.zigbeeInspection?.expectedTotalBytes !== null &&
                    result?.zigbeeInspection?.expectedTotalBytes !== undefined && (
                      <tr>
                        <td>{t.capture.wireless.expectedBytes}</td>
                        <td className="mono">
                          {result.zigbeeInspection.expectedTotalBytes.toLocaleString()} bytes{' '}
                          <span className="hint">
                            ({(result.zigbeeInspection.expectedTotalBytes / 1024).toFixed(1)} KB)
                          </span>
                        </td>
                      </tr>
                    )}

                  <tr>
                    <td>{t.capture.wireless.missingGaps}</td>
                    <td>
                      {currentInspection.missingBytes > 0 ? (
                        <span className="badge badge-high mono">
                          {t.capture.wireless.missingBytesCount(
                            currentInspection.missingBytes,
                            (tab === 'ble'
                              ? result?.bleInspection?.expectedSize
                              : result?.zigbeeInspection?.expectedTotalBytes) ?? currentInspection.reconstructedBytes,
                          )}
                        </span>
                      ) : currentInspection.missingSeqs.length > 0 ? (
                        <span className="badge badge-high mono">
                          {t.capture.wireless.missingChunksNamed(currentInspection.missingSeqs.join(', '))}
                        </span>
                      ) : (
                        <span className="badge badge-ok">{t.capture.wireless.noGaps}</span>
                      )}
                    </td>
                  </tr>

                  <tr>
                    <td>{t.capture.wireless.integrity}</td>
                    <td>
                      {tab === 'zigbee' ? (
                        (currentInspection as ZigbeeReassemblyInspection).header ? (
                          <span className="badge badge-ok mono">
                            {t.capture.wireless.integrityValidZigbee(
                              `0x${(currentInspection as ZigbeeReassemblyInspection).header?.manufacturerCode.toString(16).padStart(4, '0')}`,
                              `0x${(currentInspection as ZigbeeReassemblyInspection).header?.imageType.toString(16).padStart(4, '0')}`,
                              `v${(currentInspection as ZigbeeReassemblyInspection).header?.fileVersion}`,
                            )}
                          </span>
                        ) : (
                          <span className="badge badge-high">{t.capture.wireless.integrityNone}</span>
                        )
                      ) : (currentInspection as BleReassemblyInspection).integrityValid ? (
                        <span className="badge badge-ok mono">
                          {t.capture.wireless.integrityValidBle(
                            `${(currentInspection as BleReassemblyInspection).expectedSize?.toLocaleString()} bytes`,
                          )}
                        </span>
                      ) : (currentInspection as BleReassemblyInspection).integrityChecked ? (
                        <span className="badge badge-high mono">
                          {t.capture.wireless.missingBytesCount(
                            currentInspection.missingBytes,
                            (currentInspection as BleReassemblyInspection).expectedSize ?? 0,
                          )}
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

          {/* Workbench Ingest & Image Link */}
          {result.flowId && isComplete && (
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
