/**
 * Saved emulation presets — persist a named bring-up config (mode + optional target binary) so a known-good
 * emulation can be re-run in one click instead of re-entering it. Running a preset dispatches to the same
 * /emulate + /emulate-system + /renode + /chipsec endpoints the Simulation menu uses.
 *
 * The MODE is an identifier: `user-qemu` and the rest are what `dispatchPreset` switches on and what the API stores,
 * so the table below carries the value and whether it needs a binary, and the human label comes from the catalogue
 * keyed by that same value. A mode the catalogue does not gloss would be a compile error, not a blank row.
 */
import { useCallback, useEffect, useState } from 'react';
import { type EmulationPreset, api } from '../api';
import { useMessages } from '../i18n';

const MODES: { value: EmulationPreset['mode']; needsBinary: boolean }[] = [
  { value: 'user-qemu', needsBinary: true },
  { value: 'chroot-qemu', needsBinary: true },
  { value: 'system-qemu', needsBinary: false },
  { value: 'renode', needsBinary: false },
  { value: 'uefi-chipsec', needsBinary: false },
];

async function dispatchPreset(imageId: string, p: EmulationPreset): Promise<string> {
  const bin = p.binary ?? undefined;
  if (p.mode === 'user-qemu') return (await api.emulate(imageId, bin)).jobId;
  if (p.mode === 'chroot-qemu') return (await api.emulateSystem(imageId, 'chroot-service', bin)).jobId;
  if (p.mode === 'system-qemu') return (await api.emulateSystem(imageId, 'full-system')).jobId;
  if (p.mode === 'renode') return (await api.runRenode(imageId)).jobId;
  return (await api.runChipsec(imageId)).jobId;
}

export function PresetsPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const [presets, setPresets] = useState<EmulationPreset[]>([]);
  const [name, setName] = useState('');
  const [mode, setMode] = useState<EmulationPreset['mode']>('user-qemu');
  const [binary, setBinary] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .listPresets(imageId)
      .then(setPresets)
      .catch(() => setPresets([]));
  }, [imageId]);
  useEffect(load, [load]);

  const save = useCallback(async () => {
    setErr(null);
    try {
      const needsBinary = MODES.find((m) => m.value === mode)?.needsBinary;
      await api.savePreset(imageId, {
        name: name.trim(),
        mode,
        ...(needsBinary && binary.trim() ? { binary: binary.trim() } : {}),
      });
      setName('');
      setBinary('');
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [imageId, name, mode, binary, load]);

  const run = useCallback(
    async (p: EmulationPreset) => {
      setErr(null);
      setMsg(null);
      try {
        const jobId = await dispatchPreset(imageId, p);
        setMsg(t.panels.presets.started(p.name, jobId));
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    },
    [imageId, t],
  );

  const remove = useCallback(
    async (id: string) => {
      await api.deletePreset(id).catch(() => {});
      load();
    },
    [load],
  );

  // A mode this build does not know still shows its CODE rather than an empty pill — the identifier is the truth
  // about the row, and a stored preset can name a mode written by an older build.
  const modeLabel = (m: string): string => (t.panels.presets.mode as Record<string, string | undefined>)[m] ?? m;
  const needsBinary = MODES.find((m) => m.value === mode)?.needsBinary ?? false;

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">{t.panels.presets.title}</div>
      <div className="panel-sub">{t.panels.presets.sub}</div>

      <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          placeholder={t.panels.presets.namePlaceholder}
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={inputStyle(160)}
        />
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value as EmulationPreset['mode'])}
          style={inputStyle(160)}
        >
          {MODES.map((m) => (
            <option key={m.value} value={m.value}>
              {t.panels.presets.mode[m.value]}
            </option>
          ))}
        </select>
        {needsBinary && (
          <input
            className="mono"
            placeholder={t.panels.presets.binaryPlaceholder}
            value={binary}
            onChange={(e) => setBinary(e.target.value)}
            style={inputStyle(180)}
          />
        )}
        <button className="btn btn-sm" disabled={!name.trim()} onClick={save}>
          {t.panels.presets.save}
        </button>
      </div>

      {err && (
        <div className="banner banner-warn" style={{ marginTop: 10 }}>
          {err}
        </div>
      )}
      {msg && (
        <div className="hint" style={{ marginTop: 10 }}>
          {msg}
        </div>
      )}

      {presets.length > 0 && (
        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {presets.map((p) => (
            <div
              key={p.id}
              style={{
                display: 'flex',
                gap: 8,
                alignItems: 'center',
                background: 'var(--bg)',
                border: '1px solid var(--border-soft)',
                borderRadius: 6,
                padding: '6px 10px',
              }}
            >
              <strong style={{ fontSize: 12.5 }}>{p.name}</strong>
              <span className="badge">{modeLabel(p.mode)}</span>
              {p.binary && <span className="mono hint">{p.binary}</span>}
              <button className="btn btn-primary btn-sm" style={{ marginLeft: 'auto' }} onClick={() => run(p)}>
                {t.common.run}
              </button>
              <button className="btn btn-sm" title={t.panels.presets.remove} onClick={() => remove(p.id)}>
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function inputStyle(width: number): React.CSSProperties {
  return {
    width,
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    color: 'var(--text)',
    padding: '6px 10px',
    fontSize: 12,
  };
}
