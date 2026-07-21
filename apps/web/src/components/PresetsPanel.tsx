/**
 * Saved emulation presets — persist a named bring-up config (mode + optional target binary) so a known-good
 * emulation can be re-run in one click instead of re-entering it. Running a preset dispatches to the same
 * /emulate + /emulate-system + /renode + /chipsec endpoints the Simulation menu uses.
 */
import { useCallback, useEffect, useState } from 'react';
import { type EmulationPreset, api } from '../api';

const MODES: { value: EmulationPreset['mode']; label: string; needsBinary: boolean }[] = [
  { value: 'user-qemu', label: 'User-mode QEMU', needsBinary: true },
  { value: 'chroot-qemu', label: 'Chroot service', needsBinary: true },
  { value: 'system-qemu', label: 'Full-system QEMU', needsBinary: false },
  { value: 'renode', label: 'Renode (RTOS)', needsBinary: false },
  { value: 'uefi-chipsec', label: 'chipsec (UEFI)', needsBinary: false },
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
        setMsg(`Started "${p.name}" (job ${jobId}) — see the job log in the panels above.`);
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    },
    [imageId],
  );

  const remove = useCallback(
    async (id: string) => {
      await api.deletePreset(id).catch(() => {});
      load();
    },
    [load],
  );

  const modeLabel = (m: string): string => MODES.find((x) => x.value === m)?.label ?? m;
  const needsBinary = MODES.find((m) => m.value === mode)?.needsBinary ?? false;

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">Saved presets</div>
      <div className="panel-sub">Save a named emulation config and re-run it in one click.</div>

      <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          placeholder="preset name"
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
              {m.label}
            </option>
          ))}
        </select>
        {needsBinary && (
          <input
            className="mono"
            placeholder="bin/httpd (optional)"
            value={binary}
            onChange={(e) => setBinary(e.target.value)}
            style={inputStyle(180)}
          />
        )}
        <button className="btn btn-sm" disabled={!name.trim()} onClick={save}>
          Save preset
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
                Run
              </button>
              <button className="btn btn-sm" onClick={() => remove(p.id)}>
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
