/**
 * Persisted operator settings — today, the lane-flag overrides behind the Settings toggles.
 *
 * The value of a stored override is that it survives a restart; the risk is that it drifts silently from the
 * compose file the operator will read when something surprises them. So every row carries WHEN it was set, the
 * read path reports whether the environment or the override won (see `resolveFlags`), and clearing an override is
 * a first-class action rather than "set it back to what you think the env said" — a flag returned to the
 * environment's value is a different state from one pinned to the same value by hand, and only one of them
 * follows a later compose change.
 *
 * Writes are restricted to `TOGGLEABLE_FLAGS`. A settings table that could hold any environment variable would
 * turn a UI with one authenticated user into arbitrary process configuration, which is a much larger surface
 * than a few toggles are worth.
 */
import { isToggleableFlag } from './flags.js';
import { getDb } from './store.js';

export interface StoredSetting {
  key: string;
  value: string;
  updatedAt: number;
}

/** Read every stored flag override. Unknown keys are ignored rather than trusted — the allow-list is the gate. */
export function getFlagOverrides(): Record<string, string> {
  const rows = getDb().prepare('SELECT key, value FROM settings').all() as unknown as { key: string; value: string }[];
  const out: Record<string, string> = {};
  for (const r of rows) if (isToggleableFlag(r.key)) out[r.key] = r.value;
  return out;
}

/** Read the stored overrides with their timestamps, for a UI that wants to say when a lane was last changed. */
export function listFlagOverrides(): StoredSetting[] {
  const rows = getDb().prepare('SELECT key, value, updatedAt FROM settings ORDER BY key').all() as unknown[];
  return (rows as StoredSetting[]).filter((r) => isToggleableFlag(r.key));
}

/**
 * Pin a flag on or off, overriding the environment. Returns false for a key outside the allow-list — the caller
 * turns that into a 400 rather than a silent no-op, because a toggle that appears to work and does not is the
 * failure this whole feature is meant to avoid.
 */
export function setFlagOverride(name: string, enabled: boolean, now = Date.now()): boolean {
  if (!isToggleableFlag(name)) return false;
  getDb()
    .prepare(
      `INSERT INTO settings (key, value, updatedAt) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updatedAt = excluded.updatedAt`,
    )
    .run(name, enabled ? '1' : '0', now);
  return true;
}

/** Drop an override so the flag follows the environment again. */
export function clearFlagOverride(name: string): boolean {
  if (!isToggleableFlag(name)) return false;
  getDb().prepare('DELETE FROM settings WHERE key = ?').run(name);
  return true;
}
