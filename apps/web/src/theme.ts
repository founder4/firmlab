/**
 * Appearance store — theme (light | dark | system) and density (comfortable | compact), persisted to
 * localStorage and applied to <html> via data-theme / data-density. A module-level store (same pattern as the
 * toaster) so any component can read/set it without a context provider; changes apply instantly, no reload.
 * `system` tracks the OS preference live via matchMedia.
 */
import { useSyncExternalStore } from 'react';

export type ThemePref = 'light' | 'dark' | 'system';
export type Density = 'comfortable' | 'compact';

const THEME_KEY = 'firmlab.theme';
const DENSITY_KEY = 'firmlab.density';
const META_LIGHT = '#f4f6f9';
const META_DARK = '#0d1017';

interface Appearance {
  theme: ThemePref;
  density: Density;
}

const listeners = new Set<() => void>();
let state: Appearance = load();

function load(): Appearance {
  let theme: ThemePref = 'dark';
  let density: Density = 'comfortable';
  try {
    const t = localStorage.getItem(THEME_KEY);
    if (t === 'light' || t === 'dark' || t === 'system') theme = t;
    const d = localStorage.getItem(DENSITY_KEY);
    if (d === 'compact' || d === 'comfortable') density = d;
  } catch {
    // localStorage unavailable (private mode / SSR) — fall back to defaults.
  }
  return { theme, density };
}

function systemPrefersDark(): boolean {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

export function resolvedTheme(pref: ThemePref = state.theme): 'light' | 'dark' {
  return pref === 'system' ? (systemPrefersDark() ? 'dark' : 'light') : pref;
}

/** Write the current appearance to the DOM. Safe to call before React mounts (avoids a flash of the wrong theme). */
export function applyAppearance(): void {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  const resolved = resolvedTheme();
  root.setAttribute('data-theme', resolved);
  root.setAttribute('data-density', state.density);
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', resolved === 'dark' ? META_DARK : META_LIGHT);
}

function emit(): void {
  applyAppearance();
  for (const l of listeners) l();
}

export function setTheme(theme: ThemePref): void {
  state = { ...state, theme };
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // ignore persistence failure
  }
  emit();
}

export function setDensity(density: Density): void {
  state = { ...state, density };
  try {
    localStorage.setItem(DENSITY_KEY, density);
  } catch {
    // ignore persistence failure
  }
  emit();
}

/** Bootstrap: apply immediately and keep `system` in sync with the OS. Call once at startup. */
export function initAppearance(): void {
  applyAppearance();
  if (typeof window !== 'undefined') {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if (state.theme === 'system') emit();
    });
  }
}

const subscribe = (cb: () => void): (() => void) => {
  listeners.add(cb);
  return () => listeners.delete(cb);
};

export function useAppearance(): Appearance {
  return useSyncExternalStore(
    subscribe,
    () => state,
    () => state,
  );
}
