/**
 * Runtime-toggleable lane flags — the catalogue, and the seam that lets a stored override reach the config
 * loaders without any of them importing the store.
 *
 * Until now every lane was decided by an environment variable read at process start, so changing one meant
 * editing a compose file and recreating the container. That is a defensible default for a tool whose whole
 * posture is "no network unless you asked", and it is also why the research lane sat unused for weeks. The
 * toggles move the decision to the operator's hands at runtime.
 *
 * Two things that shift, stated rather than glossed:
 *
 *  - **Who can flip a lane changes.** It used to require shell or compose access to the host; now it requires
 *    reaching the workbench UI. On this deployment that is the same person (the router is behind SSO), but it is
 *    a real widening and the reason `ALLOWED` below is a fixed list rather than "any FIRMLAB_* variable" — a
 *    settings endpoint that could set arbitrary environment would be a far larger hole than the feature is worth.
 *  - **An override is not the environment.** The container's env still says what it says; an override sits on top
 *    in the database. Every read path reports which of the two won, because an operator who sets `FIRMLAB_RESEARCH=1`
 *    in compose and then sees the lane off deserves to be told why rather than left to guess.
 *
 * The provider indirection exists so `research/config.ts`, `capture/config.ts` and `llm.ts` stay free of any
 * store import: vitest cannot resolve `node:sqlite`, and a config module that dragged it in would take its tests
 * down with it. `settings.ts` registers the real provider at boot; with none registered — a unit test, a script —
 * `effectiveEnv()` is exactly `process.env` and behaviour is what it always was.
 *
 * **Why the prose is not in the table below.** A lane's label, what it turns on and what leaves the machine are
 * read by an operator deciding whether to flip a switch, and they are resolved fresh on every request — nothing
 * about them is stored, and none of them describes a firmware image. They are therefore interface copy about this
 * deployment, they live in `i18n/` keyed by the flag name, and `resolveFlags` takes the locale as a parameter.
 * The table here is the structure: which flags exist, which depend on which, and which of them act outward.
 */
import { type Locale, messages } from './i18n/index.js';

/**
 * The lane flags, as identifiers. These are environment-variable names: they cross the API, appear in a compose
 * file and key the localised prose, so they are never translated in either direction.
 */
export type LaneFlagName =
  | 'FIRMLAB_AGENT'
  | 'FIRMLAB_RESEARCH'
  | 'FIRMLAB_HASH_LOOKUP'
  | 'FIRMLAB_CAPTURE'
  | 'FIRMLAB_CAPTURE_GATEWAY'
  | 'FIRMLAB_EMU_ISOLATE';

/** A lane flag the operator may flip at runtime — its structure. The description of it is in the catalogue. */
export interface ToggleableFlag {
  name: LaneFlagName;
  /** A flag that only matters when another is on (the double opt-ins). */
  requires?: LaneFlagName;
  /** Flipping this changes what the deployment does to things outside itself. */
  outward: boolean;
}

/**
 * The flags a runtime toggle may set. Deliberately a fixed list: bind host, data directory, upload caps and the
 * proxy/loopback posture are read once at startup and a toggle for them would be a control that appears to work
 * and does not. Those stay in the compose file, where a change is a restart and therefore honest.
 */
export const TOGGLEABLE_FLAGS: readonly ToggleableFlag[] = [
  { name: 'FIRMLAB_AGENT', outward: true },
  { name: 'FIRMLAB_RESEARCH', outward: true },
  { name: 'FIRMLAB_HASH_LOOKUP', requires: 'FIRMLAB_RESEARCH', outward: true },
  { name: 'FIRMLAB_CAPTURE', outward: true },
  { name: 'FIRMLAB_CAPTURE_GATEWAY', requires: 'FIRMLAB_CAPTURE', outward: false },
  // The one flag here whose OFF state is the outward one, and the table must not hide that.
  //
  // Every other lane is "off ⇒ nothing leaves", so a flag named for the egress would have had to default ON to
  // preserve today's behaviour — an opt-OUT switch in a list of opt-ins, which is the shape an operator misreads.
  // This is named for what turning it on DOES: it isolates the guest. `outward: false` is therefore literal —
  // enabling it sends nothing anywhere, it stops something being sent — and the honesty lives in the prose, which
  // has to say plainly that the emulated firmware reaches the internet while this is off. See `providers/egress.ts`
  // for the measurement that makes the default defensible: the attempt is recorded either way.
  { name: 'FIRMLAB_EMU_ISOLATE', outward: false },
];

const ALLOWED: ReadonlySet<string> = new Set<string>(TOGGLEABLE_FLAGS.map((f) => f.name));

/** Is this a flag a runtime toggle is allowed to set? Takes any string — the caller's input is a request body. */
export function isToggleableFlag(name: string): boolean {
  return ALLOWED.has(name);
}

type OverrideProvider = () => Record<string, string>;

let provider: OverrideProvider = () => ({});

/** Install the store-backed override source. Called once at boot; without it nothing overrides the environment. */
export function setFlagOverrideProvider(fn: OverrideProvider): void {
  provider = fn;
}

/** The environment as the lane loaders should see it: the process environment with stored overrides on top. */
export function effectiveEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return { ...base, ...provider() };
}

/** Where a flag's effective value came from — an operator who set it in compose and sees it off deserves to know. */
export type FlagSource = 'override' | 'environment' | 'default';

export interface FlagState {
  name: LaneFlagName;
  label: string;
  effect: string;
  egress: string;
  requires?: LaneFlagName;
  outward: boolean;
  /** Whether the lane is on, after the override is applied. */
  enabled: boolean;
  source: FlagSource;
  /** What the container's environment says, independent of any override. */
  environmentValue: boolean;
  /** True when this flag is on but the flag it depends on is not — on paper, inert in practice. */
  inert: boolean;
}

/**
 * Pure: resolve every toggleable flag against an environment, a set of overrides and a locale.
 *
 * `inert` is the part worth keeping: a double opt-in switched on while its parent lane is off reads as enabled
 * and does nothing, which is exactly the kind of quiet gap between what a control says and what it does that
 * this workbench exists to close.
 *
 * The locale is a parameter and defaults to English, so a caller that predates the switch — and a request that
 * arrives with no `?lang` — gets exactly what it always got. There is no module-level current locale: two requests
 * in two languages have to be able to be in flight at once.
 */
export function resolveFlags(
  env: NodeJS.ProcessEnv,
  overrides: Record<string, string>,
  locale: Locale = 'en',
): FlagState[] {
  const text = messages(locale).flags;
  const on = (name: string): boolean => (overrides[name] ?? env[name]) === '1';
  return TOGGLEABLE_FLAGS.map((f) => {
    const overridden = Object.hasOwn(overrides, f.name);
    const environmentValue = env[f.name] === '1';
    const enabled = on(f.name);
    return {
      ...f,
      ...text[f.name],
      enabled,
      source: overridden ? 'override' : env[f.name] !== undefined ? 'environment' : 'default',
      environmentValue,
      inert: enabled && !!f.requires && !on(f.requires),
    };
  });
}
