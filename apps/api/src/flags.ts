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
  /**
   * The lane is ON when nobody has said otherwise. Absent (the normal case) means absence ⇒ off, which is what
   * "with every flag off: no network" rests on.
   *
   * Only a flag whose ON state is the CLOSED one may set this, and it exists because the alternative was a
   * deployment whose emulated guest reached the internet with every lane switched off. Setting it makes the flag
   * an opt-OUT among opt-ins, which is a real cost — it is paid here rather than in the product's headline claim,
   * and `decideFlag` reports whether anyone stated a value so an operator is never shown a default as a choice.
   */
  defaultOn?: boolean;
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
  // The one flag here whose OFF state is the outward one, and the table must not hide that. It is also the only
  // one that defaults ON, and the two facts are the same fact.
  //
  // It shipped defaulting OFF, on the argument that a flag named for the egress would have had to default ON to
  // preserve behaviour — an opt-OUT switch in a list of opt-ins, which is the shape an operator misreads. The cost
  // of that choice was that *"with every flag off: no network, no cost, deterministic behaviour"* was FALSE by
  // default: a booted TP-Link WDR3600 reached three public NTP servers from a deployment with every lane off.
  //
  // What the original note said should decide it was whether any rung DEPENDS on outbound, and the corpus has now
  // answered. Two full-system boots of the same WDR3600 image sixteen minutes apart, one open and one isolated,
  // recorded the SAME 15 external attempts and the SAME `confirmed_full_system` verdict; across every recorded
  // full-system boot only that one image ever addressed anything external at all. Isolation costs no rung
  // anything, and it confirms on real bytes what `providers/egress.ts` had only asserted: blocking the traffic
  // does not hide the attempt, because `filter-dump` captures the frame before slirp decides its fate.
  //
  // So the default is now ON and the misreadable shape is accepted, because the alternative is a false headline.
  // `outward: false` stays literal — enabling this sends nothing anywhere, it stops something being sent — which
  // means the outward act is now switching it OFF, and `decideFlag` exists so that act is never confused with
  // nobody having chosen.
  { name: 'FIRMLAB_EMU_ISOLATE', outward: false, defaultOn: true },
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

/**
 * What a lane's value is, and whether anybody actually chose it.
 *
 * `stated` is the whole reason this is not a boolean. Once a flag may default ON, `enabled === true` covers two
 * different situations — nobody said anything and the catalogue decided, or an operator asked for it — and a
 * caller that cannot tell them apart will report a default back to the person as though it were their choice. The
 * dangerous direction is the other one: `enabled === false` on `FIRMLAB_EMU_ISOLATE` can ONLY happen because
 * someone explicitly opened the guest's network, and a log line that says so is the difference between a
 * deliberate decision and a deployment quietly letting a firmware phone home.
 *
 * This is the same separation the rest of the codebase keeps between "the question was never asked" and "the
 * question was asked and the answer was nothing" — here applied to configuration rather than to findings.
 */
export interface FlagDecision {
  enabled: boolean;
  /** True when the merged environment names this flag at all. False = nobody stated a value. */
  stated: boolean;
  /** The stated value verbatim, or null when nothing stated one. `'0'` and `'anything-else'` are both off. */
  statedValue: string | null;
  /** True when the value came from the catalogue's `defaultOn` rather than from anyone. */
  byDefault: boolean;
}

/**
 * Pure: decide one lane against an already-merged environment (`effectiveEnv()`), honouring `defaultOn`.
 *
 * Takes the merged environment rather than env+overrides because the callers that need this are the lane loaders,
 * for which the two are one thing; `resolveFlags` keeps them apart because the settings UI has to report which of
 * the two won.
 */
export function decideFlag(name: LaneFlagName, env: NodeJS.ProcessEnv): FlagDecision {
  const raw = env[name];
  if (raw === undefined) {
    const byDefault = TOGGLEABLE_FLAGS.find((f) => f.name === name)?.defaultOn === true;
    return { enabled: byDefault, stated: false, statedValue: null, byDefault };
  }
  return { enabled: raw === '1', stated: true, statedValue: raw, byDefault: false };
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
  const defaultOnOf = (name: string): boolean => TOGGLEABLE_FLAGS.find((f) => f.name === name)?.defaultOn === true;
  // A stated value wins; nothing stated falls to the catalogue. Reading `=== '1'` directly — as this did — makes
  // absence mean OFF for every flag, which silently un-does `defaultOn` for the one flag that has it and would have
  // shown the isolation switch as off in Settings while the emulator was in fact isolating.
  const on = (name: string): boolean => {
    const raw = overrides[name] ?? env[name];
    return raw === undefined ? defaultOnOf(name) : raw === '1';
  };
  return TOGGLEABLE_FLAGS.map((f) => {
    const overridden = Object.hasOwn(overrides, f.name);
    const environmentValue = env[f.name] === undefined ? defaultOnOf(f.name) : env[f.name] === '1';
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
