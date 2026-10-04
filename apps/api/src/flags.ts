/**
 * Runtime-toggleable lane flags — the catalogue, and the seam that lets a stored override reach the config
 * loaders without any of them importing the store.
 *
 * Until now every lane was decided by an environment variable read at process start, so changing one meant
 * editing a compose file and recreating the container. That was a defensible default for a tool whose posture
 * was "no network unless you asked", and it is also why the research lane sat unused for weeks. The toggles move
 * the decision to the operator's hands at runtime. (The research lane has since become on-by-default by operator
 * decision — see `defaultOn` — so for it the toggle is now how an operator opts OUT.)
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
  | 'FIRMLAB_EMU_ISOLATE'
  | 'FIRMLAB_EMU_REPAIR'
  | 'FIRMLAB_EMU_CONSOLE';

/** A lane flag the operator may flip at runtime — its structure. The description of it is in the catalogue. */
export interface ToggleableFlag {
  name: LaneFlagName;
  /** A flag that only matters when another is on (the double opt-ins). */
  requires?: LaneFlagName;
  /** Flipping this changes what the deployment does to things outside itself. */
  outward: boolean;
  /**
   * The lane is ON when nobody has said otherwise. Absent (the normal case) means absence ⇒ off.
   *
   * Two flags set it, for two different reasons, and both are pinned by name in `flags.test.ts` so a third cannot
   * arrive by accident:
   *
   *  - `FIRMLAB_EMU_ISOLATE`, whose ON state is the CLOSED one: the alternative was a deployment whose emulated
   *    guest reached the internet with every lane switched off.
   *  - `FIRMLAB_RESEARCH`, by operator decision (2026-10-04): trusted outbound research is habitually authorised
   *    on this workbench, so a deployment that never mentions the lane has it. What makes that safe is not the
   *    flag but what stays fixed around it — the host allowlist, the egress ledger, derived data only (never
   *    firmware bytes), and the lanes that send something MORE stay behind their own opt-ins.
   *
   * Setting it makes the flag an opt-OUT among opt-ins, which is a real cost, and `decideFlag` reports whether
   * anyone stated a value so an operator is never shown a default as a choice. A stated value — environment or
   * stored override, anything but `'1'` — always beats the default, so an explicit opt-out survives this.
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
  // Outward AND on by default — the operator's standing authorisation for trusted outbound research, not an
  // inversion like EMU_ISOLATE below. "Trusted" is bounded by `research/config.ts`: allowlisted intel hosts only,
  // component names/versions only, every run declared and reconciled by the egress ledger. An unstated value means
  // the operator's standing decision; `FIRMLAB_RESEARCH=0` (environment) or a stored `0` (Settings) turns it off.
  { name: 'FIRMLAB_RESEARCH', outward: true, defaultOn: true },
  // Stays an opt-in even though its parent is now on by default: it sends password hashes recovered from the
  // firmware to a third party, which is a different disclosure from a component name and was never authorised by
  // the research decision. And it needs its parent STATED on, not merely defaulted on — see `decideDependent`.
  { name: 'FIRMLAB_HASH_LOOKUP', requires: 'FIRMLAB_RESEARCH', outward: true },
  // Stays an opt-in: acquiring bytes off the wire is active network access, not a query about bytes already held.
  { name: 'FIRMLAB_CAPTURE', outward: true },
  { name: 'FIRMLAB_CAPTURE_GATEWAY', requires: 'FIRMLAB_CAPTURE', outward: false },
  // The one flag here whose OFF state is the outward one, and the table must not hide that. It was the first flag
  // to default ON, and for this flag the two facts are the same fact.
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
  // The most invasive thing this workbench does to an image: it appends one line to the firmware's own init script
  // so the booted guest runs a teardown the vendor ships and never calls. `outward: false` — nothing leaves the
  // machine — but it is the one flag that changes the ARTEFACT under analysis rather than what is asked of it,
  // which is why it is off by default and why `Finding.interventions` carries the fact onto every result.
  { name: 'FIRMLAB_EMU_REPAIR', outward: false },
  // The same decision as the line above, taken from the other end: instead of writing into the image, boot it with
  // `init=/bin/sh` and type at it. It changes the ARTEFACT more than the repair does — the vendor's init never runs
  // at all — and it changes the FILES not at all, so the two are separate switches rather than one. Off by default,
  // and `planConsolePass` declines outright when the repair already modified the image, because the two
  // interventions overlap on the one measurement this pass exists to take.
  { name: 'FIRMLAB_EMU_CONSOLE', outward: false },
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

/**
 * Why a switched-on dependent flag does nothing. `parent_off`: the lane it acts inside is off. `parent_default`:
 * that lane is on only because nobody said otherwise, and a double opt-in needs two consents, not one consent and
 * a default.
 */
export type InertReason = 'parent_off' | 'parent_default';

/**
 * Pure: is a flag that `requires` another actually in force against a merged environment?
 *
 * A double opt-in is two consents. When `FIRMLAB_RESEARCH` became default-on (2026-10-04), the naive reading —
 * child on AND parent enabled — would have turned a `FIRMLAB_HASH_LOOKUP=1` that had sat INERT for months (its
 * parent unset, so off) into a live hash egress on the next deploy, with nobody having decided anything that day.
 * A deployment that armed the child and left the parent unstated had, under the old contract, consented to
 * nothing being sent; the new default must not reinterpret that silence as the second consent. So the parent has
 * to be stated `1` — in the environment or by a Settings override — and a default-on parent leaves the child held,
 * reported as `parent_default` rather than collapsed into "off".
 *
 * For a flag with no `requires` this is just `decideFlag(...).enabled`. It is general rather than special-cased to
 * hash lookup because the rule is about consent, not about one lane: a future dependent of any default-on parent
 * inherits it.
 */
export function decideDependent(
  name: LaneFlagName,
  env: NodeJS.ProcessEnv,
): { armed: boolean; held: InertReason | null } {
  if (!decideFlag(name, env).enabled) return { armed: false, held: null };
  const parentName = TOGGLEABLE_FLAGS.find((f) => f.name === name)?.requires;
  if (!parentName) return { armed: true, held: null };
  const parent = decideFlag(parentName, env);
  if (!parent.enabled) return { armed: false, held: 'parent_off' };
  if (parent.byDefault) return { armed: false, held: 'parent_default' };
  return { armed: true, held: null };
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
  /** True when this flag is on but does nothing — its parent lane is off, or on only by default. */
  inert: boolean;
  /** Present exactly when `inert` is: which of the two it is. Optional, because older readers never sent it. */
  inertReason?: InertReason;
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
  // The same merge `effectiveEnv` performs, so `inert` here and the arming in the lane loaders are one decision.
  const merged: NodeJS.ProcessEnv = { ...env, ...overrides };
  return TOGGLEABLE_FLAGS.map((f) => {
    const overridden = Object.hasOwn(overrides, f.name);
    const environmentValue = env[f.name] === undefined ? defaultOnOf(f.name) : env[f.name] === '1';
    const enabled = on(f.name);
    const { held } = decideDependent(f.name, merged);
    return {
      ...f,
      ...text[f.name],
      enabled,
      source: overridden ? 'override' : env[f.name] !== undefined ? 'environment' : 'default',
      environmentValue,
      inert: held !== null,
      ...(held !== null ? { inertReason: held } : {}),
    };
  });
}
