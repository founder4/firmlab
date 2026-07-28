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
 */

/** A lane flag the operator may flip at runtime, and the honest description of what flipping it does. */
export interface ToggleableFlag {
  name: string;
  label: string;
  /** What turns on. Written for someone deciding, not for someone who already knows. */
  effect: string;
  /** What leaves the machine, or what reaches onto the network, when this is on. Empty when nothing does. */
  egress: string;
  /** A flag that only matters when another is on (the double opt-ins). */
  requires?: string;
  /** Flipping this changes what the deployment does to things outside itself. */
  outward: boolean;
}

/**
 * The flags a runtime toggle may set. Deliberately a fixed list: bind host, data directory, upload caps and the
 * proxy/loopback posture are read once at startup and a toggle for them would be a control that appears to work
 * and does not. Those stay in the compose file, where a change is a restart and therefore honest.
 */
export const TOGGLEABLE_FLAGS: readonly ToggleableFlag[] = [
  {
    name: 'FIRMLAB_AGENT',
    label: 'AI copilot & agent',
    effect:
      'Lets the copilot and the agent skeleton run. The mechanics stay deterministic — the model only makes the judgment calls, inside a governor that halts on steps, tokens, USD or wall-clock.',
    egress:
      'Prompts built from findings and identity go to the configured LLM provider. Needs an API key; with no key the layer stays off however this is set.',
    outward: true,
  },
  {
    name: 'FIRMLAB_RESEARCH',
    label: 'External intelligence',
    effect:
      'Correlates the SBOM and the components fingerprinted out of bundled binaries against published advisories, and looks up vendor disclosure contacts.',
    egress:
      'Component names and versions go to api.osv.dev and services.nvd.nist.gov; the CISA KEV catalogue is downloaded and cross-referenced locally. Never firmware bytes, secrets or keys. The egress ledger declares a ceiling before each run and reconciles it afterwards.',
    outward: true,
  },
  {
    name: 'FIRMLAB_HASH_LOOKUP',
    label: 'Online password-hash lookup',
    effect:
      'Sends UNSALTED password digests recovered from the firmware to public reverse-lookup services. Salted crypt hashes are counted out and never sent; a recovered plaintext stays local and masked.',
    egress:
      'Password hashes from YOUR firmware reach a third party. This is a bigger step than a component name and it has its own switch for that reason — if an image is client or engagement material, treat this as a disclosure.',
    requires: 'FIRMLAB_RESEARCH',
    outward: true,
  },
  {
    name: 'FIRMLAB_CAPTURE',
    label: 'Capture lane',
    effect:
      'Unlocks LAN discovery and the interception backends used to acquire firmware from a live device. Nothing touches the wire until a specific action is armed on a single, time-boxed target.',
    egress: 'Discovery sweeps the local subnet (nmap / arp-scan / mDNS). Nothing about your firmware leaves.',
    outward: true,
  },
  {
    name: 'FIRMLAB_CAPTURE_GATEWAY',
    label: 'Declare on-path positioning',
    effect:
      'Your assertion that FirmLab is ALREADY on the target’s path — its default route, or fed by a port mirror. It spawns nothing; it is what makes an ARP spoof unnecessary, so a capture session positions as `gateway` instead. Declare it falsely and a session will report the target on-path and capture nothing.',
    egress: 'Nothing by itself. It changes how a capture session positions, not what it sends.',
    requires: 'FIRMLAB_CAPTURE',
    outward: false,
  },
];

const ALLOWED = new Set(TOGGLEABLE_FLAGS.map((f) => f.name));

/** Is this a flag a runtime toggle is allowed to set? */
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
  name: string;
  label: string;
  effect: string;
  egress: string;
  requires?: string;
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
 * Pure: resolve every toggleable flag against an environment and a set of overrides.
 *
 * `inert` is the part worth keeping: a double opt-in switched on while its parent lane is off reads as enabled
 * and does nothing, which is exactly the kind of quiet gap between what a control says and what it does that
 * this workbench exists to close.
 */
export function resolveFlags(env: NodeJS.ProcessEnv, overrides: Record<string, string>): FlagState[] {
  const on = (name: string): boolean => (overrides[name] ?? env[name]) === '1';
  return TOGGLEABLE_FLAGS.map((f) => {
    const overridden = Object.hasOwn(overrides, f.name);
    const environmentValue = env[f.name] === '1';
    const enabled = on(f.name);
    return {
      ...f,
      enabled,
      source: overridden ? 'override' : env[f.name] !== undefined ? 'environment' : 'default',
      environmentValue,
      inert: enabled && !!f.requires && !on(f.requires),
    };
  });
}
