import { describe, expect, it } from 'vitest';
import {
  TOGGLEABLE_FLAGS,
  decideFlag,
  effectiveEnv,
  isToggleableFlag,
  resolveFlags,
  setFlagOverrideProvider,
} from './flags.js';

const env = (o: Record<string, string>): NodeJS.ProcessEnv => o as NodeJS.ProcessEnv;
const find = (states: ReturnType<typeof resolveFlags>, name: string) => {
  const s = states.find((x) => x.name === name);
  if (!s) throw new Error(`no state for ${name}`);
  return s;
};

describe('the allow-list is the gate', () => {
  it('accepts the lane flags and nothing else', () => {
    expect(isToggleableFlag('FIRMLAB_RESEARCH')).toBe(true);
    expect(isToggleableFlag('FIRMLAB_CAPTURE_GATEWAY')).toBe(true);
    // Startup posture: a toggle would be a control that appears to work and does not.
    expect(isToggleableFlag('FIRMLAB_HOST')).toBe(false);
    expect(isToggleableFlag('FIRMLAB_TRUSTED_PROXY')).toBe(false);
    // And nothing arbitrary — a settings endpoint that set any env var is a far bigger hole than the feature.
    expect(isToggleableFlag('PATH')).toBe(false);
    expect(isToggleableFlag('DEEPSEEK_API_KEY')).toBe(false);
  });

  it('describes every flag it offers, including what leaves the machine, in BOTH languages', () => {
    // The prose moved to the catalogue, so the check has to run through the resolver that assembles it — and it
    // has to run for Spanish too. An egress line that shrank to a stub in translation understates what actually
    // leaves the machine, which is the one thing this panel exists to state before the switch is flipped.
    for (const locale of ['en', 'es'] as const) {
      for (const f of resolveFlags(env({}), {}, locale)) {
        expect(f.label.length).toBeGreaterThan(0);
        expect(f.effect.length).toBeGreaterThan(40);
        expect(f.egress.length).toBeGreaterThan(20);
      }
    }
  });
});

/**
 * The flag NAME is an environment variable: it is what an operator greps a compose file for and what the PUT
 * endpoint accepts. Only the description of a lane is language-dependent, and getting that backwards would produce
 * a Spanish UI whose switches address variables the container has never heard of.
 */
describe('resolveFlags is localised in its prose and identical in everything else', () => {
  it('defaults to English, so a request with no ?lang gets what every caller before it got', () => {
    const [dflt] = resolveFlags(env({}), {});
    const [english] = resolveFlags(env({}), {}, 'en');
    expect(dflt).toEqual(english);
    expect(dflt?.label).toBe('AI copilot & agent');
  });

  it('translates the label, the effect and the egress, and nothing else', () => {
    const es = resolveFlags(env({ FIRMLAB_RESEARCH: '1' }), { FIRMLAB_HASH_LOOKUP: '1' }, 'es');
    const en = resolveFlags(env({ FIRMLAB_RESEARCH: '1' }), { FIRMLAB_HASH_LOOKUP: '1' }, 'en');
    expect(es.map((f) => f.name)).toEqual(en.map((f) => f.name));
    expect(es.map((f) => f.enabled)).toEqual(en.map((f) => f.enabled));
    expect(es.map((f) => f.source)).toEqual(en.map((f) => f.source));
    expect(es.map((f) => f.inert)).toEqual(en.map((f) => f.inert));
    expect(es.map((f) => f.requires)).toEqual(en.map((f) => f.requires));
    for (const [i, f] of es.entries()) {
      expect(f.label).not.toBe(en[i]?.label);
      expect(f.effect).not.toBe(en[i]?.effect);
      expect(f.egress).not.toBe(en[i]?.egress);
    }
  });

  it('names the environment variables verbatim in Spanish — they are identifiers, not words', () => {
    const names = resolveFlags(env({}), {}, 'es').map((f) => f.name);
    expect(names).toEqual([
      'FIRMLAB_AGENT',
      'FIRMLAB_RESEARCH',
      'FIRMLAB_HASH_LOOKUP',
      'FIRMLAB_CAPTURE',
      'FIRMLAB_CAPTURE_GATEWAY',
      'FIRMLAB_EMU_ISOLATE',
      'FIRMLAB_EMU_REPAIR',
    ]);
    expect(find(resolveFlags(env({}), {}, 'es'), 'FIRMLAB_HASH_LOOKUP').requires).toBe('FIRMLAB_RESEARCH');
  });

  /**
   * The one flag in the table whose OFF state is the outward one, which makes its prose the only thing standing
   * between an operator and a firmware that reaches the internet from their machine. Both languages have to say
   * that plainly, in the `egress` line, which is what a reader consults BEFORE flipping a switch.
   */
  describe('FIRMLAB_EMU_ISOLATE — the inverted flag, and the only one that defaults ON', () => {
    /**
     * This assertion was the exact inverse until 2026-07-30, and it passed: the suite pinned a default that made
     * *"with every flag off: no network"* false, because the fixture and the code were written from the same
     * assumption. What flipped it was not a preference — it was measuring that no rung depends on outbound.
     */
    it('is ON when nobody has said anything, and reports that as the default rather than as a choice', () => {
      const f = find(resolveFlags(env({}), {}), 'FIRMLAB_EMU_ISOLATE');
      expect(f.enabled).toBe(true);
      expect(f.source).toBe('default');
      // Turning it ON sends nothing anywhere — it stops the guest sending — so it is not an outward switch. The
      // outward act is turning it OFF, which is why it is the one flag that may default on.
      expect(f.outward).toBe(false);
    });

    it('is the ONLY flag allowed to default on — every other lane stays absence ⇒ off', () => {
      const on = TOGGLEABLE_FLAGS.filter((f) => f.defaultOn === true).map((f) => f.name);
      expect(on).toEqual(['FIRMLAB_EMU_ISOLATE']);
      for (const f of resolveFlags(env({}), {})) {
        if (f.name !== 'FIRMLAB_EMU_ISOLATE') expect(f.enabled).toBe(false);
      }
    });

    it('warns, in both languages, that turning it off lets the emulated firmware reach the internet', () => {
      const en = find(resolveFlags(env({}), {}, 'en'), 'FIRMLAB_EMU_ISOLATE');
      const es = find(resolveFlags(env({}), {}, 'es'), 'FIRMLAB_EMU_ISOLATE');
      expect(en.egress).toContain('REACH THE INTERNET');
      expect(es.egress).toContain('ALCANCE INTERNET');
      // Both must say it is on by default, or a reader consulting this line before flipping the switch would
      // still believe absence means permissive.
      expect(en.egress).toMatch(/ON BY DEFAULT/);
      expect(es.egress).toMatch(/ENCENDIDO POR OMISIÓN/);
      // And both keep the property that makes the observation trustworthy either way.
      expect(en.egress).toMatch(/does not hide the attempt/i);
      expect(es.egress).toMatch(/no oculta el intento/i);
    });

    it('takes an override of 0, which is now the only way a guest gets outbound', () => {
      const f = find(resolveFlags(env({}), { FIRMLAB_EMU_ISOLATE: '0' }), 'FIRMLAB_EMU_ISOLATE');
      expect(f.enabled).toBe(false);
      expect(f.source).toBe('override');
      // What the environment would say without the override: on. An operator who removes it gets isolation back.
      expect(f.environmentValue).toBe(true);
    });

    it('still honours a stored override of 1, so a deployment that set it keeps meaning what it meant', () => {
      // Not decoration: a real deployment had FIRMLAB_EMU_ISOLATE=1 stored as an override when the default was
      // flipped. That row has to keep resolving to isolation rather than quietly becoming a contradiction.
      const f = find(resolveFlags(env({}), { FIRMLAB_EMU_ISOLATE: '1' }), 'FIRMLAB_EMU_ISOLATE');
      expect(f.enabled).toBe(true);
      expect(f.source).toBe('override');
    });
  });

  /**
   * `decideFlag` exists because `enabled` alone conflates two situations once a flag may default on, and the
   * codebase's whole discipline is that "nobody asked" and "asked, and the answer was no" are different facts.
   */
  describe('decideFlag separates the default from a decision', () => {
    it('reports an unstated defaulting-on flag as enabled, unstated, and by default', () => {
      const d = decideFlag('FIRMLAB_EMU_ISOLATE', {});
      expect(d).toEqual({ enabled: true, stated: false, statedValue: null, byDefault: true });
    });

    it('reports an explicit 1 as enabled but NOT by default — same boolean, different fact', () => {
      const d = decideFlag('FIRMLAB_EMU_ISOLATE', { FIRMLAB_EMU_ISOLATE: '1' });
      expect(d.enabled).toBe(true);
      expect(d.stated).toBe(true);
      expect(d.byDefault).toBe(false);
      // The pair that matters: both are `enabled`, and only one of them is somebody's choice.
      expect(decideFlag('FIRMLAB_EMU_ISOLATE', {}).enabled).toBe(d.enabled);
      expect(decideFlag('FIRMLAB_EMU_ISOLATE', {}).byDefault).not.toBe(d.byDefault);
    });

    it('reports an explicit 0 as a stated decision, which is the only route to an open guest', () => {
      const d = decideFlag('FIRMLAB_EMU_ISOLATE', { FIRMLAB_EMU_ISOLATE: '0' });
      expect(d).toEqual({ enabled: false, stated: true, statedValue: '0', byDefault: false });
    });

    it('treats a non-"1" value as off and keeps it verbatim, so a typo is visible rather than guessed', () => {
      const d = decideFlag('FIRMLAB_EMU_ISOLATE', { FIRMLAB_EMU_ISOLATE: 'true' });
      expect(d.enabled).toBe(false);
      expect(d.statedValue).toBe('true');
      expect(d.stated).toBe(true);
    });

    it('leaves a flag with no defaultOn off when unstated, and says nobody stated it', () => {
      const d = decideFlag('FIRMLAB_RESEARCH', {});
      expect(d).toEqual({ enabled: false, stated: false, statedValue: null, byDefault: false });
    });
  });

  it('keeps the hash-lookup egress explicit in Spanish: your firmware’s hashes reach a third party', () => {
    // The lane where a soft translation would cost the most. It must still say WHOSE data goes WHERE.
    const hash = find(resolveFlags(env({}), {}, 'es'), 'FIRMLAB_HASH_LOOKUP');
    expect(hash.egress).toContain('TU firmware');
    expect(hash.egress).toContain('un tercero');
    expect(hash.effect).toContain('SIN SAL');
  });

  it('keeps the research lane naming its destinations, which are hostnames and not translatable', () => {
    const research = find(resolveFlags(env({}), {}, 'es'), 'FIRMLAB_RESEARCH');
    expect(research.egress).toContain('api.osv.dev');
    expect(research.egress).toContain('services.nvd.nist.gov');
    expect(research.egress).toContain('KEV');
  });
});

describe('resolveFlags — an override is not the environment, and the difference is reported', () => {
  it('reports the environment when nothing overrides it', () => {
    const s = find(resolveFlags(env({ FIRMLAB_RESEARCH: '1' }), {}), 'FIRMLAB_RESEARCH');
    expect(s.enabled).toBe(true);
    expect(s.source).toBe('environment');
    expect(s.environmentValue).toBe(true);
  });

  /**
   * The case the source field exists for: compose says the lane is on, an override turned it off, and an operator
   * reading the compose file would otherwise have no way to explain what they are seeing.
   */
  it('lets an override win, and still says what the environment holds', () => {
    const s = find(resolveFlags(env({ FIRMLAB_RESEARCH: '1' }), { FIRMLAB_RESEARCH: '0' }), 'FIRMLAB_RESEARCH');
    expect(s.enabled).toBe(false);
    expect(s.source).toBe('override');
    expect(s.environmentValue).toBe(true);
  });

  it('separates "unset" from "set to off"', () => {
    expect(find(resolveFlags(env({}), {}), 'FIRMLAB_CAPTURE').source).toBe('default');
    expect(find(resolveFlags(env({ FIRMLAB_CAPTURE: '0' }), {}), 'FIRMLAB_CAPTURE').source).toBe('environment');
  });

  /**
   * A double opt-in switched on while its parent lane is off reads as enabled and does nothing. Saying so is the
   * whole point — a control whose state and behaviour disagree is the gap this workbench exists to close.
   */
  it('marks a double opt-in inert when the lane it depends on is off', () => {
    const states = resolveFlags(env({}), { FIRMLAB_HASH_LOOKUP: '1' });
    const hash = find(states, 'FIRMLAB_HASH_LOOKUP');
    expect(hash.enabled).toBe(true);
    expect(hash.inert).toBe(true);
    expect(hash.requires).toBe('FIRMLAB_RESEARCH');
  });

  it('stops calling it inert once the parent lane is on', () => {
    const states = resolveFlags(env({}), { FIRMLAB_HASH_LOOKUP: '1', FIRMLAB_RESEARCH: '1' });
    expect(find(states, 'FIRMLAB_HASH_LOOKUP').inert).toBe(false);
  });

  it('never calls a flag inert while it is off', () => {
    for (const s of resolveFlags(env({}), {})) expect(s.inert).toBe(false);
  });
});

describe('effectiveEnv — with no provider installed, behaviour is exactly what it always was', () => {
  it('is the plain environment until a provider is registered', () => {
    setFlagOverrideProvider(() => ({}));
    expect(effectiveEnv(env({ FIRMLAB_RESEARCH: '1' })).FIRMLAB_RESEARCH).toBe('1');
    expect(effectiveEnv(env({})).FIRMLAB_RESEARCH).toBeUndefined();
  });

  it('lets the provider override the process environment', () => {
    setFlagOverrideProvider(() => ({ FIRMLAB_RESEARCH: '0' }));
    expect(effectiveEnv(env({ FIRMLAB_RESEARCH: '1' })).FIRMLAB_RESEARCH).toBe('0');
    setFlagOverrideProvider(() => ({}));
  });
});
