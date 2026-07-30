/**
 * Make a booted guest answerable — by running what the firmware already ships, and saying so.
 *
 * The full-system rung boots three routers and not one port ever answers. `boot-diagnose.ts` established that the
 * silence has two different causes and that neither is the port forwarding: the MR3220's `httpd` is dead before
 * any probe arrives, and the WR940N's is alive and serving TLS while 158 SYNs vanish inside the guest without so
 * much as a RST. This addresses the second.
 *
 * **What the firmware itself turned out to contain.** An inventory of the three rootfs (2026-07-29) found:
 *
 *   - `ebtables` exists in NONE of them — no binary, no applet, no module, not even the string. The
 *     `ebtables bug: Wrong len argument` on the WR940N's console comes from the emulation KERNEL, raised by a
 *     `setsockopt` from userspace. The WR940N is also the only one of the three carrying
 *     `br_MultiSsidVlan_InputForward.ko`, the only module that imports `nf_register_sockopt`, and its own httpd
 *     insmods it at runtime. That is a lead about where the packets go, not a settled cause.
 *   - `/etc/rc.d/rcS` never invokes `iptables`. The firewall is built entirely by `/usr/bin/httpd` through
 *     `system()` — 88 to 97 `iptables …` command strings live inside that binary — so the rules appear only
 *     after the daemon has started, which is why flushing at init time would flush nothing.
 *   - **`/etc/rc.d/iptables-stop` is shipped by the vendor, byte-identical in all three, and nothing in the boot
 *     path ever calls it.** It flushes filter and nat and sets every policy to ACCEPT.
 *
 * That last fact is what makes this defensible. The repair is not a firewall flush this workbench wrote and
 * injected; it is the firmware's OWN teardown script, run at a point the vendor's boot never reaches. The
 * intervention is one appended line, and what that line calls came out of the image.
 *
 * **It is still an intervention, and it is recorded as one.** A service that answers only because the workbench
 * ran the vendor's teardown is a different claim from one that answers as shipped, and `Finding.interventions`
 * exists so that difference travels with the result instead of living in a log nobody re-reads.
 *
 * **It reads before it writes.** The appended line prints the guest's live ruleset to the console BEFORE flushing
 * anything, because the whole point is to learn whether iptables is the thing eating the packets. If the rules
 * come back empty and the SYNs still vanish, the firewall was never the cause and the `br_MultiSsidVlan` lead is.
 * A repair that cannot tell you it was unnecessary is not a diagnosis.
 *
 * Pure and I/O-free: this composes the line and the sentences, `rootfs-image.ts` writes them.
 */

/** What the staging code found in the rootfs it is about to turn into an image. */
export interface GuestRepairInputs {
  /** `etc/rc.d/rcS` or wherever `/etc/inittab`'s sysinit points. Absent means there is nothing to append to. */
  initScript: string | null;
  /** `etc/rc.d/iptables-stop` — the vendor's own teardown. */
  hasIptablesStop: boolean;
  /** `sbin/iptables-save`, for reading the rules before they go. */
  hasIptablesSave: boolean;
  /**
   * Whether busybox here has a `ping` applet.
   *
   * Not a detail: BusyBox 1.01 on the WR940N and the MR3220 ships **no `sleep` applet at all**, so the only way
   * to wait for httpd to install its rules before reading them is `ping -c N 127.0.0.1`, and `rcS` brings `lo` up
   * a few lines earlier. Without ping there is no timer, and a repair that fires before the rules exist would
   * report an empty ruleset and flush nothing — a false negative dressed as a measurement.
   */
  hasPing: boolean;
}

export interface GuestRepairPlan {
  /** The line to append to the init script, or null when this guest cannot be repaired this way. */
  line: string | null;
  /**
   * What was done to the firmware, in the words that will travel on every finding from this boot. Empty when
   * nothing was done — and empty is what `interventions` means by "the image as shipped".
   */
  interventions: string[];
  /** Why a repair was not applied, when it was not. Never silent: an unattempted repair is not a failed one. */
  skipped: string[];
}

/** Markers the appended line prints, so the console can be read for what the ruleset was. */
export const RULES_BEGIN = 'FIRMLAB_RULES_BEGIN';
export const RULES_END = 'FIRMLAB_RULES_END';
export const FLUSHED = 'FIRMLAB_FLUSHED';

/** Seconds to wait before reading the rules. `httpd` installs them within the first few; this is generous. */
const WAIT_PINGS = 20;

/**
 * Pure: the one line to append, and the sentences that describe it.
 *
 * Everything it invokes must already be in the image. Nothing is written into the guest but this line — no
 * binary, no script, no busybox of ours — so the repair cannot introduce behaviour the firmware does not already
 * contain, and the intervention sentence stays small enough to be true.
 */
export function planGuestRepair(input: GuestRepairInputs): GuestRepairPlan {
  const skipped: string[] = [];
  if (!input.initScript) {
    skipped.push(
      'No init script was found to append to, so nothing was changed. The guest boots exactly as shipped and a ' +
        'service that does not answer is the firmware, not a missed repair.',
    );
    return { line: null, interventions: [], skipped };
  }
  if (!input.hasIptablesStop) {
    skipped.push(
      `${input.initScript} exists but the firmware ships no /etc/rc.d/iptables-stop, and this repair deliberately runs only what the image already contains rather than injecting a flush of its own.`,
    );
    return { line: null, interventions: [], skipped };
  }
  if (!input.hasPing) {
    skipped.push(
      'This busybox has no `ping` applet, and BusyBox 1.01 here has no `sleep` either, so there is no way to wait ' +
        'for the daemon to install its rules before reading them. Firing immediately would report an empty ' +
        'ruleset and flush nothing, which reads as a measurement and is not one.',
    );
    return { line: null, interventions: [], skipped };
  }

  // Backgrounded, so the vendor's own boot is not held up by the wait. `ping` is the timer this busybox has.
  const read = input.hasIptablesSave ? `echo ${RULES_BEGIN}; iptables-save 2>&1; echo ${RULES_END}; ` : '';
  const line =
    `(ping -c ${WAIT_PINGS} 127.0.0.1 >/dev/null 2>&1; ` +
    `${read}/etc/rc.d/iptables-stop >/dev/null 2>&1; echo ${FLUSHED}) &`;

  const interventions = [
    `Appended one line to /${input.initScript} in the booted image, which runs the firmware's OWN /etc/rc.d/iptables-stop about 20 s into the boot — the vendor's teardown script, which flushes filter and nat and sets every policy to ACCEPT, and which nothing in the vendor boot path ever calls. Any service that answered on this run may have answered only because its packet filtering had been torn down.`,
  ];
  if (!input.hasIptablesSave) {
    skipped.push(
      'This rootfs ships no iptables-save, so the ruleset could not be read before it was flushed. The repair ' +
        'still ran; what is missing is the evidence of whether it was the thing that mattered.',
    );
  }
  return { line, interventions, skipped };
}

/**
 * The flag that arms this. Off by default and deliberately so: appending a line to a firmware's init script is the
 * most invasive thing this workbench does to an image, and it must be the operator's decision rather than a default.
 */
export const REPAIR_FLAG = 'FIRMLAB_EMU_REPAIR';

/**
 * Whether a boot's guest was repaired, and — the part that needs its own type — whether anyone ASKED.
 *
 * `interventions: []` already carries a meaning the design relies on: the image booted as shipped. But it carries
 * that meaning only if the repair was actually considered. With the flag off nothing was examined at all, and an
 * empty intervention list would then be a claim ("we looked and changed nothing") about a look that never happened
 * — the same conflation this codebase refuses everywhere else, arriving here through a field whose empty value is
 * load-bearing.
 *
 * So `attempted` is the discriminator, and every consumer of `interventions` has to read it: an empty list with
 * `attempted: false` says nothing about the image, and an empty list with `attempted: true` says the firmware was
 * inspected and left alone.
 */
export interface RepairDisposition {
  /** False when the flag is off — nobody asked, and `interventions` is silence rather than a finding. */
  attempted: boolean;
  /** What was done to the firmware. Empty WITH `attempted` means the image as shipped. */
  interventions: string[];
  /** Why no repair was applied, when none was. */
  skipped: string[];
  /** The sentence for the log and the result. Never says "as shipped" unless the question was asked. */
  note: string;
}

/**
 * Pure: turn the flag and the plan into a disposition.
 *
 * Takes `enabled` rather than reading the environment so it stays testable and so the caller keeps the single
 * responsibility for resolving the flag (`decideFlag` in flags.ts).
 */
export function describeRepairDisposition(enabled: boolean, plan: GuestRepairPlan | null): RepairDisposition {
  if (!enabled) {
    return {
      attempted: false,
      interventions: [],
      skipped: [],
      note: `${REPAIR_FLAG} is off, so this guest was not examined for a boot-time repair and nothing was appended to it. That is not a statement that the image needed none — the question was not asked.`,
    };
  }
  if (!plan) {
    return {
      attempted: true,
      interventions: [],
      skipped: [],
      note: `${REPAIR_FLAG} is on, but no rootfs was available to examine, so no repair could be planned.`,
    };
  }
  if (!plan.line) {
    return {
      attempted: true,
      interventions: [],
      skipped: plan.skipped,
      note: `${REPAIR_FLAG} is on and this firmware was examined; no repair was applied, so the image booted as shipped. ${plan.skipped.join(' ')}`.trim(),
    };
  }
  return {
    attempted: true,
    interventions: plan.interventions,
    skipped: plan.skipped,
    note: `${REPAIR_FLAG} is on and this image was MODIFIED for the boot. ${plan.interventions.join(' ')}${
      plan.skipped.length ? ` ${plan.skipped.join(' ')}` : ''
    }`,
  };
}

/** One captured ruleset, read back off the guest's console. */
export interface GuestRuleset {
  /** True when the marker pair was found — i.e. the appended line actually ran. */
  ran: boolean;
  /** The `iptables-save` output between the markers, verbatim. Empty string is a real answer: no rules. */
  rules: string;
  /** True when the flush reported completing. */
  flushed: boolean;
}

/**
 * Pure: read the repair's own report out of the boot console.
 *
 * An empty ruleset with the markers present is the most informative outcome this can return, and it must not be
 * confused with the line never running: it means the guest's packet filter was EMPTY while the SYNs were being
 * swallowed, which rules the firewall out and points at the bridge module instead.
 */
export function readGuestRuleset(consoleOutput: string): GuestRuleset {
  const begin = consoleOutput.indexOf(RULES_BEGIN);
  const end = consoleOutput.indexOf(RULES_END);
  const flushed = consoleOutput.includes(FLUSHED);
  if (begin === -1 || end === -1 || end < begin) return { ran: flushed, rules: '', flushed };
  return { ran: true, rules: consoleOutput.slice(begin + RULES_BEGIN.length, end).trim(), flushed };
}

/**
 * Pure: what the captured ruleset says about why nothing answered. One sentence, and it is allowed to say the
 * repair was pointless — that is the outcome worth having.
 */
export function describeRuleset(r: GuestRuleset): string {
  if (!r.ran) {
    return 'The repair line never reported back, so the guest either did not reach it or did not get that far.';
  }
  if (!r.rules) {
    return (
      'The guest had NO iptables rules loaded when this was read. If packets were still being dropped, the ' +
      'firewall was not the cause and flushing it changed nothing — look at the bridge/VLAN modules the httpd ' +
      'insmods instead.'
    );
  }
  const rules = r.rules.split('\n').filter((l) => l.startsWith('-A')).length;
  return `The guest had ${rules} iptables rule(s) loaded before the flush${r.flushed ? ', which then ran' : ''}.`;
}
