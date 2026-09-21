/**
 * Make a booted guest answerable — by running what the firmware already ships, at a point the boot actually
 * reaches, and saying so.
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
 * intervention is one line, and what that line calls came out of the image.
 *
 * **Where the line goes is the whole difference between a repair and a comment.** The first version of this
 * APPENDED to the end of `/etc/rc.d/rcS`, which is the one place in the boot that is never reached: the vendor's
 * `rcS` ends by starting the daemons that keep the system up, and on these images it does not return. A line after
 * that is not a repair, it is a note in a file — and the disposition happily reported `interventions: [1]` for
 * something no CPU ever executed, which is the same conflation this codebase refuses everywhere else, arriving
 * through a field nobody could check without reading the console.
 *
 * So the placement is now a decision with an order of preference, and it is made from the bytes:
 *
 *   1. **A first `sysinit` entry in `/etc/inittab`.** busybox init runs `sysinit` entries in file order and waits
 *      for each; inserting ours ABOVE the vendor's `::sysinit:/etc/rc.d/rcS` means it is executed before `rcS`
 *      starts, so whether `rcS` ever returns stops mattering. It is also the least invasive edit available — the
 *      vendor's own scripts are left byte-identical — and the most reversible, which is why it is preferred. It is
 *      taken only when the file is structurally what busybox expects (`findSysinitInsertion` below), never guessed.
 *   2. **The head of the init script**, immediately after its shebang and ahead of the vendor's body. Same
 *      guarantee about the stall, but it edits a vendor file, so it is a documented degradation and the reason the
 *      inittab route was refused travels with it.
 *   3. **Nothing**, stated as a refusal. An init layout this cannot read is not an init layout this may edit.
 *
 * **It is still an intervention, and it is recorded as one.** A service that answers only because the workbench
 * ran the vendor's teardown is a different claim from one that answers as shipped, and `Finding.interventions`
 * exists so that difference travels with the result instead of living in a log nobody re-reads. Nothing here ever
 * makes a service reachable on the evidence of having been staged: the repair reports on itself through the
 * guest's console (`readGuestRuleset`), and a run whose markers never appear is read as a line that did not run.
 *
 * **It reads before it writes.** The line prints the guest's live ruleset to the console BEFORE flushing anything,
 * because the whole point is to learn whether iptables is the thing eating the packets. If the rules come back
 * empty and the SYNs still vanish, the firewall was never the cause and the `br_MultiSsidVlan` lead is. A repair
 * that cannot tell you it was unnecessary is not a diagnosis.
 *
 * Pure and I/O-free: this composes the line, the placement and the sentences; `rootfs-image.ts` writes them and
 * puts the original bytes back.
 */

/** What the staging code found in the rootfs it is about to turn into an image. */
export interface GuestRepairInputs {
  /** `etc/rc.d/rcS`, or null when the firmware ships none. Kept alongside the text because it names the file. */
  initScript: string | null;
  /**
   * The init script's own bytes, decoded latin1 so every byte round-trips. Needed because the fallback placement
   * rewrites the file rather than appending to it, and the rewrite is composed here, purely.
   */
  initScriptText: string | null;
  /** `etc/inittab`'s bytes, latin1, or null when absent. The preferred placement is decided from this. */
  inittab: string | null;
  /** `etc/rc.d/iptables-stop` — the vendor's own teardown. */
  hasIptablesStop: boolean;
  /** `sbin/iptables-save`, for reading the rules before they go. */
  hasIptablesSave: boolean;
  /**
   * Whether busybox here has a `ping` applet.
   *
   * Not a detail: BusyBox 1.01 on the WR940N and the MR3220 ships **no `sleep` applet at all**, so the only way
   * to wait for httpd to install its rules before reading them is `ping -c N 127.0.0.1`. Without ping there is no
   * timer, and a repair that fires before the rules exist would report an empty ruleset and flush nothing — a
   * false negative dressed as a measurement.
   */
  hasPing: boolean;
}

/**
 * Where the repair line goes, and the finished bytes of the file it goes in.
 *
 * The full content rather than an offset and a line: composing it here keeps the decision testable without a
 * filesystem, and leaves `stageGuestRepair` with nothing to get wrong but the write and the restore.
 */
export interface RepairPlacement {
  kind: 'inittab-sysinit' | 'init-script-head';
  /** Rootfs-relative path of the file to rewrite. */
  file: string;
  /** The file's new contents, latin1. Exactly the original with one line inserted. */
  content: string;
  /** The line as it appears in that file — the raw command, or the `::sysinit:` entry wrapping it. */
  inserted: string;
}

export interface GuestRepairPlan {
  /** The command itself, or null when this guest cannot be repaired. Identical whichever file it lands in. */
  line: string | null;
  /** Where it lands and what the file becomes. Null whenever `line` is — and also when no file may be edited. */
  placement: RepairPlacement | null;
  /**
   * What was done to the firmware, in the words that will travel on every finding from this boot. Empty when
   * nothing was done — and empty is what `interventions` means by "the image as shipped".
   */
  interventions: string[];
  /** Why a repair was not applied, or not applied the preferred way. Never silent. */
  skipped: string[];
}

/** Markers the line prints, so the console can be read for what the ruleset was. */
export const RULES_BEGIN = 'FIRMLAB_RULES_BEGIN';
export const RULES_END = 'FIRMLAB_RULES_END';
export const FLUSHED = 'FIRMLAB_FLUSHED';

/** Seconds to wait before reading the rules. `httpd` installs them within the first few; this is generous. */
const WAIT_PINGS = 20;

/**
 * How many times the timer may find `lo` still down before it gives up waiting for it.
 *
 * The bound exists because the placement moved. Appended at the END of `rcS`, the timer could assume `lo` was
 * already up — `rcS` brings it up early and the append ran after everything. Executed BEFORE `rcS`, it cannot:
 * `ping` against a down loopback fails instantly, so a bare `ping -c 20` would elapse in milliseconds and the
 * repair would read an empty ruleset at t≈0 and flush rules that had not been installed yet. Retrying until a
 * full ping run completes is the timer; the bound is so a guest whose `lo` never comes up stops forking instead
 * of spinning for the length of the boot it is supposed to be measuring.
 */
const LO_TRIES = 600;

/**
 * busybox init reads each inittab line into a fixed 256-byte buffer and truncates silently. A line over the limit
 * does not fail loudly, it becomes a DIFFERENT command — an unterminated subshell that busybox then hands to
 * `/bin/sh -c` — so the ceiling is checked before the entry is composed rather than discovered in a console.
 */
export const INITTAB_LINE_MAX = 255;

/** Where a `::sysinit:` entry may be inserted, or why this inittab must not be touched. */
export type SysinitInsertion = { usable: true; index: number } | { usable: false; reason: string };

/**
 * Pure: find the line number of the first `sysinit` entry, and decide whether this file is one we may edit at all.
 *
 * Three refusals, and they are separate because they mean different things. A line that is not
 * `id:runlevels:action:process` means the file is not the format this parses, and editing a file you cannot read is
 * how a boot stops for a reason nobody can trace. No `sysinit` entry at all means there is no point in this boot
 * the repair could attach to — inserting one would be inventing a stage rather than using one. And a `sysinit`
 * entry carrying an id is the SysV convention rather than busybox's: busybox derives the entry's stdio from the id
 * (`/dev/<id>`), so an entry copied from that convention would have its markers written to a device instead of the
 * console, and the repair's own report — the only evidence that it ran — would vanish.
 */
export function findSysinitInsertion(text: string): SysinitInsertion {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const body = (lines[i] ?? '').replace(/\r$/, '');
    if (!body.trim() || body.trimStart().startsWith('#')) continue;
    const fields = body.split(':');
    if (fields.length < 4) {
      return {
        usable: false,
        reason: `line ${i + 1} of /etc/inittab is not id:runlevels:action:process ("${body.trim().slice(0, 48)}"), so this file is not the format this repair can read and it is left alone rather than edited on a guess`,
      };
    }
    if (fields[2] !== 'sysinit') continue;
    if (fields[0] !== '') {
      return {
        usable: false,
        reason: `the first sysinit entry in /etc/inittab carries the id "${fields[0]}", which is the SysV convention rather than busybox's — busybox attaches such an entry to /dev/${fields[0]} instead of the console, so the repair's own console markers would be unreadable and there would be no evidence it ran`,
      };
    }
    return { usable: true, index: i };
  }
  return {
    usable: false,
    reason:
      '/etc/inittab declares no sysinit entry, so there is no stage of this boot the repair could be attached to; inserting one would be inventing a stage rather than using one the firmware already runs',
  };
}

/** Pure: the init script rewritten with `line` immediately after its shebang, ahead of the vendor's own body. */
export function insertAfterShebang(text: string, line: string): string {
  if (!text.startsWith('#!')) return `${line}\n${text}`;
  const nl = text.indexOf('\n');
  // A file that is nothing but a shebang: the line has to go after it, not before.
  if (nl === -1) return `${text}\n${line}\n`;
  return `${text.slice(0, nl + 1)}${line}\n${text.slice(nl + 1)}`;
}

/**
 * Pure: choose where the line goes, preferring the inittab entry and degrading in the open.
 *
 * Returns the placement and, when the preferred one was not taken, the sentence saying why — which is the half a
 * reader needs: "the vendor's own init script was edited" is a different claim from "one line was added beside it",
 * and the reason the second was not possible belongs on the first.
 */
export function chooseRepairPlacement(
  input: Pick<GuestRepairInputs, 'initScript' | 'initScriptText' | 'inittab'>,
  line: string,
): { placement: RepairPlacement | null; degraded: string | null } {
  const entry = `::sysinit:${line}`;
  const fallback = (degraded: string): { placement: RepairPlacement | null; degraded: string } => {
    if (input.initScript === null || input.initScriptText === null) return { placement: null, degraded };
    return {
      placement: {
        kind: 'init-script-head',
        file: input.initScript,
        content: insertAfterShebang(input.initScriptText, line),
        inserted: line,
      },
      degraded,
    };
  };

  if (input.inittab === null) return fallback('the firmware ships no /etc/inittab');
  if (!input.inittab.trim()) return fallback('/etc/inittab is empty');
  if (entry.length > INITTAB_LINE_MAX) {
    return fallback(
      `the sysinit entry would be ${entry.length} bytes and busybox init truncates an inittab line at ${INITTAB_LINE_MAX}, which turns it into a different command rather than failing`,
    );
  }
  const at = findSysinitInsertion(input.inittab);
  if (!at.usable) return fallback(at.reason);

  const lines = input.inittab.split('\n');
  lines.splice(at.index, 0, entry);
  return {
    placement: { kind: 'inittab-sysinit', file: 'etc/inittab', content: lines.join('\n'), inserted: entry },
    degraded: null,
  };
}

/** The half of the intervention sentence that is the same wherever the line landed. */
const WHAT_IT_RUNS =
  "It runs the firmware's OWN /etc/rc.d/iptables-stop about 20 s into the boot — the vendor's teardown script, " +
  'which flushes filter and nat and sets every policy to ACCEPT, and which nothing in the vendor boot path ever ' +
  'calls. Any service that answered on this run may have answered only because its packet filtering had been ' +
  'torn down.';

/**
 * Pure: the one line to run, where to put it, and the sentences that describe both.
 *
 * Everything it invokes must already be in the image. Nothing is written into the guest but this line — no
 * binary, no script, no busybox of ours — so the repair cannot introduce behaviour the firmware does not already
 * contain, and the intervention sentence stays small enough to be true.
 */
export function planGuestRepair(input: GuestRepairInputs): GuestRepairPlan {
  const skipped: string[] = [];
  const refuse = (why: string): GuestRepairPlan => {
    skipped.push(why);
    return { line: null, placement: null, interventions: [], skipped };
  };

  if (input.initScript === null && input.inittab === null) {
    return refuse(
      'The firmware ships neither /etc/inittab nor an init script, so there is nothing this repair could attach ' +
        'itself to and nothing was changed. The guest boots exactly as shipped and a service that does not answer ' +
        'is the firmware, not a missed repair.',
    );
  }
  if (!input.hasIptablesStop) {
    return refuse(
      'The firmware ships no /etc/rc.d/iptables-stop, and this repair deliberately runs only what the image ' +
        'already contains rather than injecting a flush of its own. The guest boots exactly as shipped.',
    );
  }
  if (!input.hasPing) {
    return refuse(
      'This busybox has no `ping` applet, and BusyBox 1.01 here has no `sleep` either, so there is no way to wait ' +
        'for the daemon to install its rules before reading them. Firing immediately would report an empty ' +
        'ruleset and flush nothing, which reads as a measurement and is not one.',
    );
  }

  // The timer retries because the line now runs BEFORE the vendor's rcS brings `lo` up: a bare ping against a down
  // loopback fails in milliseconds and would elapse the whole wait before httpd had installed a single rule.
  const wait = `n=0; until ping -c ${WAIT_PINGS} 127.0.0.1 >/dev/null 2>&1 || [ $n -ge ${LO_TRIES} ]; do n=$((n+1)); done; `;
  const read = input.hasIptablesSave ? `echo ${RULES_BEGIN}; iptables-save 2>&1; echo ${RULES_END}; ` : '';
  // Backgrounded, so whichever stage runs it returns immediately and the vendor's own boot is not held up.
  const line = `(${wait}${read}/etc/rc.d/iptables-stop >/dev/null 2>&1; echo ${FLUSHED}) &`;

  const { placement, degraded } = chooseRepairPlacement(input, line);
  if (!placement) {
    return refuse(
      `No repair was applied: ${degraded}, and the firmware ships no init script to fall back to. Appending to a file the boot never reaches would record an intervention that no CPU executed, which is worse than none.`,
    );
  }

  const interventions = [
    placement.kind === 'inittab-sysinit'
      ? `Inserted one line into /etc/inittab in the booted image as the FIRST sysinit entry, above the vendor's own, so busybox init executes it BEFORE /etc/rc.d/rcS and the repair does not depend on rcS ever returning. No vendor script was edited. ${WHAT_IT_RUNS}`
      : `Inserted one line at the HEAD of /${placement.file} in the booted image, immediately after its shebang and ahead of the vendor's own body, so it is executed before that script stalls. The vendor's own init script was edited, rather than the one line beside it in /etc/inittab, because ${degraded}. ${WHAT_IT_RUNS}`,
  ];
  if (placement.kind === 'init-script-head' && degraded) {
    skipped.push(
      `The preferred placement — a reversible first sysinit entry in /etc/inittab, which leaves every vendor file byte-identical — was not available: ${degraded}.`,
    );
  }
  if (!input.hasIptablesSave) {
    skipped.push(
      'This rootfs ships no iptables-save, so the ruleset could not be read before it was flushed. The repair ' +
        'still ran; what is missing is the evidence of whether it was the thing that mattered.',
    );
  }
  return { line, placement, interventions, skipped };
}

/**
 * The flag that arms this. Off by default and deliberately so: editing a firmware's init layout is the
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
      note: `${REPAIR_FLAG} is off, so this guest was not examined for a boot-time repair and nothing was inserted into it. That is not a statement that the image needed none — the question was not asked.`,
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
  /** True when the marker pair was found — i.e. the inserted line actually ran. */
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
