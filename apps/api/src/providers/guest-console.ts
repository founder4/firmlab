/**
 * Driving the guest's own serial console, and reading back what it says — the third pass of the full-system rung.
 *
 * **What this exists to fix, measured.** The WR940N boots, `httpd` binds 80/443/22, and 157 SYNs are delivered to
 * a forwarded port without so much as a RST. `boot-diagnose.ts` was right that this is not "no service", and it
 * named two candidate causes. Booting the image with `init=/bin/sh` and asking the guest settles it:
 *
 *   - `iptables -L INPUT -n` reads `Chain INPUT (policy DROP …)` **with no accept rules at all**. A DROP policy is
 *     precisely a SYN that disappears without a reset.
 *   - `lsmod` is **empty**, so `br_MultiSsidVlan_InputForward.ko` — the competing lead — is not loaded and cannot
 *     be eating anything.
 *   - `/proc/net/ip_tables_names` holds `raw mangle filter` and **no `nat`**, which is why the vendor's own
 *     teardown exits non-zero while still doing its work on `filter`. A non-zero exit here is not a failure and
 *     must not be read as one.
 *
 * Running `/etc/rc.d/iptables-stop` — **shipped in the image, and never called by its own boot path** — then
 * makes the router answer: `HTTP/1.1 200 OK`, `Server: Router Webserver`, over the forwarded port. Six boots,
 * three per arm, identical schedules: ACCEPT + 200 in the intervened arm, DROP + timeout in the control, with
 * port 80 in LISTEN in both.
 *
 * **The control is the load-bearing part, and the first run of this experiment did not have one.** Its BEFORE
 * probe fired while only `:076C` was listening and `httpd` bound 80/443/22 in the ~30 s before the AFTER probe,
 * so the whole difference was very nearly attributed to an intervention that had merely been given more time. The
 * schedule is therefore fixed in `consoleScript` rather than assembled at the call site: the intervened pass and
 * the control must spend the same wall-clock in the same places, or the comparison means nothing.
 *
 * **Everything here is an intervention and is named as one.** `init=/bin/sh` replaces the vendor's init, which
 * also means `/sbin/init` never runs and `inittab`'s respawn entries — its `getty` among them — never start. That
 * is not a footnote to "the workbench flushed the firewall"; it is a second modification of the subject, and both
 * travel in `interventions` so a reader of the finding sees what answered. Why `init=/bin/sh` at all: this image's
 * `getty` wants a login, and its root hash is md5crypt and was NOT recovered — 115226 candidates out of the
 * image's own strings failed against it — so there is no credentialled way in.
 *
 * **It reads before it writes, and reads again after.** The INPUT policy is captured on both sides of the
 * teardown, because a repair that cannot tell you it was unnecessary is not a diagnosis: if the policy was already
 * ACCEPT and the SYNs still vanish, the firewall was never the cause and this pass has to say so rather than
 * claim a fix.
 *
 * **What the PRODUCT runs, and what it therefore may not say.** In the workbench this is a THIRD pass, reached only
 * when the two un-intervened passes of the same run had nothing answer — so a firmware that answers as shipped is
 * never touched, and "nothing answered without intervention" is established by those passes rather than asserted
 * here. That is not the six-boot experiment: the three-per-arm control ran an identical schedule, and passes one and
 * two do not (they never run `rcS` by hand, and never spend the 75 s this script spends waiting for `httpd` to
 * bind). So a port answering in pass three is NOT attributed to the teardown by comparing it against pass two. The
 * attribution available at n=1 is the policy transition read from inside the guest on both sides of the teardown,
 * and `classifyConsolePass` claims exactly that and no more.
 *
 * Pure and I/O-free — the script, the reading of it, and the decision whether to spend the boot at all.
 * `emulate-system.ts` owns the qemu process, its stdin and the socket.
 */
import type { ProofState } from '@firmlab/core';

/** One line sent to the guest shell, and how long to let it work before the next. */
export interface ConsoleStep {
  /** The command, exactly as typed. Empty string = send a bare newline (wake a prompt). */
  send: string;
  /** Milliseconds to wait after sending, before the next step. */
  waitMs: number;
  /** What this step is for, in the job log. */
  note: string;
}

/** What the rootfs staged for this boot actually contains. Absent capabilities change the script, never the claim. */
export interface GuestConsoleInputs {
  /** `etc/rc.d/rcS` — the vendor's init script, run by hand because `init=/bin/sh` skips `/sbin/init`. */
  hasRcS: boolean;
  /** `etc/rc.d/iptables-stop` — the vendor's own teardown, which its boot path never calls. */
  hasIptablesStop: boolean;
  /** `sbin/iptables`, for reading the policy on both sides of the teardown. */
  hasIptables: boolean;
  /** Run the teardown, or run the identical schedule without it. The control arm is `false`. */
  intervene: boolean;
}

/**
 * The kernel command line addition that gets a shell without a credential.
 *
 * Appended by the caller to the same `-append` the un-intervened passes use, so the two differ in exactly this.
 */
export const GUEST_SHELL_CMDLINE = 'init=/bin/sh';

/** Markers the guest echoes so the reader can find each section in 250 KB of vendor chatter. */
export const MARK = {
  shell: 'FIRMLAB_SHELL',
  rcsDone: 'FIRMLAB_RCS_DONE',
  polBefore: 'FIRMLAB_POL_BEFORE',
  /**
   * Echoed by the teardown step, and **by nothing else**.
   *
   * The control arm used to echo this same marker as its no-op placeholder, and `teardownRan` therefore came back
   * `true` on the arm that deliberately ran nothing — with "the firmware's own /etc/rc.d/iptables-stop was run"
   * in its intervention list. It survived every unit test because the fixtures only ever built the intervened
   * arm; the real control boot is what printed it. That is this rung's signature defect (a guard whose SUCCESS
   * path — here, the branch that must find nothing — is the path nobody exercises) and the second time it has
   * produced a false claim about an intervention on this exact rung.
   */
  stopDone: 'FIRMLAB_STOP_DONE',
  /** The control's placeholder. Deliberately a DIFFERENT string, so no reader can confuse the two arms. */
  noStop: 'FIRMLAB_NO_INTERVENTION',
  polAfter: 'FIRMLAB_POL_AFTER',
  listeners: 'FIRMLAB_LISTENERS',
} as const;

/**
 * The ordered script, with the schedule baked in.
 *
 * `rcS` is given 75 s because `httpd` binds 80/443/22 well after the script returns — the confound that nearly
 * invalidated the first run of this experiment. Its output goes to `/dev/null` because the daemon inherits the
 * console and floods it with `open device ar7100_gpio_chrdev failed`, which drowned the first read of the
 * ruleset; the daemon still runs, only its chatter is silenced.
 *
 * The control arm substitutes a no-op of the same duration rather than skipping the step, so the two arms reach
 * the probe at the same moment on the same clock.
 */
export function consoleScript(inputs: GuestConsoleInputs): ConsoleStep[] {
  const steps: ConsoleStep[] = [
    { send: '', waitMs: 1500, note: 'wake the shell' },
    { send: `echo ${MARK.shell}`, waitMs: 1500, note: 'confirm a shell is answering' },
    { send: 'mount -t proc proc /proc; mount -t sysfs sysfs /sys', waitMs: 2500, note: 'mount /proc and /sys' },
  ];
  if (inputs.hasRcS) {
    steps.push({
      send: `/etc/rc.d/rcS >/dev/null 2>&1; echo ${MARK.rcsDone}`,
      waitMs: 75_000,
      note: "run the vendor's own init script and let its daemons bind",
    });
  }
  if (inputs.hasIptables) {
    steps.push({ send: `echo ${MARK.polBefore}; iptables -L INPUT -n`, waitMs: 8000, note: 'read the policy first' });
  }
  if (inputs.intervene && inputs.hasIptablesStop) {
    steps.push({
      send: `/etc/rc.d/iptables-stop; echo ${MARK.stopDone}`,
      waitMs: 12_000,
      note: "run the firmware's own teardown",
    });
  } else {
    // The control, and any guest that ships no teardown: the same wall-clock, spent doing nothing — under its
    // OWN marker, so a transcript can never be read as having run a teardown it did not.
    steps.push({ send: `echo ${MARK.noStop}`, waitMs: 12_000, note: 'control arm — no intervention' });
  }
  if (inputs.hasIptables) {
    steps.push({ send: `echo ${MARK.polAfter}; iptables -L INPUT -n`, waitMs: 8000, note: 'read the policy again' });
  }
  steps.push({ send: `echo ${MARK.listeners}; cat /proc/net/tcp`, waitMs: 5000, note: 'read the listening sockets' });
  return steps;
}

/**
 * How long the script itself will take, read from the script rather than guessed at the call site.
 *
 * The boot box for a driven pass is `settle + this + slack`, and it has to be derived: the schedule is deliberately
 * fixed inside `consoleScript` (75 s of it is the wait for `httpd` to bind), so a caller that hard-coded a timeout
 * would silently truncate the run the first time a step's wait changed — losing the tail, which is where every
 * marker the outcome is read from lives.
 */
export function consoleScriptDurationMs(steps: readonly ConsoleStep[]): number {
  return steps.reduce((total, s) => total + s.waitMs, 0);
}

/** What the console said, read back. Every field is `null` when the console never answered the question. */
export interface ConsoleOutcome {
  /** A shell echoed its marker — without this nothing below means anything. */
  shellAnswered: boolean;
  /** The vendor init script ran to completion. */
  rcsCompleted: boolean;
  /** `iptables -L INPUT` policy before the teardown, e.g. `DROP`. Null = never read. */
  policyBefore: string | null;
  /** …and after. Null = never read. */
  policyAfter: string | null;
  /** The teardown's marker was echoed (the command returned, whatever its exit code). */
  teardownRan: boolean;
  /** Guest-side TCP ports in LISTEN, decimal, ascending. Empty = the table was read and held none. */
  listening: number[];
  /** Null = `/proc/net/tcp` was never read, which is NOT the same as "nothing was listening". */
  listenersRead: boolean;
}

/** `\r` is the serial console's, not the guest's; every reader here works on a normalised copy. */
function normalise(consoleOutput: string): string {
  return consoleOutput.replace(/\r/g, '');
}

/**
 * The INPUT policy in the section a marker opens.
 *
 * Scoped to the text BETWEEN its marker and the next one: the console carries two `iptables -L INPUT` dumps in one
 * stream, and a global match would return the first one for both and report a flush that never happened.
 */
function policyAfterMarker(text: string, marker: string, next: string[]): string | null {
  const start = text.indexOf(marker);
  if (start < 0) return null;
  let end = text.length;
  for (const n of next) {
    const i = text.indexOf(n, start + marker.length);
    if (i >= 0 && i < end) end = i;
  }
  return (text.slice(start, end).match(/Chain INPUT \(policy (\w+)/) ?? [])[1] ?? null;
}

/**
 * Pure: read the console back.
 *
 * A marker that the guest echoed appears at least twice — once as the shell's echo of the typed line, once as the
 * command's output — so presence is tested with a count above one wherever the typed line itself contains the
 * marker. Getting that wrong reports every step as having run the moment it was typed, which is the failure mode
 * that produced a retracted result on this rung once already.
 */
export function readConsoleOutcome(consoleOutput: string): ConsoleOutcome {
  const t = normalise(consoleOutput);
  const echoed = (m: string): boolean => t.split(m).length - 1 > 1;
  const listenersRead = t.includes(MARK.listeners);
  const listening: number[] = [];
  if (listenersRead) {
    const section = t.slice(t.indexOf(MARK.listeners));
    // `local_address` is `HHHHHHHH:PPPP`; `st` 0A is TCP_LISTEN. Anything else is a live or dying connection and
    // is not a service this rung may claim.
    for (const m of section.matchAll(/^\s*\d+:\s+[0-9A-F]{8}:([0-9A-F]{4})\s+[0-9A-F]{8}:[0-9A-F]{4}\s+0A\b/gm)) {
      const port = Number.parseInt(m[1] as string, 16);
      if (Number.isFinite(port) && !listening.includes(port)) listening.push(port);
    }
    listening.sort((a, b) => a - b);
  }
  return {
    shellAnswered: echoed(MARK.shell),
    rcsCompleted: echoed(MARK.rcsDone),
    policyBefore: policyAfterMarker(t, MARK.polBefore, [MARK.stopDone, MARK.noStop, MARK.polAfter, MARK.listeners]),
    policyAfter: policyAfterMarker(t, MARK.polAfter, [MARK.listeners]),
    teardownRan: echoed(MARK.stopDone),
    listening,
    listenersRead,
  };
}

/**
 * The intervention strings this pass earned, for `Finding.interventions`.
 *
 * Only what actually happened goes in the list. `init=/bin/sh` is always first when a shell answered, because it
 * is the modification a reader is least likely to think of and the one that changes the most: the vendor's init
 * never ran, so nothing `inittab` would have started is running either. A teardown that was scripted but whose
 * marker never came back is NOT listed — an intervention nobody can show executed is exactly the claim this rung
 * had to retract once.
 */
export function consoleInterventions(o: ConsoleOutcome): string[] {
  if (!o.shellAnswered) return [];
  const out = [
    'Booted with init=/bin/sh: the vendor init was replaced, so /sbin/init never ran and nothing in inittab (its getty included) was started',
  ];
  if (o.rcsCompleted) out.push('The vendor init script /etc/rc.d/rcS was run by hand from that shell');
  if (o.teardownRan && o.policyBefore !== null && o.policyAfter !== null && o.policyBefore !== o.policyAfter) {
    out.push(
      `The firmware's own /etc/rc.d/iptables-stop was run — a script shipped in this image that its boot path never calls — and the INPUT policy went ${o.policyBefore} → ${o.policyAfter}`,
    );
  } else if (o.teardownRan) {
    out.push("The firmware's own /etc/rc.d/iptables-stop was run");
  }
  return out;
}

/**
 * The sentence describing what the console established about the guest's filter table.
 *
 * It states the diagnosis when there is one, and it states the absence of one just as plainly — a policy that was
 * already ACCEPT while packets still vanish means the firewall was never the cause, and reporting that is the
 * point of reading before writing.
 */
export function describeConsole(o: ConsoleOutcome): string {
  if (!o.shellAnswered) {
    return 'No shell answered on the serial console, so nothing was asked of the guest and nothing about it is claimed here.';
  }
  const parts: string[] = [];
  parts.push(
    o.rcsCompleted
      ? 'A shell answered and the vendor init script ran to completion.'
      : 'A shell answered; the vendor init script did not report completion.',
  );
  if (o.policyBefore === null) {
    parts.push('The guest filter policy could not be read, so this run says nothing about it.');
  } else if (o.policyBefore === 'DROP' && o.policyAfter === 'ACCEPT') {
    parts.push(
      `The INPUT policy was ${o.policyBefore} before the teardown and ${o.policyAfter} after it — a DROP policy is exactly a SYN that vanishes without a reset, which is the symptom this rung reported on this image.`,
    );
  } else if (o.policyBefore === 'ACCEPT') {
    parts.push(
      'The INPUT policy was already ACCEPT before anything was changed, so the guest filter table is NOT what silences this firmware and the cause is still open.',
    );
  } else {
    parts.push(
      `The INPUT policy read ${o.policyBefore}${o.policyAfter === null ? ' and was not read again' : ` and ${o.policyAfter} afterwards`}.`,
    );
  }
  if (o.listenersRead) {
    parts.push(
      o.listening.length > 0
        ? `The guest held ${o.listening.length} listening TCP port(s): ${o.listening.join(', ')}.`
        : 'The guest held no listening TCP port at all, so no forward could have answered whatever the policy said.',
    );
  }
  return parts.join(' ');
}

/**
 * The flag that arms the console pass. Off by default, like the repair it supersedes: booting a firmware with its
 * init replaced is a modification of the artefact under analysis, and that is the operator's decision to make.
 */
export const CONSOLE_FLAG = 'FIRMLAB_EMU_CONSOLE';

/** The flag whose intervention overlaps this one's evidence. Named, because the refusal below has to quote it. */
const REPAIR_FLAG_NAME = 'FIRMLAB_EMU_REPAIR';

/** What the orchestrator knows when it decides whether to spend a third boot. */
export interface ConsolePassGate {
  /** `FIRMLAB_EMU_CONSOLE`. Off means nobody asked, and nothing about this guest is claimed either way. */
  enabled: boolean;
  /** Forwarded ports that answered on the pass the verdict is read from. Above zero, there is nothing to gain. */
  answered: number;
  /** The verdict pass printed a recognisable boot. Without a kernel there is no shell to talk to. */
  booted: boolean;
  /** …and did not panic. A panicked guest will panic again, and a third boot only doubles the wait. */
  panicked: boolean;
  /** The extracted rootfs DIRECTORY was available, so the script's inputs are read from the image. */
  rootfsAvailable: boolean;
  /**
   * `FIRMLAB_EMU_REPAIR` already appended its line to this image's init script.
   *
   * This is the one refusal that is not about cost, and it is the interesting one. The appended line runs the
   * vendor's teardown ~20 s into `rcS`, and this script runs `rcS` itself and then reads the INPUT policy — so on a
   * repaired image the "before" read happens AFTER a flush this workbench caused. It would come back ACCEPT, and
   * `describeConsole` would then state that the filter table is not what silences this firmware: a false conclusion
   * manufactured by our own other intervention. Two interventions whose evidence overlaps are worse than one.
   */
  alreadyIntervened: boolean;
}

/**
 * Pure: should a third, console-driven boot be attempted at all — and if not, WHY not.
 *
 * Every branch returns a sentence, including the one that runs. An un-attempted pass is not a failed one and must
 * never read as a fact about the firmware: "nothing answered" and "nothing answered and nobody asked the guest why"
 * are different results, and only this function knows which one a given run produced.
 */
export function planConsolePass(g: ConsolePassGate): { run: boolean; reason: string } {
  if (!g.enabled) {
    return {
      run: false,
      reason: `${CONSOLE_FLAG} is off, so the guest was not asked anything on its serial console. That is not a statement that it had nothing to say — the question was not put.`,
    };
  }
  if (g.answered > 0) {
    return {
      run: false,
      reason: `${g.answered} forwarded port(s) already answered on this run, so the firmware answers as shipped and there is nothing here to intervene in. A guest that works is never driven.`,
    };
  }
  if (g.panicked) {
    return {
      run: false,
      reason:
        'The guest kernel panicked, so there is no userspace to hold a shell. A console pass would spend a third boot timeout reaching the same panic.',
    };
  }
  if (!g.booted) {
    return {
      run: false,
      reason:
        'No pass printed a recognisable boot, so there is no evidence a shell could exist to be driven. The question this pass asks is about a booted guest.',
    };
  }
  if (!g.rootfsAvailable) {
    return {
      run: false,
      reason:
        'No extracted rootfs was available, so what this image ships — an init script, the vendor teardown, an iptables binary — could not be read. The script would then be assembled from assumptions about a filesystem nobody looked at.',
    };
  }
  if (g.alreadyIntervened) {
    return {
      run: false,
      reason: `This image was already modified for the boot by ${REPAIR_FLAG_NAME}, which runs the vendor teardown from inside the init script. Reading the INPUT policy after that would measure this workbench's own flush and report it as the firmware's shipped state, so the console pass declines rather than produce a diagnosis it cannot attribute.`,
    };
  }
  return {
    run: true,
    reason:
      'Nothing answered on a guest that booted, so the guest is asked directly: boot it again with a shell on the serial console, read its filter policy, run the teardown the image itself ships, and read the policy again.',
  };
}

/** The grading of a console pass: how much it established, and under what name it reaches the ledger. */
export interface ConsoleVerdict {
  proofState: ProofState;
  kind: string;
  title: string;
  reason: string;
}

/**
 * Pure: what a console pass established.
 *
 * Two decisions here are worth stating rather than reading off the code.
 *
 * **A port that answered keeps `confirmed_full_system`.** The kernel booted, the vendor's own init script ran, the
 * vendor's own daemon bound the port and replied — that is what this rung's strongest state means, and the module's
 * own rule (boot printed AND a service answered) is met. Inventing a weaker state for it would be the third option
 * the proof vocabulary deliberately does not have, and the codebase has refused that once already for the
 * platform/harness split. What separates it from a boot that answers as shipped is the KIND and the non-empty
 * `interventions` list, both of which a reader and a query can see; the title says it in words as well, because the
 * census is the number people quote.
 *
 * **A shell that never answered is `blocked_by_platform`, not a negative.** The question was put to the guest and
 * this deployment could not get an answer out of it. Reading that as "the firmware has no shell" would be the
 * inference this workbench exists to refuse.
 */
export function classifyConsolePass(o: ConsoleOutcome, openPorts: number): ConsoleVerdict {
  if (!o.shellAnswered) {
    return {
      proofState: 'blocked_by_platform',
      kind: 'system-console-blocked',
      title:
        'The guest was booted with a shell on its serial console and never answered — the question could not be put',
      reason:
        'A third boot was made with init=/bin/sh so the guest could be asked why nothing reaches it, and no shell echoed its marker. Nothing was established about the firmware here, in either direction.',
    };
  }
  if (openPorts > 0) {
    return {
      proofState: 'confirmed_full_system',
      kind: 'system-console-answered',
      title: `${openPorts} forwarded port(s) answered only after the guest's own firewall teardown was run from the serial console — not as shipped`,
      reason: `The two un-intervened passes of this run had nothing answer. Booted a third time with init=/bin/sh and driven from its serial console, the guest answered TCP on ${openPorts} forwarded port(s) after the firmware's OWN /etc/rc.d/iptables-stop was run — a script this image ships and its boot path never calls. The service is the firmware's; the reachability is this harness's, and both interventions are listed. This proves the sandbox. It says nothing about the physical device.`,
    };
  }
  if (o.policyBefore !== null) {
    return {
      proofState: 'confirmed_in_emulation',
      kind: 'system-console-diagnosed',
      title: `The booted guest's own INPUT policy was read from inside it: ${o.policyBefore}${o.policyAfter !== null && o.policyAfter !== o.policyBefore ? ` → ${o.policyAfter}` : ''}`,
      reason:
        "A shell answered on the serial console and the guest's packet filter was read from inside the running system, which is a property of this boot rather than an inference from outside it. No forwarded port answered even so, so what silences this firmware is not settled by the policy alone.",
    };
  }
  return {
    proofState: 'needs_runtime_reproduction',
    kind: 'system-console-inconclusive',
    title:
      'A shell answered on the guest console and nothing further could be read — this is not a verdict about the firmware',
    reason:
      'The guest reached a shell, so the boot is real, and neither its filter policy nor its listening sockets could be read from it. A precondition was observed and nothing was established.',
  };
}
