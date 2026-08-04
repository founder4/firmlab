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
 * Pure and I/O-free — the script and the reading of it. `emulate-system.ts` owns the qemu process and the socket.
 */

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
