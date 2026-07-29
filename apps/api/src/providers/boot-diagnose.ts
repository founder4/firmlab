/**
 * Why nothing answered — read from the guest's own boot trace, so an empty `open` stops being a silent result.
 *
 * The full-system rung reports the ports that answered, and across this corpus that list is empty on every image.
 * An empty list covers at least five different situations that want five different responses, and reporting them
 * identically is the conflation this workbench exists to prevent. Measured on the corpus (2026-07-29):
 *
 *   TP-Link MR3220 — 116 SYNs in, **116 RSTs back**: the guest's TCP stack is alive and nothing is on the port.
 *                    Its `/usr/bin/httpd` opened `/proc/simple_config/system_mode` and exited with code 139
 *                    (128 + SIGSEGV) at 3.5 s. The daemon is DEAD, and no amount of extra port forwarding
 *                    reaches a process that is not running.
 *   TP-Link WR940N — 158 SYNs in, **nothing back at all**: not a SYN-ACK, not a RST. And its httpd is provably
 *                    alive — the same console prints `SSL_CTX_use_certificate_file success!` — beside an
 *                    `ebtables bug: Wrong len argument`. Something INSIDE the guest is dropping the packets.
 *
 * Those two need opposite work (repair a crashing daemon vs. get past the guest's own filtering), and until this
 * existed both rendered as `open: []`. The distinction is drawn from evidence that is already being captured and
 * was simply not being read: the firmadyne kernels trace every `execve`, `open` and `exit`, and `parseGuestWire`
 * already counts SYNs, SYN-ACKs and RSTs.
 *
 * **What it refuses to do.** It never converts a diagnosis into a proof state — `classifyFullSystem` owns the
 * ladder and a reason why nothing answered is not evidence that something did. It never guesses at a cause it
 * cannot see: with no trace and no wire counts it says exactly that, rather than picking the likeliest story.
 * And a daemon that exits 0 is reported as having exited, not as having crashed; only a code above 128 is named
 * as a signal, because that is the only case where the number means one.
 *
 * Pure and I/O-free: the runner passes the console text and the wire counts, this reads them.
 */

/** What this run can say about an empty `open` list. */
export type UnreachableCause =
  | 'answered' // something answered; there is nothing to diagnose
  | 'service-died' // a network daemon started and exited
  | 'guest-dropped' // SYNs went in, nothing came back, and a daemon is alive
  | 'nothing-listening' // SYNs went in, RSTs came back: the stack is up, the port is closed
  | 'no-syns' // the probe never reached the guest
  | 'no-service-started' // nothing that looks like a network daemon was ever executed
  | 'unknown'; // no trace and no counts — said plainly rather than guessed

export interface DaemonExit {
  /** The binary as the trace named it, verbatim. */
  binary: string;
  pid: string;
  /** The raw `do_exit` code. 139 is 128 + SIGSEGV; below 128 it is an ordinary exit status. */
  code: number;
  /** The signal number when the code encodes one, else null. Named because 139 means nothing to most readers. */
  signal: number | null;
  /** The last file this pid opened before it went. On the MR3220 that is the whole diagnosis. */
  lastOpen: string | null;
}

export interface BootDiagnosis {
  cause: UnreachableCause;
  /** One sentence for the operator, naming what to fix rather than restating that nothing answered. */
  summary: string;
  /** The lines the summary was drawn from, so it can be checked instead of trusted. */
  evidence: string[];
  /** Network daemons the trace saw start, in the order they started. */
  daemonsStarted: string[];
  /** Those that then exited, with what killed them. */
  daemonsExited: DaemonExit[];
}

/**
 * Binaries whose name means "this serves the network". Deliberately the same vocabulary `servicemap` uses, plus
 * the vendor `httpd` every router in this corpus ships — a list that guessed wider would report a daemon dying
 * for a process that was never going to listen.
 */
const NETWORK_DAEMONS =
  /\b(u?httpd|lighttpd|boa|thttpd|mini_httpd|nginx|goahead|dropbear|sshd|telnetd|utelnetd|ftpd|vsftpd|dnsmasq|miniupnpd|upnpd|tr069|cwmpd|lltd|minidlna)\b/;

const RE_EXECVE = /firmadyne: do_execve\[PID: (\d+) \([^)]*\)\]: argv: ([^\s,]+)/;
const RE_EXIT = /firmadyne: do_exit\[PID: (\d+) \(([^)]*)\)\]: code:(\d+)/;
const RE_OPEN = /firmadyne: do_sys_open\[PID: (\d+) \([^)]*\)\]: file:(\S+)/;

const basename = (p: string): string => p.split('/').filter(Boolean).pop() ?? p;

/** A `do_exit` code above 128 encodes a signal; below it is an ordinary status and must not be dressed as one. */
export function signalOf(code: number): number | null {
  return code > 128 && code < 192 ? code - 128 : null;
}

const SIGNALS: Record<number, string> = { 4: 'SIGILL', 6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE', 11: 'SIGSEGV' };

/** Pure: the network daemons a firmadyne boot trace shows starting, and which of them then exited. */
export function readDaemonTrace(consoleOutput: string): { started: string[]; exited: DaemonExit[] } {
  const started: string[] = [];
  /** pid → the daemon binary it is running. A pid is reused across a boot, so the LAST execve wins. */
  const running = new Map<string, string>();
  const lastOpen = new Map<string, string>();
  const exited: DaemonExit[] = [];

  for (const line of consoleOutput.split('\n')) {
    const exec = RE_EXECVE.exec(line);
    if (exec?.[1] && exec[2]) {
      const name = basename(exec[2]);
      if (NETWORK_DAEMONS.test(name)) {
        running.set(exec[1], name);
        lastOpen.delete(exec[1]);
        started.push(name);
      } else {
        // A pid that becomes something else is no longer the daemon it was, and its exit is not the daemon's.
        running.delete(exec[1]);
      }
      continue;
    }
    const open = RE_OPEN.exec(line);
    if (open?.[1] && open[2]) {
      if (running.has(open[1])) lastOpen.set(open[1], open[2]);
      continue;
    }
    const exit = RE_EXIT.exec(line);
    if (exit?.[1] && exit[3]) {
      const binary = running.get(exit[1]);
      if (!binary) continue;
      const code = Number.parseInt(exit[3], 10);
      exited.push({
        binary,
        pid: exit[1],
        code,
        signal: signalOf(code),
        lastOpen: lastOpen.get(exit[1]) ?? null,
      });
      running.delete(exit[1]);
    }
  }
  return { started: [...new Set(started)], exited };
}

export interface DiagnoseInput {
  consoleOutput: string;
  /** How many host→guest forwards this run set up, so "nothing was even asked" is distinguishable. */
  forwards: number;
  /** Of those, how many answered. Non-zero short-circuits: there is nothing to diagnose. */
  open: number;
  /** From `parseGuestWire`. Absent when this qemu could not capture frames. */
  wire?: { synsToGuest: number; synAcksFromGuest: number; resetsFromGuest: number } | null;
}

/**
 * Pure: why nothing answered on this boot.
 *
 * The order of the tests is the order of the evidence's strength. A dead daemon is the strongest thing the trace
 * can say and it explains a RST as well as a silence, so it is tested first; the wire counts then separate a
 * guest that refused the connection from one that swallowed it, which is the distinction the corpus turned on.
 */
export function diagnoseUnreachable(input: DiagnoseInput): BootDiagnosis {
  const { started, exited } = readDaemonTrace(input.consoleOutput);
  const base = { daemonsStarted: started, daemonsExited: exited };
  if (input.open > 0) {
    return { ...base, cause: 'answered', summary: 'A service answered; there is nothing to diagnose.', evidence: [] };
  }

  const dead = exited[0];
  if (dead) {
    const sig = dead.signal;
    const how = sig
      ? `died on ${SIGNALS[sig] ?? `signal ${sig}`} (exit code ${dead.code})`
      : `exited with status ${dead.code}`;
    const doing = dead.lastOpen ? `, and the last file it opened was ${dead.lastOpen}` : '';
    return {
      ...base,
      cause: 'service-died',
      summary: `The firmware started ${dead.binary} and it ${how}${doing}. Nothing answered because the daemon is not running — forwarding more ports cannot reach a process that already exited. What this needs is the resource it died on, not a wider probe.`,
      evidence: [
        `${dead.binary} (pid ${dead.pid}) exit code ${dead.code}`,
        ...(dead.lastOpen ? [`last open: ${dead.lastOpen}`] : []),
      ],
    };
  }

  if (input.forwards === 0) {
    return {
      ...base,
      cause: 'no-syns',
      summary: 'This run forwarded no ports at all, so nothing was ever asked of the guest.',
      evidence: [],
    };
  }

  const w = input.wire;
  if (!w) {
    return {
      ...base,
      cause: 'unknown',
      summary:
        'Nothing answered, and this run captured no frames, so whether the probe even reached the guest is not ' +
        'something this deployment can say.',
      evidence: [],
    };
  }
  if (w.synsToGuest === 0) {
    return {
      ...base,
      cause: 'no-syns',
      summary:
        'No SYN ever reached the guest, so the silence is on the host side of the forward rather than in the ' +
        'firmware — the guest was never asked.',
      evidence: ['0 SYNs delivered to the guest'],
    };
  }
  if (w.resetsFromGuest > 0) {
    const swallowed = w.synsToGuest - w.resetsFromGuest;
    // Measured on the WDR3600: 159 SYNs in, FOUR RSTs. Reading that as "nothing is bound" throws away the 155
    // that vanished, which is the more interesting half — a stack that refuses some and swallows most changed
    // state part-way through the boot, and that is a different thing to go and look at.
    const mixed =
      swallowed > w.resetsFromGuest
        ? ` But ${swallowed} of them got no answer at all, so this is not a clean refusal: something started dropping packets part-way through the boot, and only the first few were refused.`
        : '';
    return {
      ...base,
      cause: swallowed > w.resetsFromGuest ? 'guest-dropped' : 'nothing-listening',
      summary: `The guest refused ${w.resetsFromGuest} of ${w.synsToGuest} connection(s) with a RST, so its TCP stack is up and reachable and has nothing bound to the forwarded ports. Either the service listens somewhere this run did not forward, or it never started.${mixed}`,
      evidence: [`${w.synsToGuest} SYN(s) in, ${w.resetsFromGuest} RST(s) back, 0 accepted`],
    };
  }
  const alive = started.length > 0 ? ` — and ${started.join(', ')} started and did not exit` : '';
  return {
    ...base,
    cause: 'guest-dropped',
    summary: `${w.synsToGuest} SYN(s) went into the guest and NOTHING came back: no handshake and no refusal${alive}. A closed port answers with a RST, so silence means the packets were dropped inside the guest — its own firewall, its bridge, or an interface the emulated hardware does not satisfy. This is not "no service".`,
    evidence: [
      `${w.synsToGuest} SYN(s) in, 0 SYN-ACK, 0 RST`,
      ...(started.length ? [`running: ${started.join(', ')}`] : []),
    ],
  };
}
