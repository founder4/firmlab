import { describe, expect, it } from 'vitest';
import { type UserEmulationResult, buildUserEmulationFindings, emulatorRefusal } from './emulate.js';

/** A run that got as far as producing output. Each test overrides only the field it is about. */
function run(over: Partial<UserEmulationResult> = {}): UserEmulationResult {
  return {
    ran: true,
    exitCode: 0,
    timedOut: false,
    stdout: '',
    stderr: '',
    command: 'qemu-mipsel-static -L /rootfs /rootfs/usr/bin/httpd',
    ...over,
  };
}

/** Verbatim from the corpus sweep of 2026-08-03 — three of seven user-mode runs printed exactly this. */
const REFUSAL = 'qemu-mipsel-static: /path/usr/bin/httpd: Invalid ELF image for this architecture';

describe('emulatorRefusal — the harness never starting is not the program failing', () => {
  it('returns the offending line for the real string the corpus produced', () => {
    expect(emulatorRefusal(REFUSAL)).toBe(REFUSAL);
  });

  it('finds the refusal among the other lines qemu wrote around it', () => {
    expect(emulatorRefusal(`some warning\n${REFUSAL}\ntrailing noise`)).toBe(REFUSAL);
  });

  it('says nothing about ordinary program stderr, which is the program running', () => {
    expect(emulatorRefusal('Usage: httpd [-p port]')).toBeNull();
  });

  it('says nothing about an empty stderr', () => {
    expect(emulatorRefusal('')).toBeNull();
  });

  /**
   * The mirror of the trap `parseTargetStderr` documents: the TARGET's own output shares this buffer. Matched
   * loose, "unknown architecture" coming out of the guest would turn a real execution into a platform block and
   * throw the result away — so the line has to be qemu speaking, prefix and all.
   */
  it('ignores the same words when the guest, not qemu, is the one saying them', () => {
    expect(emulatorRefusal('busybox: unknown architecture in /proc/cpuinfo')).toBeNull();
    expect(emulatorRefusal('httpd: Unable to find dynamic linker config, using defaults')).toBeNull();
  });

  it('reads a prefixed refusal other than the ELF one', () => {
    const line = 'qemu-arm-static: Unable to find dynamic linker';
    expect(emulatorRefusal(line)).toBe(line);
  });
});

describe('buildUserEmulationFindings — severity is info everywhere, and a refusal is not a result', () => {
  it('a refusal earns exactly one blocked_by_platform row and calls itself a deployment gap', () => {
    const drafts = buildUserEmulationFindings('usr/bin/httpd', run({ exitCode: 255, stderr: REFUSAL }));
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('binary-execution-blocked');
    expect(drafts[0]?.proofState).toBe('blocked_by_platform');
    expect(drafts[0]?.severity).toBe('info');
    expect(drafts[0]?.title).toContain('not a verdict about the firmware');
    expect(drafts[0]?.rationale).toContain('not a negative result about the code');
    expect(drafts[0]?.evidence?.emulatorRefusal).toBe(REFUSAL);
  });

  // The channel says HOW something was learned, and nothing was: the program never executed one instruction.
  it('carries no evidence channel at all on the refusal row, because nothing ran', () => {
    const [draft] = buildUserEmulationFindings('usr/bin/httpd', run({ exitCode: 255, stderr: REFUSAL }));
    expect(draft && 'evidenceChannel' in draft).toBe(false);
  });

  /**
   * The WR940N case, and the whole reason `emulatorRefusal` exists: read as an exit code this is a program that
   * failed 255, and a ledger row saying so would be a claim about a binary that never got to run.
   */
  it('lets the refusal outrank exit 255 rather than filing a program-failed row', () => {
    const [draft] = buildUserEmulationFindings('usr/bin/httpd', run({ exitCode: 255, stderr: REFUSAL }));
    expect(draft?.kind).toBe('binary-execution-blocked');
    expect(draft?.proofState).toBe('blocked_by_platform');
    expect(draft?.kind).not.toBe('binary-execution-nonzero');
  });

  it('a clean exit is confirmed_in_emulation about ONE input and never about the device', () => {
    const [draft] = buildUserEmulationFindings('bin/busybox', run({ exitCode: 0, stdout: 'BusyBox v1.01\n' }));
    expect(draft?.kind).toBe('binary-executed-in-emulation');
    expect(draft?.proofState).toBe('confirmed_in_emulation');
    expect(draft?.evidenceChannel).toBe('emulated_run');
    expect(draft?.severity).toBe('info');
    expect(draft?.rationale).toContain('ONE input');
    expect(draft?.rationale).toContain('never about the physical device');
    expect(draft?.rationale).toContain('nowhere near enough to call the binary sound');
  });

  it('a run the time box killed is still emulation-confirmed, because it did execute', () => {
    const [draft] = buildUserEmulationFindings('usr/sbin/httpd', run({ exitCode: null, timedOut: true }));
    expect(draft?.kind).toBe('binary-execution-timeboxed');
    expect(draft?.proofState).toBe('confirmed_in_emulation');
    expect(draft?.evidenceChannel).toBe('emulated_run');
    expect(draft?.rationale).toContain('says nothing about the physical device');
    expect(draft?.evidence?.timedOut).toBe(true);
  });

  // Under a foreign libc, with no NVRAM and no peripherals, a non-zero exit is as likely to be the sandbox as
  // the program — so it is recorded as what happened, at the severity of every other branch.
  it('a non-zero exit is recorded as what happened and never raised above info', () => {
    const [draft] = buildUserEmulationFindings('usr/bin/httpd', run({ exitCode: 1, stderr: 'nvram_get: no such key' }));
    expect(draft?.kind).toBe('binary-execution-nonzero');
    expect(draft?.proofState).toBe('confirmed_in_emulation');
    expect(draft?.evidenceChannel).toBe('emulated_run');
    expect(draft?.severity).toBe('info');
    expect(draft?.severity).not.toBe('high');
    expect(draft?.severity).not.toBe('critical');
    expect(draft?.rationale).toContain('not as a defect');
  });

  /**
   * `ran: false` is the emulator process never starting — `runIsolated` resolves exactly this on a spawn error,
   * and the auto-run lane feeds its result straight in here. Without this branch a stored result with `ran: false`
   * and `exitCode: 0` would have earned an execution claim, evidence channel and all, for a run that never was.
   */
  it('a run that never started is a platform block, not an execution', () => {
    const [draft] = buildUserEmulationFindings('usr/bin/httpd', run({ ran: false, exitCode: null }));
    expect(draft?.kind).toBe('binary-execution-blocked');
    expect(draft?.proofState).toBe('blocked_by_platform');
    expect(draft && 'evidenceChannel' in draft).toBe(false);
    expect(draft?.title).toContain('could not be started');
    expect(draft?.rationale).toContain('never executed');
  });

  it('names the binary and the exact command on every row, so the run can be re-read', () => {
    const [draft] = buildUserEmulationFindings('usr/bin/httpd', run({ exitCode: 255, stderr: REFUSAL }));
    expect(draft?.title).toContain('usr/bin/httpd');
    expect(draft?.evidence?.binary).toBe('usr/bin/httpd');
    expect(draft?.evidence?.command).toBe('qemu-mipsel-static -L /rootfs /rootfs/usr/bin/httpd');
  });
});
