/**
 * Is a refused process-group signal a denial, or the kernel reporting that the group is already dead?
 *
 * On XNU, `kill(-pgid, sig)` walks the group, skips zombie members, and answers EPERM when it signalled nobody.
 * A group whose only member is an exited leader not yet reaped therefore refuses SIGKILL exactly like a group of
 * processes this user may not signal. That window is real for owned tools: libuv reaps on SIGCHLD, and when a
 * child writes and exits within one event-loop turn, the stdout read that trips `maxBuffer` can run before the
 * reap, so the group kill lands on a zombie (reproduced in docs/JOB-PROCESS-MACOS-EPERM-20261123.md).
 *
 * The two are told apart only by the OS state read at the refusal, never by the error code alone: the refusal is
 * discharged when the group still exists, its leader is among the members, and every member is a zombie, which
 * means dead and holding nothing. Anything else is a denial and stays visible, including a member that is alive,
 * an empty or unreadable listing, and an absent leader. Linux delivers signals to its own zombies, so it never
 * produces this refusal, and there an EPERM is always treated as a denial. This module decides only what a refusal
 * means. Capacity release still waits for verified group exit in `job-cancellation.ts`.
 */
import { execFileSync } from 'node:child_process';

export interface GroupMember {
  pid: number;
  live: boolean;
}

/** Members of `group` from `ps -A -o pid=,pgid=,stat=`. One unparseable row makes the whole listing unusable. */
export function psGroupMembers(text: string, group: number): GroupMember[] | null {
  const members: GroupMember[] = [];
  for (const line of text.split('\n')) {
    const row = line.trim();
    if (!row) continue;
    const [pidField, pgidField, stat] = row.split(/\s+/);
    const pid = Number(pidField);
    const pgid = Number(pgidField);
    if (!Number.isInteger(pid) || !Number.isInteger(pgid) || !stat) return null;
    if (pgid === group) members.push({ pid, live: !stat.startsWith('Z') });
  }
  return members;
}

export type GroupSignalRefusal = 'exited_unreaped' | 'denied';

export function classifyGroupSignalRefusal(
  code: string | undefined,
  leader: number,
  members: readonly GroupMember[] | null,
): GroupSignalRefusal {
  if (code !== 'EPERM' || !members || members.length === 0) return 'denied';
  if (!members.some((member) => member.pid === leader)) return 'denied';
  return members.every((member) => !member.live) ? 'exited_unreaped' : 'denied';
}

/**
 * Read the group state right after a refusal and classify it. The caller is still inside the synchronous callback
 * that signalled, so the event loop cannot reap the leader between the refusal and this read.
 */
export function groupSignalRefusal(error: unknown, leader: number): GroupSignalRefusal {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  if (code !== 'EPERM' || process.platform === 'win32' || process.platform === 'linux') return 'denied';
  let members: GroupMember[] | null = null;
  try {
    const listing = execFileSync('ps', ['-A', '-o', 'pid=,pgid=,stat='], { encoding: 'utf8', timeout: 2000 });
    members = psGroupMembers(listing, leader);
  } catch {
    // An unreadable process table proves nothing, so the refusal stays a denial.
  }
  return classifyGroupSignalRefusal(code, leader, members);
}
