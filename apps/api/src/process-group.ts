/** Exit verification for owned Unix process groups. A delivered signal is not proof that sockets are free. */
import { readFileSync, readdirSync, readlinkSync } from 'node:fs';

/**
 * `pgrp` from `/proc/<pid>/stat`. Group 0 is real, not unreadable: kernel threads carry it, and on a Linux host (a CI
 * VM, unlike a container's PID namespace) they are in `/proc`. Rejecting it made every teardown there throw.
 */
export function procGroupMember(stat: string): { group: number; live: boolean } | null {
  const end = stat.lastIndexOf(')');
  if (end < 0) return null;
  const fields = stat.slice(end + 2).split(' ');
  const group = Number(fields[2]);
  if (!Number.isInteger(group) || group < 0 || !fields[0]) return null;
  return { group, live: fields[0] !== 'Z' && fields[0] !== 'X' };
}

export function processGroupIsAlive(group: number): boolean {
  try {
    process.kill(-group, 0);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    if ((error as NodeJS.ErrnoException).code !== 'EPERM') throw error;
  }
  if (process.platform !== 'linux') return true;
  // Container PID 1 may not reap orphan zombies. Zombies are dead and cannot retain sockets or execute work.
  for (const name of readdirSync('/proc')) {
    if (!/^\d+$/.test(name)) continue;
    let stat: string;
    try {
      stat = readFileSync(`/proc/${name}/stat`, 'utf8');
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT' || code === 'ESRCH') continue;
      throw error;
    }
    const member = procGroupMember(stat);
    if (!member) throw new Error(`Unreadable process state for PID ${name}; group exit cannot be verified`);
    if (member.group === group && member.live) return true;
  }
  return false;
}

/** Snapshot socket ownership before signalling: Linux can remove a task from its group before exit_files frees sockets. */
export function processGroupSockets(group: number): Set<string> {
  const sockets = new Set<string>();
  if (process.platform !== 'linux') return sockets;
  for (const name of readdirSync('/proc')) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const member = procGroupMember(readFileSync(`/proc/${name}/stat`, 'utf8'));
      // A zombie has released its files, and Linux refuses its fd directory (EACCES) because it has no mm left.
      if (member?.group !== group || !member.live) continue;
      let fds: string[];
      try {
        fds = readdirSync(`/proc/${name}/fd`);
      } catch (error) {
        // The member may have exited between the two reads; only a still-live member's refusal is a real gap.
        if ((error as NodeJS.ErrnoException).code !== 'EACCES' || !stillLiveMember(name, group)) continue;
        throw error;
      }
      for (const fd of fds) {
        try {
          const socket = /^socket:\[(\d+)\]$/.exec(readlinkSync(`/proc/${name}/fd/${fd}`));
          if (socket?.[1]) sockets.add(socket[1]);
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code !== 'ENOENT' && code !== 'ESRCH') throw error;
        }
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT' && code !== 'ESRCH') throw error;
    }
  }
  return sockets;
}

function stillLiveMember(pid: string, group: number): boolean {
  try {
    const member = procGroupMember(readFileSync(`/proc/${pid}/stat`, 'utf8'));
    return member?.group === group && member.live;
  } catch {
    return false;
  }
}

function ownedSocketsRemain(sockets: ReadonlySet<string>): boolean {
  if (sockets.size === 0 || process.platform !== 'linux') return false;
  for (const table of ['tcp', 'tcp6', 'udp', 'udp6', 'unix']) {
    let text: string;
    try {
      text = readFileSync(`/proc/net/${table}`, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    for (const row of text.trim().split('\n').slice(1)) {
      const inode = row.trim().split(/\s+/)[table === 'unix' ? 6 : 9];
      if (inode && sockets.has(inode)) return true;
    }
  }
  return false;
}

export async function waitForProcessGroupExit(
  group: number,
  timeoutMs = 5000,
  sockets: ReadonlySet<string> = new Set(),
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (processGroupIsAlive(group) || ownedSocketsRemain(sockets)) {
    if (Date.now() >= deadline)
      throw new Error(`Process group ${group} teardown could not be verified within ${timeoutMs}ms`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
