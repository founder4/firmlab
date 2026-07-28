/**
 * Component dependency-map provider. For the ELF binaries in an extracted rootfs, maps each binary to its
 * DT_NEEDED shared libraries (read with `rabin2 -l`) and assembles a dependency graph: nodes are the binaries
 * plus every referenced shared object, edges are "needs" (binary → lib). This is offline structural analysis of
 * the linked bytes — the primary output is the graph itself, never a security verdict. The single optional
 * finding is an honest INFO/`static_confirmed` inventory (N binaries, M libraries, K unresolved references).
 *
 * radare2 is an opt-in layer (like Ghidra/AFL++): with `rabin2` absent the runner degrades HONESTLY to
 * available:false and an empty graph — it never fabricates dependencies. The parse (`parseNeeded`), the ELF
 * sniff (`isElf`), the symlink index (`indexSymlinks`), the graph assembly (`buildGraph`) and the orphan
 * detector are PURE and unit-tested; the runner only walks the rootfs, probes the tool, and composes them.
 *
 * ## Why the walk still refuses to follow a symlink — and what resolving by NAME does instead
 *
 * `walkRootfs` does not follow links and must not. Following them costs containment twice over: a link cycle
 * makes the traversal non-terminating, and a carved rootfs whose `usr/lib` is a link to `/` (or to `../../..`)
 * walks the HOST — reading, timing and reporting on files that are not part of the image at all. Neither risk is
 * hypothetical on firmware carves, so the refusal stays.
 *
 * What the refusal cost, until this module was fixed, was the truth of the whole unresolved column. A soname is
 * usually a symlink — `libc.so.0 → libuClibc-0.9.33.so`, `libssl.so.1.1 → libssl.so.1.1.0k` — so the library the
 * binary names is present and the file the walk collected has a DIFFERENT name. Measured on the Tenda camera
 * carve: 63 of 67 binaries "needed" a missing `libc.so.0`, an artifact of the walk rather than a fact about the
 * rootfs, and a component-map view renders that table as its headline content.
 *
 * So resolution is by NAME, against an index the walk itself built. `readlink(2)` returns the link's own text and
 * does not traverse; the target is then resolved LEXICALLY (`resolveLinkPath` — pure string work, zero filesystem
 * calls) against the paths the walk collected. Nothing is opened through a link, no `realpath` is called, and an
 * absolute target means the carve's own root, because chroot semantics are what a rootfs link is written in: a
 * link to `/lib/libc.so.6` resolves against the CARVE's `lib/libc.so.6` and, if the carve does not contain it,
 * counts as nothing at all. A target that climbs above the root escapes and provides nothing. The host is
 * unreachable by construction, not by check.
 *
 * ## What a name resolution does and does not prove
 *
 * A soname matched to a walked file is the strong case: a file of that name is in the carve. A soname matched
 * only through a link is WEAKER, and stays labelled as such (`graph.linkProvided`, node kind `link`) with the
 * link and its target named, because all it proves is that the rootfs says the name exists — the target was
 * never opened, and nothing here checked that it is an ELF, let alone the right one. Neither case says anything
 * about the RUNTIME loader: `LD_LIBRARY_PATH`, a vendor overlay mounted at boot and a second partition are all
 * libraries the device has and this image does not, and a `dlopen(3)`ed plugin leaves no DT_NEEDED entry to
 * resolve in the first place. And a bound is not an answer: when the walk stops at its cap (`walkTruncated`),
 * "absent" is a claim about what it saw.
 *
 * A link that resolves to nothing is itself worth reporting (`graph.brokenLinks`): the rootfs names something the
 * carve did not produce. It is reported under a stated rule and never as a verdict — `/etc/resolv.conf → /tmp/…`
 * is dangling in every carve ever made and entirely correct on the device, which is why the rule keeps to names
 * that are shaped like a shared object or that some binary actually needs.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingDraft } from '../findings.js';

const execFileAsync = promisify(execFile);

/** A symlink exactly as the walk found it: its own text, read with `readlink`, never followed. */
export interface RootfsLink {
  /** The link itself, rootfs-relative (`lib/libc.so.0`). */
  path: string;
  /** The link text verbatim (`libuClibc-0.9.33.so`, `../../bin/busybox`, `/tmp/resolv.conf`) — not a resolution. */
  target: string;
}

/**
 * A name the rootfs provides only because a symlink says so — the weaker of the two ways a soname can resolve,
 * kept in its own list for exactly that reason. `resolvesTo` is where a lexical walk of the link text lands
 * inside the carve, not a path anything opened, and nothing checked that the file there is the library named.
 */
export interface LinkProvision {
  /** The basename the link contributes — for a soname, the name the DT_NEEDED entry asks for. */
  name: string;
  /** The symlink providing it, rootfs-relative. */
  link: string;
  /** The link text verbatim, so a reader can judge the claim rather than take it. */
  target: string;
  /** The rootfs-relative regular file the text resolves to lexically, through zero or more further links. */
  resolvesTo: string;
  /** Links traversed lexically to get there (1 = the link points straight at the file). */
  hops: number;
}

/**
 * A symlink that provides nothing, and why. Never a verdict: a rootfs is full of links into `/tmp`, `/proc` and
 * `/dev` that are dangling in the carve by design and correct on the running device.
 */
export interface BrokenLink {
  /** The symlink, rootfs-relative. */
  link: string;
  /** The link text verbatim. */
  target: string;
  /**
   * `dangling` — the target names a path the walk did not find; `escapes-rootfs` — it climbs above the root, so
   * it is outside the image and deliberately not followed; `cycle` — the links loop; `hop-limit` — the chain was
   * longer than the bound, which is a bound and not a proof of a loop.
   */
  reason: 'dangling' | 'escapes-rootfs' | 'cycle' | 'hop-limit';
  /** True when some binary's DT_NEEDED names this link — i.e. this broken link explains an unresolved reference. */
  needed?: boolean;
}

/** The facts `indexSymlinks` derived from the link texts. Selection and reporting rules are `buildGraph`'s job. */
export interface SymlinkIndex {
  /** basename → the provision, for every link whose text lands on a walked file inside the rootfs. */
  provides: Map<string, LinkProvision>;
  /** Every link that lands on nothing usable — unfiltered, so the caller can state its own reporting rule. */
  broken: BrokenLink[];
}

/** A dependency graph over the rootfs binaries and the shared objects they link against. */
export interface CompGraph {
  /**
   * One node per binary (an entry, kind `binary`), per soname a symlink provides (kind `link`) and per soname
   * nothing in the rootfs provides (kind `lib`). The three kinds are the three ways a reference can end, and the
   * codebase refuses to collapse them: `binary` = a file of that name was walked; `link` = only a link says so;
   * `lib` = unresolved.
   */
  nodes: { id: string; kind: 'binary' | 'lib' | 'link' }[];
  /** A "needs" edge from a binary to each shared object it links (both keyed by soname/basename). */
  edges: { from: string; to: string }[];
  /** Sonames no walked file and no symlink in the rootfs provides. Exactly the `lib` node set — see `buildGraph`. */
  unresolved: string[];
  /**
   * Sonames that resolved ONLY through a symlink, each naming the link and its target. Optional forever: a result
   * stored before this existed simply does not carry it, and absent means "this build never looked", which is not
   * the same claim as the empty array ("looked, found none").
   */
  linkProvided?: LinkProvision[];
  /** The broken links worth reporting, selected by `brokenLinkRule` and capped. Optional forever. */
  brokenLinks?: BrokenLink[];
  /** How many broken links the walk found in total, before the reporting rule and the cap. Optional forever. */
  brokenLinkCount?: number;
  /** The sentence stating which broken links are listed and which were left out. Rendered always, not only on a cut. */
  brokenLinkRule?: string;
}

export interface CompMapResult {
  available: boolean;
  graph: CompGraph;
  /** ELF FILES the walk collected. */
  binaryCount: number;
  /**
   * Distinct BASENAMES among those files — i.e. the graph's `binary` nodes. A DT_NEEDED reference is a basename,
   * so the graph is keyed by basename and two files called `busybox` in different directories are one node;
   * `binaryCount - binaryNodeCount` is how many files that collapse absorbed. Optional forever.
   */
  binaryNodeCount?: number;
  /**
   * The binaries nothing links against, in full. The web recomputes this from the persisted graph (older results
   * carry no such field); computing it here under the same rule makes the two provably the same list rather than
   * the finding's 200-item slice. Optional forever.
   */
  orphanBinaries?: string[];
  /** Symlinks the walk read (`readlink` only — none was followed). Optional forever. */
  symlinkCount?: number;
  /** True when a cap stopped the walk early, so every "absent" and "dangling" is a claim about what it saw. */
  walkTruncated?: boolean;
  findings: FindingDraft[];
  reason: string;
}

/**
 * Pure: extract the shared-object sonames from the plain output of `rabin2 -l <bin>` (a list of linked
 * libraries, possibly wrapped in a `[Linked libraries]` header and an `N libraries` footer). Tolerant of
 * surrounding formatting (brackets, quotes, leading paths): keeps only tokens that look like `*.so*`
 * (e.g. `libc.so.0`, `libcrypto.so.1.1`), reduces each to its basename, and dedupes preserving order. A
 * `.socket`-style false neighbour is rejected because the `.so` extension must terminate a version segment.
 */
export function parseNeeded(rabin2LibsOutput: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  // A soname: a `.so` extension optionally followed by `.<version>` segments, not glued to more letters
  // (so `foo.socket` / `foo.solib` don't match). The name char class excludes `/`, so a path yields its basename.
  const re = /[A-Za-z0-9_][A-Za-z0-9_.+-]*?\.so(?:\.[0-9A-Za-z_]+)*(?![A-Za-z0-9])/g;
  for (const m of rabin2LibsOutput.matchAll(re)) {
    const name = m[0];
    if (seen.has(name)) continue;
    seen.add(name);
    out.push(name);
  }
  return out;
}

/**
 * Pure: does this basename look like a shared object — a `.so` that terminates a version segment, so `foo.socket`
 * is not one? It decides which broken links are worth reporting: a dangling `libfoo.so.1` says the carve is
 * missing a library, a dangling `/var/run` says the device mounts a tmpfs there.
 */
export function looksLikeSoname(name: string): boolean {
  return /\.so(\.[0-9A-Za-z_]+)*$/.test(name);
}

/** Pure: true iff the bytes start with the ELF magic (0x7F 'E' 'L' 'F'). */
export function isElf(head: Uint8Array): boolean {
  return head.length >= 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46;
}

const base = (p: string): string => p.split('/').pop() ?? p;
const dirOf = (p: string): string => {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
};

/** How many links a chain may traverse before the resolution gives up. A bound, stated as one in `BrokenLink`. */
const MAX_LINK_HOPS = 8;

/**
 * Pure: resolve a link's text to a rootfs-relative path LEXICALLY — string work only, not one filesystem call.
 *
 * This function is the containment argument. An absolute target is rootfs-ABSOLUTE, because chroot semantics are
 * what a rootfs link is written in: inside the carve `/lib/libc.so.6` means the carve's `lib/libc.so.6` and never
 * the host's, so a link that would point at the host's libc simply resolves to a path the carve does not have. A
 * `..` that climbs above the root returns null — the link leaves the image, and a link that leaves the image
 * provides nothing rather than being followed to see.
 */
export function resolveLinkPath(linkDir: string, target: string): string | null {
  const raw = target.startsWith('/') ? target.slice(1) : linkDir === '' ? target : `${linkDir}/${target}`;
  const out: string[] = [];
  for (const part of raw.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (out.length === 0) return null; // climbs above the rootfs root: an escape, not a resolution
      out.pop();
      continue;
    }
    out.push(part);
  }
  return out.join('/');
}

/**
 * Pure: index what the rootfs's own symlinks provide, by NAME, from the link texts alone.
 *
 * For each link, its text is resolved lexically and followed THROUGH THE INDEX (never through the filesystem)
 * until it lands on a walked file — then the link's basename is a provision — or on nothing usable, and then the
 * link is broken and says why. A link onto a walked directory (`lib → usr/lib`, ordinary on any rootfs) is
 * neither: it provides no file and it is not broken, so it is reported as neither.
 *
 * Two links can carry the same basename (`lib/libc.so.0` and `usr/lib/libc.so.0` both exist on plenty of
 * images), so the links are sorted by path and the first wins — the answer must not be an artifact of readdir
 * order (CLAUDE.md rule 4).
 */
export function indexSymlinks(
  files: Iterable<string>,
  dirs: Iterable<string>,
  links: readonly RootfsLink[],
): SymlinkIndex {
  const fileSet = new Set(files);
  const dirSet = new Set(dirs);
  dirSet.add(''); // the rootfs root itself, so a link to `/` is a directory link rather than a dangling one
  const linkText = new Map(links.map((l) => [l.path, l.target]));
  const provides = new Map<string, LinkProvision>();
  const broken: BrokenLink[] = [];

  for (const link of [...links].sort((a, b) => a.path.localeCompare(b.path))) {
    const name = base(link.path);
    const seen = new Set<string>([link.path]);
    let at = resolveLinkPath(dirOf(link.path), link.target);
    let hops = 1;
    for (;;) {
      if (at === null) {
        broken.push({ link: link.path, target: link.target, reason: 'escapes-rootfs' });
        break;
      }
      if (fileSet.has(at)) {
        if (!provides.has(name)) {
          provides.set(name, { name, link: link.path, target: link.target, resolvesTo: at, hops });
        }
        break;
      }
      const next = linkText.get(at);
      if (next !== undefined) {
        if (seen.has(at)) {
          broken.push({ link: link.path, target: link.target, reason: 'cycle' });
          break;
        }
        if (hops >= MAX_LINK_HOPS) {
          broken.push({ link: link.path, target: link.target, reason: 'hop-limit' });
          break;
        }
        seen.add(at);
        at = resolveLinkPath(dirOf(at), next);
        hops += 1;
        continue;
      }
      if (dirSet.has(at)) break; // a directory link: provides no file, and is NOT broken
      broken.push({ link: link.path, target: link.target, reason: 'dangling' });
      break;
    }
  }

  return { provides, broken };
}

/** How many broken links the graph lists before it stops and states what it dropped. */
const BROKEN_LINK_CAP = 200;

/**
 * Pure: assemble the dependency graph from per-binary DT_NEEDED lists, and (given the rootfs's symlink index)
 * resolve sonames by name.
 *
 * Every entry becomes a `binary` node, keyed by basename since a DT_NEEDED soname is a basename. Every referenced
 * soname that is not itself an entry ends one of two ways, and the two are different facts kept apart: a symlink
 * in the rootfs provides the name (`link` node, listed in `linkProvided` with the link and its target, because it
 * is the weaker claim), or nothing does (`lib` node — unresolved). Without a `symlinks` index the function
 * behaves exactly as it always did: no `link` nodes, no link fields at all, absence meaning "never looked".
 */
export function buildGraph(entries: { binary: string; needs: string[] }[], symlinks?: SymlinkIndex): CompGraph {
  const nodeKind = new Map<string, 'binary' | 'lib' | 'link'>();

  // First pass: every present file is a binary node, which is also what "the rootfs has this name" means below.
  for (const e of entries) nodeKind.set(base(e.binary), 'binary');

  const edgeSeen = new Set<string>();
  const edges: { from: string; to: string }[] = [];
  const referenced = new Set<string>();
  const provisions = new Map<string, LinkProvision>();

  for (const e of entries) {
    const from = base(e.binary);
    for (const need of e.needs) {
      const to = base(need);
      referenced.add(to);
      if (!nodeKind.has(to)) {
        // Not a walked file. Either a symlink of that name resolves it — a weaker fact, so it gets its own kind
        // and is named in `linkProvided` — or nothing in the rootfs provides it and the reference is unresolved.
        const provision = symlinks?.provides.get(to);
        if (provision) {
          nodeKind.set(to, 'link');
          provisions.set(to, provision);
        } else {
          nodeKind.set(to, 'lib');
        }
      }
      const key = `${from}\u0000${to}`;
      if (!edgeSeen.has(key)) {
        edgeSeen.add(key);
        edges.push({ from, to });
      }
    }
  }

  const nodes = [...nodeKind].map(([id, kind]) => ({ id, kind }));
  // `unresolved` is DERIVED from the node kinds rather than accumulated beside them, and deliberately so: it used
  // to be a second set filled on the same branch, i.e. one decision stored twice, and the web's fallback
  // (`ComponentMap.unresolvedSonames`) reads the `lib` nodes whenever a stored result predates the field. The two
  // must therefore be the same set — derived here, they cannot drift.
  const unresolved = nodes.filter((n) => n.kind === 'lib').map((n) => n.id);

  const graph: CompGraph = { nodes, edges, unresolved };
  if (!symlinks) return graph;

  graph.linkProvided = [...provisions.values()].sort((a, b) => a.name.localeCompare(b.name));

  // The reporting rule for broken links, stated rather than implied: a rootfs is full of links into `/tmp`,
  // `/proc` and `/dev` that are dangling in every carve and correct on the device, so listing all of them would
  // bury the two that matter. Kept: a link some binary actually needs (it EXPLAINS an unresolved reference), and
  // any other link whose own name is shaped like a shared object (the carve is missing a library).
  const selected = symlinks.broken
    .map((b) => (referenced.has(base(b.link)) ? { ...b, needed: true } : b))
    .filter((b) => b.needed === true || looksLikeSoname(base(b.link)))
    .sort((a, b) => Number(b.needed ?? false) - Number(a.needed ?? false) || a.link.localeCompare(b.link));
  graph.brokenLinks = selected.slice(0, BROKEN_LINK_CAP);
  graph.brokenLinkCount = symlinks.broken.length;
  graph.brokenLinkRule = [
    `Listing ${graph.brokenLinks.length} of ${selected.length} broken symlinks that name a needed soname or a`,
    `shared object, out of ${symlinks.broken.length} broken in total (needed first, then by path — never by`,
    'directory order). The rest point at runtime paths such as /tmp, /proc and /dev, which no carve contains',
    'and which are correct on the device.',
  ].join(' ');
  return graph;
}

/**
 * Pure (honest, optional): the binary nodes that nothing depends on — no incoming "needs" edge. These are the
 * top-level executables / potentially-unused binaries worth a look as attack surface. Not a verdict: a daemon
 * or CLI is legitimately an orphan in a link graph. Can seed an INFO finding.
 *
 * `link` nodes are excluded along with `lib` ones, and that changes nothing: a node of either kind exists only
 * because some binary referenced it, so it always has an incoming edge. Sorted by name so this list and the web's
 * recomputation of it from the persisted graph are the same list, element for element.
 */
export function orphanBinaries(graph: CompGraph): string[] {
  const depended = new Set(graph.edges.map((e) => e.to));
  return graph.nodes
    .filter((n) => n.kind === 'binary' && !depended.has(n.id))
    .map((n) => n.id)
    .sort((a, b) => a.localeCompare(b));
}

/** Probe radare2's rabin2 — a present binary (even a non-zero exit) proves availability; only ENOENT is absent. */
async function detectRabin2(): Promise<boolean> {
  try {
    await execFileAsync('rabin2', ['-v'], { timeout: 8000 });
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== 'ENOENT';
  }
}

const WALK_CAP = 4000;
const LINK_CAP = 8000;
const BINARY_CAP = 300;
const RABIN2_TIMEOUT_MS = 15_000;
const EMPTY_GRAPH: CompGraph = { nodes: [], edges: [], unresolved: [] };

/** Read the first `n` bytes of a file (for the ELF sniff), or null if it can't be opened/read. */
function readHead(abs: string, n: number): Uint8Array | null {
  let fd: number | null = null;
  try {
    fd = fs.openSync(abs, 'r');
    const buf = Buffer.alloc(n);
    const read = fs.readSync(fd, buf, 0, n, 0);
    return buf.subarray(0, read);
  } catch {
    return null;
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

/** Read a link's own text. `readlink(2)` does NOT traverse — it returns the string stored in the link. */
function readLinkText(abs: string): string | null {
  try {
    return fs.readlinkSync(abs);
  } catch {
    return null;
  }
}

/** What one bounded, non-following walk of a rootfs saw. */
export interface RootfsScan {
  /** Regular files, rootfs-relative. Symlinks are not here: a link is a name, not a file. */
  files: string[];
  /** Real directories the walk entered, rootfs-relative (the root itself is implied). */
  dirs: string[];
  /** Every symlink found, with its own text. Read with `readlink`; not one of them was followed. */
  links: RootfsLink[];
  /** True when a cap stopped the walk early — every "absent" and "dangling" is then a claim about what it saw. */
  truncated: boolean;
}

/**
 * Collect the regular files, directories and symlinks under `root` (relative paths), bounded, WITHOUT following
 * any symlink. The refusal is the containment guarantee — a link cycle would not terminate and a link to `/` or
 * `../../..` would walk the host — and recording the link's own text costs nothing and takes nothing back: it is
 * read with `readlink`, which does not traverse, on a path every ancestor of which the walk itself read with
 * `readdir`, so it cannot have been reached through a link either.
 */
export function walkRootfs(root: string, cap: number, linkCap: number = LINK_CAP): RootfsScan {
  const files: string[] = [];
  const dirs: string[] = [];
  const links: RootfsLink[] = [];
  let truncated = false;
  const stack: string[] = ['.'];
  while (stack.length > 0 && files.length < cap) {
    const relDir = stack.pop() as string;
    let ents: fs.Dirent[];
    try {
      ents = fs.readdirSync(path.join(root, relDir), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of ents) {
      if (files.length >= cap) {
        truncated = true;
        break;
      }
      const rel = relDir === '.' ? e.name : `${relDir}/${e.name}`;
      if (e.isSymbolicLink()) {
        // Record what the link SAYS and move on. Descending through it is what we refuse; reading its text is not
        // descending, and it is the only thing that lets a soname resolve to the file it names.
        if (links.length >= linkCap) {
          truncated = true;
          continue;
        }
        const target = readLinkText(path.join(root, rel));
        if (target !== null) links.push({ path: rel, target });
        continue;
      }
      if (e.isDirectory()) {
        dirs.push(rel);
        stack.push(rel);
      } else if (e.isFile()) {
        files.push(rel);
      }
    }
  }
  if (stack.length > 0) truncated = true;
  return { files, dirs, links, truncated };
}

/**
 * Build the component dependency map for an extracted rootfs — offline and honest. rabin2 absent or the rootfs
 * missing → available:false with an empty graph and a clear reason (never a fabricated graph). Otherwise walk
 * the rootfs (bounded, never through a link), sniff each file for the ELF magic, read its DT_NEEDED libs with
 * `rabin2 -l`, resolve each soname by name against the files and link texts the walk collected, and assemble the
 * graph. The one optional finding is an INFO/`static_confirmed` inventory of what was linked.
 */
export async function runComponentMap(rootfsPath: string): Promise<CompMapResult> {
  if (!(await detectRabin2())) {
    return {
      available: false,
      graph: EMPTY_GRAPH,
      binaryCount: 0,
      findings: [],
      reason: 'radare2 (rabin2) not installed — component map needs it.',
    };
  }

  let rootOk = false;
  try {
    rootOk = fs.statSync(rootfsPath).isDirectory();
  } catch {
    rootOk = false;
  }
  if (!rootOk) {
    return {
      available: false,
      graph: EMPTY_GRAPH,
      binaryCount: 0,
      findings: [],
      reason: `Rootfs not found at ${rootfsPath} — run extraction first; the component map needs an extracted rootfs.`,
    };
  }

  const scan = walkRootfs(rootfsPath, WALK_CAP);
  const symlinks = indexSymlinks(scan.files, scan.dirs, scan.links);

  const entries: { binary: string; needs: string[] }[] = [];
  for (const rel of scan.files) {
    if (entries.length >= BINARY_CAP) break;
    const abs = path.join(rootfsPath, rel);
    const head = readHead(abs, 4);
    if (!head || !isElf(head)) continue;
    let needs: string[] = [];
    try {
      const { stdout } = await execFileAsync('rabin2', ['-l', abs], {
        timeout: RABIN2_TIMEOUT_MS,
        maxBuffer: 4 * 1024 * 1024,
      });
      needs = parseNeeded(stdout);
    } catch {
      needs = []; // an unreadable/odd ELF contributes a node but no edges — honest, not a failure
    }
    entries.push({ binary: rel, needs });
  }

  const graph = buildGraph(entries, symlinks);
  // "External library" = a soname referenced by some binary that is not itself one of the walked ELFs, however it
  // resolved. `lib` and `link` together are that set; the count is split so the weaker half never hides.
  const linkProvidedCount = graph.nodes.filter((n) => n.kind === 'link').length;
  const libCount = graph.unresolved.length + linkProvidedCount;
  const binaryNodeCount = graph.nodes.filter((n) => n.kind === 'binary').length;
  const orphans = orphanBinaries(graph);
  const plural = (n: number): string => (n === 1 ? 'library' : 'libraries');
  const viaLink = linkProvidedCount > 0 ? `, ${linkProvidedCount} of them only through a symlink` : '';

  const findings: FindingDraft[] = [];
  if (entries.length > 0) {
    findings.push({
      kind: 'component-map',
      title: `Component map: ${entries.length} ELF binaries, ${libCount} external ${plural(libCount)}${viaLink}, ${graph.unresolved.length} unresolved library reference${graph.unresolved.length === 1 ? '' : 's'}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: {
        binaryCount: entries.length,
        binaryNodeCount,
        libCount,
        linkProvidedCount,
        unresolved: graph.unresolved.slice(0, 200),
        linkProvided: (graph.linkProvided ?? []).slice(0, 200),
        brokenLinks: (graph.brokenLinks ?? []).slice(0, 50),
        brokenLinkCount: graph.brokenLinkCount ?? 0,
        symlinkCount: scan.links.length,
        walkTruncated: scan.truncated,
        orphanBinaries: orphans.slice(0, 200),
      },
      rationale:
        'Mapped each ELF binary to its DT_NEEDED shared libraries with rabin2 — a factual link-dependency graph ' +
        'of the rootfs (proves what is linked in the bytes, not runtime behavior). Not a security verdict. A ' +
        'soname is resolved against the names the rootfs provides, including the ones contributed by symlinks, ' +
        'whose text is read but never followed; a name that resolved only through a link is listed separately, ' +
        'because it proves the rootfs says the name exists and nothing more.',
    });
  }

  const collapsed = entries.length - binaryNodeCount;
  const collapseNote =
    collapsed > 0 ? ` ${collapsed} file${collapsed === 1 ? '' : 's'} share a basename with another and collapse.` : '';
  const truncationNote = scan.truncated
    ? ` The walk stopped at its bound, so "unresolved" and "dangling" describe the ${scan.files.length} files it saw.`
    : '';
  // Measured on the GL.iNet carve (6,496 files, walked 4,000): a link to `/usr/lib/gl/libexfat.so` was reported
  // dangling while the target is right there, past the bound. The rule the web renders has to say so itself —
  // the caveat living only in `reason`, beside a different number, is how a bound gets read as an answer.
  if (scan.truncated && graph.brokenLinkRule !== undefined) {
    graph.brokenLinkRule = [
      graph.brokenLinkRule,
      `The walk stopped at its bound after ${scan.files.length} files, so a target reported missing here may be`,
      'one it never reached.',
    ].join(' ');
  }

  return {
    available: true,
    graph,
    binaryCount: entries.length,
    binaryNodeCount,
    orphanBinaries: orphans,
    symlinkCount: scan.links.length,
    walkTruncated: scan.truncated,
    findings,
    reason:
      `Mapped ${entries.length} ELF binar${entries.length === 1 ? 'y' : 'ies'} to their shared-library ` +
      `dependencies (${libCount} external ${plural(libCount)}${viaLink}, ${graph.unresolved.length} ` +
      `unresolved).${collapseNote}${truncationNote}`,
  };
}
