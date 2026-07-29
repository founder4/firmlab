/**
 * Component dependency-map provider. For the ELF binaries in an extracted rootfs, maps each binary to its
 * DT_NEEDED shared libraries (read with `rabin2 -l`) and assembles a dependency graph: nodes are the binaries
 * plus every referenced shared object, edges are "needs" (binary → lib). This is offline structural analysis of
 * the linked bytes — the primary output is the graph itself, never a security verdict. The single optional
 * finding is an honest INFO/`static_confirmed` inventory (N binaries, M libraries, K unresolved references).
 *
 * radare2 is an opt-in layer (like Ghidra/AFL++): with `rabin2` absent the runner degrades HONESTLY to
 * available:false and an empty graph — it never fabricates dependencies. The parse (`parseNeeded`), the ELF
 * sniff (`isElf`), the symlink index (`indexSymlinks`), the file-name index (`indexFileNames`), the ELF-scan
 * ranking (`selectElfScan`), the graph assembly (`buildGraph`) and the orphan detector are PURE and unit-tested;
 * the runner only walks the rootfs, probes the tool, and composes them.
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
 * resolve in the first place.
 *
 * ## Two bounds, split by what they cost — and the fourth outcome that split creates
 *
 * Indexing NAMES costs a `readdir` and, for a link, a `readlink`. That is bounded by the tree itself and by
 * nothing else, so the walk covers every file and every symlink in the carve: there is no defensible reason for a
 * directory listing to stop at 4,000 entries, and one very good reason not to. Measured on the GL.iNet carve, with
 * the old bounds: the walk reached 4,000 of 6,496 files and the ELF pass stopped at 300, so a real 590 KB
 * `lib/libc.so` that 298 binaries link against was never seen, and 65 of that image's 65 unresolved sonames were
 * artifacts of the two caps rather than facts about the rootfs. The uncapped walk still terminates for the same
 * reason it is contained — it never follows a symlink, so what it traverses is a finite tree and not a graph.
 *
 * What stays bounded is the EXPENSIVE pass. Sniffing four bytes for the ELF magic costs about what the `readdir`
 * that found the file did, so every walked file is sniffed; spawning `rabin2` per ELF does not, so only
 * `ELF_SCAN_CAP` of them have their DT_NEEDED read. That cap RANKS rather than taking arrival order
 * (`selectElfScan`, CLAUDE.md rule 4): programs under `bin`/`sbin`/`libexec`, then the libraries a symlink names,
 * then any other program, then the remaining shared objects, with `.ko` kernel modules last because a relocatable
 * module carries no DT_NEEDED at all — 375 of the GL.iNet's 1,171 ELF files are modules, and an arrival-order
 * budget was being spent reading nothing out of them. Ties break by path, never by directory order, and the rule
 * travels with the result (`elfScanRule`) instead of living in a comment.
 *
 * Resolving a soname against the whole tree while opening only part of it produces a FOURTH outcome, and it is
 * kept apart from the other three because it is a different fact: `file` — the carve contains a file of that name,
 * the ELF pass never opened it, so the reference resolves but nothing here read what IT links against. That is
 * what the ELF cap now costs: edges out of the unopened files, never a soname wrongly called absent.
 *
 * Measured in-container after the split, against the same three carves: the GL.iNet goes from 65 unresolved to 0
 * (107 of its sonames resolve as `file`, 82 through a link) and from 13 broken links to 5, since a link's target is
 * now looked for in the whole tree too; the IMOU stays at 0; the Tenda stays at 1 — `libcrypto.so.1.0.0`, against a
 * carve that ships `libcrypto.so.1.1`, which is the answer being right rather than the bound being wide.
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
 * A name a WALKED FILE provides that the ELF pass never opened — the fourth outcome, and deliberately not folded
 * into the `binary` one. `binary` means this module read the file's DT_NEEDED; this means only that the carve
 * contains a file of that name. Both are stronger than a link (the file is literally there), and neither is a
 * claim that the file is the library the soname meant.
 */
export interface FileProvision {
  /** The basename the file contributes — for a soname, the name the DT_NEEDED entry asks for. */
  name: string;
  /** The rootfs-relative walked file of that basename; the lowest path when several carry it, never readdir order. */
  path: string;
  /** How many walked files carry this basename (>1 means the carve has several and `path` is the lowest). */
  count: number;
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
   * The FOUR ways a reference can end, one node kind each, and the codebase refuses to collapse them because they
   * are four different facts, in descending strength: `binary` = a file of that name was walked AND its DT_NEEDED
   * read by this run; `file` = the carve contains a file of that name but the ELF pass never opened it (so the
   * name resolves and its own dependencies are unknown); `link` = only a symlink says the name exists; `lib` =
   * nothing in the carve provides it — unresolved.
   *
   * `file` is newer than the other three. A graph stored before it existed has no `file` nodes at all, which means
   * "that build resolved against the ELF entries only", not "the carve had none".
   */
  nodes: { id: string; kind: 'binary' | 'lib' | 'link' | 'file' }[];
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
  /**
   * Sonames a walked file provides that the ELF pass never opened — the `file` nodes, each naming the file. What
   * the ELF cap costs is listed here rather than inferred: these names resolve, and no edge leaves them. Optional
   * forever, and absent means the run resolved against the ELF entries alone.
   */
  fileProvided?: FileProvision[];
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
  /** ELF files whose DT_NEEDED was actually read — the expensive pass, and what `elfScanRule` bounds. */
  binaryCount: number;
  /** Regular files the walk indexed by name, i.e. the whole carve. Optional forever. */
  fileCount?: number;
  /** ELF files the sniff found in the whole tree — the denominator `binaryCount` is out of. Optional forever. */
  elfCount?: number;
  /**
   * The sentence stating which ELFs had their DT_NEEDED read, by what ranking, and what the ones left out still
   * contribute (their names, not their edges). Rendered always, not only on a cut. Optional forever.
   */
  elfScanRule?: string;
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

/**
 * Pure: index the walked files by BASENAME — the cheap half of the answer, and the reason a soname no longer
 * depends on whether the expensive pass happened to reach the file.
 *
 * A DT_NEEDED entry is a basename, so this is the same key the graph uses. Several files can carry one basename
 * (`lib/libc.so` and `usr/lib/libc.so`), so the lowest path wins and `count` says how many there were: the answer
 * must not be an artifact of readdir order (CLAUDE.md rule 4), and the reader is told when the choice was made.
 */
export function indexFileNames(files: Iterable<string>): Map<string, FileProvision> {
  const byName = new Map<string, FileProvision>();
  for (const rel of files) {
    const name = base(rel);
    const seen = byName.get(name);
    if (seen === undefined) {
      byName.set(name, { name, path: rel, count: 1 });
      continue;
    }
    seen.count += 1;
    if (rel.localeCompare(seen.path) < 0) seen.path = rel;
  }
  return byName;
}

/** How many broken links the graph lists before it stops and states what it dropped. */
const BROKEN_LINK_CAP = 200;

/**
 * Pure: assemble the dependency graph from per-binary DT_NEEDED lists, and (given the rootfs's symlink index)
 * resolve sonames by name.
 *
 * Every entry becomes a `binary` node, keyed by basename since a DT_NEEDED soname is a basename. Every referenced
 * soname that is not itself an entry ends one of three ways, and the three are different facts kept apart, in
 * descending strength: a walked FILE of that name exists but the ELF pass never opened it (`file` node, listed in
 * `fileProvided`), or a symlink provides the name (`link` node, listed in `linkProvided` with the link and its
 * target, because the target was never opened either), or nothing does (`lib` node — unresolved).
 *
 * Both indexes are optional and independently so, and absence means "this run never looked" rather than "found
 * none": with neither, the function behaves exactly as it always did — no `link` or `file` nodes and no such
 * fields at all, a soname resolving only against the entries themselves.
 */
export function buildGraph(
  entries: { binary: string; needs: string[] }[],
  symlinks?: SymlinkIndex,
  fileNames?: ReadonlyMap<string, FileProvision>,
): CompGraph {
  const nodeKind = new Map<string, 'binary' | 'lib' | 'link' | 'file'>();

  // First pass: every entry is a binary node — a file this run both walked AND read the DT_NEEDED of.
  for (const e of entries) nodeKind.set(base(e.binary), 'binary');

  const edgeSeen = new Set<string>();
  const edges: { from: string; to: string }[] = [];
  const referenced = new Set<string>();
  const provisions = new Map<string, LinkProvision>();
  const fileProvisions = new Map<string, FileProvision>();

  for (const e of entries) {
    const from = base(e.binary);
    for (const need of e.needs) {
      const to = base(need);
      referenced.add(to);
      if (!nodeKind.has(to)) {
        // Not an entry. A walked file of that name is the strongest remaining answer (it is literally in the
        // carve; only its own dependencies are unknown), then a symlink saying the name exists, then nothing.
        const fileProvision = fileNames?.get(to);
        const provision = symlinks?.provides.get(to);
        if (fileProvision) {
          nodeKind.set(to, 'file');
          fileProvisions.set(to, fileProvision);
        } else if (provision) {
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
  // The two indexes are independent: a run may have walked the whole tree without reading a single link text, and
  // each field is present exactly when the run looked, so an absent one never reads as an empty answer.
  if (fileNames) graph.fileProvided = [...fileProvisions.values()].sort((a, b) => a.name.localeCompare(b.name));
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
 * `link`, `file` and `lib` nodes are all excluded, and that changes nothing: a node of any of those kinds exists
 * only because some binary referenced it, so it always has an incoming edge. Sorted by name so this list and the
 * web's recomputation of it from the persisted graph are the same list, element for element.
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

/**
 * How many ELFs have their DT_NEEDED read with `rabin2`. The one bound left, because it is the one that costs: a
 * process spawn per file against a four-byte read per file for the sniff and a `readdir` per directory for the
 * walk. It is applied by `selectElfScan`, which ranks — the ELFs it leaves out are still indexed by NAME, so what
 * the cap drops is their outgoing edges and never the resolution of a soname they provide.
 */
const ELF_SCAN_CAP = 300;
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

/** What one non-following walk of a rootfs saw. */
export interface RootfsScan {
  /** Regular files, rootfs-relative. Symlinks are not here: a link is a name, not a file. */
  files: string[];
  /** Real directories the walk entered, rootfs-relative (the root itself is implied). */
  dirs: string[];
  /** Every symlink found, with its own text. Read with `readlink`; not one of them was followed. */
  links: RootfsLink[];
  /**
   * True when a caller's cap stopped the walk early — every "absent" and "dangling" is then a claim about what it
   * saw. The provider passes no cap, so on its own results this is false; the parameters remain for a caller that
   * wants a bound, and the flag remains so the claim stays honest if one ever does.
   */
  truncated: boolean;
}

/**
 * Collect the regular files, directories and symlinks under `root` (relative paths), WITHOUT following any
 * symlink. The refusal is the containment guarantee — a link cycle would not terminate and a link to `/` or
 * `../../..` would walk the host — and recording the link's own text costs nothing and takes nothing back: it is
 * read with `readlink`, which does not traverse, on a path every ancestor of which the walk itself read with
 * `readdir`, so it cannot have been reached through a link either.
 *
 * Uncapped by default, and that is safe for the same reason it is contained: refusing to descend through a link
 * makes this a walk of a finite TREE rather than of a graph, so it terminates on its own. It is also why it can be
 * uncapped honestly — a `readdir` per directory and a `readlink` per link is the cheapest question this module
 * asks, and capping it made the expensive pass's cut decide which libraries EXIST (CLAUDE.md rule 4). The `cap`
 * and `linkCap` parameters stay for callers that want a bound and for the tests that exercise one.
 */
export function walkRootfs(
  root: string,
  cap: number = Number.POSITIVE_INFINITY,
  linkCap: number = Number.POSITIVE_INFINITY,
): RootfsScan {
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

/** Directory names whose contents are programs, wherever in the tree they sit: `bin`, `usr/sbin`, `opt/x/libexec`. */
const PROGRAM_DIRS = new Set(['bin', 'sbin', 'libexec']);

/** Pure: is this basename a relocatable kernel module? Such an ELF has no dynamic section, so no DT_NEEDED at all. */
function isKernelModule(name: string): boolean {
  return /\.ko(\.[0-9A-Za-z_]+)*$/.test(name);
}

/** Pure: does some ancestor directory of this path hold programs? */
function inProgramDir(rel: string): boolean {
  const parts = rel.split('/');
  parts.pop();
  return parts.some((p) => PROGRAM_DIRS.has(p));
}

/** What the expensive pass will open, how many it left, and the rule that decided — carried, not implied. */
export interface ElfScanSelection {
  /** The ELFs whose DT_NEEDED will be read, in the order the ranking put them. */
  scan: string[];
  /** ELFs the cap left unopened. They are still indexed by name; what is lost is the edges OUT of them. */
  dropped: number;
  /** ELFs the sniff found in the whole tree — the denominator. */
  total: number;
  /** The sentence stating both, and by what rule. Rendered always, not only on a cut. */
  rule: string;
}

/**
 * Pure: choose which ELFs get a `rabin2` spawn, by RANK and never by arrival (CLAUDE.md rule 4).
 *
 * Taking the first N off the walk made the set an artifact of directory layout — and on the GL.iNet carve it was
 * worse than that: 375 of its 1,171 ELF files are `lib/modules/**.ko`, and a relocatable kernel module carries no
 * DT_NEEDED entry at all, so an arrival-order budget was being spent reading nothing out of files that cannot
 * answer. They rank last for exactly that reason.
 *
 * Above them the order follows what an unopened file COSTS, now that names resolve without opening anything. An
 * unopened library still resolves — it becomes a `file` node — so all that is lost is the libraries it itself
 * links. An unopened PROGRAM is lost entirely: nothing references it by soname, so it is not in the graph at all,
 * and it is missing from the orphan list the panel calls its top-level executables. Programs therefore come first
 * (those under `bin`/`sbin`/`libexec`, then any other ELF not shaped like a shared object — a CGI, an `/opt`
 * daemon), with the libraries a symlink names between them, because a soname target is what the DT_NEEDED entries
 * actually point at and opening it is what chains the graph past its first hop. Ties break by path, so two runs
 * over the same carve select the same set.
 */
export function selectElfScan(
  elfFiles: readonly string[],
  linkTargets: ReadonlySet<string>,
  cap: number,
): ElfScanSelection {
  const rank = (rel: string): number => {
    const name = base(rel);
    if (isKernelModule(name)) return 4;
    if (inProgramDir(rel)) return 0;
    if (linkTargets.has(rel)) return 1;
    if (!looksLikeSoname(name)) return 2;
    return 3;
  };
  const ranked = [...elfFiles].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  const scan = ranked.slice(0, Math.max(0, cap));
  const dropped = ranked.length - scan.length;
  const rule = [
    `Read DT_NEEDED from ${scan.length} of ${ranked.length} ELF file${ranked.length === 1 ? '' : 's'}, ranked:`,
    'programs under bin/sbin/libexec, then the libraries a symlink names, then any other program, then the',
    'remaining shared objects, with .ko kernel modules last (a relocatable module carries no DT_NEEDED at all) —',
    'ties by path, never by directory order.',
    dropped > 0
      ? [
          `The ${dropped} left unopened are still indexed by NAME, so a soname one of them provides still resolves`,
          '(as a file this run did not open) instead of reading as unresolved; what is missing is the libraries',
          'THEY link.',
        ].join(' ')
      : '',
  ]
    .filter((s) => s !== '')
    .join(' ');
  return { scan, dropped, total: ranked.length, rule };
}

/**
 * Build the component dependency map for an extracted rootfs — offline and honest. rabin2 absent or the rootfs
 * missing → available:false with an empty graph and a clear reason (never a fabricated graph). Otherwise walk the
 * WHOLE rootfs (never through a link), index every file and link text by name, sniff every file for the ELF magic,
 * read the DT_NEEDED libs of the ranked top `ELF_SCAN_CAP` of them with `rabin2 -l`, resolve each soname by name
 * against everything the walk collected, and assemble the graph. The one optional finding is an
 * INFO/`static_confirmed` inventory of what was linked.
 *
 * The two passes are bounded differently on purpose, and that is the whole shape of this function: naming is cheap
 * and covers everything, opening is expensive and is ranked and capped.
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

  // Pass 1 — names, over the WHOLE tree. `readdir` and `readlink` only, and nothing is opened.
  const scan = walkRootfs(rootfsPath);
  const symlinks = indexSymlinks(scan.files, scan.dirs, scan.links);
  const fileNames = indexFileNames(scan.files);

  // Pass 2 — the sniff: four bytes per walked file, which is about what the readdir that found it cost. Every file,
  // because this count is the denominator the expensive pass's bound is stated against, and a bound whose
  // denominator is itself bounded states nothing.
  const elfFiles: string[] = [];
  for (const rel of scan.files) {
    const head = readHead(path.join(rootfsPath, rel), 4);
    if (head && isElf(head)) elfFiles.push(rel);
  }

  // Pass 3 — the expensive one: a `rabin2` spawn per ELF, so this is the pass that is capped, and it ranks.
  // `provides` values are the files the rootfs names by soname, i.e. exactly what a DT_NEEDED entry resolves to.
  const linkTargets = new Set([...symlinks.provides.values()].map((p) => p.resolvesTo));
  const selection = selectElfScan(elfFiles, linkTargets, ELF_SCAN_CAP);

  const entries: { binary: string; needs: string[] }[] = [];
  for (const rel of selection.scan) {
    const abs = path.join(rootfsPath, rel);
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

  const graph = buildGraph(entries, symlinks, fileNames);
  // "External library" = a soname referenced by some binary that is not itself one of the ELFs this run read,
  // however it resolved. `file`, `link` and `lib` together are that set; the count is split three ways so neither
  // weaker half hides inside the total.
  const linkProvidedCount = graph.nodes.filter((n) => n.kind === 'link').length;
  const fileProvidedCount = graph.nodes.filter((n) => n.kind === 'file').length;
  const libCount = graph.unresolved.length + linkProvidedCount + fileProvidedCount;
  const binaryNodeCount = graph.nodes.filter((n) => n.kind === 'binary').length;
  const orphans = orphanBinaries(graph);
  const plural = (n: number): string => (n === 1 ? 'library' : 'libraries');
  const via = [
    linkProvidedCount > 0 ? `${linkProvidedCount} of them only through a symlink` : '',
    fileProvidedCount > 0 ? `${fileProvidedCount} through a file this run did not open` : '',
  ].filter((s) => s !== '');
  const viaLink = via.length > 0 ? `, ${via.join(' and ')}` : '';

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
        fileProvidedCount,
        fileCount: scan.files.length,
        elfCount: elfFiles.length,
        elfScanRule: selection.rule,
        unresolved: graph.unresolved.slice(0, 200),
        linkProvided: (graph.linkProvided ?? []).slice(0, 200),
        fileProvided: (graph.fileProvided ?? []).slice(0, 200),
        brokenLinks: (graph.brokenLinks ?? []).slice(0, 50),
        brokenLinkCount: graph.brokenLinkCount ?? 0,
        symlinkCount: scan.links.length,
        walkTruncated: scan.truncated,
        orphanBinaries: orphans.slice(0, 200),
      },
      rationale:
        'Mapped each ELF binary to its DT_NEEDED shared libraries with rabin2 — a factual link-dependency graph ' +
        'of the rootfs (proves what is linked in the bytes, not runtime behavior). Not a security verdict. A ' +
        'soname is resolved against every name the walk collected from the whole tree — the files themselves and ' +
        'the ones symlinks contribute, whose text is read but never followed. The three weaker outcomes stay ' +
        'labelled: a name provided by a file this run did not open (it is in the carve; its own dependencies are ' +
        'not known here), a name provided only by a link (the rootfs says it exists, and nothing more), and a ' +
        'name nothing provides.',
    });
  }

  const collapsed = entries.length - binaryNodeCount;
  const collapseNote =
    collapsed > 0 ? ` ${collapsed} file${collapsed === 1 ? '' : 's'} share a basename with another and collapse.` : '';
  // The branch that runs is the first one, and it is the news: naming covers the whole carve, so "unresolved" is no
  // longer a statement about where the walk stopped. The second exists because `walkRootfs` still takes a bound and
  // a caller may one day pass one — a claim about part of a tree must never be printed as a claim about the tree.
  const indexNote = scan.truncated
    ? [
        `Name indexing stopped at a bound after ${scan.files.length} files, so "unresolved" and "dangling"`,
        'describe what it saw and not what the carve holds.',
      ].join(' ')
    : [
        `Indexed all ${scan.files.length} files and ${scan.links.length} symlinks in the carve by name, so a`,
        "soname — and a link's target — is resolved against the whole tree.",
      ].join(' ');

  return {
    available: true,
    graph,
    binaryCount: entries.length,
    binaryNodeCount,
    fileCount: scan.files.length,
    elfCount: elfFiles.length,
    elfScanRule: selection.rule,
    orphanBinaries: orphans,
    symlinkCount: scan.links.length,
    walkTruncated: scan.truncated,
    findings,
    reason:
      `Mapped ${entries.length} ELF binar${entries.length === 1 ? 'y' : 'ies'} to their shared-library ` +
      `dependencies (${libCount} external ${plural(libCount)}${viaLink}, ${graph.unresolved.length} ` +
      `unresolved).${collapseNote} ${indexNote} ${selection.rule}`,
  };
}
