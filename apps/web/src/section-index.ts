/**
 * Every analysis section, and whether you can get to it.
 *
 * Measured 2026-07-30: the app has exactly THREE places that navigate to a section — the step timeline (8 steps),
 * one link to `operator`, one to `dossier` — against 20 sections in `SECTION_IDS`. So **ten are reachable only by
 * typing a URL**: `structure`, `files`, `secrets`, `hardware`, `compmap`, `deepscans`, `testbench`, `diff`,
 * `opacidad`, `agent`. The backlog entry said four. It also said the costliest is `files`, whose own comment calls it
 * *"the surface that lets a finding's evidence be checked instead of trusted"* — and `secrets` and `testbench` were
 * missing from the count entirely.
 *
 * And the shell tells the reader to navigate from the timeline. A hint that points at a control which cannot reach
 * half the surface is worse than no hint: it answers the question, wrongly.
 *
 * **What this module refuses to do.** It does not decide which sections a DEVICE CLASS routes to. That mapping
 * already exists once, in `opacidad-plan.ts`'s `specsForClass`, and a second copy in the web would be two lists of
 * the same thing one commit from disagreeing — the trap this codebase names about its own `SECTION_TITLES`. So every
 * section is listed and reachable for every image, always, and nothing is hidden on a guess about relevance.
 *
 * What it DOES decide is why a section may be empty when you get there, from the two facts the page already holds:
 * whether extraction ran, and whether it produced a rootfs. Those are different, and the difference is the one this
 * whole codebase keeps insisting on — a stage nobody ran versus a stage that ran and found nothing.
 *
 * Pure and dependency-free.
 */

/** The sections that read files out of an extracted rootfs, and can say nothing without one. */
const NEEDS_ROOTFS = new Set([
  'filesystem',
  'files',
  'secrets',
  'compmap',
  'binaries',
  'testbench',
  'opacidad',
] as const);

/** What extraction has done for this image, as the two booleans the page already knows. */
export interface ExtractionFacts {
  /** Has an extraction job completed at all? */
  ran: boolean;
  /** Did it produce a rootfs? Meaningless unless `ran`. */
  rootfs: boolean;
}

export type SectionReadiness =
  | { kind: 'ready' }
  | { kind: 'extraction-not-run' }
  | { kind: 'extraction-found-no-rootfs' };

/**
 * Pure: what a reader will find when they get to this section.
 *
 * `extraction-not-run` and `extraction-found-no-rootfs` are separate for the reason they always are: the first is a
 * statement about this workbench, the second a measured property of the image. A single "nothing here" would let the
 * second be read as the first — the operator would go run an extraction that already ran.
 *
 * A section that does not read the rootfs is always `ready`: reachability is the defect being fixed, and gating a
 * section on state it does not depend on would replace an unreachable panel with an unreasonably locked one.
 */
export function sectionReadiness(section: string, extraction: ExtractionFacts): SectionReadiness {
  if (!NEEDS_ROOTFS.has(section as never)) return { kind: 'ready' };
  if (!extraction.ran) return { kind: 'extraction-not-run' };
  return extraction.rootfs ? { kind: 'ready' } : { kind: 'extraction-found-no-rootfs' };
}

/** True when this section depends on an extracted rootfs at all — so the index can group by it honestly. */
export function needsRootfs(section: string): boolean {
  return NEEDS_ROOTFS.has(section as never);
}

/**
 * The sections the step timeline navigates to, as a fact rather than a guess.
 *
 * Kept here so the index can mark which sections were previously URL-only WITHOUT re-deriving the timeline's list:
 * it is imported from the timeline itself by the caller and passed in, and this function only compares. Passing the
 * list in is the point — a hardcoded copy here would be the third list of the same thing.
 */
export function reachableBefore(
  section: string,
  timelineSteps: readonly string[],
  explicitLinks: readonly string[],
): boolean {
  return timelineSteps.includes(section) || explicitLinks.includes(section);
}

/**
 * The analysis sections, grouped — the one ordering the sidebar and the in-page index both read.
 *
 * **Why this exists.** Reachability was fixed once (`8457011`) by listing every section on one page; it did not fix
 * findability. The shell's own navigation still offers five destinations and none of them is a section, so a reader
 * who wants the SBOM graph or the component map — both of which have existed and rendered for months — has to know
 * they exist, remember which page indexes them, and go there first. Measured against the deployed build: nineteen
 * sections, **zero** in the sidebar, eight in the step timeline. That single fact is what makes "I ran the scan and
 * I cannot find the results" the honest description of this app rather than a complaint about any one panel.
 *
 * **Why the grouping lives here and not in the sidebar.** Two orderings of the same nineteen ids would be two lists
 * of the same thing one commit from disagreeing — the trap this file already names about `SECTION_TITLES`. The
 * sidebar and `SectionIndex` render this; neither owns it.
 *
 * **What it deliberately does NOT do.** It does not decide which sections a device class routes to. That lives once,
 * in the API's `specsForClass`. Every section is grouped for every image, and a section that has nothing to show
 * says why when you get there — `sectionReadiness` — rather than being hidden on a guess.
 */
export interface SectionGroup {
  /** Catalogue key for the group's heading. */
  id: string;
  /** Section route segments, in the order a reader should meet them. */
  sections: readonly string[];
}

export const SECTION_GROUPS: readonly SectionGroup[] = [
  // What the image IS, before anything is unpacked from it.
  { id: 'identity', sections: ['dossier', 'structure', 'entropy', 'hardware', 'bootloader'] },
  // What came OUT of it.
  { id: 'content', sections: ['filesystem', 'files', 'secrets'] },
  // What it is MADE of, and how those parts depend on each other.
  { id: 'components', sections: ['sbom', 'compmap'] },
  // The tool-backed passes over those parts.
  { id: 'deep', sections: ['deepscans', 'binvuln', 'kernel', 'kmod', 'testbench'] },
  // What it DOES when something runs it.
  { id: 'dynamic', sections: ['simulate', 'egress', 'opacidad', 'agent'] },
  // What all of it adds up to, and what a person says about that.
  { id: 'verdict', sections: ['findings', 'operator', 'diff'] },
];

/** A grouping of the sections a screen actually serves, plus the ones no group claimed. */
export interface GroupedSections {
  groups: { id: string; sections: string[] }[];
  /**
   * Sections this screen serves that no group names.
   *
   * Returned rather than dropped, and rendered rather than ignored. A section added to `SECTION_IDS` and forgotten
   * here would otherwise vanish from the navigation silently — which is the exact defect this grouping exists to
   * fix, re-introduced by the fix for it. A test asserts the list is empty for the real catalogue; the UI still
   * shows whatever turns up, because the test only holds while someone runs it.
   */
  ungrouped: string[];
}

/**
 * Pure: partition the sections a screen serves into the groups, preserving each group's declared order.
 *
 * `overview` is dropped — it is a dead id that `resolveSection` remaps onto `dossier`, and offering both would be
 * two links to one page. `binaries` is dropped for the same reason: it is the legacy alias that still routes to
 * `testbench`, and a nav listing both would imply two surfaces where there is one. Neither is "ungrouped"; they are
 * aliases, and an alias is not a missing section.
 */
const ALIASES: ReadonlySet<string> = new Set(['overview', 'binaries']);

export function groupedSections(sections: readonly string[]): GroupedSections {
  const serves = new Set(sections.filter((s) => !ALIASES.has(s)));
  const claimed = new Set<string>();
  const groups = SECTION_GROUPS.map((g) => {
    const present = g.sections.filter((s) => serves.has(s));
    for (const s of present) claimed.add(s);
    return { id: g.id, sections: present };
  }).filter((g) => g.sections.length > 0);
  return { groups, ungrouped: [...serves].filter((s) => !claimed.has(s)) };
}
