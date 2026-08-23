import { describe, expect, it } from 'vitest';
import { SECTION_IDS } from './image-sections';
import { SECTION_GROUPS, groupedSections, needsRootfs, reachableBefore, sectionReadiness } from './section-index.js';

describe('sectionReadiness — an unrun extraction is not an extraction that found nothing', () => {
  /**
   * The pair. Both leave a rootfs-reading section with nothing to show, and only one is a fact about the image —
   * a single "nothing here" would send the operator to run an extraction that already ran.
   */
  it('separates extraction-not-run from extraction-found-no-rootfs', () => {
    const notRun = sectionReadiness('files', { ran: false, rootfs: false });
    const noRootfs = sectionReadiness('files', { ran: true, rootfs: false });
    expect(notRun).toEqual({ kind: 'extraction-not-run' });
    expect(noRootfs).toEqual({ kind: 'extraction-found-no-rootfs' });
    expect(notRun.kind).not.toBe(noRootfs.kind);
  });

  it('reports a rootfs-reading section as ready once extraction produced one', () => {
    expect(sectionReadiness('files', { ran: true, rootfs: true })).toEqual({ kind: 'ready' });
  });

  it('ignores the rootfs flag entirely when extraction has not run', () => {
    // `rootfs: true` with `ran: false` is a state the page cannot produce; it must not read as ready anyway.
    expect(sectionReadiness('secrets', { ran: false, rootfs: true })).toEqual({ kind: 'extraction-not-run' });
  });

  it('leaves a section that does not read the rootfs always ready, whatever extraction did', () => {
    for (const facts of [
      { ran: false, rootfs: false },
      { ran: true, rootfs: false },
      { ran: true, rootfs: true },
    ]) {
      expect(sectionReadiness('entropy', facts).kind).toBe('ready');
      expect(sectionReadiness('deepscans', facts).kind).toBe('ready');
      expect(sectionReadiness('findings', facts).kind).toBe('ready');
    }
  });

  it('knows which sections read the rootfs, and does not claim it for the ones that do not', () => {
    for (const s of ['filesystem', 'files', 'secrets', 'compmap', 'binaries', 'testbench', 'opacidad']) {
      expect(needsRootfs(s)).toBe(true);
    }
    for (const s of ['dossier', 'entropy', 'structure', 'hardware', 'bootloader', 'sbom', 'findings', 'diff']) {
      expect(needsRootfs(s)).toBe(false);
    }
  });

  it('treats an unknown section id as not needing a rootfs, rather than guessing it does', () => {
    // Locking a section this module does not know about would turn a new panel into an unreachable one — the very
    // defect being fixed, arriving through a default.
    expect(needsRootfs('a-section-added-later')).toBe(false);
    expect(sectionReadiness('a-section-added-later', { ran: false, rootfs: false }).kind).toBe('ready');
  });
});

describe('reachableBefore — which sections were URL-only, compared rather than re-derived', () => {
  const timeline = ['overview', 'entropy', 'filesystem', 'bootloader', 'sbom', 'binaries', 'simulate', 'findings'];
  const links = ['operator', 'dossier'];

  it('counts a timeline step and an explicit link as reachable', () => {
    expect(reachableBefore('sbom', timeline, links)).toBe(true);
    expect(reachableBefore('operator', timeline, links)).toBe(true);
  });

  it('reports the ten that were reachable only by typing a URL', () => {
    const all = [
      'dossier',
      'overview',
      'structure',
      'entropy',
      'filesystem',
      'files',
      'secrets',
      'hardware',
      'bootloader',
      'sbom',
      'compmap',
      'deepscans',
      'binaries',
      'testbench',
      'findings',
      'operator',
      'diff',
      'simulate',
      'opacidad',
      'agent',
    ];
    const orphans = all.filter((s) => !reachableBefore(s, timeline, links));
    // The backlog entry said four. Measured on the real app, it is ten — `secrets` and `testbench` were not even
    // in the count.
    expect(orphans).toEqual([
      'structure',
      'files',
      'secrets',
      'hardware',
      'compmap',
      'deepscans',
      'testbench',
      'diff',
      'opacidad',
      'agent',
    ]);
  });

  it('takes the lists as parameters, so a third copy of them cannot drift', () => {
    // Passing an empty timeline makes everything an orphan — proving nothing is hardcoded here.
    expect(reachableBefore('sbom', [], [])).toBe(false);
  });
});

describe('SECTION_GROUPS — the one ordering the sidebar and the index share', () => {
  it('claims every section the app serves, so none can vanish from the navigation', () => {
    // The defect this guards: a section added to SECTION_IDS and forgotten here would disappear from the sidebar
    // silently — which is the exact defect the grouping exists to fix, re-introduced by the fix for it.
    const { ungrouped } = groupedSections(SECTION_IDS);
    expect(ungrouped).toEqual([]);
  });

  it('names no section the app does not serve', () => {
    const served = new Set<string>(SECTION_IDS);
    for (const g of SECTION_GROUPS) {
      for (const s of g.sections) expect(served.has(s), `${g.id} names ${s}`).toBe(true);
    }
  });

  it('reports an unknown section instead of dropping it', () => {
    const { groups, ungrouped } = groupedSections([...SECTION_IDS, 'brand-new-panel']);
    expect(ungrouped).toEqual(['brand-new-panel']);
    expect(groups.flatMap((g) => g.sections)).not.toContain('brand-new-panel');
  });

  it('drops the two aliases rather than offering two links to one page', () => {
    // `overview` is remapped onto `dossier` by resolveSection; `binaries` is the legacy alias for `testbench`.
    const all = groupedSections(SECTION_IDS);
    const listed = all.groups.flatMap((g) => g.sections);
    expect(listed).not.toContain('overview');
    expect(listed).not.toContain('binaries');
    expect(listed).toContain('dossier');
    expect(listed).toContain('testbench');
    expect(all.ungrouped).toEqual([]);
  });

  it('omits a group entirely when the screen serves none of its sections', () => {
    const { groups } = groupedSections(['dossier', 'entropy']);
    expect(groups.map((g) => g.id)).toEqual(['identity']);
  });

  it('keeps each group in its declared order, not the caller order', () => {
    const { groups } = groupedSections(['entropy', 'dossier', 'structure']);
    expect(groups[0]?.sections).toEqual(['dossier', 'structure', 'entropy']);
  });

  it('lists every section exactly once across all groups', () => {
    const listed = SECTION_GROUPS.flatMap((g) => g.sections);
    expect(listed.length).toBe(new Set(listed).size);
  });
});
