/**
 * sectionGroups — the headings over the analysis sections in the sidebar. English source of truth.
 *
 * The keys are the group ids in `section-index.ts`. Each heading answers a question about the image rather than
 * naming a technology, because the reader arriving at this nav does not yet know which tool answers what: they
 * know what they want to find out.
 */
export const sectionGroups = {
  identity: 'What it is',
  content: 'What came out of it',
  components: 'What it is made of',
  deep: 'Deep scans',
  dynamic: 'What it does when it runs',
  verdict: 'The verdict',
};
