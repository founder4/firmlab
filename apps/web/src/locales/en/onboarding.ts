/**
 * onboarding — the guided tour that opens once on a fresh profile. English source of truth. Adding a key here makes
 * the Spanish file fail to compile until it is translated.
 *
 * **This is the first prose a new operator reads, and it teaches how to read every screen after it.** The `proof`
 * step is the load-bearing one. It names the proof states verbatim — they are identifiers that cross the API and
 * land in SQLite, so they appear inside the sentence exactly as the database stores them — and it states what each
 * one refuses to claim. Two of those claims invert if a translation softens them:
 *
 *   • `needs_runtime_reproduction` is a LEAD. A precondition was observed and nothing was proven.
 *   • `blocked_by_platform` means the question WAS asked and this deployment could not answer it. It is not a
 *     negative result, and a rendering that reads like "no problems" would teach the opposite of the workbench's
 *     central invariant on the first screen a reader ever sees.
 *
 * The step keys are named for the interface element each one spotlights, so the catalogue and the selector list in
 * `onboarding.tsx` can be read side by side.
 */
export const onboarding = {
  ariaLabel: 'Product tour',
  progress: (step: number, total: number) => `Step ${step} / ${total}`,
  skip: 'Skip',
  back: 'Back',
  next: 'Next',
  done: 'Done',

  welcome: {
    title: 'Welcome to FirmLab',
    body: [
      'A local, private firmware workbench. Everything is analyzed on this machine — nothing is uploaded.',
      'Here is a 20-second tour; you can skip it any time.',
    ].join(' '),
  },
  sidebar: {
    title: 'Navigate here',
    body: [
      'The sidebar holds your workspace — the dashboard, the corpus and what this deployment can do — and, once a',
      'firmware image is open, its analysis sections grouped by purpose.',
    ].join(' '),
  },
  health: {
    title: 'Security posture, always visible',
    body: [
      'This tells you whether the API is bound to loopback (local-only) or reachable over the network.',
      'FirmLab is meant to stay local.',
    ].join(' '),
  },
  appearance: {
    title: 'Make it yours',
    body: [
      'Switch between light, dark, and system themes, and toggle comfortable/compact density for long analysis',
      'sessions. Full controls live in Settings.',
    ].join(' '),
  },
  upload: {
    title: 'Start an analysis',
    body: [
      'Drop a firmware image (or browse) to analyze it instantly with the deterministic engine — no toolchain',
      'required. External tools add depth when present.',
    ].join(' '),
  },
  /** The proof-state discipline, taught before the reader has seen a single finding. */
  proof: {
    title: 'Read the proof state first',
    body: [
      'Findings are not opinions: each one carries a proof state. static_confirmed means the property is literally',
      'in the bytes; needs_runtime_reproduction is a lead and nothing more; blocked_by_platform means the question',
      'was asked and could not be answered here — never that the image is clean. An empty list is not clean either.',
    ].join(' '),
  },
  end: {
    title: 'That’s it',
    body: 'Restart this tour any time from the ? button in the header or from Settings → Help. Happy hunting.',
  },
};
