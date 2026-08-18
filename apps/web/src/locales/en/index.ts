import { agents } from './agents';
import { binvuln } from './binvuln';
import { capabilities } from './capabilities';
import { capture } from './capture';
/**
 * The English catalogue — the source of truth for every user-facing string in the workbench shell.
 *
 * `Messages` is derived from this object, and every Spanish namespace declares itself against its slice of it. That
 * is the whole enforcement mechanism: adding a key here breaks `pnpm check` in `locales/es/<namespace>.ts` until it
 * is translated, so a half-translated build cannot reach a reader looking finished.
 *
 * One namespace per screen or panel, and each lives in its own file — the catalogue is edited by many hands, and a
 * single shared file would be a permanent merge conflict.
 */
import { common } from './common';
import { compmap } from './compmap';
import { corpus } from './corpus';
import { coverage } from './coverage';
import { dashboard } from './dashboard';
import { egressSection } from './egressSection';
import { exportreach } from './exportreach';
import { files } from './files';
import { findings } from './findings';
import { hardware } from './hardware';
import { imageDetail } from './imageDetail';
import { kernelPosture } from './kernelPosture';
import { kmod } from './kmod';
import { nav } from './nav';
import { onboarding } from './onboarding';
import { operator } from './operator';
import { overview } from './overview';
import { panels } from './panels';
import { proofState } from './proofState';
import { report } from './report';
import { sectionGroups } from './sectionGroups';
import { sectionIndex, sections } from './sections';
import { settings } from './settings';
import { shell } from './shell';
import { simulation } from './simulation';
import { techniques } from './techniques';
import { testbench } from './testbench';
import { updatepath } from './updatepath';
import { visuals } from './visuals';

export const en = {
  common,
  nav,
  sectionIndex,
  sections,
  proofState,
  settings,
  dashboard,
  overview,
  imageDetail,
  compmap,
  report,
  capabilities,
  capture,
  operator,
  hardware,
  testbench,
  simulation,
  files,
  updatepath,
  findings,
  agents,
  corpus,
  coverage,
  onboarding,
  panels,
  techniques,
  visuals,
  shell,
  binvuln,
  kernelPosture,
  kmod,
  sectionGroups,
  egressSection,
  exportreach,
};

export type Messages = typeof en;
