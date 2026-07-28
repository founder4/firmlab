/**
 * The Spanish catalogue. Each namespace is typed against its English counterpart in its own file, so this file
 * only assembles them — the type error for an untranslated key surfaces where the translation belongs.
 */
import type { Messages } from '../en';
import { agents } from './agents';
import { capture } from './capture';
import { common } from './common';
import { compmap } from './compmap';
import { corpus } from './corpus';
import { coverage } from './coverage';
import { dashboard } from './dashboard';
import { files } from './files';
import { findings } from './findings';
import { hardware } from './hardware';
import { imageDetail } from './imageDetail';
import { nav } from './nav';
import { onboarding } from './onboarding';
import { operator } from './operator';
import { overview } from './overview';
import { panels } from './panels';
import { proofState } from './proofState';
import { report } from './report';
import { sections } from './sections';
import { settings } from './settings';
import { simulation } from './simulation';
import { testbench } from './testbench';
import { updatepath } from './updatepath';

export const es: Messages = {
  common,
  nav,
  sections,
  proofState,
  settings,
  dashboard,
  overview,
  imageDetail,
  compmap,
  report,
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
};
