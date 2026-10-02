/** FirmLab compatibility entry point for the shared, project-independent Orca supervisor. */
import { existsSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runCli } from '../skills/orca-campaign/scripts/watch.mjs';
export * from '../skills/orca-campaign/scripts/watch.mjs';

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url))
  await runCli();
