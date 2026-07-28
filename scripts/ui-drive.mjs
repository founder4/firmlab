/**
 * Drive the FirmLab web UI in a real browser and report what a person would actually see.
 *
 * It exists because every check so far has been behavioural — unit tests and API calls — and a green suite proves
 * the code is consistent with its fixtures, not that a screen renders. This loads the REAL deployed build against
 * the REAL corpus (socat sidecar → the live container), so what it captures is what the operator sees.
 *
 * It reports three things beyond the screenshot, because a picture hides exactly the failures that matter most:
 *   • console errors and page exceptions — a React subtree that threw renders as blank, not as an error;
 *   • failed network requests — a 404/500 behind a panel that shows an empty state looks identical to "no data";
 *   • the visible text of the section, so an assertion can be made about content rather than about pixels.
 *
 * Usage:  node drive.mjs <route> <out.png> [--click "<text>"] [--wait <ms>] [--theme dark|light]
 */
import { chromium } from 'playwright';

const [route = '/', out = 'shot.png', ...rest] = process.argv.slice(2);
const arg = (name, dflt) => {
  const i = rest.indexOf(name);
  return i === -1 ? dflt : rest[i + 1];
};
const BASE = process.env.FIRMLAB_UI ?? 'http://127.0.0.1:8899';

const browser = await chromium.launch();
const ctx = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
  deviceScaleFactor: 2,
  colorScheme: arg('--theme', 'dark') === 'light' ? 'light' : 'dark',
});
// The onboarding tour opens over the content on any fresh profile and its "Skip" button is not reliably
// clickable before the overlay settles. Mark it seen the way the app itself does (`onboarding.tsx` DONE_KEY),
// so every capture shows the screen rather than the welcome card. `--tour` opts back in to test the tour itself.
if (!rest.includes('--tour')) {
  await ctx.addInitScript(() => {
    try {
      localStorage.setItem('firmlab.tour.done', '1');
    } catch {
      /* a context without storage access is not a reason to fail the capture */
    }
  });
}

const page = await ctx.newPage();

const consoleErrors = [];
const failedRequests = [];
page.on('console', (m) => {
  if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 300));
});
page.on('pageerror', (e) => consoleErrors.push(`PAGE EXCEPTION: ${e.message}`.slice(0, 300)));
page.on('requestfailed', (r) => failedRequests.push(`${r.method()} ${r.url()} — ${r.failure()?.errorText}`));
page.on('response', (r) => {
  if (r.status() >= 400) failedRequests.push(`${r.status()} ${r.request().method()} ${r.url()}`);
});

const url = `${BASE}/#${route}`;
await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 }).catch(() => {});

const click = arg('--click', null);
if (click) {
  const target = page.getByText(click, { exact: false }).first();
  await target.click({ timeout: 10000 }).catch((e) => consoleErrors.push(`CLICK FAILED "${click}": ${e.message}`));
  await page.waitForLoadState('networkidle').catch(() => {});
}
await page.waitForTimeout(Number(arg('--wait', 900)));

await page.screenshot({ path: out, fullPage: true });

const text = (
  await page
    .locator('body')
    .innerText()
    .catch(() => '')
).replace(/\n{3,}/g, '\n\n');
console.log(`URL      ${url}`);
console.log(`TITLE    ${await page.title()}`);
console.log(`SHOT     ${out}`);
console.log(`ERRORS   ${consoleErrors.length ? `\n  - ${consoleErrors.join('\n  - ')}` : 'none'}`);
console.log(
  `NET FAIL ${failedRequests.length ? `\n  - ${[...new Set(failedRequests)].slice(0, 8).join('\n  - ')}` : 'none'}`,
);
console.log(`--- visible text (first 1800 chars) ---\n${text.slice(0, 1800)}`);

await browser.close();
