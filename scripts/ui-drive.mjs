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

const theme = arg('--theme', 'dark') === 'light' ? 'light' : 'dark';

const browser = await chromium.launch();
const ctx = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
  deviceScaleFactor: 2,
  colorScheme: theme,
});
// `colorScheme` alone was a lie for as long as this flag has existed. It drives `prefers-color-scheme`, and
// `theme.ts` only consults that when the STORED preference is `system` — its default is a hard `'dark'`, and a
// fresh capture profile has nothing stored. So `--theme light` set the media query, the app ignored it, and the
// screenshot came back dark while the run reported it as light. Seed the app's own key, exactly as the tour
// suppression below does; the media query stays set so anything that genuinely reads it agrees with the token.
await ctx.addInitScript((t) => {
  try {
    localStorage.setItem('firmlab.theme', t);
  } catch {
    /* a context without storage access is not a reason to fail the capture */
  }
}, theme);
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
  // `getByText(x, {exact:false}).first()` was the whole implementation, and it clicks the wrong thing in silence.
  // Measured: `--click "Amend"` on the operator ledger landed on the row's PROSE, because the attribution sentence
  // contains "Amended 2026-07-30" and that paragraph comes first in the document. Clicking a <div> succeeds, so
  // nothing failed and the screenshot simply showed an unopened form — the instrument reporting a false negative
  // about the app it exists to check.
  //
  // So: interactive elements first, exact match before substring, and SAY which one was clicked. A driver that
  // cannot tell you what it pressed cannot be used to prove what it saw.
  const candidates = [
    ['button (exact)', page.getByRole('button', { name: click, exact: true })],
    ['link (exact)', page.getByRole('link', { name: click, exact: true })],
    ['button (substring)', page.getByRole('button', { name: click })],
    ['link (substring)', page.getByRole('link', { name: click })],
    ['text (exact)', page.getByText(click, { exact: true })],
    ['text (substring)', page.getByText(click, { exact: false })],
  ];
  let clicked = null;
  for (const [how, locator] of candidates) {
    const n = await locator.count().catch(() => 0);
    if (n === 0) continue;
    const err = await locator
      .first()
      .click({ timeout: 5000 })
      .then(() => null)
      .catch((e) => e);
    if (!err) {
      clicked = `${how}${n > 1 ? ` (${n} matched, took the first)` : ''}`;
      break;
    }
  }
  if (clicked) console.log(`CLICKED  "${click}" as ${clicked}`);
  else consoleErrors.push(`CLICK FAILED "${click}": nothing matched as a button, link or text`);
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
