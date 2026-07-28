/**
 * The `api` mock every web test builds on — and the reason it exists instead of each file spreading `...actual.api`.
 *
 * `vi.mock('../api', … { ...actual.api, foo: vi.fn() })` names the methods a test knows about and leaves every other
 * one pointing at the REAL client. Nothing checks that the list is complete, and it goes stale the moment a component
 * grows a call, so a method the component reaches and the file forgot to name issues a live `fetch` from inside
 * jsdom. That is not hypothetical: `SimulationMenu` loads the extracted binaries to populate its target selector,
 * `binaries` was never in the spread, and every test in that file made a network call. It surfaced only because the
 * rejection happened to land after the test had finished and React complained about the late state update — an
 * unmocked call that RESOLVES during the test says nothing at all, and a warning-free suite is not evidence that the
 * other twelve files are clean.
 *
 * So the surface is not a list: it is enumerated from the real client at runtime, and every method starts as a
 * `vi.fn()` that throws `unmocked api call: <name>`. A test overrides the ones it cares about, and anything it missed
 * names itself in the failure rather than reaching the network. A method added to `api.ts` is covered the day it is
 * added, without anyone remembering to come here.
 *
 * What this does NOT claim. It is not evidence that a test covers what the component does with the call: a component
 * that swallows its own errors will swallow this one too, and a default stubbed with the wrong fixture is as wrong as
 * it ever was. The one guarantee is narrow, and worth having by itself — no web test talks to a network.
 */
import { type Mock, vi } from 'vitest';
import type { api } from './api';

/** The real client's shape. Every mock is built from its own keys, so the two cannot drift apart. */
type ApiClient = typeof api;
type ApiMethod = keyof ApiClient;

/**
 * Arguments stay typed — `toHaveBeenCalledWith` is most of what these tests assert, and it should be checked. The
 * resolved value is deliberately left `unknown`: a fixture is a partial stand-in for a provider result on purpose,
 * and forcing each one to be a complete `SbomResult` would make the fixtures longer without making them truer.
 */
export type MockedApi = {
  [K in ApiMethod]: ApiClient[K] extends (...args: infer A) => unknown ? Mock<(...args: A) => unknown> : never;
};

/**
 * Build the whole mocked client from the real one. Call it inside the `vi.mock` factory, handing it `actual.api`:
 *
 * ```ts
 * vi.mock('../api', async (importOriginal) => {
 *   const actual = await importOriginal<typeof import('../api')>();
 *   const { buildApiMock } = await import('../test-api-mock');
 *   return { ...actual, api: buildApiMock(actual.api) };
 * });
 * ```
 */
export function buildApiMock(actual: ApiClient): MockedApi {
  const entries = (Object.keys(actual) as ApiMethod[]).map((name) => [
    name,
    vi.fn(() => {
      throw new Error(
        `unmocked api call: ${name}. The component under test calls api.${name}(), and this test file never ` +
          `stubbed it — left alone it would reach the network. Add mockApi.${name}.mockResolvedValue(…) to the setup.`,
      );
    }),
  ]);
  return Object.fromEntries(entries) as MockedApi;
}

/**
 * The mocked client, typed. One cast, here, instead of a hand-maintained `Record` of method names in every test file
 * — which is the same list that went stale in the mock factory, kept in a second place.
 */
export function mockedApi(client: ApiClient): MockedApi {
  return client as unknown as MockedApi;
}
