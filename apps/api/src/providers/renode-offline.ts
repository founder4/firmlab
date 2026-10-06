/**
 * The offline environment every Renode process runs under, in a module with no imports so that the capability probe
 * in `tools.ts` can apply it without pulling the Renode provider (and its isolation/job machinery) into the module
 * that answers "what can this deployment do?". `renode.ts` re-exports all of it; the rationale for the proxies lives
 * in that module's header.
 *
 * This contains Renode's own HTTP traffic. It is not network isolation: anything that ignores proxy variables is
 * untouched by it, and nothing here claims otherwise.
 */

/** A loopback port nothing listens on (discard, 9): a proxied request is refused at once, never forwarded. */
export const RENODE_REFUSING_PROXY = 'http://127.0.0.1:9';

/**
 * The proxy variables .NET's default HttpClient reads, in both spellings, all aimed at the refusing port. The
 * bypass list (NO_PROXY / no_proxy) is REMOVED by `offlineRenodeEnv`, not merely left alone: an inherited
 * `NO_PROXY=*` or `.antmicro.com` would send the request straight past the proxy to the network.
 */
export const OFFLINE_RENODE_ENV: Readonly<Record<string, string>> = {
  HTTP_PROXY: RENODE_REFUSING_PROXY,
  HTTPS_PROXY: RENODE_REFUSING_PROXY,
  ALL_PROXY: RENODE_REFUSING_PROXY,
  http_proxy: RENODE_REFUSING_PROXY,
  https_proxy: RENODE_REFUSING_PROXY,
  all_proxy: RENODE_REFUSING_PROXY,
};

/** Variables that would exempt a host from the refusing proxy, and so must not survive into Renode's env. */
export const RENODE_PROXY_BYPASS_VARS: readonly string[] = ['NO_PROXY', 'no_proxy'];

/**
 * Pure: the environment every Renode process gets — the caller's, with the offline proxies forced over it and the
 * bypass list removed. `home`, when given, replaces HOME (the boot run uses a per-run directory); otherwise HOME
 * is passed through untouched.
 */
export function offlineRenodeEnv(base: NodeJS.ProcessEnv, home?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base, ...OFFLINE_RENODE_ENV };
  for (const k of RENODE_PROXY_BYPASS_VARS) delete env[k];
  if (home !== undefined) env.HOME = home;
  return env;
}
