/** Pure helpers for the two caps in the research gatherer. A cap changes the meaning, so both return that meaning. */

export function rootfsKeyWalkWasBounded(input: {
  keysFound: number;
  keyCap: number;
  entryBudgetExhausted: boolean;
}): boolean {
  return input.keysFound >= input.keyCap || input.entryBudgetExhausted;
}

export function selectSecurityDomains(
  domains: readonly string[],
  cap: number,
): { selected: string[]; total: number; unchecked: number } {
  const boundedCap = Math.max(0, Math.floor(cap));
  const selected = domains.slice(0, boundedCap);
  return { selected, total: domains.length, unchecked: Math.max(0, domains.length - selected.length) };
}
