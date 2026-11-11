import type { SecurityCheck } from './SecurityCheck.js';

/**
 * A --checks selection plus the checks that fill the cache it reads. CheckEngine refuses a check
 * whose cache keys no earlier check populates, so `--checks apex-sharing` alone could not run.
 * Each needed key is filled by the earliest registry check that populates it, transitively, and the
 * result keeps registry order so providers run before their readers. `added` lists the providers
 * the user did not ask for, so the command can say why they ran.
 */
export function withCacheProviders(
  selected: readonly SecurityCheck[],
  registry: readonly SecurityCheck[],
): { checks: SecurityCheck[]; added: SecurityCheck[] } {
  const chosen = new Set<SecurityCheck>(selected);
  const pending = [...selected];
  while (pending.length > 0) {
    const check = pending.pop()!;
    for (const key of check.dependsOnCache ?? []) {
      const provider = registry.find((c) => (c.populatesCache ?? []).includes(key));
      if (provider && !chosen.has(provider)) {
        chosen.add(provider);
        pending.push(provider);
      }
    }
  }
  const checks = registry.filter((c) => chosen.has(c));
  return { checks, added: checks.filter((c) => !selected.includes(c)) };
}
