import { CHECKS } from '../../../src/checks/registry.js';
import { CheckEngine } from '../../../src/checks/CheckEngine.js';
import { withCacheProviders } from '../../../src/checks/selection.js';
import type { SecurityCheck } from '../../../src/checks/SecurityCheck.js';

const ids = (cs: readonly SecurityCheck[]) => cs.map((c) => c.id);
const fake = (id: string, opts: Partial<SecurityCheck> = {}) =>
  ({ id, name: id, category: 'c', description: 'd', run: async () => ({ findings: [] }), ...opts }) as SecurityCheck;

describe('withCacheProviders: a --checks selection also runs the checks that fill the cache it reads', () => {
  it('adds the providers of each cache key a selected check depends on, transitively, in registry order', () => {
    const all = [
      fake('a', { populatesCache: ['apexBodies'] as never }),
      fake('b', { dependsOnCache: ['apexBodies'] as never, populatesCache: ['connectedAppNames'] as never }),
      fake('c'),
      fake('d', { dependsOnCache: ['connectedAppNames'] as never }),
    ];
    const r = withCacheProviders([all[3]], all);
    expect(ids(r.checks)).toEqual(['a', 'b', 'd']);
    expect(ids(r.added)).toEqual(['a', 'b']);
  });

  it('adds nothing when the selection needs no cache', () => {
    const all = [fake('a', { populatesCache: ['apexBodies'] as never }), fake('c')];
    const r = withCacheProviders([all[1]], all);
    expect(ids(r.checks)).toEqual(['c']);
    expect(r.added).toEqual([]);
  });

  // Every check the registry has must be runnable on its own: none may throw on cache ordering.
  it.each(CHECKS.map((c) => [c.id]))('%s runs alone with its providers added', (id) => {
    const { checks } = withCacheProviders(CHECKS.filter((c) => c.id === id), CHECKS);
    expect(() => new CheckEngine(checks, { cache: {} } as never)).not.toThrow();
  });

  it('runs the documented example hardcoded-credentials,apex-sharing', () => {
    const { checks } = withCacheProviders(CHECKS.filter((c) => ['hardcoded-credentials', 'apex-sharing'].includes(c.id)), CHECKS);
    expect(() => new CheckEngine(checks, { cache: {} } as never)).not.toThrow();
    expect(ids(checks)).toEqual(expect.arrayContaining(['hardcoded-credentials', 'apex-sharing']));
  });
});
