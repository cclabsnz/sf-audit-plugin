import type { AppFinding, AppUsage, GrantedAccess, ResolvedApp, Verb } from './types.js';

export function buildFinding(
  app: ResolvedApp,
  used: AppUsage,
  granted: GrantedAccess,
  window: { since: number; attributionRatePct: number },
  soakDays: number,
): AppFinding {
  const usedObjects = new Set(used.objects.map((o) => o.object));
  const usedVerbs = new Map(used.objects.map((o) => [o.object, new Set(o.verbs)]));
  const belowSoak = window.since < soakDays;
  const notes: string[] = [];

  notes.push(
    `Observed over ${window.since} day(s); RestApi attribution ${window.attributionRatePct}% — "used" is a lower bound.`,
  );
  if (belowSoak) notes.push(`Window below the ${soakDays}-day soak threshold: revoke recommendations suppressed.`);
  if (used.soapOnly) notes.push('SOAP usage present but not app-attributable; not treated as dormant.');
  if (granted.multiUserInteractive) notes.push('Interactive app with many run-as users; object delta not asserted.');

  const assertDelta = !belowSoak && !granted.multiUserInteractive;

  const unusedObjects = assertDelta
    ? granted.objects.map((o) => o.object).filter((o) => !usedObjects.has(o)).sort()
    : [];

  const unusedVerbs = assertDelta
    ? granted.objects
        .filter((o) => usedObjects.has(o.object))
        .map((o) => {
          const u = usedVerbs.get(o.object) ?? new Set<Verb>();
          const extra = o.verbs.filter((v) => !u.has(v)).sort();
          return { object: o.object, verbs: extra };
        })
        .filter((x) => x.verbs.length > 0)
    : [];

  const anyWriteUsed = used.objects.some((o) => o.verbs.some((v) => v === 'write' || v === 'delete'));
  const scopeDowngrade = assertDelta && granted.scope === 'full' && !anyWriteUsed ? 'full -> api' : null;

  const dormant = assertDelta && used.objects.length === 0 && granted.objects.length > 0;

  const objectPermissions = used.objects.map((o) => ({
    object: o.object,
    read: o.verbs.includes('read'),
    create: o.verbs.includes('write'),
    edit: o.verbs.includes('write'),
    delete: o.verbs.includes('delete'),
  }));

  return {
    app,
    window,
    used,
    granted,
    overGrant: { unusedObjects, unusedVerbs, scopeDowngrade, dormant },
    recommendation: { permissionSet: { objectPermissions } },
    notes,
  };
}
