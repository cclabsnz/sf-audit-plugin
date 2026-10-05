import type { ActionClass } from '../model.js';

const DESCRIPTOR = /(?:serviceComponent|aura|apex):\/\/([\w.]+)\/ACTION\$(\w+)(?:\(([\w.]+)\))?/g;

/** `Controller.method` names in invocation order. ApexActionController.execute(X.y) yields `X.y`. */
export function parseActions(actionMessage: string): string[] {
  const out: string[] = [];
  for (const m of actionMessage.matchAll(DESCRIPTOR)) {
    if (m[3]) { out.push(m[3]); continue; }
    const controller = m[1].split('.').pop()!;
    out.push(`${controller}.${m[2]}`);
  }
  return out;
}

/** Matched against the METHOD only, never the controller: LoginHistoryController.getRecords is a read. */
const AUTH_METHOD = /(login|logout|password|selfreg|register|signup|verif)/i;
const PLUMBING = [
  /^RichTextController\./, /^NavigationMenuDataProviderController\./, /^NetworkTrackingController\./,
  /^InstrumentationBeaconController\./, /^QuarterbackController\./, /^ComponentController\./,
  /^HostConfigController\./, /^PubliclyCacheableAttributeLoaderController\./, /^omnistudio__/,
  /recaptcha/i, /^LabelController\./, /^DynamicThemeController\./,
];
const DATA_ACCESS_METHOD = [
  /^getItems$/, /^getRecord\w*$/, /^executeGraphQL$/, /^getListUi\w*$/, /^getRelatedList\w*$/,
  /^getLookupRecords$/, /^search\w*$/,
];

/**
 * Classified by method, data access first: a known read method is data access whatever its
 * controller is called. Then auth (method only), then known plumbing. Anything else that parsed
 * may read data — an @AuraEnabled method callable by a guest is a read surface — so it is
 * assessed as data access. `unknown` is kept for compatibility and never returned for a parsed name.
 */
export function classifyAction(name: string): ActionClass {
  const method = name.slice(name.lastIndexOf('.') + 1);
  if (DATA_ACCESS_METHOD.some((r) => r.test(method))) return 'data-access';
  if (AUTH_METHOD.test(method)) return 'auth';
  if (PLUMBING.some((r) => r.test(name))) return 'plumbing';
  return 'data-access';
}

export function classesOf(actionMessage: string): Set<ActionClass> {
  return new Set(parseActions(actionMessage).map(classifyAction));
}

export interface ActionSummary {
  byClass: Record<ActionClass, number>;
  byName: Array<{ name: string; cls: ActionClass; count: number }>;
}

export function summariseActionCounts(counts: Iterable<Record<string, number>>): ActionSummary {
  const byClass: Record<ActionClass, number> = { 'data-access': 0, auth: 0, plumbing: 0, unknown: 0 };
  const byName = new Map<string, number>();
  for (const c of counts) {
    for (const [name, n] of Object.entries(c)) {
      byClass[classifyAction(name)] += n;
      byName.set(name, (byName.get(name) ?? 0) + n);
    }
  }
  return {
    byClass,
    byName: [...byName.entries()].map(([name, count]) => ({ name, cls: classifyAction(name), count }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
  };
}

export function summariseActions(messages: Iterable<string>): ActionSummary {
  const counts: Record<string, number> = {};
  for (const m of messages) for (const n of parseActions(m)) counts[n] = (counts[n] ?? 0) + 1;
  return summariseActionCounts([counts]);
}
