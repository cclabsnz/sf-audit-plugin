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

const AUTH = /(login|forgotpassword|selfregist|signup|register|passwordless|verif)/i;
const PLUMBING = [
  /^RichTextController\./, /^NavigationMenuDataProviderController\./, /^NetworkTrackingController\./,
  /^InstrumentationBeaconController\./, /^QuarterbackController\./, /^ComponentController\./,
  /^HostConfigController\./, /^PubliclyCacheableAttributeLoaderController\./, /^omnistudio__/,
  /recaptcha/i, /^LabelController\./, /^DynamicThemeController\./,
];
const DATA_ACCESS = [
  /\.getItems$/, /\.getRecord\w*$/, /\.executeGraphQL$/, /\.getListUi\w*$/, /\.getRelatedList\w*$/,
  /\.getLookupRecords$/, /\.search\w*$/,
];
const STANDARD_CONTROLLER = /^(?:[A-Z]\w*Controller|[A-Z]\w*DataProvider)\.\w+$/;

/**
 * Auth wins over everything (a login controller is never data access). Custom Apex that is not
 * plumbing counts as data access: an @AuraEnabled method callable by a guest is a read surface.
 */
export function classifyAction(name: string): ActionClass {
  if (AUTH.test(name)) return 'auth';
  if (PLUMBING.some((r) => r.test(name))) return 'plumbing';
  if (DATA_ACCESS.some((r) => r.test(name))) return 'data-access';
  if (STANDARD_CONTROLLER.test(name)) return 'data-access';
  return 'unknown';
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
