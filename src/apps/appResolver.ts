import type { AppCategory, ResolvedApp } from './types.js';
import { lookupStandardApp } from './standardAppCatalog.js';
import type { SoqlClient } from '@cclabsnz/sf-core';

interface AppMenuRow {
  ApplicationId: string;
  Label?: string;
  Name?: string;
}
interface ConnAppRow {
  Id: string;
  Name: string;
}
interface LoginRow {
  Application: string;
  UserId?: string;
}

const SECURITY_VENDOR = /datadog|defender|appomni|crowdstrike|splunk|siem|sentinel/i;
const SALESFORCE_VENDOR = /salesforce|dataloader|workbench|force\.com|chatter|salesforcea/i;

function categorise(name: string, viaStandard: AppCategory | null): AppCategory {
  if (viaStandard) return viaStandard;
  if (SECURITY_VENDOR.test(name)) return 'Security-vendor';
  if (SALESFORCE_VENDOR.test(name)) return 'Salesforce-standard';
  return 'Org-custom';
}

export async function resolveApps(
  appIds: string[],
  soql: SoqlClient,
  userIds: string[],
): Promise<ResolvedApp[]> {
  const menu = await soql
    .queryAll<AppMenuRow>("SELECT ApplicationId, Label, Name FROM AppMenuItem WHERE Type = 'ConnectedApplication'")
    .catch(() => []);
  const connApps = await soql
    .queryAll<ConnAppRow>('SELECT Id, Name FROM ConnectedApplication')
    .catch(() => []);
  const menuByKey = new Map(menu.map((m) => [m.ApplicationId.slice(0, 15), m.Label ?? m.Name ?? '']));
  const connByKey = new Map(connApps.map((c) => [c.Id.slice(0, 15), c.Name]));

  // Only pay for LoginHistory if some ids are still unresolved after 1-3.
  const stillUnknown = appIds.filter(
    (id) => !menuByKey.has(id.slice(0, 15)) && !connByKey.has(id.slice(0, 15)) && !lookupStandardApp(id),
  );
  let logins: LoginRow[] = [];
  if (stillUnknown.length > 0 && userIds.length > 0) {
    logins = await soql
      .queryAll<LoginRow>(
        `SELECT Application, UserId FROM LoginHistory WHERE UserId IN (${userIds
          .map((u) => `'${u}'`)
          .join(',')}) AND LoginTime = LAST_N_DAYS:7`,
      )
      .catch(() => []);
  }
  const loginNames = [...new Set(logins.map((l) => l.Application).filter((a) => a && a !== 'Browser' && a !== 'N/A'))];

  return appIds.map((appId) => {
    const key = appId.slice(0, 15);
    const menuName = menuByKey.get(key);
    if (menuName) return { appId, name: menuName, category: categorise(menuName, null), confidence: 'resolved' as const };

    const connName = connByKey.get(key);
    if (connName) return { appId, name: connName, category: categorise(connName, null), confidence: 'resolved' as const };

    const std = lookupStandardApp(appId);
    if (std) return { appId, name: std.name, category: std.category, vendor: std.vendor, purpose: std.purpose, confidence: 'resolved' as const };

    if (loginNames.length === 1) {
      return { appId, name: loginNames[0], category: categorise(loginNames[0], null), confidence: 'inferred' as const };
    }

    return { appId, name: `Unidentified connected app ${appId}`, category: 'Unidentified' as const, confidence: 'unidentified' as const };
  });
}
