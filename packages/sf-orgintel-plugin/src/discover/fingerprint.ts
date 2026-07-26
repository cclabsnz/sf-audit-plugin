import type { IntelContext } from '../lib/wire.js';
import type { DomainFingerprint, InstalledPackage, RecordTypeRef, StatusPicklistRef } from './types.js';
import type { SObjectCatalog } from '../probe/sobjectCatalog.js';

export async function buildFingerprint(
  ctx: IntelContext,
  catalog: SObjectCatalog,
  statusPicklists: StatusPicklistRef[],
): Promise<DomainFingerprint> {
  const installedPackages = await queryPackages(ctx);
  const recordTypes = await queryRecordTypes(ctx);
  const apps = await queryApps(ctx);
  const objectInventory = catalog.all().map((s) => s.name).sort();
  const clouds = detectClouds(catalog, installedPackages);

  return { version: 1, installedPackages, clouds, objectInventory, statusPicklists, recordTypes, apps };
}

interface InstalledPkgRow {
  SubscriberPackage?: { Name?: string; NamespacePrefix?: string | null };
  SubscriberPackageVersion?: { Name?: string };
}

async function queryPackages(ctx: IntelContext): Promise<InstalledPackage[]> {
  try {
    const rows = await ctx.tooling.query<InstalledPkgRow>(
      'SELECT SubscriberPackage.Name, SubscriberPackage.NamespacePrefix, SubscriberPackageVersion.Name FROM InstalledSubscriberPackage',
    );
    return rows
      .map((r) => ({
        namespace: r.SubscriberPackage?.NamespacePrefix ?? null,
        name: r.SubscriberPackage?.Name ?? '(unknown)',
        version: r.SubscriberPackageVersion?.Name ?? null,
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  } catch {
    return [];
  }
}

interface RecordTypeRow {
  SobjectType: string;
  DeveloperName: string;
  Name: string;
}

async function queryRecordTypes(ctx: IntelContext): Promise<RecordTypeRef[]> {
  try {
    const rows = await ctx.soql.queryAll<RecordTypeRow>(
      'SELECT SobjectType, DeveloperName, Name FROM RecordType WHERE IsActive = true',
    );
    return rows
      .map((r) => ({ object: r.SobjectType, developerName: r.DeveloperName, label: r.Name }))
      .sort((a, b) => a.object.localeCompare(b.object) || a.developerName.localeCompare(b.developerName));
  } catch {
    return [];
  }
}

interface AppMenuRow {
  Label: string;
  Name: string;
}

async function queryApps(ctx: IntelContext): Promise<string[]> {
  try {
    const rows = await ctx.soql.queryAll<AppMenuRow>(
      "SELECT Label, Name FROM AppMenuItem WHERE Type = 'TabSet'",
    );
    return [...new Set(rows.map((r) => r.Label).filter(Boolean))].sort();
  } catch {
    return [];
  }
}

/** Deterministic cloud detection from telltale objects and installed-package namespaces. */
function detectClouds(catalog: SObjectCatalog, packages: InstalledPackage[]): string[] {
  const clouds = new Set<string>();
  const has = (name: string) => catalog.has(name);
  const ns = new Set(packages.map((p) => (p.namespace ?? '').toLowerCase()).filter(Boolean));

  if (has('Opportunity') && has('Lead')) clouds.add('Sales Cloud');
  if (has('Case')) clouds.add('Service Cloud');
  if (has('WorkOrder')) clouds.add('Field Service');
  if (has('Campaign') && has('CampaignMember')) clouds.add('Marketing / Campaigns');
  if (has('Network')) clouds.add('Experience Cloud');
  if (ns.has('sbqq') || has('SBQQ__Quote__c')) clouds.add('CPQ');
  if (ns.has('finserv') || [...ns].some((n) => n.startsWith('finserv'))) clouds.add('Financial Services Cloud');
  if (
    [...ns].some((n) => n.includes('health')) ||
    catalog.all().some((s) => /^HealthCloud/i.test(s.name))
  ) {
    clouds.add('Health Cloud');
  }

  return [...clouds].sort();
}
