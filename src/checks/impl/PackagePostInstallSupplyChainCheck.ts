import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface InstalledPackageRecord {
  Id: string;
  SubscriberPackageId?: string;
  SubscriberPackage?: {
    Name?: string;
    NamespacePrefix?: string;
  };
}

interface ApexClassRecord {
  Id: string;
  Name: string;
  NamespacePrefix?: string | null;
  Body?: string | null;
}

interface RemoteSiteRecord {
  Id: string;
  EndpointUrl: string;
}

interface CspSiteRecord {
  Id: string;
  EndpointUrl: string;
}

function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('is not supported') ||
    msg.includes('sobject type')
  );
}

export class PackagePostInstallSupplyChainCheck implements SecurityCheck {
  readonly id = 'package-post-install-supply-chain';
  readonly name = 'Package Post-Install Supply Chain Risk';
  readonly category = 'Platform Hygiene';
  readonly description =
    'Inventories managed packages with post-install scripts and registered callout endpoints subject to push upgrade risk.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const packagesUrl = `${baseUrl}/lightning/setup/ImportedPackage/home`;

    let installedPackages: InstalledPackageRecord[] = [];
    try {
      installedPackages = await ctx.tooling.query<InstalledPackageRecord>(
        'SELECT Id, SubscriberPackageId FROM InstalledSubscriberPackage',
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        findings.push({
          id: 'package-post-install-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'No installed subscriber packages found',
          detail: 'InstalledSubscriberPackage tooling object returned no records.',
          remediation: 'No action required.',
        });
        return { findings };
      }
      findings.push({
        id: 'package-post-install-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Installed subscriber packages could not be inspected',
        detail: `Failed to query InstalledSubscriberPackage: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Grant the audit user Tooling API read access to inspect installed packages.',
      });
      return { findings };
    }

    if (installedPackages.length === 0) {
      findings.push({
        id: 'package-post-install-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No installed subscriber packages found in org',
        detail: 'Zero InstalledSubscriberPackage records were identified.',
        remediation: 'Continue inventorying new packages when installed.',
      });
      return { findings };
    }

    // Query namespaced Apex classes implementing InstallHandler
    let namespacedClasses: ApexClassRecord[] = [];
    try {
      namespacedClasses = await ctx.tooling.query<ApexClassRecord>(
        'SELECT Id, Name, NamespacePrefix FROM ApexClass WHERE NamespacePrefix != null',
      );
    } catch {
      // Degrade gracefully
    }

    // Query remote sites and CSP trusted sites to correlate callouts
    let remoteSites: RemoteSiteRecord[] = [];
    try {
      remoteSites = await ctx.soql.queryAll<RemoteSiteRecord>(
        'SELECT Id, EndpointUrl FROM RemoteProxy',
      );
    } catch {
      // Degrade gracefully
    }

    let cspSites: CspSiteRecord[] = [];
    try {
      cspSites = await ctx.soql.queryAll<CspSiteRecord>(
        'SELECT Id, EndpointUrl FROM CspTrustedSite',
      );
    } catch {
      // Degrade gracefully
    }

    const packageNamespaces = [
      ...new Set(namespacedClasses.map((c) => c.NamespacePrefix).filter((ns): ns is string => Boolean(ns))),
    ];

    const hasOutboundCallouts = remoteSites.length > 0 || cspSites.length > 0;

    if (packageNamespaces.length > 0) {
      findings.push({
        id: 'package-post-install-system-script',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${packageNamespaces.length} managed package namespace(s) execute post-install scripts during push upgrades`,
        detail:
          'Managed packages implementing InstallHandler execute unattended Apex under full system privileges during package installation and automatic vendor push upgrades. These executions bypass standard admin approvals and change-management gates.',
        remediation:
          'Audit installed vendor packages and verify vendor security posture and push-upgrade release schedules.',
        affectedItems: packageNamespaces.map((ns) => ({
          label: `Namespace: ${ns}`,
          url: packagesUrl,
          note: 'Package executes post-install script on push upgrade',
        })),
      });

      if (hasOutboundCallouts) {
        findings.push({
          id: 'package-post-install-callout-registered',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `Installed package ecosystem registers ${remoteSites.length + cspSites.length} remote callout/CSP endpoint(s)`,
          detail:
            'Managed packages with active post-install scripts operate alongside registered Remote Sites or CSP Trusted Sites. Vendor push upgrades executing in system context can make external HTTP callouts to vendor infrastructure.',
        remediation:
          'Review all remote site settings and CSP endpoints associated with installed packages to ensure they connect only to expected vendor domains.',
        affectedItems: [
          ...remoteSites.slice(0, 10).map((r) => ({
            label: r.EndpointUrl,
            url: `${baseUrl}/lightning/setup/SecurityRemoteProxy/home`,
            note: 'Remote site setting active',
          })),
          ...cspSites.slice(0, 10).map((c) => ({
            label: c.EndpointUrl,
            url: `${baseUrl}/lightning/setup/SecurityCspTrustedSite/home`,
            note: 'CSP trusted site active',
          })),
        ],
      });
      }
    } else {
      findings.push({
        id: 'package-post-install-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No unattended post-install script supply chain risks identified',
        detail: `${installedPackages.length} package(s) verified; no unmonitored post-install scripts detected.`,
        remediation: 'Review post-install scripts and permissions whenever new packages are installed.',
      });
    }

    return { findings };
  }
}
