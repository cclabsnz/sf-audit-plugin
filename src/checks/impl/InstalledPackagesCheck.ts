import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface InstalledPkgRecord {
  SubscriberPackage: { Name: string; NamespacePrefix: string | null };
  SubscriberPackageVersion: {
    MajorVersion: number;
    MinorVersion: number;
    PatchVersion: number;
    ReleaseState: string;
    PublisherName: string | null;
  };
}

export class InstalledPackagesCheck implements SecurityCheck {
  readonly id = 'installed-packages';
  readonly name = 'Installed Packages';
  readonly category = 'App Security';
  readonly description = 'Inventories installed managed and unmanaged packages; flags unmanaged packages and beta package versions';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/ImportedPackage/home`;

    let packages: InstalledPkgRecord[] = [];
    try {
      packages = await ctx.tooling.query<InstalledPkgRecord>(
        `SELECT Id, SubscriberPackage.Name, SubscriberPackage.NamespacePrefix,
                SubscriberPackageVersion.MajorVersion, SubscriberPackageVersion.MinorVersion,
                SubscriberPackageVersion.PatchVersion, SubscriberPackageVersion.ReleaseState,
                SubscriberPackageVersion.PublisherName
         FROM InstalledSubscriberPackage`
      );
    } catch {
      findings.push({
        id: 'installed-packages-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Installed package inventory could not be retrieved via Tooling API',
        detail:
          'The InstalledSubscriberPackage Tooling API object was not accessible. This may indicate the audit user lacks Tooling API access or the org edition does not support this query.',
        remediation:
          'Review installed packages manually in Setup → Apps → Packaging → Installed Packages. Ensure the audit user has API access enabled.',
        affectedItems: [{ label: 'Installed Packages Setup', url: setupUrl }],
      });
      return { findings };
    }

    if (packages.length === 0) {
      findings.push({
        id: 'installed-packages-none',
        category: this.category,
        riskLevel: 'INFO',
        title: 'No installed packages found',
        detail:
          'No InstalledSubscriberPackage records were found. This org does not have any AppExchange or custom packages installed.',
        remediation:
          'No action required. Monitor for new package installations as part of your change management process.',
      });
      return { findings };
    }

    const unmanagedPackages = packages.filter(
      (p) => p.SubscriberPackage.NamespacePrefix === null || p.SubscriberPackage.NamespacePrefix === ''
    );
    const betaPackages = packages.filter(
      (p) => p.SubscriberPackageVersion.ReleaseState === 'Beta'
    );

    function versionString(pkg: InstalledPkgRecord): string {
      const v = pkg.SubscriberPackageVersion;
      return `${v.MajorVersion}.${v.MinorVersion}.${v.PatchVersion}`;
    }

    if (unmanagedPackages.length > 0) {
      findings.push({
        id: 'installed-packages-unmanaged',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${unmanagedPackages.length} unmanaged package(s) installed: code is editable and bypasses AppExchange security review`,
        detail:
          'Unmanaged packages contain Apex code, Visualforce pages, and other metadata that can be edited directly in the target org. Unlike managed packages, unmanaged packages are not subject to the Salesforce AppExchange security review process. Installed unmanaged code should be treated as untrusted third-party code and reviewed manually for data access, SOQL injection vulnerabilities, and hardcoded credentials.',
        remediation:
          'Review the code in each unmanaged package. Remove any unmanaged packages that are no longer required. For required packages, conduct a manual security review of the included Apex code and ensure it follows Salesforce security best practices. Consider migrating functionality to managed packages or native platform features.',
        affectedItems: unmanagedPackages.map((p) => ({
          label: p.SubscriberPackage.Name,
          url: setupUrl,
          note: `no namespace | unmanaged | publisher: ${p.SubscriberPackageVersion.PublisherName ?? 'unknown'} | version: ${versionString(p)}`,
        })),
      });
    }

    // Salesforce installs beta package versions only in scratch, sandbox and Developer Edition
    // orgs, or test orgs from the Environment Hub, never production, and an installed beta can't
    // be upgraded. So this is a development-org hygiene item, not a production exposure.
    // https://developer.salesforce.com/docs/atlas.en-us.packagingGuide.meta/packagingGuide/packaging_about_beta_packages.htm
    if (betaPackages.length > 0) {
      const orgKind = ctx.orgInfo.isSandbox ? 'sandbox' : 'non-production org';
      findings.push({
        id: 'installed-packages-beta',
        category: this.category,
        riskLevel: 'LOW',
        title: `${betaPackages.length} beta package version(s) installed in this ${orgKind}`,
        detail:
          `Beta package versions can only be installed in scratch, sandbox and Developer Edition orgs, so this ${orgKind} is not production. A beta version can't be upgraded once installed and may not match the version that is finally released, so code and data built against it here may not carry forward. That matters most in a sandbox used for UAT or staging.`,
        remediation:
          'Uninstall each beta version once testing is done, and install the released version for further testing. Keep beta versions out of sandboxes in your release pipeline, such as UAT or staging.',
        affectedItems: betaPackages.map((p) => ({
          label: p.SubscriberPackage.Name,
          url: setupUrl,
          note: `namespace: ${p.SubscriberPackage.NamespacePrefix ?? 'none'} | state: Beta | version: ${versionString(p)} | publisher: ${p.SubscriberPackageVersion.PublisherName ?? 'unknown'}`,
        })),
      });
    }

    findings.push({
      id: 'installed-packages-inventory',
      category: this.category,
      riskLevel: 'INFO',
      title: `${packages.length} package(s) installed: full inventory`,
      detail:
        `${packages.length} installed package(s) found. All installed packages should be reviewed periodically to confirm they are still required, up to date, and from trusted publishers. Packages with elevated data access permissions should be audited for field-level security and sharing configurations.`,
      remediation:
        'Review the package inventory at least annually. Remove packages that are no longer in use. Ensure all packages are updated to their latest GA versions to receive security patches.',
      affectedItems: packages.map((p) => ({
        label: p.SubscriberPackage.Name,
        url: setupUrl,
        note: `namespace: ${p.SubscriberPackage.NamespacePrefix ?? 'no namespace (unmanaged)'} | version: ${versionString(p)} | publisher: ${p.SubscriberPackageVersion.PublisherName ?? 'unknown'} | state: ${p.SubscriberPackageVersion.ReleaseState}`,
      })),
    });

    return { findings };
  }
}
