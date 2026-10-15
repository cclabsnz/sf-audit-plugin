import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isMissingObjectError } from '../support/missingObject.js';

interface InstalledPackageRecord {
  Id: string;
  SubscriberPackageId?: string;
}

interface ApexClassRecord {
  Id: string;
  Name: string;
  NamespacePrefix?: string | null;
  Body?: string | null;
}

// Managed-package Apex is returned with its body replaced by this marker, so whether such a
// class implements InstallHandler cannot be read from the org.
const HIDDEN_BODY = '(hidden)';
const IMPLEMENTS_INSTALL_HANDLER = /\bimplements\b[^{]*\bInstallHandler\b/i;

export class PackagePostInstallSupplyChainCheck implements SecurityCheck {
  readonly id = 'package-post-install-supply-chain';
  readonly name = 'Package Post-Install Supply Chain Risk';
  readonly category = 'Platform Hygiene';
  readonly description =
    'Finds packaged Apex implementing InstallHandler, which runs in system context on every install and push upgrade.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const packagesUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ImportedPackage/home`;

    let installedPackages: InstalledPackageRecord[];
    try {
      installedPackages = await ctx.tooling.query<InstalledPackageRecord>(
        'SELECT Id, SubscriberPackageId FROM InstalledSubscriberPackage',
      );
    } catch (err) {
      if (!isMissingObjectError(err)) throw err;
      installedPackages = [];
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

    const namespacedClasses = await ctx.tooling.query<ApexClassRecord>(
      'SELECT Id, Name, NamespacePrefix, Body FROM ApexClass WHERE NamespacePrefix != null',
    );

    const handlers: ApexClassRecord[] = [];
    const hiddenNamespaces = new Set<string>();
    for (const c of namespacedClasses) {
      const classBody = c.Body ?? '';
      if (classBody.trim() === HIDDEN_BODY || classBody === '') {
        if (c.NamespacePrefix) hiddenNamespaces.add(c.NamespacePrefix);
      } else if (IMPLEMENTS_INSTALL_HANDLER.test(classBody)) {
        handlers.push(c);
      }
    }

    if (handlers.length > 0) {
      findings.push({
        id: 'package-post-install-system-script',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${handlers.length} packaged class(es) implement InstallHandler and run on install and upgrade`,
        detail:
          'A class implementing InstallHandler runs unattended Apex in system context whenever its package is installed or upgraded, including vendor push upgrades. That execution bypasses admin approval and change-management gates.',
        remediation:
          'Review what each post-install script does, confirm the vendor publishes it, and agree a push-upgrade schedule with the vendor.',
        affectedItems: handlers.map((c) => ({
          label: `${c.NamespacePrefix}.${c.Name}`,
          url: packagesUrl,
          note: 'Implements InstallHandler',
        })),
      });
    }

    if (hiddenNamespaces.size > 0) {
      const namespaces = [...hiddenNamespaces].sort();
      findings.push({
        id: 'package-post-install-unverifiable',
        category: this.category,
        riskLevel: 'INFO',
        title: `${namespaces.length} managed package namespace(s) hide their Apex, so post-install scripts cannot be checked`,
        detail:
          'Managed packages hide their Apex source, so this run cannot tell whether any of them implements InstallHandler. A package that does runs Apex in system context on every install and push upgrade.',
        remediation:
          'Ask each vendor whether the package runs a post-install script and what it does, and review push-upgrade notices before they apply.',
        affectedItems: namespaces.map((ns) => ({ label: `Namespace: ${ns}`, url: packagesUrl })),
      });
    }

    if (handlers.length === 0 && hiddenNamespaces.size === 0) {
      findings.push({
        id: 'package-post-install-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No post-install scripts found in installed packages',
        detail: `${installedPackages.length} package(s) installed; none of their readable Apex implements InstallHandler.`,
        remediation: 'Review post-install scripts and permissions whenever new packages are installed.',
      });
    }

    return { findings };
  }
}
