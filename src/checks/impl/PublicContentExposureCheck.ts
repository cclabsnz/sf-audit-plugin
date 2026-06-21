import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface DocumentRecord {
  Id: string;
  Name: string;
  IsPublic: boolean;
  Folder?: { Name?: string } | null;
}

interface StaticResourceRecord {
  Id: string;
  Name: string;
  CacheControl: string;
  ContentType: string | null;
}

export class PublicContentExposureCheck implements SecurityCheck {
  readonly id = 'public-content-exposure';
  readonly name = 'Public Static Resources & Documents';
  readonly category = 'File Security';
  readonly description =
    'Flags Documents marked externally available (retrievable without authentication) and static resources cached publicly';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const docUrl = `${baseUrl}/lightning/setup/DocumentManagement/home`;
    const resUrl = `${baseUrl}/lightning/setup/StaticResources/home`;

    // 1. Documents flagged "Externally Available Image" (IsPublic) — anonymous URL access.
    try {
      const docs = await ctx.soql.queryAll<DocumentRecord>(
        'SELECT Id, Name, IsPublic, Folder.Name FROM Document WHERE IsPublic = true',
      );
      if (docs.length > 0) {
        findings.push({
          id: 'public-content-public-documents',
          category: this.category,
          riskLevel: 'HIGH',
          title: `${docs.length} Document(s) are marked externally available (public)`,
          detail:
            'A Document with "Externally Available Image" enabled is served from a stable, guessable URL with no authentication. Anyone who obtains or guesses the URL — including search-engine crawlers — can download the file. Documents are frequently used to store images, but also exported reports, spreadsheets, and other data that should not be world-readable.',
          remediation:
            'Review each public Document and clear "Externally Available Image" unless the file is genuinely intended for anonymous access. Move sensitive files to authenticated storage (Files/ContentVersion).',
          affectedItems: docs.map((d) => ({
            label: d.Name,
            url: docUrl,
            note: `Folder: ${d.Folder?.Name ?? 'unknown'} — clear "Externally Available Image" if not intended`,
          })),
        });
      } else {
        findings.push({
          id: 'public-content-documents-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'No externally available Documents found',
          detail: 'No Document is marked "Externally Available Image", so none are retrievable without authentication.',
          remediation: 'Continue to keep Documents private unless anonymous access is explicitly required.',
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'public-content-documents-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Public Documents could not be read',
        detail: `The Document query was not accessible: ${msg}`,
        remediation: 'Grant the audit user read access to Documents, then re-run the audit.',
      });
    }

    // 2. Static resources with public cache control — cacheable by shared/CDN caches.
    try {
      const resources = await ctx.tooling.query<StaticResourceRecord>(
        "SELECT Id, Name, CacheControl, ContentType FROM StaticResource WHERE CacheControl = 'Public'",
      );
      if (resources.length > 0) {
        findings.push({
          id: 'public-content-public-static-resources',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `${resources.length} static resource(s) use Public cache control`,
          detail:
            'A static resource set to "Public" cache control is served with caching headers that allow shared and CDN caches to store it, and it is reachable by guest users on Experience Cloud sites. Static resources commonly bundle JavaScript, config, and occasionally secrets (API keys, endpoints); a Public resource widens who can retrieve those contents.',
          remediation:
            'Set cache control to "Private" for any static resource that is not deliberately public, and remove embedded secrets from static resource contents.',
          affectedItems: resources.map((r) => ({
            label: r.Name,
            url: resUrl,
            note: `${r.ContentType ?? 'unknown type'} — set cache control to Private if not intentionally public`,
          })),
        });
      } else {
        findings.push({
          id: 'public-content-static-resources-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'No static resources use Public cache control',
          detail: 'All static resources use Private cache control or none exist.',
          remediation: 'Continue to keep static resources Private unless public delivery is required.',
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'public-content-static-resources-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Static resource cache settings could not be read',
        detail: `The StaticResource Tooling query was not accessible: ${msg}`,
        remediation: 'Grant the audit user "View Setup and Configuration", then re-run the audit.',
      });
    }

    return { findings };
  }
}
