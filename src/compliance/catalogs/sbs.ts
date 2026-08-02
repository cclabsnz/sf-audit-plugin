import type { ControlDef } from '../types.js';

// Security Benchmark for Salesforce (SBS) — an independent, public Salesforce security standard.
// Titles VERIFIED 2026-06 against the official catalog: https://docs.securitybenchmark.org/controls-at-a-glance.html
// `title` is the verbatim official control statement; `requirement` is a faithful one-line summary.
const V = 'Security Benchmark for Salesforce (SBS)';
const ref = (id: string): string => `Security Benchmark for Salesforce, ${id}`;
const URL = 'https://docs.securitybenchmark.org/controls-at-a-glance.html';

export const SBS_CONTROLS: ControlDef[] = [
  // Access Controls
  { id: 'SBS-ACS-002', framework: 'SBS', version: V, title: 'Documented Justification for All API-Enabled Authorizations', requirement: 'Every grant of the API Enabled permission is justified and documented.', sourceRef: ref('SBS-ACS-002'), url: URL, verified: true },
  { id: 'SBS-ACS-004', framework: 'SBS', version: V, title: 'Documented Justification for All Super Admin–Equivalent Users', requirement: 'Users with super-admin-equivalent permissions (Modify All Data, etc.) are justified and documented.', sourceRef: ref('SBS-ACS-004'), url: URL, verified: true },
  { id: 'SBS-ACS-005', framework: 'SBS', version: V, title: 'Only Use Custom Profiles for Active Users', requirement: 'Active users are assigned least-privilege custom profiles, not standard profiles.', sourceRef: ref('SBS-ACS-005'), url: URL, verified: true },
  { id: 'SBS-ACS-006', framework: 'SBS', version: V, title: 'Documented Justification for Use Any API Client Permission', requirement: 'Every grant of the "Use Any API Client" permission is justified and documented.', sourceRef: ref('SBS-ACS-006'), url: URL, verified: true },
  { id: 'SBS-ACS-007', framework: 'SBS', version: V, title: 'Maintain Inventory of Non-Human Identities', requirement: 'A current inventory of non-human/integration identities is maintained.', sourceRef: ref('SBS-ACS-007'), url: URL, verified: true },
  { id: 'SBS-ACS-008', framework: 'SBS', version: V, title: 'Restrict Broad Privileges for Non-Human Identities', requirement: 'Non-human identities are not granted broad or excessive privileges.', sourceRef: ref('SBS-ACS-008'), url: URL, verified: true },
  { id: 'SBS-ACS-009', framework: 'SBS', version: V, title: 'Implement Compensating Controls for Privileged Non-Human Identities', requirement: 'Privileged non-human identities have compensating controls (IP restriction, monitoring).', sourceRef: ref('SBS-ACS-009'), url: URL, verified: true },
  // Authentication
  { id: 'SBS-AUTH-001', framework: 'SBS', version: V, title: 'Enable Organization-Wide SSO Enforcement Setting', requirement: 'Org-wide single sign-on enforcement is enabled.', sourceRef: ref('SBS-AUTH-001'), url: URL, verified: true },
  { id: 'SBS-AUTH-002', framework: 'SBS', version: V, title: 'Govern and Document All Users Permitted to Bypass Single Sign-On', requirement: 'Users allowed to bypass SSO are governed and documented.', sourceRef: ref('SBS-AUTH-002'), url: URL, verified: true },
  { id: 'SBS-AUTH-003', framework: 'SBS', version: V, title: 'Prohibit Broad or Unrestricted Profile Login IP Ranges', requirement: 'Profile login IP ranges are not broad or unrestricted (which would bypass MFA).', sourceRef: ref('SBS-AUTH-003'), url: URL, verified: true },
  { id: 'SBS-AUTH-004', framework: 'SBS', version: V, title: 'Enforce Strong Multi-Factor Authentication for External Users', requirement: 'Strong MFA is enforced for external/portal users.', sourceRef: ref('SBS-AUTH-004'), url: URL, verified: true },
  // Code Security
  { id: 'SBS-CODE-002', framework: 'SBS', version: V, title: 'Pre-Merge Static Code Analysis for Apex and LWC', requirement: 'Static code analysis runs on Apex and LWC before merge.', sourceRef: ref('SBS-CODE-002'), url: URL, verified: true },
  { id: 'SBS-CODE-003', framework: 'SBS', version: V, title: 'Implement Persistent Apex Application Logging', requirement: 'A persistent Apex application logging framework is in place.', sourceRef: ref('SBS-CODE-003'), url: URL, verified: true },
  { id: 'SBS-CODE-004', framework: 'SBS', version: V, title: 'Prevent Sensitive Data in Application Logs', requirement: 'Application logs do not capture sensitive data.', sourceRef: ref('SBS-CODE-004'), url: URL, verified: true },
  // Customer Portals
  { id: 'SBS-CPORTAL-001', framework: 'SBS', version: V, title: 'Prevent Parameter-Based Record Access in Portal Apex', requirement: 'Portal-reachable Apex does not allow parameter-based record access bypassing sharing.', sourceRef: ref('SBS-CPORTAL-001'), url: URL, verified: true },
  { id: 'SBS-CPORTAL-002', framework: 'SBS', version: V, title: 'Restrict Guest User Record Access', requirement: 'Guest user record access is restricted to the minimum necessary.', sourceRef: ref('SBS-CPORTAL-002'), url: URL, verified: true },
  { id: 'SBS-CPORTAL-003', framework: 'SBS', version: V, title: 'Inventory Portal-Exposed Apex Classes and Flows', requirement: 'Portal-exposed Apex classes and flows are inventoried.', sourceRef: ref('SBS-CPORTAL-003'), url: URL, verified: true },
  { id: 'SBS-CPORTAL-004', framework: 'SBS', version: V, title: 'Prevent Parameter-Based Record Access in Portal-Exposed Flows', requirement: 'Portal-exposed flows do not allow parameter-based record access bypassing sharing.', sourceRef: ref('SBS-CPORTAL-004'), url: URL, verified: true },
  // Data Security
  { id: 'SBS-DATA-001', framework: 'SBS', version: V, title: 'Implement Mechanisms to Detect Regulated Data in Long Text Fields', requirement: 'Mechanisms detect regulated data stored in long text fields.', sourceRef: ref('SBS-DATA-001'), url: URL, verified: true },
  { id: 'SBS-DATA-002', framework: 'SBS', version: V, title: 'Maintain an Inventory of Long Text Area Fields Containing Data', requirement: 'An inventory of long text area fields containing data is maintained.', sourceRef: ref('SBS-DATA-002'), url: URL, verified: true },
  { id: 'SBS-DATA-003', framework: 'SBS', version: V, title: 'Maintain Tested Backup and Recovery for Salesforce Data', requirement: 'Tested backup and recovery is maintained for Salesforce data.', sourceRef: ref('SBS-DATA-003'), url: URL, verified: true },
  { id: 'SBS-DATA-004', framework: 'SBS', version: V, title: 'Require Field History Tracking for Sensitive Fields', requirement: 'Field history tracking is enabled for sensitive fields.', sourceRef: ref('SBS-DATA-004'), url: URL, verified: true },
  // Deployments
  { id: 'SBS-DEP-001', framework: 'SBS', version: V, title: 'Require a Designated Deployment Identity for Metadata Changes', requirement: 'Metadata changes deploy under a designated deployment identity.', sourceRef: ref('SBS-DEP-001'), url: URL, verified: true },
  { id: 'SBS-DEP-003', framework: 'SBS', version: V, title: 'Monitor and Alert on Unauthorized Modifications to High-Risk Metadata', requirement: 'Unauthorized changes to high-risk metadata are monitored and alerted.', sourceRef: ref('SBS-DEP-003'), url: URL, verified: true },
  { id: 'SBS-DEP-005', framework: 'SBS', version: V, title: 'Implement Secret Scanning for Salesforce Source Repositories', requirement: 'Secret scanning runs on Salesforce source repositories.', sourceRef: ref('SBS-DEP-005'), url: URL, verified: true },
  { id: 'SBS-DEP-006', framework: 'SBS', version: V, title: 'Configure Salesforce CLI Connected App with Token Expiration', requirement: 'The Salesforce CLI connected app is configured with token expiration.', sourceRef: ref('SBS-DEP-006'), url: URL, verified: true },
  // File Security
  { id: 'SBS-FILE-001', framework: 'SBS', version: V, title: 'Require Expiry Dates on Public Content Links', requirement: 'Public content links require expiry dates.', sourceRef: ref('SBS-FILE-001'), url: URL, verified: true },
  { id: 'SBS-FILE-002', framework: 'SBS', version: V, title: 'Require Passwords on Public Content Links for Sensitive Content', requirement: 'Public content links for sensitive content require passwords.', sourceRef: ref('SBS-FILE-002'), url: URL, verified: true },
  { id: 'SBS-FILE-003', framework: 'SBS', version: V, title: 'Periodic Review and Cleanup of Public Content Links', requirement: 'Public content links are periodically reviewed and cleaned up.', sourceRef: ref('SBS-FILE-003'), url: URL, verified: true },
  // Integrations
  { id: 'SBS-INT-002', framework: 'SBS', version: V, title: 'Inventory and Justification of Remote Site Settings', requirement: 'Remote site settings are inventoried and justified.', sourceRef: ref('SBS-INT-002'), url: URL, verified: true },
  { id: 'SBS-INT-003', framework: 'SBS', version: V, title: 'Inventory and Justification of Named Credentials', requirement: 'Named credentials are inventoried and justified.', sourceRef: ref('SBS-INT-003'), url: URL, verified: true },
  { id: 'SBS-INT-004', framework: 'SBS', version: V, title: 'Retain API Total Usage Event Logs for 30 Days', requirement: 'API Total Usage event logs are retained for at least 30 days.', sourceRef: ref('SBS-INT-004'), url: URL, verified: true },
  // Event Monitoring
  { id: 'SBS-MON-001', framework: 'SBS', version: V, title: 'Enable Event Monitoring Log Storage', requirement: 'Event Monitoring log storage is enabled.', sourceRef: ref('SBS-MON-001'), url: URL, verified: true },
  { id: 'SBS-MON-002', framework: 'SBS', version: V, title: 'Retaining Event Logs', requirement: 'Event logs are retained for an adequate period.', sourceRef: ref('SBS-MON-002'), url: URL, verified: true },
  { id: 'SBS-MON-003', framework: 'SBS', version: V, title: 'Monitor for Suspicious Logins', requirement: 'Suspicious logins are monitored and alerted.', sourceRef: ref('SBS-MON-003'), url: URL, verified: true },
  { id: 'SBS-MON-004', framework: 'SBS', version: V, title: 'Monitor for Suspicious API Activity', requirement: 'Suspicious API activity is monitored and alerted.', sourceRef: ref('SBS-MON-004'), url: URL, verified: true },
  { id: 'SBS-MON-005', framework: 'SBS', version: V, title: 'Monitor API Usage Against Limits', requirement: 'API usage is monitored against daily and concurrent limits.', sourceRef: ref('SBS-MON-005'), url: URL, verified: true },
  // OAuth Security
  { id: 'SBS-OAUTH-001', framework: 'SBS', version: V, title: 'Require Formal Installation of Connected Apps', requirement: 'Connected apps require formal installation.', sourceRef: ref('SBS-OAUTH-001'), url: URL, verified: true },
  { id: 'SBS-OAUTH-002', framework: 'SBS', version: V, title: 'Require Profile or Permission Set Access Control for Connected Apps', requirement: 'Connected apps require profile or permission-set access control (admin-approved users).', sourceRef: ref('SBS-OAUTH-002'), url: URL, verified: true },
  // Security Configuration
  { id: 'SBS-SECCONF-001', framework: 'SBS', version: V, title: 'Establish a Salesforce Health Check Baseline', requirement: 'A Salesforce Health Check baseline is established.', sourceRef: ref('SBS-SECCONF-001'), url: URL, verified: true },
  { id: 'SBS-SECCONF-002', framework: 'SBS', version: V, title: 'Review and Remediate Salesforce Health Check Deviations', requirement: 'Health Check deviations from baseline are reviewed and remediated.', sourceRef: ref('SBS-SECCONF-002'), url: URL, verified: true },
];
