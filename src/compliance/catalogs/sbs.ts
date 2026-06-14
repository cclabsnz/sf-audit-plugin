import type { ControlDef } from '../types.js';

// Salesforce Security Baseline (SBS) — the project's Salesforce-native control set.
// Drafts (verified:false); requirement wording is confirmed against the baseline in the
// verification pass. Domains: ACS access/sharing, AUTH authentication, CODE code security,
// CPORTAL communities/guest, DATA data protection, DEP deployment, FILE content sharing,
// INT integration, MON monitoring, OAUTH connected apps, SECCONF security configuration.
const V = 'Salesforce Security Baseline';
const ref = (id: string): string => `Salesforce Security Baseline, ${id}`;

export const SBS_CONTROLS: ControlDef[] = [
  // Access Control & Sharing
  { id: 'SBS-ACS-002', framework: 'SBS', version: V, title: 'Permission set sprawl', requirement: 'Permission sets and assignments are minimised and reviewed; unassigned/redundant permission sets are removed.', sourceRef: ref('SBS-ACS-002'), verified: false },
  { id: 'SBS-ACS-004', framework: 'SBS', version: V, title: 'System-wide administrative permissions', requirement: 'High-impact permissions (Modify All Data, View All Data, Author Apex, Customize Application) are restricted to the minimum necessary users.', sourceRef: ref('SBS-ACS-004'), verified: false },
  { id: 'SBS-ACS-005', framework: 'SBS', version: V, title: 'Standard profile usage', requirement: 'Active users are not assigned out-of-the-box standard profiles; least-privilege custom profiles are used instead.', sourceRef: ref('SBS-ACS-005'), verified: false },
  { id: 'SBS-ACS-006', framework: 'SBS', version: V, title: 'API access control', requirement: 'The "Use Any API Client" permission is tightly restricted so API Access Control cannot be bypassed.', sourceRef: ref('SBS-ACS-006'), verified: false },
  { id: 'SBS-ACS-007', framework: 'SBS', version: V, title: 'Inactive and dormant accounts', requirement: 'Active licences without recent login are reviewed and deactivated to reduce standing attack surface.', sourceRef: ref('SBS-ACS-007'), verified: false },
  { id: 'SBS-ACS-008', framework: 'SBS', version: V, title: 'Integration account privilege', requirement: 'Non-human/integration identities are inventoried and granted least privilege, separate from human admin accounts.', sourceRef: ref('SBS-ACS-008'), verified: false },
  { id: 'SBS-ACS-009', framework: 'SBS', version: V, title: 'Service account governance', requirement: 'Service/integration accounts are owned, monitored, and credential-rotated under a defined governance process.', sourceRef: ref('SBS-ACS-009'), verified: false },
  // Authentication
  { id: 'SBS-AUTH-001', framework: 'SBS', version: V, title: 'Single sign-on enforcement', requirement: 'Org-wide SSO is enforced so direct username/password authentication is prevented.', sourceRef: ref('SBS-AUTH-001'), verified: false },
  { id: 'SBS-AUTH-002', framework: 'SBS', version: V, title: 'My Domain login policy', requirement: 'My Domain is configured and login from login.salesforce.com is blocked to prevent SSO bypass.', sourceRef: ref('SBS-AUTH-002'), verified: false },
  { id: 'SBS-AUTH-003', framework: 'SBS', version: V, title: 'Login IP restrictions', requirement: 'Login IP ranges and trusted-IP policy are configured so authentication is constrained and MFA is not broadly bypassed.', sourceRef: ref('SBS-AUTH-003'), verified: false },
  { id: 'SBS-AUTH-004', framework: 'SBS', version: V, title: 'Multi-factor authentication enforcement', requirement: 'MFA is enforced for all internal and external users with data access.', sourceRef: ref('SBS-AUTH-004'), verified: false },
  // Code Security
  { id: 'SBS-CODE-002', framework: 'SBS', version: V, title: 'Apex security and test coverage', requirement: 'Apex follows secure coding practices with adequate test coverage and no injection-prone patterns.', sourceRef: ref('SBS-CODE-002'), verified: false },
  { id: 'SBS-CODE-003', framework: 'SBS', version: V, title: 'Logging framework usage', requirement: 'A persistent logging framework records security-relevant Apex activity for investigation.', sourceRef: ref('SBS-CODE-003'), verified: false },
  { id: 'SBS-CODE-004', framework: 'SBS', version: V, title: 'Sensitive data in logs', requirement: 'Apex logs do not capture credentials or sensitive personal data.', sourceRef: ref('SBS-CODE-004'), verified: false },
  // Communities / Guest / Portal
  { id: 'SBS-CPORTAL-001', framework: 'SBS', version: V, title: 'Apex sharing declarations', requirement: 'Apex classes declare sharing explicitly so guest/portal-reachable code does not bypass record access.', sourceRef: ref('SBS-CPORTAL-001'), verified: false },
  { id: 'SBS-CPORTAL-002', framework: 'SBS', version: V, title: 'Guest user access', requirement: 'Unauthenticated guest users are granted the minimum object permissions and sharing necessary.', sourceRef: ref('SBS-CPORTAL-002'), verified: false },
  { id: 'SBS-CPORTAL-003', framework: 'SBS', version: V, title: 'Experience Cloud site exposure', requirement: 'Live Experience Cloud sites restrict self-registration and guest exposure to prevent unauthenticated account creation/access.', sourceRef: ref('SBS-CPORTAL-003'), verified: false },
  { id: 'SBS-CPORTAL-004', framework: 'SBS', version: V, title: 'Flow sharing context', requirement: 'Active flows do not run in system context without sharing where they handle externally-reachable data.', sourceRef: ref('SBS-CPORTAL-004'), verified: false },
  // Data Protection
  { id: 'SBS-DATA-001', framework: 'SBS', version: V, title: 'Data classification', requirement: 'Sensitive fields are classified using Salesforce data classification metadata.', sourceRef: ref('SBS-DATA-001'), verified: false },
  { id: 'SBS-DATA-002', framework: 'SBS', version: V, title: 'Encryption of sensitive data', requirement: 'Shield Platform Encryption (or equivalent) protects sensitive data at rest where required.', sourceRef: ref('SBS-DATA-002'), verified: false },
  { id: 'SBS-DATA-003', framework: 'SBS', version: V, title: 'Sensitive data handling', requirement: 'Sensitive data is identified and handled according to its classification across the org.', sourceRef: ref('SBS-DATA-003'), verified: false },
  { id: 'SBS-DATA-004', framework: 'SBS', version: V, title: 'Field history tracking', requirement: 'Field history tracking is enabled on sensitive standard objects to support audit and investigation.', sourceRef: ref('SBS-DATA-004'), verified: false },
  // Deployment
  { id: 'SBS-DEP-001', framework: 'SBS', version: V, title: 'Designated deployment identity', requirement: 'Deployments run under a designated, controlled identity rather than ad-hoc admin accounts.', sourceRef: ref('SBS-DEP-001'), verified: false },
  { id: 'SBS-DEP-003', framework: 'SBS', version: V, title: 'Controlled deployment activity', requirement: 'Deployment activity is monitored and controlled to detect uncontrolled or unauthorised changes.', sourceRef: ref('SBS-DEP-003'), verified: false },
  { id: 'SBS-DEP-005', framework: 'SBS', version: V, title: 'No hardcoded credentials', requirement: 'Credentials and secrets are not hardcoded in Apex or metadata.', sourceRef: ref('SBS-DEP-005'), verified: false },
  { id: 'SBS-DEP-006', framework: 'SBS', version: V, title: 'Connected app approval', requirement: 'Connected apps are restricted to admin-approved users and reviewed.', sourceRef: ref('SBS-DEP-006'), verified: false },
  // File / Content Sharing
  { id: 'SBS-FILE-001', framework: 'SBS', version: V, title: 'Public content link expiry', requirement: 'Public content distribution links have expiry dates set.', sourceRef: ref('SBS-FILE-001'), verified: false },
  { id: 'SBS-FILE-002', framework: 'SBS', version: V, title: 'Public content link passwords', requirement: 'Public content distribution links are password-protected where they expose sensitive content.', sourceRef: ref('SBS-FILE-002'), verified: false },
  { id: 'SBS-FILE-003', framework: 'SBS', version: V, title: 'Stale content links', requirement: 'Stale or unused public content links are reviewed and revoked.', sourceRef: ref('SBS-FILE-003'), verified: false },
  // Integration
  { id: 'SBS-INT-002', framework: 'SBS', version: V, title: 'Remote site settings', requirement: 'Remote site registrations use secure protocols and are limited to required endpoints.', sourceRef: ref('SBS-INT-002'), verified: false },
  { id: 'SBS-INT-003', framework: 'SBS', version: V, title: 'Named credential usage', requirement: 'Outbound integrations use Named Credentials rather than hardcoded endpoints/secrets.', sourceRef: ref('SBS-INT-003'), verified: false },
  { id: 'SBS-INT-004', framework: 'SBS', version: V, title: 'Monitoring integration', requirement: 'Security telemetry is integrated with monitoring/SIEM tooling for external visibility.', sourceRef: ref('SBS-INT-004'), verified: false },
  // Monitoring
  { id: 'SBS-MON-001', framework: 'SBS', version: V, title: 'Event monitoring enabled', requirement: 'Event Monitoring is enabled with sufficient log retention to support detection.', sourceRef: ref('SBS-MON-001'), verified: false },
  { id: 'SBS-MON-002', framework: 'SBS', version: V, title: 'Setup audit trail review', requirement: 'The setup audit trail is reviewed for permission changes and Login-As events.', sourceRef: ref('SBS-MON-002'), verified: false },
  { id: 'SBS-MON-003', framework: 'SBS', version: V, title: 'SIEM forwarding', requirement: 'Security events are forwarded to an external SIEM for correlation and alerting.', sourceRef: ref('SBS-MON-003'), verified: false },
  { id: 'SBS-MON-004', framework: 'SBS', version: V, title: 'External monitoring coverage', requirement: 'Monitoring integration covers the security-relevant event sources in the org.', sourceRef: ref('SBS-MON-004'), verified: false },
  { id: 'SBS-MON-005', framework: 'SBS', version: V, title: 'API and resource limit monitoring', requirement: 'API request and resource consumption are monitored against daily/concurrent limits.', sourceRef: ref('SBS-MON-005'), verified: false },
  // OAuth / Connected Apps
  { id: 'SBS-OAUTH-001', framework: 'SBS', version: V, title: 'Connected app restriction', requirement: 'Connected apps are restricted to admin-approved users with appropriate IP/session policy.', sourceRef: ref('SBS-OAUTH-001'), verified: false },
  { id: 'SBS-OAUTH-002', framework: 'SBS', version: V, title: 'OAuth scope and token policy', requirement: 'Connected apps avoid full OAuth scope and infinite refresh-token policies that widen token blast radius.', sourceRef: ref('SBS-OAUTH-002'), verified: false },
  // Security Configuration
  { id: 'SBS-SECCONF-001', framework: 'SBS', version: V, title: 'Security Health Check baseline', requirement: 'The org meets the Salesforce Security Health Check baseline with no unaddressed high-risk settings.', sourceRef: ref('SBS-SECCONF-001'), verified: false },
  { id: 'SBS-SECCONF-002', framework: 'SBS', version: V, title: 'High-risk setting remediation', requirement: 'High-risk security settings flagged by Health Check are remediated to recommended values.', sourceRef: ref('SBS-SECCONF-002'), verified: false },
];
