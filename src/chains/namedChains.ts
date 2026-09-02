// src/chains/namedChains.ts
import type { RiskLevel } from '@cclabsnz/sf-core';
import type { Finding } from '../findings/Finding.js';
import type { Capability } from './Capability.js';
import { capabilitiesFor } from './CapabilityRegistry.js';

export interface NamedChainDef {
  id: string;
  title: string;
  severity: RiskLevel;
  narrative: string;
  remediation: string;
  /** Returns the member findings (chain steps) if present in this org, else null. */
  match(present: Set<Capability>, active: Finding[]): Finding[] | null;
}

const has = (s: Set<Capability>, ...caps: Capability[]): boolean => caps.every((c) => s.has(c));
const hasAny = (s: Set<Capability>, ...caps: Capability[]): boolean => caps.some((c) => s.has(c));
const byIds = (active: Finding[], ids: string[]): Finding[] =>
  active.filter((f) => ids.includes(f.id));
// The AI & Agents findings carry dynamic id suffixes (userId, agent dev name, channel slug,
// domain), so their chain ingredients are matched by id prefix rather than exact id.
const byPrefixes = (active: Finding[], prefixes: string[]): Finding[] =>
  active.filter((f) => prefixes.some((p) => f.id === p || f.id.startsWith(p)));

export const NAMED_CHAINS: NamedChainDef[] = [
  {
    id: 'unauth-bulk-exfil',
    title: 'Unauthenticated bulk exfiltration',
    severity: 'CRITICAL',
    narrative:
      'An unauthenticated guest foothold combines with guest-reachable code execution or public ' +
      'external sharing to read business data in bulk without any login. In practice this is ' +
      'reached over the site\'s Aura endpoint (/s/sfsites/aura) with aura.token=null: ' +
      'RecordUiController/ACTION$executeGraphQL returns record data the guest user can see, and ' +
      'aura.ApexAction.execute invokes @AuraEnabled Apex — which, in a class that runs without ' +
      'sharing, skips record-level access control entirely and will accept arbitrary record ids. ' +
      'No credentials are involved at any point, so login-based controls (MFA, IP ranges, SSO) ' +
      'never engage.',
    remediation:
      'Remove guest object/sharing access, ensure no guest-invokable Apex runs without sharing, ' +
      'and set external OWD to Private. Grant portal access only via sharing sets. Because the ' +
      'requests never reach a login page, tightening authentication does not mitigate this — the ' +
      'object permissions, sharing model and Apex sharing declarations are the controls that apply.',
    match(present, active) {
      if (!has(present, 'unauth-foothold')) return null;
      if (!hasAny(present, 'code-exec', 'data-read-bulk', 'data-write')) return null;
      const steps = byIds(active, [
        'guest-user-read-access', 'guest-user-write-access', 'guest-user-sharing-exposure', 'guest-user-baseline',
        'guest-executable-apex-unprotected', 'guest-executable-apex-exposed',
        'guest-object-exposure-public-owd', 'guest-object-exposure-guest-owned',
        'guest-api-access-enabled', 'guest-api-hard-delete', 'classic-sites-active',
        'guest-user-visibility-view-all-users', 'guest-user-visibility-owd', 'guest-user-visibility-object-read',
        'portal-exposed-apex-without-sharing', 'sharing-model-external-read', 'sharing-model-external-write',
        'field-level-security-high', 'field-level-security-medium',
        // The guardrail whose absence lets guest-owned records defeat a Private OWD, and the Flow
        // analogue of portal-exposed Apex running without sharing.
        'guest-record-access-policy-not-enforced',
        'flows-autolaunched-without-sharing', 'flows-screen-without-sharing',
      ]);
      return steps.length >= 2 ? steps : null;
    },
  },
  {
    id: 'active-guest-exfil',
    title: 'Active guest reconnaissance against an exposed data surface',
    severity: 'CRITICAL',
    narrative:
      'Live EventLogFile evidence shows unauthenticated guests probing from anonymizer/hosting IPs or ' +
      'running GraphQL object-enumeration (totalCount) sweeps, AND the org exposes objects that are ' +
      'bulk-readable by those same guests. The sweeps arrive as AuraRequest/GraphQlQueryExecution ' +
      'events against /s/sfsites/aura — aura://RecordUiController/ACTION$executeGraphQL asking only ' +
      'for totalCount per object, which is how an attacker maps the readable surface before pulling ' +
      'from it. This is not a theoretical exposure — it is reconnaissance against a confirmed ' +
      'exfiltration surface, i.e. an incident likely already in progress.',
    remediation:
      'Treat as an active incident: block the source IPs at the WAF/CDN, close the guest bulk-read surface ' +
      '(set external OWD to Private, strip guest object read, enforce "Secure guest user record access"), ' +
      'and preserve/forward the event logs before the short EventLogFile retention window closes.',
    match(_present, active) {
      const traffic = byIds(active, ['guest-traffic-anomaly-recon', 'guest-traffic-anomaly-anonymizer']);
      // A readable User roster counts as an exposed surface in its own right — recon against an org
      // that leaks its staff list is the same incident. The object-level Read grant is excluded: on
      // its own it is not a confirmed exposure, and this chain asserts one already in progress.
      const exposure = byIds(active, [
        'guest-object-exposure-public-owd', 'guest-object-exposure-guest-owned',
        'guest-user-visibility-view-all-users', 'guest-user-visibility-owd',
      ]);
      if (traffic.length === 0 || exposure.length === 0) return null;
      return [...traffic, ...exposure];
    },
  },
  {
    id: 'standard-to-takeover',
    title: 'Standard user to org takeover',
    severity: 'CRITICAL',
    narrative:
      'A low-trust authenticated user combines with a privilege-escalation permission ' +
      '(assign permission sets, manage users, author apex, modify metadata) to reach full org control.',
    remediation:
      'Remove escalation permissions from non-admin profiles/permission sets and review who holds them.',
    match(present, active) {
      if (!hasAny(present, 'low-trust-authenticated', 'unauth-foothold')) return null;
      if (!hasAny(present, 'priv-esc', 'org-takeover')) return null;
      const steps = byIds(active, [
        'sharing-model-external-read', 'sharing-model-external-write', 'guest-user-baseline',
        'escalation-perms-found', 'users-author-apex', 'users-super-admin-combo',
        'login-access-policy-delegated-admins', 'login-access-policy-login-as-enabled',
        // Admin-equivalent users off the System Administrator profile, and the toxic combinations
        // that let one user grant themselves access, are escalation steps in their own right.
        'privileged-access-shadow-admins',
        'separation-of-duties-self-escalation', 'separation-of-duties-identity-takeover',
        'separation-of-duties-grant-self-data',
      ]);
      return steps.length >= 2 ? steps : null;
    },
  },
  {
    id: 'cred-theft-pivot',
    title: 'Credential theft to external pivot',
    severity: 'CRITICAL',
    narrative:
      'Exposed secrets (hardcoded credentials, credentials in custom labels, debug logs, or broad CORS) ' +
      'combine with an external egress path (named credential or remote site) to exfiltrate data to attacker infrastructure.',
    remediation:
      'Rotate and remove exposed secrets, tighten CORS origins, and review external callout endpoints.',
    match(present, active) {
      if (!has(present, 'credential-theft', 'external-egress')) return null;
      const steps = byIds(active, [
        'hardcoded-credentials-found', 'custom-labels-credential-value-match', 'custom-labels-credential-name-match',
        'debug-log-active-traces', 'cors-wildcard-origin', 'cors-broad-origin',
        'named-credentials-inventory', 'named-credentials-http-endpoint', 'remote-sites-inventory',
        // A user who can stand up connected apps and bypass API access control has provisioned
        // their own egress path.
        'separation-of-duties-external-exfil-channel',
      ]);
      return steps.length >= 2 ? steps : null;
    },
  },
  {
    id: 'soql-injection-read',
    title: 'SOQL injection to mass read',
    severity: 'HIGH',
    narrative:
      'Injectable dynamic SOQL combines with bulk data readability to let an attacker extract large datasets.',
    remediation:
      'Use bind variables in all dynamic SOQL and enforce CRUD/FLS; restrict bulk read access.',
    match(present, active) {
      if (!has(present, 'code-exec')) return null;
      const inj = byIds(active, ['soql-injection-risk']);
      if (inj.length === 0) return null;
      const sink = byIds(active, [
        'sharing-model-external-read', 'sharing-model-external-write',
        'field-level-security-high', 'field-level-security-medium', 'users-view-all-data',
        'public-group-sharing-exposure', 'report-folder-access-public',
        'encryption-coverage-unencrypted-sensitive',
      ]);
      return sink.length > 0 ? [...inj, ...sink] : null;
    },
  },
  {
    id: 'prompt-injection-blast-radius',
    title: 'Prompt injection blast radius',
    severity: 'CRITICAL',
    narrative:
      'A guest-reachable Agentforce channel lets an unauthenticated attacker send prompt-injection input to an ' +
      'agent that runs as an over-privileged user (Modify/View All Data or broad object write) and can drive ' +
      'write-capable actions. Public input, privileged identity, and state-changing actions are all present at ' +
      'once, so a single injected prompt can read, alter, or destroy data across the agent\'s reach. ' +
      'Note this does NOT ride the site\'s Aura endpoint: agent conversations go to the org\'s messaging host ' +
      '(<subdomain>.my.salesforce-scrt.com) over the Messaging for In-App and Web API (/iamessage/api/v2/...). ' +
      'Guest reachability comes from that API\'s unauthenticated access-token flow, which needs only the org id ' +
      'and the Embedded Service deployment\'s API name (esDeveloperName) — both of which appear in the ' +
      'client-side bootstrap of any page hosting the widget. That flow is a supported configuration for public ' +
      'support chat; the risk here is not the channel existing, it is the channel reaching a privileged agent.',
    remediation:
      'Break any one link: remove the guest/public binding, scope the agent run-as user to least privilege, ' +
      'or remove write-capable actions from the exposed agent (and add confirmation/guardrails where they must stay).',
    match(_present, active) {
      const channel = byPrefixes(active, ['agent-channel-exposure-guest-']);
      const privilege = byPrefixes(active, [
        'agent-user-privilege-admin-', 'agent-user-privilege-broad-write-',
      ]);
      const actions = byIds(active, ['agent-action-surface-write']);
      if (channel.length === 0 || privilege.length === 0 || actions.length === 0) return null;
      return [...channel, ...privilege, ...actions];
    },
  },
  {
    id: 'forcedleak-pattern',
    title: 'ForcedLeak pattern',
    severity: 'CRITICAL',
    narrative:
      'Active Agentforce agents run in an org that has a stale CSP-trusted domain (unresolvable or parked) on ' +
      'its allowlist and no Event Monitoring capture of agent activity. This is the exact ForcedLeak chain ' +
      '(Noma Security, Sept 2025): an attacker registers the lapsed allowlisted domain, prompt-injects an agent ' +
      'into sending data to it, and nothing records or responds to the exfiltration.',
    remediation:
      'Remove or reclaim the stale trusted domain immediately, then enable Event Monitoring (and pull agent logs ' +
      'with `sf audit events pull`) plus a Transaction Security policy so agent-driven exfiltration is detected.',
    match(_present, active) {
      const agents = byIds(active, ['agent-inventory-summary']);
      const staleUrl = byPrefixes(active, [
        'trusted-url-hygiene-unresolvable-', 'trusted-url-hygiene-parked-',
      ]);
      const noCapture = byIds(active, ['agent-monitoring-coverage-none']);
      if (agents.length === 0 || staleUrl.length === 0 || noCapture.length === 0) return null;
      return [...agents, ...staleUrl, ...noCapture];
    },
  },
  {
    id: 'sandbox-pii-exposure',
    title: 'Unmasked production PII in a weakly-controlled sandbox',
    severity: 'HIGH',
    narrative:
      'This sandbox holds populated PII fields — almost certainly a copy of production data that was ' +
      'never masked — and it is not held to production access standards. Sandboxes routinely carry ' +
      'more admins, weaker authentication and broader sharing than the org they were refreshed from, ' +
      'so the same records sit behind materially weaker controls. The data is real; only the ' +
      'protection is not.',
    remediation:
      'Run Salesforce Data Mask on the sandbox (or refresh without production data), and bring its ' +
      'authentication and sharing configuration up to production standard for as long as real data ' +
      'remains in it.',
    match(_present, active) {
      const pii = byIds(active, ['sandbox-data-masking-pii-present']);
      if (pii.length === 0) return null;
      const weakControls = byIds(active, [
        'internal-user-mfa-gaps', 'trusted-ip-broad-ranges', 'mfa-portal-users-without-enforcement',
        'public-group-sharing-exposure', 'report-folder-access-public', 'standard-profiles-in-use',
        'privileged-access-shadow-admins', 'sharing-model-external-read', 'sharing-model-external-write',
        'guest-user-read-access', 'guest-user-write-access', 'guest-user-sharing-exposure',
      ]);
      return weakControls.length > 0 ? [...pii, ...weakControls] : null;
    },
  },
  {
    id: 'insider-bulk-exfil',
    title: 'Insider bulk export without monitoring',
    severity: 'HIGH',
    narrative:
      'Business data is readable in bulk by any authenticated internal user, at least one profile or ' +
      'permission set can export it en masse (Weekly Data Export, or API access combined with ' +
      'View/Modify All Data), and there is no monitoring that would record the export happening. ' +
      'Broad read plus bulk egress plus no audit trail is the insider-threat and post-credential-' +
      'compromise path — and the missing third element is what makes it unreconstructable afterwards.',
    remediation:
      'Narrow the broad internal sharing, restrict Weekly Data Export and Bulk API access to a named ' +
      'few, and enable Event Monitoring (plus forwarding to a SIEM) so bulk reads are recorded and ' +
      'alertable.',
    match(_present, active) {
      const broadRead = byIds(active, [
        'public-group-sharing-exposure', 'report-folder-access-public',
        'users-view-all-data', 'users-modify-all-data',
      ]);
      const bulkEgress = byIds(active, [
        'data-export-weekly-export', 'data-export-bulk-api-viewall',
        'separation-of-duties-external-exfil-channel',
      ]);
      const blindSpot = byIds(active, [
        'event-monitoring-disabled', 'siem-integration-not-detected', 'event-monitoring-retention-short',
      ]);
      if (broadRead.length === 0 || bulkEgress.length === 0 || blindSpot.length === 0) return null;
      return [...broadRead, ...bulkEgress, ...blindSpot];
    },
  },
  {
    id: 'undetected-compromise',
    title: 'Exploitable access with no detection coverage',
    severity: 'MEDIUM',
    narrative:
      'The org already presents a real attacker capability — an unauthenticated foothold, a ' +
      'privilege-escalation path, or org takeover — and simultaneously lacks the controls that ' +
      'would notice it being used. Two or more of threat detection, Event Monitoring, a Transaction ' +
      'Security policy and SIEM forwarding are absent. This chain does not add exposure; it means ' +
      'the exposure already present would go unobserved, and an incident could not be reconstructed.',
    remediation:
      'Close the detection gap first: enable Event Monitoring with adequate retention, turn on threat ' +
      'detection event storage, add a Transaction Security policy, and forward events to a SIEM. Then ' +
      'remediate the underlying access findings.',
    match(present, active) {
      if (!hasAny(present, 'unauth-foothold', 'priv-esc', 'org-takeover')) return null;
      const blindSpots = byIds(active, [
        'threat-detection-inactive', 'threat-detection-guest-anomaly-missing',
        'event-monitoring-disabled', 'event-monitoring-retention-short',
        'transaction-security-policy-none', 'siem-integration-not-detected', 'siem-retention-gap',
      ]);
      // One missing control is a finding on its own; two or more is a systemic blind spot. Requiring
      // two keeps this from firing on every org that has not bought Shield.
      if (blindSpots.length < 2) return null;
      const exposure = active.filter((f) => {
        const g = capabilitiesFor(f).grants;
        return g.includes('unauth-foothold') || g.includes('priv-esc') || g.includes('org-takeover');
      });
      return exposure.length > 0 ? [...exposure.slice(0, 3), ...blindSpots] : null;
    },
  },
  {
    id: 'mfa-bypass-admin',
    title: 'MFA bypass to privileged compromise',
    severity: 'HIGH',
    narrative:
      'Weak MFA enforcement or trusted-IP MFA bypass combines with the presence of highly-privileged ' +
      'accounts, so a credential-stuffing or phishing attacker can take over an admin without a second factor.',
    remediation:
      'Enforce MFA for all internal users, remove trusted-IP MFA bypass ranges, and minimise privileged accounts.',
    match(_present, active) {
      const weakness = byIds(active, [
        'trusted-ip-broad-ranges', 'internal-user-mfa-gaps', 'mfa-portal-users-without-enforcement',
      ]);
      const targets = byIds(active, [
        'users-modify-all-data', 'users-view-all-data', 'users-super-admin-combo',
        'privileged-access-shadow-admins', 'separation-of-duties-self-escalation',
      ]);
      return weakness.length > 0 && targets.length > 0 ? [...weakness, ...targets] : null;
    },
  },
];
