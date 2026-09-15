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
        // An integration account holding Author Apex, Customize Application or user-management
        // permissions it does not use has the same escalation reach as users-author-apex above.
        'integration-least-privilege-escalation-permissions',
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
        // An unused Data Export or View All Users grant on an integration account is the same
        // bulk-read reach as the other members of this set.
        'integration-least-privilege-data-permissions',
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
  {
    id: 'oauth-standing-access',
    title: 'Standing OAuth access outside every login control',
    severity: 'HIGH',
    narrative:
      'A connected app holds broad standing API access, and something in the org means nobody would ' +
      'notice it being used. The distinction that matters here is that a refresh token is not a ' +
      'session. Login controls — MFA, login IP ranges, SSO, session timeout — engage once, at the ' +
      'moment the app is authorised, and never again: every later API call exchanges the refresh ' +
      'token for an access token without a login, so an org can enforce MFA on every human and still ' +
      'hand a token holder the same reach. Full scope makes that reach equal to the authorising ' +
      'user, including Modify All Data where that user is an admin, and a refresh token with no ' +
      'expiry makes it permanent until somebody revokes it. ' +
      'The token exchange produces no OAuth login row, so this access is absent from LoginHistory ' +
      'and invisible to the connected-app inactivity check — which is why a token that has gone ' +
      'unused for months, or that belongs to an app no longer in the connected app list, is the ' +
      'shape a forgotten or third-party integration leaves behind. That is the path the 2025 and ' +
      '2026 campaigns against Salesforce customers took: the tokens were not stolen from the org, ' +
      'they were taken from the integration vendor and replayed against it, with no login and no ' +
      'user interaction anywhere in the victim org.',
    remediation:
      'Revoke first and tidy later. Any standing token whose app is not in the current connected app ' +
      'list, or that has not been used in months, should be revoked now rather than investigated ' +
      'first — re-authorising a live integration is a minor inconvenience, and a token is a working ' +
      'credential for as long as it exists. Then replace the Full scope with the specific scopes an ' +
      'integration actually uses, set a refresh token policy that expires on inactivity instead of ' +
      'never, and stop relaxing IP enforcement for connected apps, since that removes the one ' +
      'control still applying after authorisation. Treat a vendor breach notice as a trigger to ' +
      'revoke every token for that publisher rather than waiting to confirm your own org was ' +
      'touched: with no login row to search, absence of evidence is not evidence of absence here.',
    match(_present, active) {
      // Standing reach: a token that can act broadly, and keeps being able to.
      const standing = byIds(active, [
        'connected-app-full-scope-infinite-token',
        'connected-app-full-scope',
        'connected-app-infinite-refresh-token',
      ]);
      if (standing.length === 0) return null;
      // What removes the containment or the observation. Any one of these turns standing access
      // into access nobody is watching or limiting.
      const uncontained = byIds(active, [
        // Nobody is reviewing it: tokens with no matching app, or long unused.
        'oauth-token-unmatched-app', 'oauth-token-stale', 'oauth-token-no-app-inventory',
        // Nothing is limiting it: the network control that survives authorisation, removed.
        'connected-apps-bypass-ip', 'connected-apps-relax-ip', 'unrestricted-connected-apps',
        'connected-apps-long-session-timeout', 'admin-no-ip-restrictions',
        // The authorising identity is worth more than it needs to be, so the token inherits more.
        'integration-least-privilege-escalation-permissions',
        'integration-least-privilege-data-permissions',
        'api-client-permission-assigned',
      ]);
      if (uncontained.length === 0) return null;
      return [...standing, ...uncontained];
    },
  },
  {
    id: 'self-registration-foothold',
    title: 'Self-service registration into an over-shared portal',
    severity: 'HIGH',
    narrative:
      'A live Experience Cloud site accepts self-registration, and the external sharing model or ' +
      'portal-reachable code gives whoever holds an account more than their own records. Every other ' +
      'chain that starts from "an authenticated external user" assumes the attacker already has an ' +
      'account; this is the one that says anyone may have one, for the cost of an email address. ' +
      'The account is legitimate, so it arrives through the front door with a real session: MFA, ' +
      'login IP ranges and SSO all behave exactly as configured and none of them object, because ' +
      'nothing here is a bypass. What the attacker gets is decided entirely by the external OWD, ' +
      'the portal profile and whether the Apex or Flow reachable from the site enforces sharing. ' +
      'Self-registration alone is a supported feature and not a finding; the sharing model alone ' +
      'assumes an account the attacker may never obtain. The pair is the path.',
    remediation:
      'Decide which half to close, because either breaks the chain. Turning self-registration off, ' +
      'or putting an approval step in front of it, restores the assumption every other control ' +
      'depends on. Leaving it on means treating the self-registration profile as hostile input: ' +
      'set external OWD to Private and grant through sharing sets rather than org-wide defaults, ' +
      'and make sure Apex and Flows reachable from the site run with sharing. Check what the ' +
      'self-registration handler assigns as the default profile and licence — the exposure is ' +
      'whatever that profile can reach, and it is rarely reviewed after the site goes live.',
    match(_present, active) {
      const acquisition = byIds(active, ['experience-cloud-site-self-registration']);
      if (acquisition.length === 0) return null;
      // What an account is worth once obtained. Deliberately excludes report-folder-access-public:
      // it is real for internal users, but a self-registered portal account is a Customer Community
      // licence, which generally has no report access at all, so including it would overstate reach.
      const reach = byIds(active, [
        'sharing-model-external-read', 'sharing-model-external-write',
        'portal-exposed-apex-without-sharing',
        'flows-autolaunched-without-sharing', 'flows-screen-without-sharing',
        'apex-rest-without-sharing',
      ]);
      if (reach.length === 0) return null;
      // Social sign-on is a second way in rather than a requirement, so it joins as evidence when
      // present but never gates the chain on its own.
      const alsoOpen = byIds(active, ['auth-providers-social']);
      return [...acquisition, ...reach, ...alsoOpen];
    },
  },
  {
    id: 'session-id-egress',
    title: 'Live session ID handed to an external endpoint',
    severity: 'HIGH',
    narrative:
      'A workflow outbound message is configured to include the Salesforce session ID, so every time ' +
      'it fires the org sends a working credential to a third-party endpoint. This is a supported ' +
      'option rather than a flaw, which is exactly why it survives: it was switched on to let the ' +
      'receiving system call back into Salesforce, and it never came off. The session it hands over ' +
      'acts as the outbound message\'s running user for as long as it is valid, and nothing about ' +
      'that request looks anomalous, because it is the org doing the sending. ' +
      'Whoever holds the endpoint holds the credential, which makes the org\'s exposure equal to the ' +
      'weakest party that has ever operated it — a vendor, a subcontractor, or whoever registered ' +
      'the domain after the integration was retired. The other findings in this chain are the ' +
      'reasons a replayed session would neither be blocked nor noticed.',
    remediation:
      'Clear the "Send Session ID" option on the outbound message and give the receiving system its ' +
      'own authenticated path instead: a connected app with a specific OAuth scope, or a named ' +
      'credential, both of which can be scoped and revoked without touching a user session. If an ' +
      'endpoint is cleartext http://, treat the session as already disclosed and change it first, ' +
      'since anything on the path has seen it. Confirm the outbound message\'s running user is the ' +
      'least-privileged account that can do the job, because that is the reach being handed out.',
    match(_present, active) {
      const leak = byIds(active, ['outbound-messages-session-id']);
      if (leak.length === 0) return null;
      // Why a replayed session would not be stopped or seen. Any one is enough; the point of the
      // chain is the credential leaving, and these say what happens next.
      const unchecked = byIds(active, [
        // Disclosed in transit, so compromising the endpoint is not even required.
        'outbound-messages-cleartext',
        // Nothing binds or shortens the session that was handed over.
        'session-hardening-risks', 'session-security-deviations',
        'admin-no-ip-restrictions', 'broad-ip-ranges',
        // Nothing would record the replay.
        'event-monitoring-disabled', 'siem-integration-not-detected', 'threat-detection-inactive',
      ]);
      if (unchecked.length === 0) return null;
      return [...leak, ...unchecked];
    },
  },
  {
    id: 'anonymous-file-exposure',
    title: 'Org files served to anonymous callers, with no record of what left',
    severity: 'HIGH',
    narrative:
      'Files hosted by the org are fetchable without authentication — public Documents or static ' +
      'resources, content distribution links that never expire or ask for a password, or a site ' +
      'that grants guests file access — and nothing in the org would establish what those files ' +
      'contained or who collected them. ' +
      'Files are the blind spot in a sharing model. Org-wide defaults, sharing rules and ' +
      'field-level security all govern records, and none of them apply to a static resource served ' +
      'from a URL. Static resources in particular tend to accumulate the things front-end code ' +
      'needs and nobody re-reads: configuration, endpoint lists, and occasionally an API key that ' +
      'was only ever meant to reach the browser. ' +
      'This chain deliberately claims less than the guest chains do. It does not assert a pivot ' +
      'into org data, because there is none — anonymous file access returns the file and stops. ' +
      'What it asserts is that content left the org outside every record control, and that the ' +
      'absence of classification or monitoring means the question "what was in it" has no answer ' +
      'available after the fact.',
    remediation:
      'Retrieve and read the exposed files before deciding how urgent this is: the exposure is ' +
      'whatever they actually contain, and that is knowable now in a way it will not be later. ' +
      'Then remove external availability from Documents and static resources that do not need it, ' +
      'set expiry and passwords on content distribution links, and turn off guest file access on ' +
      'sites that do not depend on it. Treat any credential found in a static resource as ' +
      'disclosed and rotate it rather than removing the file, since the file has already been ' +
      'served and may be cached anywhere.',
    match(_present, active) {
      const surface = byIds(active, [
        'public-content-public-documents', 'public-content-public-static-resources',
        'content-links-no-expiry', 'content-links-no-password', 'content-links-stale',
        'guest-site-options-file-access',
      ]);
      if (surface.length === 0) return null;
      // No way to answer "what was in it" or "who took it". Classification and monitoring only:
      // content-links-stale is a subset of content-links-no-expiry, so counting it on both sides
      // would let one check satisfy the conjunction by itself.
      const unaccounted = byIds(active, [
        'data-classification-missing', 'data-encryption-not-detected',
        'event-monitoring-disabled', 'siem-integration-not-detected', 'threat-detection-inactive',
      ]);
      if (unaccounted.length === 0) return null;
      return [...surface, ...unaccounted];
    },
  },
  {
    id: 'xss-to-privileged-session',
    title: 'Visualforce XSS pattern reaching a privileged session',
    severity: 'HIGH',
    narrative:
      'Custom Visualforce markup contains a pattern that renders data without encoding it — ' +
      'escape="false", a merge field inside a <script> block without JSENCODE, or one in an href, ' +
      'src or action attribute — while the browser-side protections that would blunt an injected ' +
      'script are weakened, and the org contains accounts whose session is worth stealing. Script ' +
      'running in an administrator\'s session acts as that administrator: it inherits Modify All ' +
      'Data if they hold it, and the requests it makes are indistinguishable from theirs. ' +
      'What this chain does not claim is that the XSS is exploitable. The scan reads page markup, ' +
      'so it can show that a page renders something unencoded but not whether an attacker can ' +
      'influence what is rendered. A page interpolating a hard-coded label is a false positive and ' +
      'a page interpolating a record field an external user can set is not — and only reading the ' +
      'page tells you which. The chain is a prioritisation of which pages to read first, ordered ' +
      'by the fact that a privileged population exists to be targeted.',
    remediation:
      'Read the flagged pages before anything else, and ask one question of each: can a user who is ' +
      'not you influence the value being rendered? Where the answer is yes, encode at the output — ' +
      'HTMLENCODE, JSENCODE or URLENCODE according to where the value lands, since the correct ' +
      'function depends on the context, not the value. Separately, restore the session hardening ' +
      'settings that deviate from the Salesforce baseline and replace insecure http:// CSP trusted ' +
      'sites with https:// equivalents, both of which widen what an injected script can do once it ' +
      'runs.',
    match(_present, active) {
      const vector = byIds(active, [
        'visualforce-xss-escape-false',
        'visualforce-xss-js-merge-field',
        'visualforce-xss-attr-merge-field',
      ]);
      if (vector.length === 0) return null;
      // The browser-side controls that would otherwise contain an injected script. Excludes
      // 'experience-csp-verify', which asks the operator to confirm a setting rather than reporting
      // a weakness — treating an advisory as a confirmed gap would inflate the chain.
      const weakened = byIds(active, ['session-hardening-risks', 'csp-trusted-sites-insecure']);
      if (weakened.length === 0) return null;
      // Somebody whose session is worth the trouble.
      const targets = byIds(active, [
        'users-super-admin-combo', 'privileged-access-shadow-admins',
        'users-modify-all-data', 'users-view-all-data',
        'separation-of-duties-self-escalation',
      ]);
      if (targets.length === 0) return null;
      return [...vector, ...weakened, ...targets];
    },
  },
];
