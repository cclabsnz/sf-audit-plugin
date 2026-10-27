// src/chains/namedChains.ts
import type { RiskLevel } from '@cclabsnz/sf-core';
import type { Finding } from '../findings/Finding.js';
import type { Capability } from './Capability.js';
import { capabilitiesFor } from './CapabilityRegistry.js';

/**
 * Findings a chain reads: by exact id, by id prefix, or any finding granting one of the capabilities.
 * A group is satisfied by any one member; a chain that needs two capabilities lists two groups.
 */
export interface FindingGroup {
  ids?: readonly string[];
  prefixes?: readonly string[];
  capabilities?: readonly Capability[];
}

/**
 * A named chain as a structured abuse case (RULE-110). `preconditions` are the groups `match()`
 * reads, built from the same constants; `breakPoint` indexes the one group whose complete removal
 * stops the chain (RULE-111). The prose fields name roles, never people or finding ids (RULE-112).
 */
export interface AbuseCaseDef {
  actor: string;
  goal: string;
  preconditions: readonly FindingGroup[];
  breakPoint: number;
  /** What to fix to break the chain, in plain language for every output. */
  breakPointText: string;
}

export interface NamedChainDef {
  id: string;
  title: string;
  severity: RiskLevel;
  narrative: string;
  remediation: string;
  abuseCase: AbuseCaseDef;
  /** Returns the member findings (chain steps) if present in this org, else null. */
  match(present: Set<Capability>, active: Finding[]): Finding[] | null;
}

/** True when the finding belongs to the group (a capability group matches on granted capabilities). */
export function inGroup(f: Finding, g: FindingGroup): boolean {
  if (g.ids?.includes(f.id)) return true;
  if (g.prefixes?.some((p) => f.id === p || f.id.startsWith(p))) return true;
  if (g.capabilities) {
    const grants = capabilitiesFor(f).grants;
    if (g.capabilities.some((c) => grants.includes(c))) return true;
  }
  return false;
}

const has = (s: Set<Capability>, ...caps: Capability[]): boolean => caps.every((c) => s.has(c));
const hasAny = (s: Set<Capability>, ...caps: Capability[]): boolean => caps.some((c) => s.has(c));
const byIds = (active: Finding[], ids: readonly string[]): Finding[] =>
  active.filter((f) => ids.includes(f.id));
// The AI & Agents findings carry dynamic id suffixes (userId, agent dev name, channel slug,
// domain), so their chain ingredients are matched by id prefix rather than exact id.
const byPrefixes = (active: Finding[], prefixes: readonly string[]): Finding[] =>
  active.filter((f) => prefixes.some((p) => f.id === p || f.id.startsWith(p)));

// Findings that show an unauthenticated visitor can actually read, write or run something. A guest
// user existing (`guest-user-baseline`) or a site being live (`classic-sites-active`) is a surface,
// not an exposure: every org with a site has one. RULE-071.
export const GUEST_EXPOSURE = [
  'guest-user-read-access', 'guest-user-write-access', 'guest-user-sharing-exposure',
  'guest-executable-apex-unprotected', 'guest-executable-apex-exposed', 'guest-executable-apex-system-mode',
  'guest-object-exposure-public-owd', 'guest-object-exposure-guest-owned',
  'guest-api-access-enabled', 'guest-api-hard-delete',
  'guest-user-visibility-view-all-users', 'guest-user-visibility-owd', 'guest-user-visibility-object-read',
  'guest-record-access-policy-not-enforced',
  'inbound-email-handler-unauthenticated-execution',
];

// Ways in for a low-trust principal: external users with public sharing, social sign-on,
// self-registration, or a confirmed guest exposure. RULE-072.
export const LOW_TRUST_ENTRY = [
  'sharing-model-external-read', 'sharing-model-external-write',
  'auth-providers-social', 'experience-cloud-site-self-registration',
  ...GUEST_EXPOSURE,
];

// Escalations a non-admin can use. Admins holding admin permissions (`users-super-admin-combo`,
// `users-author-apex`) are not an escalation: they already have the access. RULE-072.
export const NON_ADMIN_ESCALATION = [
  'escalation-perms-found', 'privileged-access-shadow-admins',
  'separation-of-duties-self-escalation', 'separation-of-duties-identity-takeover', 'separation-of-duties-grant-self-data',
  'login-access-policy-delegated-admins',
  'integration-least-privilege-escalation-permissions',
];

// Each chain's finding groups, shared by match() and its abuse case so the two cannot drift.

export const UNAUTH_EXFIL_STEPS = [
  'guest-user-read-access', 'guest-user-write-access', 'guest-user-sharing-exposure', 'guest-user-baseline',
  'guest-executable-apex-unprotected', 'guest-executable-apex-exposed', 'guest-executable-apex-system-mode',
  'guest-object-exposure-public-owd', 'guest-object-exposure-guest-owned',
  'guest-api-access-enabled', 'guest-api-hard-delete', 'classic-sites-active',
  'guest-user-visibility-view-all-users', 'guest-user-visibility-owd', 'guest-user-visibility-object-read',
  'portal-exposed-apex-without-sharing', 'sharing-model-external-read', 'sharing-model-external-write',
  'field-level-security-high', 'field-level-security-medium',
  // The guardrail whose absence lets guest-owned records defeat a Private OWD, and the Flow
  // analogue of portal-exposed Apex running without sharing.
  'guest-record-access-policy-not-enforced',
  'flows-autolaunched-without-sharing', 'flows-screen-without-sharing',
  // An open inbound email handler grants unauth-foothold, so it must appear whenever it
  // is what opened the gate.
  'inbound-email-handler-unauthenticated-execution',
];
// Internal-only weaknesses that widen what a foothold reaches. They join as evidence but
// never count toward the floor: without a guest-side step they describe no unauthenticated path.
export const UNAUTH_EXFIL_WIDENERS = ['data-cloud-data-space-default-overshared', 'restriction-rules-inactive'];

export const GUEST_TRAFFIC = ['guest-traffic-anomaly-recon', 'guest-traffic-anomaly-anonymizer'];
// A readable User roster counts as an exposed surface in its own right — recon against an org
// that leaks its staff list is the same incident. The object-level Read grant is excluded: on
// its own it is not a confirmed exposure, and this chain asserts one already in progress.
export const GUEST_BULK_SURFACE = [
  'guest-object-exposure-public-owd', 'guest-object-exposure-guest-owned',
  'guest-user-visibility-view-all-users', 'guest-user-visibility-owd',
];

// Admin powers: they widen what a takeover reaches but are not themselves the escalation.
export const TAKEOVER_ADMIN_EVIDENCE = [
  'users-super-admin-combo', 'users-author-apex', 'guest-user-baseline', 'login-access-policy-login-as-enabled',
  'separation-of-duties-code-and-data',
  'delegated-administration-groups-active',
  'auth-provider-registration-handler-admin-exec', 'auth-provider-registration-handler-unverified-email-linking',
  'delegated-authentication-admin-assigned', 'platform-event-subscriber-escalation',
];

// Exposed secrets: every finding here that grants credential-theft.
export const EXPOSED_SECRETS = [
  'hardcoded-credentials-found', 'custom-labels-credential-value-match', 'custom-labels-credential-name-match',
  'debug-log-active-traces', 'cors-wildcard-origin', 'cors-broad-origin',
  'flow-http-callout-hardcoded-secret', 'oauth-device-flow-enabled', 'oauth-password-flow-enabled',
  'custom-settings-credentials',
];
export const EGRESS_PATHS = [
  'named-credentials-inventory', 'named-credentials-http-endpoint', 'remote-sites-inventory',
  // A user who can stand up connected apps and bypass API access control has provisioned
  // their own egress path.
  'separation-of-duties-external-exfil-channel',
];

export const SOQL_INJECTION = ['soql-injection-risk'];
export const SOQL_READ_SINKS = [
  'sharing-model-external-read', 'sharing-model-external-write',
  'field-level-security-high', 'field-level-security-medium', 'users-view-all-data',
  'public-group-sharing-exposure', 'report-folder-access-public',
  'encryption-coverage-unencrypted-sensitive',
];

export const AGENT_GUEST_CHANNEL = ['agent-channel-exposure-guest-'];
export const AGENT_PRIVILEGE = ['agent-user-privilege-admin-', 'agent-user-privilege-broad-write-'];
export const AGENT_WRITE_ACTIONS = ['agent-action-surface-write'];

export const ACTIVE_AGENTS = ['agent-inventory-summary'];
export const STALE_TRUSTED_URL = ['trusted-url-hygiene-unresolvable-', 'trusted-url-hygiene-parked-'];
export const AGENT_NO_CAPTURE = ['agent-monitoring-coverage-none'];

export const AGENT_QUERY_REACH = ['agent-query-reach-'];
// Egress: an outbound action that needs no confirmation, or a trusted domain anyone can claim.
export const AGENT_OUTBOUND = ['agent-outbound-actions-unconfirmed', 'agent-outbound-actions-unverified'];
// Where outsider text enters, when the org shows it. Evidence only: the chain fires without
// it, since Web-to-Lead, Web-to-Case and email exist in almost every org.
export const UNTRUSTED_INPUT = [
  'inbound-email-handler-unauthenticated-execution',
  'guest-user-write-access',
  'guest-object-exposure-guest-owned',
];

export const SANDBOX_PII = ['sandbox-data-masking-pii-present'];
export const SANDBOX_WEAK_CONTROLS = [
  'internal-user-mfa-gaps', 'trusted-ip-broad-ranges', 'mfa-portal-users-without-enforcement',
  'public-group-sharing-exposure', 'report-folder-access-public', 'standard-profiles-in-use',
  'privileged-access-shadow-admins', 'sharing-model-external-read', 'sharing-model-external-write',
  'guest-user-read-access', 'guest-user-write-access', 'guest-user-sharing-exposure',
];

export const INSIDER_BROAD_READ = [
  'public-group-sharing-exposure', 'report-folder-access-public',
  'users-view-all-data', 'users-modify-all-data',
  // An unused Data Export or View All Users grant on an integration account is the same
  // bulk-read reach as the other members of this set.
  'integration-least-privilege-data-permissions',
];
export const INSIDER_BULK_EGRESS = [
  'data-export-weekly-export', 'data-export-bulk-api-viewall',
  'separation-of-duties-external-exfil-channel',
];
export const INSIDER_BLIND_SPOT = [
  'event-monitoring-disabled', 'siem-integration-not-detected', 'event-monitoring-retention-short',
];

export const DETECTION_BLIND_SPOTS = [
  'threat-detection-inactive', 'threat-detection-guest-anomaly-missing',
  'event-monitoring-disabled', 'event-monitoring-retention-short',
  'transaction-security-policy-none', 'siem-integration-not-detected', 'siem-retention-gap',
];
export const EXPLOITABLE_ACCESS: readonly Capability[] = ['unauth-foothold', 'priv-esc', 'org-takeover'];

export const MFA_WEAKNESS = ['trusted-ip-broad-ranges', 'internal-user-mfa-gaps', 'mfa-portal-users-without-enforcement'];
export const PRIVILEGED_ACCOUNTS = [
  'users-modify-all-data', 'users-view-all-data', 'users-super-admin-combo',
  'privileged-access-shadow-admins', 'separation-of-duties-self-escalation',
];

// Standing reach: a token that can act broadly, and keeps being able to.
export const OAUTH_STANDING = [
  'connected-app-full-scope-infinite-token',
  'connected-app-full-scope',
  'connected-app-infinite-refresh-token',
];
// What removes the containment or the observation. Any one of these turns standing access
// into access nobody is watching or limiting.
export const OAUTH_UNCONTAINED = [
  // Nobody is reviewing it: tokens with no matching app, or long unused.
  'oauth-token-unmatched-app', 'oauth-token-stale', 'oauth-token-no-app-inventory',
  // Nothing is limiting it: the network control that survives authorisation, removed.
  'connected-apps-bypass-ip', 'connected-apps-relax-ip', 'unrestricted-connected-apps',
  'connected-apps-long-session-timeout', 'admin-no-ip-restrictions',
  // The authorising identity is worth more than it needs to be, so the token inherits more.
  'integration-least-privilege-escalation-permissions',
  'integration-least-privilege-data-permissions',
  'api-client-permission-assigned',
];

export const SELF_REGISTRATION = ['experience-cloud-site-self-registration'];
// What an account is worth once obtained. Deliberately excludes report-folder-access-public:
// it is real for internal users, but a self-registered portal account is a Customer Community
// licence, which generally has no report access at all, so including it would overstate reach.
export const PORTAL_REACH = [
  'sharing-model-external-read', 'sharing-model-external-write',
  'portal-exposed-apex-without-sharing',
  'flows-autolaunched-without-sharing', 'flows-screen-without-sharing',
  'apex-rest-without-sharing',
  'external-account-hierarchy-super-users', 'external-account-hierarchy-active',
];
// Social sign-on is a second way in rather than a requirement, so it joins as evidence when
// present but never gates the chain on its own.
export const SOCIAL_SIGN_ON = ['auth-providers-social'];

export const SESSION_ID_LEAK = ['outbound-messages-session-id'];
// Why a replayed session would not be stopped or seen. Any one is enough; the point of the
// chain is the credential leaving, and these say what happens next.
export const SESSION_UNCHECKED = [
  // Disclosed in transit, so compromising the endpoint is not even required.
  'outbound-messages-cleartext',
  // Nothing binds or shortens the session that was handed over.
  'session-hardening-risks', 'session-security-deviations',
  'admin-no-ip-restrictions', 'broad-ip-ranges',
  // Nothing would record the replay.
  'event-monitoring-disabled', 'siem-integration-not-detected', 'threat-detection-inactive',
];

export const ANONYMOUS_FILES = [
  'public-content-public-documents', 'public-content-public-static-resources',
  'content-links-no-expiry', 'content-links-no-password', 'content-links-stale',
  'guest-site-options-file-access',
];
// No way to answer "what was in it" or "who took it". Classification and monitoring only:
// content-links-stale is a subset of content-links-no-expiry, so counting it on both sides
// would let one check satisfy the conjunction by itself.
export const FILES_UNACCOUNTED = [
  'data-classification-missing', 'data-encryption-not-detected',
  'event-monitoring-disabled', 'siem-integration-not-detected', 'threat-detection-inactive',
];

export const VF_XSS = ['visualforce-xss-escape-false', 'visualforce-xss-js-merge-field', 'visualforce-xss-attr-merge-field'];
// The browser-side controls that would otherwise contain an injected script. Excludes
// 'experience-csp-verify', which asks the operator to confirm a setting rather than reporting
// a weakness — treating an advisory as a confirmed gap would inflate the chain.
export const BROWSER_WEAKENED = ['session-hardening-risks', 'csp-trusted-sites-insecure'];
// Somebody whose session is worth the trouble.
export const SESSION_TARGETS = [
  'users-super-admin-combo', 'privileged-access-shadow-admins',
  'users-modify-all-data', 'users-view-all-data',
  'separation-of-duties-self-escalation',
];

export const OPEN_EMAIL_HANDLER = ['inbound-email-handler-unauthenticated-execution'];
export const EMAIL_FOLLOW_ON = [
  'apex-crud-fls-without-sharing', 'soql-injection-risk', 'portal-exposed-apex-without-sharing',
  'flows-autolaunched-without-sharing', 'users-modify-all-data', 'users-super-admin-combo',
  'privileged-access-shadow-admins',
];

export const EVENT_SUBSCRIBER_ESCALATION = ['platform-event-subscriber-escalation'];
export const EVENT_PUBLISHER_FOOTHOLD = [
  'guest-user-read-access', 'guest-user-write-access', 'guest-user-sharing-exposure', 'guest-user-baseline',
  'sharing-model-external-read', 'sharing-model-external-write', 'experience-cloud-site-self-registration',
];
export const EVENT_PRIVILEGED_TARGETS = ['users-super-admin-combo', 'users-modify-all-data', 'privileged-access-shadow-admins'];

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
    abuseCase: {
      actor: 'an unauthenticated site visitor',
      goal: 'read or change business data in bulk without logging in',
      preconditions: [{ ids: GUEST_EXPOSURE }, { ids: UNAUTH_EXFIL_STEPS }, { ids: UNAUTH_EXFIL_WIDENERS }, { capabilities: ['unauth-foothold'] }, { capabilities: ['code-exec', 'data-read-bulk', 'data-write'] }],
      breakPoint: 0,
      breakPointText:
        'Close every confirmed guest exposure: guest object and record access, guest-callable Apex, guest API access, guest visibility of users, the guest record-access policy, and unauthenticated email handlers.',
    },
    match(present, active) {
      if (!has(present, 'unauth-foothold')) return null;
      if (!hasAny(present, 'code-exec', 'data-read-bulk', 'data-write')) return null;
      // A surface and internal weaknesses are not a path: an unauthenticated visitor must be shown
      // to reach something.
      if (byIds(active, GUEST_EXPOSURE).length === 0) return null;
      const steps = byIds(active, UNAUTH_EXFIL_STEPS);
      if (steps.length < 2) return null;
      return [...steps, ...byIds(active, UNAUTH_EXFIL_WIDENERS)];
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
    abuseCase: {
      actor: 'an unauthenticated visitor already probing the site',
      goal: 'map the guest-readable data and pull it',
      preconditions: [{ ids: GUEST_TRAFFIC }, { ids: GUEST_BULK_SURFACE }],
      breakPoint: 1,
      breakPointText:
        'Close the guest bulk-read surface: guest object exposure and guest visibility of users.',
    },
    match(_present, active) {
      const traffic = byIds(active, GUEST_TRAFFIC);
      const exposure = byIds(active, GUEST_BULK_SURFACE);
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
    abuseCase: {
      actor: 'a low-trust authenticated user (external, social sign-on, self-registered, or a guest with confirmed access)',
      goal: 'take full control of the org',
      preconditions: [{ ids: LOW_TRUST_ENTRY }, { ids: NON_ADMIN_ESCALATION }, { ids: TAKEOVER_ADMIN_EVIDENCE }],
      breakPoint: 1,
      breakPointText:
        'Remove every escalation permission held by someone who is not an administrator.',
    },
    match(_present, active) {
      // Both ends must be present: a way in for a low-trust principal, and an escalation that
      // principal could use. Admin-held power and a guest user merely existing join only as evidence.
      const entry = byIds(active, LOW_TRUST_ENTRY);
      const escalation = byIds(active, NON_ADMIN_ESCALATION);
      if (entry.length === 0 || escalation.length === 0) return null;
      return [...entry, ...escalation, ...byIds(active, TAKEOVER_ADMIN_EVIDENCE)];
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
    abuseCase: {
      actor: 'anyone who obtains an exposed secret',
      goal: 'use it to move data to infrastructure they control',
      preconditions: [{ ids: EXPOSED_SECRETS }, { ids: EGRESS_PATHS }, { capabilities: ['credential-theft'] }, { capabilities: ['external-egress'] }],
      breakPoint: 0,
      breakPointText:
        'Rotate and remove every exposed secret: hardcoded credentials, credentials in custom settings or labels, active debug traces, broad CORS origins and enabled device or password OAuth flows.',
    },
    match(present, active) {
      if (!has(present, 'credential-theft', 'external-egress')) return null;
      // An exposed secret must be one of the steps: credential-theft granted elsewhere (a session id
      // in an outbound message) is session-id-egress, and egress paths alone are no pivot. INT-012.
      if (byIds(active, EXPOSED_SECRETS).length === 0) return null;
      const steps = byIds(active, [...EXPOSED_SECRETS, ...EGRESS_PATHS]);
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
    abuseCase: {
      actor: 'a user who can reach injectable Apex',
      goal: 'read large datasets beyond their own access',
      preconditions: [{ ids: SOQL_INJECTION }, { ids: SOQL_READ_SINKS }, { capabilities: ['code-exec'] }],
      breakPoint: 0,
      breakPointText:
        'Use bind variables in the injectable dynamic SOQL.',
    },
    match(present, active) {
      if (!has(present, 'code-exec')) return null;
      const inj = byIds(active, SOQL_INJECTION);
      if (inj.length === 0) return null;
      const sink = byIds(active, SOQL_READ_SINKS);
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
    abuseCase: {
      actor: 'an unauthenticated chat visitor',
      goal: 'steer a privileged agent into reading, changing or deleting data',
      preconditions: [{ prefixes: AGENT_GUEST_CHANNEL }, { prefixes: AGENT_PRIVILEGE }, { ids: AGENT_WRITE_ACTIONS }],
      breakPoint: 0,
      breakPointText:
        'Remove the guest or public channel binding from the privileged agent.',
    },
    match(_present, active) {
      const channel = byPrefixes(active, AGENT_GUEST_CHANNEL);
      const privilege = byPrefixes(active, AGENT_PRIVILEGE);
      const actions = byIds(active, AGENT_WRITE_ACTIONS);
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
    abuseCase: {
      actor: 'an outsider who registers a lapsed allowlisted domain',
      goal: 'receive data an injected agent sends there, with nothing recorded',
      preconditions: [{ ids: ACTIVE_AGENTS }, { prefixes: STALE_TRUSTED_URL }, { ids: AGENT_NO_CAPTURE }],
      breakPoint: 1,
      breakPointText:
        'Remove or reclaim every stale trusted domain.',
    },
    match(_present, active) {
      const agents = byIds(active, ACTIVE_AGENTS);
      const staleUrl = byPrefixes(active, STALE_TRUSTED_URL);
      const noCapture = byIds(active, AGENT_NO_CAPTURE);
      if (agents.length === 0 || staleUrl.length === 0 || noCapture.length === 0) return null;
      return [...agents, ...staleUrl, ...noCapture];
    },
  },
  {
    id: 'salesbleed-pattern',
    title: 'SalesBleed pattern',
    severity: 'HIGH',
    narrative:
      'An active agent can run open-ended record queries (the General CRM topic or Query Records action) and ' +
      'the org has a way to send data out: agent actions that do so (Slack, email, external services) without ' +
      'user confirmation, or a CSP Trusted URL whose domain is parked or no longer resolves, which anyone can ' +
      'register and then receive whatever the agent puts in a link or image it returns. ' +
      'That is two of the three ingredients in SalesBleed (Zenity Labs, Sept 2026) and PipeLeak (Capsule ' +
      'Security, Apr 2026); the third, text an outsider wrote, arrives through Web-to-Lead, Web-to-Case, email or ' +
      'chat in almost every org. One injected instruction in a lead can query Accounts and send the result out.',
    remediation:
      'Break any one link: remove open-ended querying from agents that read untrusted records, require user ' +
      'confirmation on every outbound action, remove CSP Trusted URLs whose domains you no longer control, or ' +
      'keep the agent that queries separate from the agent that sends.',
    abuseCase: {
      actor: 'an outsider who can put text in a record an agent reads',
      goal: 'have the agent query records and send them out',
      preconditions: [{ prefixes: AGENT_QUERY_REACH }, { ids: AGENT_OUTBOUND, prefixes: STALE_TRUSTED_URL }, { ids: UNTRUSTED_INPUT }],
      breakPoint: 1,
      breakPointText:
        'Require confirmation on every outbound agent action and remove trusted domains you no longer control.',
    },
    match(_present, active) {
      const reach = byPrefixes(active, AGENT_QUERY_REACH);
      const outbound = [...byIds(active, AGENT_OUTBOUND), ...byPrefixes(active, STALE_TRUSTED_URL)];
      if (reach.length === 0 || outbound.length === 0) return null;
      const untrusted = byIds(active, UNTRUSTED_INPUT);
      return [...untrusted, ...reach, ...outbound];
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
    abuseCase: {
      actor: 'anyone with access to the sandbox',
      goal: 'read real production personal data under weaker controls',
      preconditions: [{ ids: SANDBOX_PII }, { ids: SANDBOX_WEAK_CONTROLS }],
      breakPoint: 0,
      breakPointText:
        'Mask the production personal data in the sandbox, or refresh it without production data.',
    },
    match(_present, active) {
      const pii = byIds(active, SANDBOX_PII);
      if (pii.length === 0) return null;
      const weakControls = byIds(active, SANDBOX_WEAK_CONTROLS);
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
    abuseCase: {
      actor: 'an internal user or whoever holds their stolen credentials',
      goal: 'export business data in bulk without a record of it',
      preconditions: [{ ids: INSIDER_BROAD_READ }, { ids: INSIDER_BULK_EGRESS }, { ids: INSIDER_BLIND_SPOT }],
      breakPoint: 1,
      breakPointText:
        'Restrict Weekly Data Export and bulk API export to a named few, and remove self-provisioned connected-app or API export channels.',
    },
    match(_present, active) {
      const broadRead = byIds(active, INSIDER_BROAD_READ);
      const bulkEgress = byIds(active, INSIDER_BULK_EGRESS);
      const blindSpot = byIds(active, INSIDER_BLIND_SPOT);
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
    abuseCase: {
      actor: 'an attacker using an access path the org already exposes',
      goal: 'act without being detected or reconstructed afterwards',
      preconditions: [{ ids: DETECTION_BLIND_SPOTS }, { capabilities: EXPLOITABLE_ACCESS }],
      breakPoint: 0,
      breakPointText:
        'Restore detection: Event Monitoring with adequate retention, threat detection, a Transaction Security policy and SIEM forwarding.',
    },
    match(present, active) {
      if (!hasAny(present, ...EXPLOITABLE_ACCESS)) return null;
      const blindSpots = byIds(active, DETECTION_BLIND_SPOTS);
      // One missing control is a finding on its own; two or more is a systemic blind spot. Requiring
      // two keeps this from firing on every org that has not bought Shield.
      if (blindSpots.length < 2) return null;
      const exposure = active.filter((f) => inGroup(f, { capabilities: EXPLOITABLE_ACCESS }));
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
    abuseCase: {
      actor: 'a credential-stuffing or phishing attacker',
      goal: 'take over a privileged account without a second factor',
      preconditions: [{ ids: MFA_WEAKNESS }, { ids: PRIVILEGED_ACCOUNTS }],
      breakPoint: 0,
      breakPointText:
        'Enforce MFA for every user and remove trusted-IP ranges that bypass it.',
    },
    match(_present, active) {
      const weakness = byIds(active, MFA_WEAKNESS);
      const targets = byIds(active, PRIVILEGED_ACCOUNTS);
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
    abuseCase: {
      actor: "the holder of a connected app's refresh token",
      goal: 'use standing API access that no login control sees',
      preconditions: [{ ids: OAUTH_STANDING }, { ids: OAUTH_UNCONTAINED }],
      breakPoint: 0,
      breakPointText:
        'Replace Full scope with the scopes each integration uses, and set refresh tokens to expire.',
    },
    match(_present, active) {
      const standing = byIds(active, OAUTH_STANDING);
      if (standing.length === 0) return null;
      const uncontained = byIds(active, OAUTH_UNCONTAINED);
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
    abuseCase: {
      actor: 'anyone with an email address',
      goal: 'self-register and read more than their own records',
      preconditions: [{ ids: SELF_REGISTRATION }, { ids: PORTAL_REACH }, { ids: SOCIAL_SIGN_ON }],
      breakPoint: 0,
      breakPointText:
        'Turn off self-registration on the site.',
    },
    match(_present, active) {
      const acquisition = byIds(active, SELF_REGISTRATION);
      if (acquisition.length === 0) return null;
      const reach = byIds(active, PORTAL_REACH);
      if (reach.length === 0) return null;
      return [...acquisition, ...reach, ...byIds(active, SOCIAL_SIGN_ON)];
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
    abuseCase: {
      actor: 'whoever controls the outbound message endpoint',
      goal: 'replay the session it receives as the running user',
      preconditions: [{ ids: SESSION_ID_LEAK }, { ids: SESSION_UNCHECKED }],
      breakPoint: 0,
      breakPointText:
        'Clear Send Session ID on the outbound message.',
    },
    match(_present, active) {
      const leak = byIds(active, SESSION_ID_LEAK);
      if (leak.length === 0) return null;
      const unchecked = byIds(active, SESSION_UNCHECKED);
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
    abuseCase: {
      actor: 'an anonymous internet caller',
      goal: 'collect org files outside every record control',
      preconditions: [{ ids: ANONYMOUS_FILES }, { ids: FILES_UNACCOUNTED }],
      breakPoint: 0,
      breakPointText:
        'Remove anonymous access to files: public documents and static resources, links without expiry or password, and guest file access.',
    },
    match(_present, active) {
      const surface = byIds(active, ANONYMOUS_FILES);
      if (surface.length === 0) return null;
      const unaccounted = byIds(active, FILES_UNACCOUNTED);
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
    abuseCase: {
      actor: 'anyone who can influence a value the page renders',
      goal: "run script in a privileged user's session",
      preconditions: [{ ids: VF_XSS }, { ids: BROWSER_WEAKENED }, { ids: SESSION_TARGETS }],
      breakPoint: 0,
      breakPointText:
        'Encode every flagged Visualforce output for the context it lands in.',
    },
    match(_present, active) {
      const vector = byIds(active, VF_XSS);
      if (vector.length === 0) return null;
      const weakened = byIds(active, BROWSER_WEAKENED);
      if (weakened.length === 0) return null;
      const targets = byIds(active, SESSION_TARGETS);
      if (targets.length === 0) return null;
      return [...vector, ...weakened, ...targets];
    },
  },
  {
    id: 'inbound-email-rce',
    title: 'Unauthenticated inbound email to privileged code execution',
    severity: 'CRITICAL',
    narrative:
      'An unauthenticated inbound email service address with no sender allowlist and no SPF/DKIM verification ' +
      'accepts messages from any internet sender, executing Apex logic under a privileged running user or in a class ' +
      'that bypasses CRUD/FLS and sharing. Attackers can trigger unattended data manipulation or code execution without credentials.',
    remediation:
      'Populate AuthorizedSenders on each email service address, set AuthenticationFailureAction to reject spoofed email, ' +
      'and ensure email handler Apex classes enforce sharing, validate input, and execute as a dedicated least-privilege user.',
    abuseCase: {
      actor: 'any internet email sender',
      goal: 'trigger privileged Apex without credentials',
      preconditions: [{ ids: OPEN_EMAIL_HANDLER }, { ids: EMAIL_FOLLOW_ON }, { capabilities: ['unauth-foothold'] }, { capabilities: ['code-exec'] }],
      breakPoint: 0,
      breakPointText:
        'Restrict the email service to authorised senders and reject mail that fails authentication.',
    },
    match(present, active) {
      if (!has(present, 'unauth-foothold', 'code-exec')) return null;
      const vector = byIds(active, OPEN_EMAIL_HANDLER);
      if (vector.length === 0) return null;
      const followOn = byIds(active, EMAIL_FOLLOW_ON);
      return followOn.length > 0 ? [...vector, ...followOn] : null;
    },
  },
  {
    id: 'platform-event-priv-esc',
    title: 'Guest or low-trust platform event publish to automated process escalation',
    severity: 'CRITICAL',
    narrative:
      'A guest or portal user publishes a custom Platform Event that triggers an Apex trigger or Flow subscriber ' +
      'executing as the Automated Process system user or an administrator. This bypasses normal user sharing, CRUD, and FLS, ' +
      'providing an unauthenticated or low-trust path to system-context privilege escalation and state tampering.',
    remediation:
      'Revoke Create permissions on Platform Events from guest and Experience Cloud profiles. Configure ' +
      'PlatformEventSubscriberConfig to run event triggers as a dedicated least-privilege user rather than Automated Process or an admin.',
    abuseCase: {
      actor: 'a guest or portal user',
      goal: 'publish an event that runs as a privileged user',
      preconditions: [{ ids: EVENT_PUBLISHER_FOOTHOLD }, { ids: EVENT_SUBSCRIBER_ESCALATION }, { ids: EVENT_PRIVILEGED_TARGETS }, { capabilities: ['unauth-foothold', 'low-trust-authenticated'] }, { capabilities: ['priv-esc', 'data-write'] }],
      breakPoint: 1,
      breakPointText:
        'Run event subscribers as a dedicated least-privilege user, not Automated Process or an administrator.',
    },
    match(present, active) {
      if (!hasAny(present, 'unauth-foothold', 'low-trust-authenticated')) return null;
      if (!hasAny(present, 'priv-esc', 'data-write')) return null;
      const escalation = byIds(active, EVENT_SUBSCRIBER_ESCALATION);
      if (escalation.length === 0) return null;
      const foothold = byIds(active, EVENT_PUBLISHER_FOOTHOLD);
      if (foothold.length === 0) return null;
      return [...foothold, ...escalation, ...byIds(active, EVENT_PRIVILEGED_TARGETS)];
    },
  },
];
