// src/chains/namedChains.ts
import type { RiskLevel } from '@cclabsnz/sf-core';
import type { Finding } from '../findings/Finding.js';
import type { Capability } from './Capability.js';

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
      'external sharing to read business data in bulk without any login.',
    remediation:
      'Remove guest object/sharing access, ensure no guest-invokable Apex runs without sharing, ' +
      'and set external OWD to Private. Grant portal access only via sharing sets.',
    match(present, active) {
      if (!has(present, 'unauth-foothold')) return null;
      if (!hasAny(present, 'code-exec', 'data-read-bulk', 'data-write')) return null;
      const steps = byIds(active, [
        'guest-user-read-access', 'guest-user-write-access', 'guest-user-sharing-exposure', 'guest-user-baseline',
        'guest-executable-apex-unprotected', 'guest-executable-apex-exposed',
        'guest-object-exposure-public-owd', 'guest-object-exposure-guest-owned',
        'guest-api-access-enabled', 'guest-api-hard-delete', 'classic-sites-active',
        'portal-exposed-apex-without-sharing', 'sharing-model-external-read', 'sharing-model-external-write',
        'field-level-security-high', 'field-level-security-medium',
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
      'bulk-readable by those same guests. This is not a theoretical exposure — it is reconnaissance ' +
      'against a confirmed exfiltration surface, i.e. an incident likely already in progress.',
    remediation:
      'Treat as an active incident: block the source IPs at the WAF/CDN, close the guest bulk-read surface ' +
      '(set external OWD to Private, strip guest object read, enforce "Secure guest user record access"), ' +
      'and preserve/forward the event logs before the short EventLogFile retention window closes.',
    match(_present, active) {
      const traffic = byIds(active, ['guest-traffic-anomaly-recon', 'guest-traffic-anomaly-anonymizer']);
      const exposure = byIds(active, ['guest-object-exposure-public-owd', 'guest-object-exposure-guest-owned']);
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
      'once, so a single injected prompt can read, alter, or destroy data across the agent\'s reach.',
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
      const targets = byIds(active, ['users-modify-all-data', 'users-view-all-data', 'users-super-admin-combo']);
      return weakness.length > 0 && targets.length > 0 ? [...weakness, ...targets] : null;
    },
  },
];
