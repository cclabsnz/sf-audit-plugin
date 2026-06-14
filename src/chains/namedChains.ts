// src/chains/namedChains.ts
import type { RiskLevel } from '../findings/RiskLevel.js';
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
        'portal-exposed-apex-without-sharing', 'sharing-model-external-read', 'sharing-model-external-write',
        'field-level-security-high', 'field-level-security-medium',
      ]);
      return steps.length >= 2 ? steps : null;
    },
  },
  {
    id: 'standard-to-takeover',
    title: 'Standard user → org takeover',
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
      ]);
      return steps.length >= 2 ? steps : null;
    },
  },
  {
    id: 'cred-theft-pivot',
    title: 'Credential theft → external pivot',
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
    title: 'SOQL injection → mass read',
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
    id: 'mfa-bypass-admin',
    title: 'MFA bypass → privileged compromise',
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
