// src/chains/CapabilityRegistry.ts
import type { Capability } from './Capability.js';
import type { Finding } from '../findings/Finding.js';

export interface CapabilityEntry {
  grants?: Capability[];
  requires?: Capability[];
}

/**
 * The full attack model lives here: finding id → attacker capabilities it grants.
 * Keep this the single source of truth so the ~75 checks stay untouched.
 * Every key MUST correspond to a finding id some check can emit (see registry-integrity test).
 */
export const CAPABILITY_REGISTRY: Record<string, CapabilityEntry> = {
  // Guest / unauthenticated foothold
  'guest-user-write-access':       { grants: ['unauth-foothold', 'data-write', 'data-read'] },
  'guest-user-read-access':        { grants: ['unauth-foothold', 'data-read'] },
  'guest-user-sharing-exposure':   { grants: ['unauth-foothold', 'data-read'] },
  'guest-user-baseline':           { grants: ['unauth-foothold'] },
  // External / portal sharing
  'sharing-model-external-write':  { grants: ['low-trust-authenticated', 'data-write', 'data-read-bulk'] },
  'sharing-model-external-read':   { grants: ['low-trust-authenticated', 'data-read-bulk'] },
  // Apex / code execution surfaces
  'portal-exposed-apex-without-sharing': { grants: ['code-exec', 'data-read', 'data-write'] },
  'soql-injection-risk':           { grants: ['code-exec', 'data-read-bulk'] },
  // Sensitive data presence
  'field-level-security-high':     { grants: ['data-read'] },
  'field-level-security-medium':   { grants: ['data-read'] },
  // Credential / secret exposure
  'hardcoded-credentials-found':           { grants: ['credential-theft'] },
  'custom-labels-credential-value-match':  { grants: ['credential-theft'] },
  'custom-labels-credential-name-match':   { grants: ['credential-theft'] },
  'debug-log-active-traces':               { grants: ['credential-theft'] },
  // Egress
  'named-credentials-inventory':     { grants: ['external-egress'] },
  'named-credentials-http-endpoint': { grants: ['external-egress'] },
  'remote-sites-inventory':          { grants: ['external-egress'] },
  // Privileged users
  'users-modify-all-data':  { grants: ['data-read-bulk', 'data-write'] },
  'users-view-all-data':    { grants: ['data-read-bulk'] },
  'users-super-admin-combo':{ grants: ['org-takeover'] },
  'users-author-apex':      { grants: ['code-exec', 'priv-esc'] },
  // New checks (Tasks 8–10)
  'guest-executable-apex-unprotected': { grants: ['code-exec', 'data-read-bulk', 'data-write'] },
  'guest-executable-apex-exposed':     { grants: ['code-exec'] },
  'cors-wildcard-origin':              { grants: ['credential-theft'] },
  'cors-broad-origin':                 { grants: ['credential-theft'] },
  'escalation-perms-found':            { grants: ['priv-esc'] },
};

/** Resolve the effective capabilities for a finding (inline overrides registry; passed/inconclusive yield nothing). */
export function capabilitiesFor(finding: Finding): { grants: Capability[]; requires: Capability[] } {
  if (finding.passed || finding.inconclusive) return { grants: [], requires: [] };
  const inline = finding.capabilities;
  if (inline && (inline.grants || inline.requires)) {
    return { grants: inline.grants ?? [], requires: inline.requires ?? [] };
  }
  const entry = CAPABILITY_REGISTRY[finding.id];
  return { grants: entry?.grants ?? [], requires: entry?.requires ?? [] };
}
