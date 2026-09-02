// src/chains/CapabilityRegistry.ts
import type { Capability } from './Capability.js';
import type { Finding } from '../findings/Finding.js';

export interface CapabilityEntry {
  grants?: Capability[];
  requires?: Capability[];
}

/**
 * The full attack model lives here: finding id → attacker capabilities it grants.
 * Keep this the single source of truth so the 88 checks stay untouched.
 *
 * Every key MUST correspond to a finding id some check can actually emit, and every id referenced
 * by a named chain must be emittable too — a typo in either place fails silently (a key that
 * matches nothing simply never grants, and a chain ingredient that matches nothing means the chain
 * never fires). `test/unit/chains/registryIntegrity.test.ts` enforces both directions.
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
  // Guest bulk-read surface (UI-API reachable) — the confirmed exfiltration sink
  'guest-object-exposure-public-owd':  { grants: ['unauth-foothold', 'data-read-bulk'] },
  'guest-object-exposure-guest-owned': { grants: ['unauth-foothold', 'data-read-bulk'] },
  // Observed guest recon in EventLogFile — an active unauthenticated foothold
  'guest-traffic-anomaly-recon':       { grants: ['unauth-foothold'] },
  'guest-traffic-anomaly-anonymizer':  { grants: ['unauth-foothold'] },
  // Guest API/Bulk access — programmatic unauthenticated bulk read / destruction
  'guest-api-access-enabled':          { grants: ['unauth-foothold', 'data-read-bulk'] },
  'guest-api-hard-delete':             { grants: ['unauth-foothold', 'data-write'] },
  // Guest enumeration of other USERS. The staff roster is the targeting asset behind credential
  // stuffing and phishing at named admins, and both of the first two paths expose every User record
  // on their own, so both are bulk reads. The object-level Read grant is not: it makes User
  // queryable but still needs a sharing path before it returns anyone else's record.
  'guest-user-visibility-view-all-users': { grants: ['unauth-foothold', 'data-read-bulk'] },
  'guest-user-visibility-owd':            { grants: ['unauth-foothold', 'data-read-bulk'] },
  'guest-user-visibility-object-read':    { grants: ['unauth-foothold', 'data-read'] },
  // Classic Visualforce sites — a second unauthenticated foothold surface
  'classic-sites-active':              { grants: ['unauth-foothold'] },
  // Mass data-export capability — a bulk-read sink for an authenticated actor
  'data-export-weekly-export':         { grants: ['data-read-bulk'] },
  'data-export-bulk-api-viewall':      { grants: ['data-read-bulk', 'data-write'] },
  // Impersonation / delegated-admin escalation
  'login-access-policy-delegated-admins': { grants: ['priv-esc'] },
  'login-access-policy-login-as-enabled': { grants: ['priv-esc', 'data-read-bulk'] },
  // External federation an attacker could ride in on
  'auth-providers-social':             { grants: ['low-trust-authenticated'] },

  // Toxic permission combinations held by one user. Capabilities follow each combo's own stated
  // outcome — see COMBOS in SeparationOfDutiesCheck, where the ids are defined.
  'separation-of-duties-self-escalation':       { grants: ['priv-esc', 'org-takeover'] },
  'separation-of-duties-identity-takeover':     { grants: ['priv-esc', 'org-takeover'] },
  'separation-of-duties-grant-self-data':       { grants: ['priv-esc', 'data-read-bulk'] },
  'separation-of-duties-code-and-data':         { grants: ['code-exec', 'data-read-bulk', 'data-write'] },
  'separation-of-duties-external-exfil-channel':{ grants: ['external-egress', 'data-read-bulk'] },
  'separation-of-duties-tamper-and-cover':      { grants: ['data-write', 'data-read-bulk'] },
  // Admin-equivalent users who are not on the System Administrator profile: the same reach as
  // 'users-super-admin-combo', which is why it grants the same capability.
  'privileged-access-shadow-admins':            { grants: ['org-takeover', 'priv-esc'] },
  // Flows running in system context without sharing enforcement — the Flow analogue of
  // 'portal-exposed-apex-without-sharing'. Screen flows need a user to drive them, so they do not
  // grant the unattended write that an autolaunched flow does.
  'flows-autolaunched-without-sharing':         { grants: ['code-exec', 'data-read', 'data-write'] },
  'flows-screen-without-sharing':               { grants: ['code-exec', 'data-read'] },
  // Sharing rules granting All Internal Users — bulk read for any authenticated employee. Internal
  // by definition, so this grants no 'low-trust-authenticated' entry point of its own.
  'public-group-sharing-exposure':              { grants: ['data-read-bulk'] },
  // Report folders any authenticated user can view.
  'report-folder-access-public':                { grants: ['data-read'] },
  // "Secure guest user record access" not enforced: guest-owned records can defeat a Private OWD.
  // The policy gap widens guest visibility rather than creating the surface itself, so it mirrors
  // 'guest-user-sharing-exposure' rather than the confirmed bulk-read sinks.
  'guest-record-access-policy-not-enforced':    { grants: ['unauth-foothold', 'data-read'] },
  // Sensitive data present and readable — what every other capability is ultimately reaching for.
  'encryption-coverage-unencrypted-sensitive':  { grants: ['data-read'] },
  'sandbox-data-masking-pii-present':           { grants: ['data-read'] },
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
