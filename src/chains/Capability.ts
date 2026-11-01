// src/chains/Capability.ts
export type Capability =
  | 'unauth-foothold'
  | 'low-trust-authenticated'
  | 'data-read'
  | 'data-read-bulk'
  | 'data-write'
  | 'code-exec'
  | 'credential-theft'
  | 'priv-esc'
  | 'org-takeover'
  | 'external-egress'
  // A real user's credentials work without a second factor. Not an entry point of a potential path
  // (not in SOURCE_CAPS): weak MFA alone reaches nothing until a named chain pairs it with a target.
  | 'valid-account';

export const ALL_CAPABILITIES: readonly Capability[] = [
  'unauth-foothold', 'low-trust-authenticated', 'data-read', 'data-read-bulk',
  'data-write', 'code-exec', 'credential-theft', 'priv-esc', 'org-takeover', 'external-egress', 'valid-account',
];

/** Capabilities that represent an attacker entry point. */
export const SOURCE_CAPS: readonly Capability[] = ['unauth-foothold', 'low-trust-authenticated'];

/** Capabilities that represent a high-impact outcome (a chain "sink"). */
export const HIGH_IMPACT_SINKS: readonly Capability[] = [
  'org-takeover', 'data-write', 'data-read-bulk', 'credential-theft',
];
