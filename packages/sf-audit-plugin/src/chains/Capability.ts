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
  | 'external-egress';

export const ALL_CAPABILITIES: readonly Capability[] = [
  'unauth-foothold', 'low-trust-authenticated', 'data-read', 'data-read-bulk',
  'data-write', 'code-exec', 'credential-theft', 'priv-esc', 'org-takeover', 'external-egress',
];

/** Capabilities that represent an attacker entry point. */
export const SOURCE_CAPS: readonly Capability[] = ['unauth-foothold', 'low-trust-authenticated'];

/** Capabilities that represent a high-impact outcome (a chain "sink"). */
export const HIGH_IMPACT_SINKS: readonly Capability[] = [
  'org-takeover', 'data-write', 'data-read-bulk', 'credential-theft',
];
