import type { ControlDef } from '../types.js';

// New Zealand Information Security Manual (NZISM), GCSB/NCSC.
// Chapter references VERIFIED 2026-06 against the official manual (https://nzism.gcsb.govt.nz/ism-document),
// current version v3.8 (July 2025). These are CHAPTER/SECTION-level mappings; refining to individual
// NZISM control numbers (e.g. 16.1.35) is a future granularity pass. `verified` = the chapter reference
// is confirmed to exist with this title in the current NZISM.
const V = 'NZISM v3.8';
const URL = 'https://nzism.gcsb.govt.nz/ism-document';

export const NZISM_CONTROLS: ControlDef[] = [
  { id: 'NZISM-AC', framework: 'NZISM', version: V, title: 'Access control and privilege management',
    requirement: 'Access to systems and information is granted on a least-privilege, need-to-know basis; privileged access is controlled and reviewed.',
    sourceRef: 'NZISM v3.8, Ch.16 Authentication and Access Controls (16.2 System Access, 16.3 Privileged User Access)', url: URL, verified: true },
  { id: 'NZISM-AUTH', framework: 'NZISM', version: V, title: 'Identification, authentication and MFA',
    requirement: 'Users and systems are uniquely identified and strongly authenticated, including multi-factor authentication.',
    sourceRef: 'NZISM v3.8, Ch.16 Authentication and Access Controls (16.1 Identification, Authentication and Authorisation, 16.7 Multi-Factor Authentication)', url: URL, verified: true },
  { id: 'NZISM-LOG', framework: 'NZISM', version: V, title: 'Event monitoring, logging and auditing',
    requirement: 'Security-relevant events are logged with sufficient detail and retention, and reviewed to detect and investigate incidents.',
    sourceRef: 'NZISM v3.8, §16.6 Event Monitoring, Logging and Auditing', url: URL, verified: true },
  { id: 'NZISM-CRYPTO', framework: 'NZISM', version: V, title: 'Cryptography and key management',
    requirement: 'Approved cryptographic algorithms, protocols, and key management protect information in transit and at rest.',
    sourceRef: 'NZISM v3.8, Ch.17 Cryptography', url: URL, verified: true },
  { id: 'NZISM-SW', framework: 'NZISM', version: V, title: 'Software and application security',
    requirement: 'Applications are developed and configured securely, mitigating common code-level vulnerabilities and unsafe execution.',
    sourceRef: 'NZISM v3.8, Ch.14 Software Security', url: URL, verified: true },
  { id: 'NZISM-NET', framework: 'NZISM', version: V, title: 'Network security and gateways',
    requirement: 'Network connections, gateways, and external integrations are restricted to authorised, secured endpoints.',
    sourceRef: 'NZISM v3.8, Ch.18 Network Security / Ch.19 Gateway Security', url: URL, verified: true },
  { id: 'NZISM-CONFIG', framework: 'NZISM', version: V, title: 'System hardening and configuration',
    requirement: 'Systems are hardened to a secure baseline, kept current with security updates, and unnecessary functionality is disabled.',
    sourceRef: 'NZISM v3.8, Ch.12 Product Security (configuration and patching)', url: URL, verified: true },
];
