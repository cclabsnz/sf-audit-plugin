import type { ControlDef } from '../types.js';

// New Zealand Information Security Manual (NZISM), GCSB/NCSC.
// These are CHAPTER-LEVEL drafts: they reference the correct NZISM chapter/control area by
// name (not a fabricated fine-grained control number). The verification pass maps each to the
// exact NZISM control reference for the version in force. verified:false until then.
const V = 'NZISM v3.7';
const ref = (chapter: string): string => `NZISM v3.7, ${chapter}`;

export const NZISM_CONTROLS: ControlDef[] = [
  { id: 'NZISM-AC', framework: 'NZISM', version: V, title: 'Access control and privilege management',
    requirement: 'Access to systems and information is granted on a least-privilege, need-to-know basis and reviewed; privileged access is tightly controlled.',
    sourceRef: ref('Access Control and Passwords'), verified: false },
  { id: 'NZISM-AUTH', framework: 'NZISM', version: V, title: 'Identification and authentication',
    requirement: 'Users and systems are uniquely identified and authenticated using strong methods, including multi-factor authentication for privileged and remote access.',
    sourceRef: ref('Authentication'), verified: false },
  { id: 'NZISM-LOG', framework: 'NZISM', version: V, title: 'Event logging and auditing',
    requirement: 'Security-relevant events are logged with sufficient detail and retention, and reviewed to detect and investigate security incidents.',
    sourceRef: ref('Event Logging and Auditing'), verified: false },
  { id: 'NZISM-CRYPTO', framework: 'NZISM', version: V, title: 'Cryptography and key management',
    requirement: 'Approved cryptographic algorithms and key/credential management protect information confidentiality and integrity in transit and at rest.',
    sourceRef: ref('Cryptography'), verified: false },
  { id: 'NZISM-SW', framework: 'NZISM', version: V, title: 'Software and application security',
    requirement: 'Applications are developed, configured, and maintained securely, mitigating common code-level vulnerabilities and unsafe execution.',
    sourceRef: ref('Software Security'), verified: false },
  { id: 'NZISM-NET', framework: 'NZISM', version: V, title: 'Network security and gateways',
    requirement: 'Network connections, gateways, and external integrations are restricted to authorised, secured endpoints and protected against unauthorised access.',
    sourceRef: ref('Gateway and Network Security'), verified: false },
  { id: 'NZISM-CONFIG', framework: 'NZISM', version: V, title: 'System hardening and configuration',
    requirement: 'Systems are hardened to a secure baseline, kept current with security updates, and unnecessary functionality is disabled.',
    sourceRef: ref('System Hardening'), verified: false },
];
