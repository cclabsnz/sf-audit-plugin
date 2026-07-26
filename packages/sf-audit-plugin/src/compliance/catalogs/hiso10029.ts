import type { ControlDef } from '../types.js';

// HISO 10029:2022 — Health Information Security Framework (HISF), Health NZ / Te Whatu Ora.
// Basis VERIFIED 2026-06: HISF is explicitly built on AS/NZS ISO/IEC 27002 (confirmed via the
// framework and Te Whatu Ora cyber standards). These are DOMAIN-LEVEL controls mapped to the
// ISO 27002 control areas HISF adopts. `verified` = the framework basis and domain coverage are
// confirmed; exact HISF 2022 clause references are a later granularity pass needing the MoH document.
const V = 'HISO 10029:2022 (HISF)';
const URL = 'https://www.tewhatuora.govt.nz/health-services-and-programmes/cyber-hub/cyber-standards';
const ref = (domain: string): string => `HISO 10029:2022 (HISF, AS/NZS ISO/IEC 27002-aligned), ${domain}`;

export const HISO10029_CONTROLS: ControlDef[] = [
  { id: 'HISO-AC', framework: 'HISO10029', version: V, title: 'Access control',
    requirement: 'Access to health information and supporting systems is restricted to authorised users on a need-to-know, least-privilege basis.',
    sourceRef: ref('Access Control'), url: URL, verified: true },
  { id: 'HISO-AUTH', framework: 'HISO10029', version: V, title: 'Identity and authentication',
    requirement: 'Users are uniquely identified and strongly authenticated (including multi-factor) before accessing health information.',
    sourceRef: ref('Authentication'), url: URL, verified: true },
  { id: 'HISO-CRYPTO', framework: 'HISO10029', version: V, title: 'Cryptography and key management',
    requirement: 'Health information is protected using appropriate cryptographic controls in transit and at rest, with managed keys and credentials.',
    sourceRef: ref('Cryptography'), url: URL, verified: true },
  { id: 'HISO-LOG', framework: 'HISO10029', version: V, title: 'Logging, monitoring and audit',
    requirement: 'Security-relevant events affecting health information are logged, retained, and monitored to support detection and investigation.',
    sourceRef: ref('Logging and Monitoring'), url: URL, verified: true },
  { id: 'HISO-DATA', framework: 'HISO10029', version: V, title: 'Information classification and handling',
    requirement: 'Health information is classified and handled according to its sensitivity, including identification of personal and sensitive data.',
    sourceRef: ref('Information Classification'), url: URL, verified: true },
  { id: 'HISO-DEV', framework: 'HISO10029', version: V, title: 'Secure development and change',
    requirement: 'Application code and changes follow secure development practices that prevent introduction of vulnerabilities affecting health information.',
    sourceRef: ref('Secure Development'), url: URL, verified: true },
  { id: 'HISO-COMM', framework: 'HISO10029', version: V, title: 'Communications and integration security',
    requirement: 'Integrations and external communications carrying health information use secure, controlled, and authorised channels.',
    sourceRef: ref('Communications Security'), url: URL, verified: true },
  { id: 'HISO-GOV', framework: 'HISO10029', version: V, title: 'Security configuration and governance',
    requirement: 'Systems holding health information are securely configured, kept current, and governed against a defined security baseline.',
    sourceRef: ref('Security Governance'), url: URL, verified: true },
];
