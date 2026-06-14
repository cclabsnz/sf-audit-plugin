import type { ControlDef } from '../types.js';

// HISO 10029:2022 — Health Information Security Framework (HISF), NZ Ministry of Health.
// HISF aligns to ISO/IEC 27002 control areas. These are DOMAIN-LEVEL crosswalk drafts:
// they point to the correct framework + control area by name, and the verification pass
// maps each to the exact HISF control statement. verified:false until then.
const V = 'HISO 10029:2022 (HISF)';
const ref = (domain: string): string => `HISO 10029:2022 (HISF), ${domain}`;

export const HISO10029_CONTROLS: ControlDef[] = [
  { id: 'HISO-AC', framework: 'HISO10029', version: V, title: 'Access control',
    requirement: 'Access to health information and supporting systems is restricted to authorised users on a need-to-know, least-privilege basis.',
    sourceRef: ref('Access Control'), verified: false },
  { id: 'HISO-AUTH', framework: 'HISO10029', version: V, title: 'Identity and authentication',
    requirement: 'Users are uniquely identified and strongly authenticated (including multi-factor) before accessing health information.',
    sourceRef: ref('Authentication'), verified: false },
  { id: 'HISO-CRYPTO', framework: 'HISO10029', version: V, title: 'Cryptography and key management',
    requirement: 'Health information is protected using appropriate cryptographic controls in transit and at rest, with managed keys and credentials.',
    sourceRef: ref('Cryptography'), verified: false },
  { id: 'HISO-LOG', framework: 'HISO10029', version: V, title: 'Logging, monitoring and audit',
    requirement: 'Security-relevant events affecting health information are logged, retained, and monitored to support detection and investigation.',
    sourceRef: ref('Logging and Monitoring'), verified: false },
  { id: 'HISO-DATA', framework: 'HISO10029', version: V, title: 'Information classification and handling',
    requirement: 'Health information is classified and handled according to its sensitivity, including identification of personal and sensitive data.',
    sourceRef: ref('Information Classification'), verified: false },
  { id: 'HISO-DEV', framework: 'HISO10029', version: V, title: 'Secure development and change',
    requirement: 'Application code and changes follow secure development practices that prevent introduction of vulnerabilities affecting health information.',
    sourceRef: ref('Secure Development'), verified: false },
  { id: 'HISO-COMM', framework: 'HISO10029', version: V, title: 'Communications and integration security',
    requirement: 'Integrations and external communications carrying health information use secure, controlled, and authorised channels.',
    sourceRef: ref('Communications Security'), verified: false },
  { id: 'HISO-GOV', framework: 'HISO10029', version: V, title: 'Security configuration and governance',
    requirement: 'Systems holding health information are securely configured, kept current, and governed against a defined security baseline.',
    sourceRef: ref('Security Governance'), verified: false },
];
