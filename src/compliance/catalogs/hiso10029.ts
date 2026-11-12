import type { ControlDef } from '../types.js';

// HISO 10029:2022 — Health Information Security Framework (HISF), Health NZ / Te Whatu Ora.
// Basis VERIFIED 2026-11 against the published PDFs: HISF is built on the NIST Cybersecurity
// Framework (core s3: it "switches its focus from the ISO-centric model used previously" to a
// NIST CSF-based model). ISO/IEC 27002 is one of several catalogues it maps to (core s5.4), not its
// basis. These are DOMAIN-LEVEL controls; each sourceRef cites the HISO 10029.3:2023 requirement IDs
// (HML, medium to large organisations) the domain covers. Suppliers report against HISO 10029.4:2025
// (HSUP IDs) instead. `verified` = every cited HML ID and its requirement text were confirmed in the
// 10029.3 PDF.
const V = 'HISO 10029:2022 (HISF)';
const URL = 'https://www.healthnz.govt.nz/health-professionals/guidance-standards/topic/digital-technologies/cyber-security-hub/health-security-frameworks';
const ref = (hml: string): string => `HISO 10029:2022 (HISF); HISO 10029.3:2023 ${hml}`;

export const HISO10029_CONTROLS: ControlDef[] = [
  { id: 'HISO-AC', framework: 'HISO10029', version: V, title: 'Access control',
    requirement: 'Access to health information and supporting systems is restricted to authorised users on a need-to-know, least-privilege basis.',
    sourceRef: ref('HML10, HML38, HML40, HML41'), url: URL, verified: true },
  { id: 'HISO-AUTH', framework: 'HISO10029', version: V, title: 'Identity and authentication',
    requirement: 'Users are uniquely identified and strongly authenticated (including multi-factor) before accessing health information.',
    sourceRef: ref('HML39'), url: URL, verified: true },
  { id: 'HISO-CRYPTO', framework: 'HISO10029', version: V, title: 'Cryptography and key management',
    requirement: 'Health information is protected using appropriate cryptographic controls in transit and at rest, with managed keys and credentials.',
    sourceRef: ref('HML37'), url: URL, verified: true },
  { id: 'HISO-LOG', framework: 'HISO10029', version: V, title: 'Logging, monitoring and audit',
    requirement: 'Security-relevant events affecting health information are logged, retained, and monitored to support detection and investigation.',
    sourceRef: ref('HML70'), url: URL, verified: true },
  { id: 'HISO-DATA', framework: 'HISO10029', version: V, title: 'Information classification and handling',
    requirement: 'Health information is classified and handled according to its sensitivity, including identification of personal and sensitive data.',
    sourceRef: ref('HML05, HML69'), url: URL, verified: true },
  { id: 'HISO-DEV', framework: 'HISO10029', version: V, title: 'Secure development and change',
    requirement: 'Application code and changes follow secure development practices that prevent introduction of vulnerabilities affecting health information.',
    sourceRef: ref('HML18, HML42, HML50, HML58, HML67'), url: URL, verified: true },
  { id: 'HISO-COMM', framework: 'HISO10029', version: V, title: 'Communications and integration security',
    requirement: 'Integrations and external communications carrying health information use secure, controlled, and authorised channels.',
    sourceRef: ref('HML52, HML54'), url: URL, verified: true },
  { id: 'HISO-GOV', framework: 'HISO10029', version: V, title: 'Security configuration and governance',
    requirement: 'Systems holding health information are securely configured, kept current, and governed against a defined security baseline.',
    sourceRef: ref('HML19, HML59, HML60'), url: URL, verified: true },
];
