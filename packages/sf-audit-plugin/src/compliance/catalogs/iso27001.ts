import type { ControlDef } from '../types.js';

// ISO/IEC 27001:2022 Annex A. Control numbers + titles VERIFIED 2026-06 against an authoritative
// Annex A reference (isms.online). Remapped from the withdrawn 2013 Annex A numbering to the 2022
// structure (Organisational 5.x, People 6.x, Physical 7.x, Technological 8.x). `requirement` is a
// faithful paraphrase; verbatim control text is in the purchased standard.
const V = 'ISO/IEC 27001:2022';
const ref = (n: string): string => `ISO/IEC 27001:2022, Annex A ${n}`;

export const ISO27001_CONTROLS: ControlDef[] = [
  { id: 'ISO-A.5.12', framework: 'ISO27001', version: V, title: 'Classification of information',
    requirement: 'Information is classified according to its confidentiality, integrity, and availability needs and legal requirements.',
    sourceRef: ref('A.5.12'), verified: true },
  { id: 'ISO-A.5.14', framework: 'ISO27001', version: V, title: 'Information transfer',
    requirement: 'Information transfer is protected by rules, procedures, and agreements across all communication channels.',
    sourceRef: ref('A.5.14'), verified: true },
  { id: 'ISO-A.5.18', framework: 'ISO27001', version: V, title: 'Access rights',
    requirement: 'Access rights to information and assets are provisioned, reviewed, modified, and removed per the access control policy.',
    sourceRef: ref('A.5.18'), verified: true },
  { id: 'ISO-A.8.3', framework: 'ISO27001', version: V, title: 'Information access restriction',
    requirement: 'Access to information and application functions is restricted in line with the access control policy.',
    sourceRef: ref('A.8.3'), verified: true },
  { id: 'ISO-A.8.8', framework: 'ISO27001', version: V, title: 'Management of technical vulnerabilities',
    requirement: 'Technical vulnerabilities are identified, evaluated, and remediated in a timely manner.',
    sourceRef: ref('A.8.8'), verified: true },
  { id: 'ISO-A.8.15', framework: 'ISO27001', version: V, title: 'Logging',
    requirement: 'Logs recording activities, exceptions, faults, and security events are produced, stored, protected, and reviewed.',
    sourceRef: ref('A.8.15'), verified: true },
  { id: 'ISO-A.8.24', framework: 'ISO27001', version: V, title: 'Use of cryptography',
    requirement: 'Rules for the effective use of cryptography, including key management, protect information confidentiality and integrity.',
    sourceRef: ref('A.8.24'), verified: true },
  { id: 'ISO-A.8.25', framework: 'ISO27001', version: V, title: 'Secure development life cycle',
    requirement: 'Rules for the secure development of software and systems are established and applied.',
    sourceRef: ref('A.8.25'), verified: true },
  { id: 'ISO-A.8.26', framework: 'ISO27001', version: V, title: 'Application security requirements',
    requirement: 'Information security requirements are identified, specified, and approved when developing or acquiring applications.',
    sourceRef: ref('A.8.26'), verified: true },
  { id: 'ISO-A.8.32', framework: 'ISO27001', version: V, title: 'Change management',
    requirement: 'Changes to information processing facilities and systems are subject to change management procedures.',
    sourceRef: ref('A.8.32'), verified: true },
];
