import type { ControlDef } from '../types.js';

// NOTE: ids use ISO/IEC 27001:2013 Annex A numbering (the scheme the existing tags use).
// The 2022 revision renumbered Annex A; re-mapping these to 2022 controls is part of the
// verification pass. version is labelled to match the numbering scheme honestly.
const V = 'ISO/IEC 27001:2013 (Annex A)';

export const ISO27001_CONTROLS: ControlDef[] = [
  { id: 'ISO-A.8.2', framework: 'ISO27001', version: V, title: 'Information classification',
    requirement: 'Information is classified and handled according to its value, sensitivity, and legal requirements.',
    sourceRef: 'ISO/IEC 27001:2013, A.8.2', verified: false },
  { id: 'ISO-A.9.2', framework: 'ISO27001', version: V, title: 'User access management',
    requirement: 'Formal user access provisioning and de-provisioning controls restrict access to authorized users.',
    sourceRef: 'ISO/IEC 27001:2013, A.9.2', verified: false },
  { id: 'ISO-A.9.4', framework: 'ISO27001', version: V, title: 'System and application access control',
    requirement: 'Access to systems and applications is restricted in line with the access control policy, including secure log-on.',
    sourceRef: 'ISO/IEC 27001:2013, A.9.4', verified: false },
  { id: 'ISO-A.10.1', framework: 'ISO27001', version: V, title: 'Cryptographic controls',
    requirement: 'A policy on the use of cryptographic controls and key management protects confidentiality and integrity of information.',
    sourceRef: 'ISO/IEC 27001:2013, A.10.1', verified: false },
  { id: 'ISO-A.12.1', framework: 'ISO27001', version: V, title: 'Operational procedures and responsibilities',
    requirement: 'Operating procedures and change controls ensure correct and secure operation of information processing facilities.',
    sourceRef: 'ISO/IEC 27001:2013, A.12.1', verified: false },
  { id: 'ISO-A.12.4', framework: 'ISO27001', version: V, title: 'Logging and monitoring',
    requirement: 'Event logs recording user activities, exceptions, and security events are produced, kept, and reviewed.',
    sourceRef: 'ISO/IEC 27001:2013, A.12.4', verified: false },
  { id: 'ISO-A.12.6', framework: 'ISO27001', version: V, title: 'Technical vulnerability management',
    requirement: 'Technical vulnerabilities are identified, evaluated, and addressed in a timely manner.',
    sourceRef: 'ISO/IEC 27001:2013, A.12.6', verified: false },
  { id: 'ISO-A.13.2', framework: 'ISO27001', version: V, title: 'Information transfer',
    requirement: 'Controls protect the transfer of information through all types of communication facilities and external sharing.',
    sourceRef: 'ISO/IEC 27001:2013, A.13.2', verified: false },
  { id: 'ISO-A.14.1', framework: 'ISO27001', version: V, title: 'Security requirements of information systems',
    requirement: 'Security requirements are included in systems, and information in application services on public networks is protected.',
    sourceRef: 'ISO/IEC 27001:2013, A.14.1', verified: false },
  { id: 'ISO-A.14.2', framework: 'ISO27001', version: V, title: 'Security in development and support',
    requirement: 'Secure development practices, including secure coding and review, are applied across the development lifecycle.',
    sourceRef: 'ISO/IEC 27001:2013, A.14.2', verified: false },
];
