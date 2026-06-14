import type { ControlDef } from '../types.js';

// SOC 2 Common Criteria (AICPA Trust Services Criteria, 2017 with 2022 revised points of focus).
// Titles/intent confirmed 2026-06 against the AICPA TSC structure via authoritative secondary
// sources; the primary AICPA TSC document is the canonical reference. `requirement` is a faithful
// paraphrase of each criterion.
const V = 'AICPA TSC 2017 (Common Criteria)';
const ref = (cc: string): string => `AICPA Trust Services Criteria 2017, ${cc}`;

export const SOC2_CONTROLS: ControlDef[] = [
  { id: 'SOC2-CC6.1', framework: 'SOC2', version: V, title: 'Logical access controls',
    requirement: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.',
    sourceRef: ref('CC6.1'), verified: true },
  { id: 'SOC2-CC6.2', framework: 'SOC2', version: V, title: 'Registration and de-provisioning of users',
    requirement: 'New internal and external users are registered and authorized before being issued credentials; credentials are removed when access is no longer required.',
    sourceRef: ref('CC6.2'), verified: true },
  { id: 'SOC2-CC6.3', framework: 'SOC2', version: V, title: 'Role-based access and least privilege',
    requirement: 'Access to information assets is authorized and modified based on roles, least privilege, and segregation of duties.',
    sourceRef: ref('CC6.3'), verified: true },
  { id: 'SOC2-CC6.4', framework: 'SOC2', version: V, title: 'Physical access controls',
    requirement: 'The entity restricts physical access to facilities and protected information assets to authorized personnel. (Generally a data-centre control, not org configuration.)',
    sourceRef: ref('CC6.4'), verified: true },
  { id: 'SOC2-CC6.6', framework: 'SOC2', version: V, title: 'Boundary protection against external threats',
    requirement: 'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.',
    sourceRef: ref('CC6.6'), verified: true },
  { id: 'SOC2-CC6.7', framework: 'SOC2', version: V, title: 'Restriction of information transmission and movement',
    requirement: 'The entity restricts the transmission, movement, and removal of information to authorized users and processes, and protects it during transmission.',
    sourceRef: ref('CC6.7'), verified: true },
  { id: 'SOC2-CC7.1', framework: 'SOC2', version: V, title: 'Detection of configuration changes and vulnerabilities',
    requirement: 'The entity uses detection and monitoring procedures to identify configuration changes and susceptibility to newly discovered vulnerabilities.',
    sourceRef: ref('CC7.1'), verified: true },
  { id: 'SOC2-CC7.2', framework: 'SOC2', version: V, title: 'Monitoring for anomalies and security events',
    requirement: 'The entity monitors system components for anomalies indicative of malicious acts, errors, or other security events.',
    sourceRef: ref('CC7.2'), verified: true },
  { id: 'SOC2-CC8.1', framework: 'SOC2', version: V, title: 'Change management',
    requirement: 'Changes to infrastructure, data, software, and procedures are authorized, designed, tested, approved, and implemented under a controlled process.',
    sourceRef: ref('CC8.1'), verified: true },
  { id: 'SOC2-CC9.1', framework: 'SOC2', version: V, title: 'Risk mitigation for business disruptions',
    requirement: 'The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.',
    sourceRef: ref('CC9.1'), verified: true },
  { id: 'SOC2-CC9.2', framework: 'SOC2', version: V, title: 'Vendor and third-party risk management',
    requirement: 'The entity assesses and manages risks associated with vendors and business partners.',
    sourceRef: ref('CC9.2'), verified: true },
];
