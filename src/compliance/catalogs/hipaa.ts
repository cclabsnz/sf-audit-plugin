import type { ControlDef } from '../types.js';

// HIPAA Security Rule — 45 CFR Part 164, Subpart C ("Security Standards for the Protection of
// Electronic Protected Health Information"), as amended by the 2013 Omnibus Rule.
//
// Version pinning matters here. HHS published an NPRM on 2025-01-06 that would rewrite these
// safeguards — removing the Required/Addressable distinction and making encryption, MFA and
// network segmentation mandatory. As of 2026-08 that rule is still PROPOSED, not final, so this
// catalog maps the operative rule. When the final rule lands, `version` and the affected
// `requirement` texts must be re-pinned and re-verified, not silently amended.
//
// Standard headings and implementation-specification names verified 2026-08 against the
// codified text of 45 CFR 164.308 / 164.310 / 164.312, including each spec's
// Required vs Addressable designation. `requirement` quotes the regulatory text.
//
// Scope note: only safeguards a read-only Salesforce org-configuration review can speak to are
// catalogued. The physical safeguards (164.310), contingency planning (164.308(a)(7)) and the
// documentation requirements (164.316) are out of scope for this tool and deliberately absent —
// their absence is not a claim that they do not apply.
const V = '45 CFR Part 164 Subpart C (HIPAA Security Rule, 2013 Omnibus)';
const URL = 'https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C';
const ref = (cite: string): string => `45 CFR ${cite}`;

export const HIPAA_CONTROLS: ControlDef[] = [
  // --- 164.308 Administrative safeguards ---
  { id: 'HIPAA-164.308(a)(1)(ii)(A)', framework: 'HIPAA', version: V,
    title: 'Risk analysis (Required)',
    requirement: 'Conduct an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of electronic protected health information held by the covered entity or business associate.',
    sourceRef: ref('164.308(a)(1)(ii)(A)'), url: URL, verified: true },
  { id: 'HIPAA-164.308(a)(1)(ii)(B)', framework: 'HIPAA', version: V,
    title: 'Risk management (Required)',
    requirement: 'Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level.',
    sourceRef: ref('164.308(a)(1)(ii)(B)'), url: URL, verified: true },
  { id: 'HIPAA-164.308(a)(1)(ii)(D)', framework: 'HIPAA', version: V,
    title: 'Information system activity review (Required)',
    requirement: 'Implement procedures to regularly review records of information system activity, such as audit logs, access reports, and security incident tracking reports.',
    sourceRef: ref('164.308(a)(1)(ii)(D)'), url: URL, verified: true },
  { id: 'HIPAA-164.308(a)(3)', framework: 'HIPAA', version: V,
    title: 'Workforce security',
    requirement: 'Implement policies and procedures to ensure that all members of the workforce have appropriate access to electronic protected health information, and to prevent those who do not have access from obtaining access — including termination procedures for ending access when employment or authorisation ends.',
    sourceRef: ref('164.308(a)(3)'), url: URL, verified: true },
  { id: 'HIPAA-164.308(a)(4)', framework: 'HIPAA', version: V,
    title: 'Information access management',
    requirement: 'Implement policies and procedures for authorising access to electronic protected health information that are consistent with the applicable requirements of subpart E, including access authorisation and access establishment and modification.',
    sourceRef: ref('164.308(a)(4)'), url: URL, verified: true },
  { id: 'HIPAA-164.308(a)(5)(ii)(C)', framework: 'HIPAA', version: V,
    title: 'Log-in monitoring (Addressable)',
    requirement: 'Procedures for monitoring log-in attempts and reporting discrepancies.',
    sourceRef: ref('164.308(a)(5)(ii)(C)'), url: URL, verified: true },
  { id: 'HIPAA-164.308(a)(5)(ii)(D)', framework: 'HIPAA', version: V,
    title: 'Password management (Addressable)',
    requirement: 'Procedures for creating, changing, and safeguarding passwords.',
    sourceRef: ref('164.308(a)(5)(ii)(D)'), url: URL, verified: true },
  { id: 'HIPAA-164.308(a)(6)', framework: 'HIPAA', version: V,
    title: 'Security incident procedures',
    requirement: 'Implement policies and procedures to address security incidents, including identifying and responding to suspected or known security incidents, mitigating their harmful effects, and documenting incidents and their outcomes.',
    sourceRef: ref('164.308(a)(6)'), url: URL, verified: true },
  { id: 'HIPAA-164.308(a)(8)', framework: 'HIPAA', version: V,
    title: 'Evaluation',
    requirement: 'Perform a periodic technical and nontechnical evaluation, in response to environmental or operational changes affecting the security of electronic protected health information, that establishes the extent to which security policies and procedures meet the requirements of this subpart.',
    sourceRef: ref('164.308(a)(8)'), url: URL, verified: true },

  // --- 164.312 Technical safeguards ---
  { id: 'HIPAA-164.312(a)(1)', framework: 'HIPAA', version: V,
    title: 'Access control',
    requirement: 'Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights as specified in 164.308(a)(4).',
    sourceRef: ref('164.312(a)(1)'), url: URL, verified: true },
  { id: 'HIPAA-164.312(a)(2)(i)', framework: 'HIPAA', version: V,
    title: 'Unique user identification (Required)',
    requirement: 'Assign a unique name and/or number for identifying and tracking user identity.',
    sourceRef: ref('164.312(a)(2)(i)'), url: URL, verified: true },
  { id: 'HIPAA-164.312(a)(2)(iii)', framework: 'HIPAA', version: V,
    title: 'Automatic logoff (Addressable)',
    requirement: 'Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity.',
    sourceRef: ref('164.312(a)(2)(iii)'), url: URL, verified: true },
  { id: 'HIPAA-164.312(a)(2)(iv)', framework: 'HIPAA', version: V,
    title: 'Encryption and decryption (Addressable)',
    requirement: 'Implement a mechanism to encrypt and decrypt electronic protected health information.',
    sourceRef: ref('164.312(a)(2)(iv)'), url: URL, verified: true },
  { id: 'HIPAA-164.312(b)', framework: 'HIPAA', version: V,
    title: 'Audit controls',
    requirement: 'Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information.',
    sourceRef: ref('164.312(b)'), url: URL, verified: true },
  { id: 'HIPAA-164.312(c)(1)', framework: 'HIPAA', version: V,
    title: 'Integrity',
    requirement: 'Implement policies and procedures to protect electronic protected health information from improper alteration or destruction.',
    sourceRef: ref('164.312(c)(1)'), url: URL, verified: true },
  { id: 'HIPAA-164.312(d)', framework: 'HIPAA', version: V,
    title: 'Person or entity authentication',
    requirement: 'Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed.',
    sourceRef: ref('164.312(d)'), url: URL, verified: true },
  { id: 'HIPAA-164.312(e)(1)', framework: 'HIPAA', version: V,
    title: 'Transmission security',
    requirement: 'Implement technical security measures to guard against unauthorised access to electronic protected health information that is being transmitted over an electronic communications network.',
    sourceRef: ref('164.312(e)(1)'), url: URL, verified: true },
  { id: 'HIPAA-164.312(e)(2)(ii)', framework: 'HIPAA', version: V,
    title: 'Encryption in transmission (Addressable)',
    requirement: 'Implement a mechanism to encrypt electronic protected health information whenever deemed appropriate.',
    sourceRef: ref('164.312(e)(2)(ii)'), url: URL, verified: true },
];
