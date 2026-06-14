import type { ControlDef } from '../types.js';

const V = 'OWASP Top 10:2021';

export const OWASP_CONTROLS: ControlDef[] = [
  { id: 'OWASP-A01', framework: 'OWASP', version: V, title: 'Broken Access Control',
    requirement: 'Access control enforces policy so users cannot act outside their intended permissions; deny by default, enforce record/field ownership.',
    sourceRef: 'OWASP Top 10:2021 A01', verified: false },
  { id: 'OWASP-A02', framework: 'OWASP', version: V, title: 'Cryptographic Failures',
    requirement: 'Sensitive data (credentials, secrets, PII) is protected in transit and at rest; secrets are not hardcoded or exposed.',
    sourceRef: 'OWASP Top 10:2021 A02', verified: false },
  { id: 'OWASP-A03', framework: 'OWASP', version: V, title: 'Injection',
    requirement: 'Untrusted input is validated/escaped so it cannot alter queries, markup, or commands (SOQL injection, XSS).',
    sourceRef: 'OWASP Top 10:2021 A03', verified: false },
  { id: 'OWASP-A05', framework: 'OWASP', version: V, title: 'Security Misconfiguration',
    requirement: 'Platform and application security settings are hardened and reviewed; unnecessary features and exposure are removed.',
    sourceRef: 'OWASP Top 10:2021 A05', verified: false },
  { id: 'OWASP-A06', framework: 'OWASP', version: V, title: 'Vulnerable and Outdated Components',
    requirement: 'Installed packages and platform components are inventoried and kept current; outdated/unsupported components are flagged.',
    sourceRef: 'OWASP Top 10:2021 A06', verified: false },
  { id: 'OWASP-A07', framework: 'OWASP', version: V, title: 'Identification and Authentication Failures',
    requirement: 'Authentication is strong (MFA, session controls, IP/login policy) and resistant to credential stuffing and session abuse.',
    sourceRef: 'OWASP Top 10:2021 A07', verified: false },
  { id: 'OWASP-A09', framework: 'OWASP', version: V, title: 'Security Logging and Monitoring Failures',
    requirement: 'Security-relevant events are logged, retained, and monitored so incidents can be detected and investigated.',
    sourceRef: 'OWASP Top 10:2021 A09', verified: false },
];
