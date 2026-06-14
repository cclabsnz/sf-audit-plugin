import type { ControlDef } from '../types.js';

// New Zealand Privacy Act 2020 — Information Privacy Principles (IPPs).
// IPP numbers are well-defined in statute; requirement text is a close paraphrase and is
// confirmed against the Act in the verification pass. verified:false until then.
const V = 'NZ Privacy Act 2020 (IPPs)';

export const PRIVACY_ACT_CONTROLS: ControlDef[] = [
  { id: 'PRIVACY-IPP5', framework: 'PRIVACY_ACT', version: V, title: 'IPP 5 — Storage and security of personal information',
    requirement: 'An agency holding personal information must ensure it is protected by such security safeguards as are reasonable to prevent loss, misuse, and unauthorised access, use, modification, or disclosure.',
    sourceRef: 'Privacy Act 2020, IPP 5', url: 'https://www.legislation.govt.nz/act/public/2020/0031/latest/LMS23342.html', verified: false },
  { id: 'PRIVACY-IPP9', framework: 'PRIVACY_ACT', version: V, title: 'IPP 9 — Retention of personal information',
    requirement: 'An agency must not keep personal information for longer than is required for the purposes for which it may lawfully be used.',
    sourceRef: 'Privacy Act 2020, IPP 9', verified: false },
  { id: 'PRIVACY-IPP12', framework: 'PRIVACY_ACT', version: V, title: 'IPP 12 — Disclosure of personal information outside New Zealand',
    requirement: 'An agency may disclose personal information to a foreign person or entity only where comparable safeguards (or specified exceptions) apply.',
    sourceRef: 'Privacy Act 2020, IPP 12', verified: false },
];
