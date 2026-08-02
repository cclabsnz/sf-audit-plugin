import type { ControlDef } from '../types.js';

// OWASP Top 10 for Large Language Model Applications, 2025 edition.
// Ids and titles verified 2026-07 against the official list: https://genai.owasp.org/llm-top-10/
// Only the risks that a read-only Salesforce/Agentforce config audit can speak to are
// catalogued here; the remaining 2025 entries (LLM03 Supply Chain, LLM04 Data & Model
// Poisoning, LLM07 System Prompt Leakage, LLM08 Vector & Embedding Weaknesses, LLM09
// Misinformation, LLM10 Unbounded Consumption) concern model/training/runtime behaviour that
// is not observable from org metadata, so they are intentionally omitted rather than mapped
// weakly — the same discipline OWASP web A04 (Insecure Design) is treated with in owasp.ts.
const V = 'OWASP Top 10 for LLM Applications 2025';
const ref = (id: string): string => `OWASP Top 10 for LLM Applications 2025, ${id}`;
const url = 'https://genai.owasp.org/llm-top-10/';

export const OWASP_LLM_CONTROLS: ControlDef[] = [
  { id: 'LLM01', framework: 'OWASP_LLM', version: V, title: 'Prompt Injection',
    requirement:
      'User or content-supplied input can alter an LLM application\'s behaviour or outputs in unintended, ' +
      'attacker-controlled ways. Untrusted input paths to an agent (public channels) and the destinations ' +
      'that injected output can reach (allowlisted egress domains) are constrained and reviewed.',
    sourceRef: ref('LLM01'), url, verified: true },
  { id: 'LLM02', framework: 'OWASP_LLM', version: V, title: 'Sensitive Information Disclosure',
    requirement:
      'The LLM application must not expose sensitive data through its outputs, and misuse that leads to such ' +
      'disclosure must be detectable. Access to sensitive data by the agent identity is minimised and agent ' +
      'activity is captured so exfiltration can be detected and investigated.',
    sourceRef: ref('LLM02'), url, verified: true },
  { id: 'LLM05', framework: 'OWASP_LLM', version: V, title: 'Improper Output Handling',
    requirement:
      'LLM-generated output is validated and safely handled by downstream components rather than trusted ' +
      'implicitly. Channels that agent output can be sent to (e.g. CSP-trusted / allowlisted domains) are ' +
      'owned, current, and expected, so output cannot be routed to an attacker-controlled destination.',
    sourceRef: ref('LLM05'), url, verified: true },
  { id: 'LLM06', framework: 'OWASP_LLM', version: V, title: 'Excessive Agency',
    requirement:
      'An LLM-based system is granted only the functionality, permissions, and autonomy it strictly needs. ' +
      'The agent\'s run-as identity is least-privilege and its action surface (especially write-capable ' +
      'actions) is minimal, inventoried, and reviewed.',
    sourceRef: ref('LLM06'), url, verified: true },
];
