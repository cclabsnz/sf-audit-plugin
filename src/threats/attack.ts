// MITRE ATT&CK techniques. They attach to the attacker capabilities a finding grants, never to a
// check (RULE-106), and only verified techniques ever render (RULE-107, MN-059).

import type { Capability } from '../chains/Capability.js';
import { ALL_CAPABILITIES } from '../chains/Capability.js';
import { CAPABILITY_REGISTRY, capabilitiesFor } from '../chains/CapabilityRegistry.js';
import type { Finding } from '../findings/Finding.js';

/** The Enterprise ATT&CK release every technique below was checked against. */
export const ATTACK_RELEASE = '20.0';

export interface AttackTechnique {
  id: string;
  name: string;
  /** Tactic short names as the pinned release spells them. */
  tactics: string[];
  release: string;
  url: string;
  /** Provenance gate: true only once id, name, tactics and fit are recorded in the verification worksheet. */
  verified: boolean;
}

function t(id: string, name: string, tactics: string[], verified: boolean): AttackTechnique {
  return {
    id, name, tactics, release: ATTACK_RELEASE,
    url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}`,
    verified,
  };
}

export const ATTACK_TECHNIQUES: Record<string, AttackTechnique> = {
  'T1190':     t('T1190', 'Exploit Public-Facing Application', ['initial-access'], true),
  'T1078.004': t('T1078.004', 'Cloud Accounts', ['stealth', 'persistence', 'privilege-escalation', 'initial-access'], true),
  'T1213.004': t('T1213.004', 'Customer Relationship Management Software', ['collection'], true),
  'T1565.001': t('T1565.001', 'Stored Data Manipulation', ['impact'], true),
  'T1059.009': t('T1059.009', 'Cloud API', ['execution'], true),
  'T1552':     t('T1552', 'Unsecured Credentials', ['credential-access'], true),
  'T1528':     t('T1528', 'Steal Application Access Token', ['credential-access'], true),
  'T1110':     t('T1110', 'Brute Force', ['credential-access'], true),
  'T1098.003': t('T1098.003', 'Additional Cloud Roles', ['persistence', 'privilege-escalation'], true),
  'T1098':     t('T1098', 'Account Manipulation', ['persistence', 'privilege-escalation'], true),
  'T1546':     t('T1546', 'Event Triggered Execution', ['privilege-escalation', 'persistence'], true),
  'T1648':     t('T1648', 'Serverless Execution', ['execution'], true),
  'T1567':     t('T1567', 'Exfiltration Over Web Service', ['exfiltration'], true),
  'T1685.002': t('T1685.002', 'Disable or Modify Cloud Log', ['defense-impairment'], true),
};

/**
 * What an attacker does with each capability. A technique sits here only if it fits every finding
 * that grants the capability; a finding it does not fit overrides it in its registry entry
 * (`CapabilityEntry.techniques`).
 */
export const CAPABILITY_TECHNIQUES: Record<Capability, string[]> = {
  'unauth-foothold':         ['T1190'],
  'low-trust-authenticated': ['T1078.004'],
  'data-read':               ['T1213.004'],
  'data-read-bulk':          ['T1213.004'],
  'data-write':              ['T1565.001'],
  'code-exec':               ['T1059.009'],
  'credential-theft':        ['T1552'],
  'priv-esc':                ['T1098.003'],
  'org-takeover':            ['T1098'],
  'external-egress':         ['T1567'],
};

/**
 * Detection gaps: the technique a finding leaves unobserved (RULE-108). Never a technique the
 * finding grants, and never added to a chain step.
 */
export const DETECTION_GAP_TECHNIQUES: Record<string, string[]> = {
  // No copy of the logs outside the org, so an attacker who disables or edits them there leaves no record.
  'siem-integration-not-detected': ['T1685.002'],
};

/** RULE-109: on only while every capability has a verified technique. */
export const ATTACK_OUTPUT_ENABLED = true;

function verifiedIds(ids: readonly string[] | undefined): string[] {
  if (!ATTACK_OUTPUT_ENABLED || !ids) return [];
  return ids.filter((id) => ATTACK_TECHNIQUES[id]?.verified);
}

/** Verified techniques for one capability as granted by this finding id. */
export function techniquesForGrant(findingId: string, capability: Capability): string[] {
  const override = CAPABILITY_REGISTRY[findingId]?.techniques?.[capability];
  return verifiedIds(override ?? CAPABILITY_TECHNIQUES[capability]);
}

/** Verified techniques for every capability the finding grants; none for capabilities it only requires. */
export function attackFor(finding: Finding): string[] | undefined {
  const out = new Set<string>();
  for (const cap of capabilitiesFor(finding).grants) {
    for (const id of techniquesForGrant(finding.id, cap)) out.add(id);
  }
  return out.size ? [...out] : undefined;
}

/** Verified techniques this detection-gap finding leaves unobserved. */
export function detectsFor(finding: Finding): string[] | undefined {
  if (finding.passed || finding.inconclusive) return undefined;
  const ids = verifiedIds(DETECTION_GAP_TECHNIQUES[finding.id]);
  return ids.length ? ids : undefined;
}

/** "T1213.004 Customer Relationship Management Software" — for text outputs. */
export function techniqueLabel(id: string): string {
  const tech = ATTACK_TECHNIQUES[id];
  return tech ? `${tech.id} ${tech.name}` : id;
}

/** Capabilities with no verified technique; RULE-109 requires this to be empty while output is on. */
export function capabilitiesWithoutTechnique(): Capability[] {
  return ALL_CAPABILITIES.filter(
    (c) => !(CAPABILITY_TECHNIQUES[c] ?? []).some((id) => ATTACK_TECHNIQUES[id]?.verified),
  );
}
