// Threat categories. These classify the harm a finding describes; they are not compliance
// controls and never enter the compliance catalog or matrix (RULE-100).

/** Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. */
export type StrideCategory = 'S' | 'T' | 'R' | 'I' | 'D' | 'E';

/**
 * LINDDUN (2023): Linking, Identifying, Non-repudiation, Detecting, Data disclosure,
 * Unawareness & unintervenability, Non-compliance.
 */
export type LinddunCategory = 'L' | 'I' | 'Nr' | 'D' | 'DD' | 'U' | 'Nc';

export interface FindingThreats {
  stride?: StrideCategory[];
  linddun?: LinddunCategory[];
  /** Verified ATT&CK technique ids for the capabilities the finding grants (RULE-106). */
  attack?: string[];
  /** Verified ATT&CK technique ids a detection gap leaves unobserved (RULE-108). */
  detects?: string[];
}

export const STRIDE_CATEGORIES: readonly StrideCategory[] = ['S', 'T', 'R', 'I', 'D', 'E'];
export const LINDDUN_CATEGORIES: readonly LinddunCategory[] = ['L', 'I', 'Nr', 'D', 'DD', 'U', 'Nc'];

export const STRIDE_NAMES: Record<StrideCategory, string> = {
  S: 'Spoofing',
  T: 'Tampering',
  R: 'Repudiation',
  I: 'Information disclosure',
  D: 'Denial of service',
  E: 'Elevation of privilege',
};

export const LINDDUN_NAMES: Record<LinddunCategory, string> = {
  L: 'Linking',
  I: 'Identifying',
  Nr: 'Non-repudiation',
  D: 'Detecting',
  DD: 'Data disclosure',
  U: 'Unawareness & unintervenability',
  Nc: 'Non-compliance',
};
