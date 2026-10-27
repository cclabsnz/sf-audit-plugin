import type { LinddunCategory } from './types.js';

// LINDDUN categories of the checks that concern personal data (RULE-102). A check with no privacy
// bearing has no entry: there is no default category.
export const CHECK_LINDDUN_MAP: Record<string, LinddunCategory[]> = {
  // Who can see personal data
  'sharing-model':                       ['DD', 'L'],
  'public-group-sharing':                ['DD'],
  'field-level-security':                ['DD'],
  'report-folder-access':                ['DD'],
  'restriction-rules-integrity':         ['DD'],
  'external-account-hierarchy-exposure': ['DD'],
  'guest-user-access':                   ['DD', 'I'],
  'guest-object-exposure':               ['DD'],
  'guest-record-access-policy':          ['DD'],
  'guest-site-options':                  ['DD'],
  'guest-api-access':                    ['DD'],
  'guest-user-visibility':               ['I', 'DD'],
  'experience-cloud-site':               ['DD', 'I'],
  'classic-sites':                       ['DD'],
  'content-links':                       ['DD', 'L'],
  'public-content-exposure':             ['DD'],
  'data-export-access':                  ['DD'],
  'debug-log-access':                    ['DD'],
  'data-cloud-data-space-isolation':     ['L', 'DD'],
  'agent-query-reach':                   ['DD'],
  'agent-outbound-actions':              ['DD', 'Nc'],
  'genai-prompt-template-grounding':     ['DD'],

  // How personal data is protected and governed
  'data-classification':                 ['Nc', 'U'],
  'encryption-coverage':                 ['DD'],
  'shield-tenant-secret-lifecycle':      ['DD'],
  'sandbox-data-masking':                ['DD', 'Nc'],

  // Logging that records personal data (read both ways with STRIDE R, RULE-103)
  'audit-trail':                         ['Nr', 'D'],
  'field-history-tracking':              ['Nr', 'D'],
  'event-monitoring':                    ['D', 'Nr'],
  'apex-logging':                        ['DD', 'D'],
  'siem-integration':                    ['D', 'Nc'],
  'agent-monitoring-coverage':           ['D', 'Nr'],
};
