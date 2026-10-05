// src/incident/render/labels.ts
import type { Classification, WaveOutcome } from '../model.js';

export const CLASSIFICATION_LABEL: Record<Classification, string> = {
  'internal-testing': 'Consistent with internal testing',
  'automated-scan': 'Unattributed automated scan',
  organic: 'Organic spike',
  indeterminate: 'Indeterminate',
};

export const RESULT_LABEL: Record<WaveOutcome, string> = {
  'access-gained': 'Access gained',
  'content-returned': 'Content returned, contents unknown',
  'no-evidence': 'No evidence of access',
  'not-assessed': 'Not assessed',
};
