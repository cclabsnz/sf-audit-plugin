import type { ControlDef } from '../types.js';
import { OWASP_CONTROLS } from './owasp.js';
import { OWASP_LLM_CONTROLS } from './owaspLlm.js';
import { SOC2_CONTROLS } from './soc2.js';
import { ISO27001_CONTROLS } from './iso27001.js';
import { SBS_CONTROLS } from './sbs.js';
import { PRIVACY_ACT_CONTROLS } from './privacyAct.js';
import { HISO10029_CONTROLS } from './hiso10029.js';
import { NZISM_CONTROLS } from './nzism.js';
import { HIPAA_CONTROLS } from './hipaa.js';
import { GDPR_CONTROLS } from './gdpr.js';

export const ALL_CONTROLS: ControlDef[] = [
  ...OWASP_CONTROLS,
  ...OWASP_LLM_CONTROLS,
  ...SOC2_CONTROLS,
  ...ISO27001_CONTROLS,
  ...SBS_CONTROLS,
  ...PRIVACY_ACT_CONTROLS,
  ...HISO10029_CONTROLS,
  ...NZISM_CONTROLS,
  ...HIPAA_CONTROLS,
  ...GDPR_CONTROLS,
];

const BY_ID: Map<string, ControlDef> = new Map(ALL_CONTROLS.map((c) => [c.id, c]));

export function getControl(id: string): ControlDef | undefined {
  return BY_ID.get(id);
}
