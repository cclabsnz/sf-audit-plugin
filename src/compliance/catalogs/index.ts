import type { ControlDef } from '../types.js';
import { OWASP_CONTROLS } from './owasp.js';
import { SOC2_CONTROLS } from './soc2.js';
import { ISO27001_CONTROLS } from './iso27001.js';
import { SBS_CONTROLS } from './sbs.js';

export const ALL_CONTROLS: ControlDef[] = [
  ...OWASP_CONTROLS,
  ...SOC2_CONTROLS,
  ...ISO27001_CONTROLS,
  ...SBS_CONTROLS,
];

const BY_ID: Map<string, ControlDef> = new Map(ALL_CONTROLS.map((c) => [c.id, c]));

export function getControl(id: string): ControlDef | undefined {
  return BY_ID.get(id);
}
