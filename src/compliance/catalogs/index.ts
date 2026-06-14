import type { ControlDef } from '../types.js';
import { OWASP_CONTROLS } from './owasp.js';

export const ALL_CONTROLS: ControlDef[] = [
  ...OWASP_CONTROLS,
];

const BY_ID: Map<string, ControlDef> = new Map(ALL_CONTROLS.map((c) => [c.id, c]));

export function getControl(id: string): ControlDef | undefined {
  return BY_ID.get(id);
}
