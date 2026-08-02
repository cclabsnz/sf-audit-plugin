// src/renderers/DiffRenderer.ts
import type { AuditDiff } from '../history/AuditDiff.js';

export interface DiffRenderer {
  readonly format: string;
  readonly fileExtension: string;
  render(diff: AuditDiff): string;
}
