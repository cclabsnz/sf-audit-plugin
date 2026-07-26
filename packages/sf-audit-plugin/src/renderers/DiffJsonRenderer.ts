// src/renderers/DiffJsonRenderer.ts
import type { AuditDiff } from '../history/AuditDiff.js';
import type { DiffRenderer } from './DiffRenderer.js';

export class DiffJsonRenderer implements DiffRenderer {
  readonly format = 'json';
  readonly fileExtension = '.json';

  render(diff: AuditDiff): string {
    return JSON.stringify(diff, null, 2);
  }
}
