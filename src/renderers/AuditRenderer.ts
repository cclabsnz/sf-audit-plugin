import type { AuditResult } from '../findings/AuditResult.js';

export interface AuditRenderer {
  readonly format: string;
  readonly fileExtension: string;
  /** When set, used instead of 'sf-audit' for the output filename (avoids collisions between renderers sharing an extension). */
  readonly filenamePrefix?: string;
  render(result: AuditResult): string;
}
