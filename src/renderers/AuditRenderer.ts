import type { AuditResult } from '../findings/AuditResult.js';

export interface AuditRenderer {
  readonly format: string;
  readonly fileExtension: string;
  render(result: AuditResult): string;
}
