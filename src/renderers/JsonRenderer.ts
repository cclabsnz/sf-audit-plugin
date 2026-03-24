import type { AuditResult } from '../findings/AuditResult.js';
import type { AuditRenderer } from './AuditRenderer.js';

export class JsonRenderer implements AuditRenderer {
  readonly format = 'json';
  readonly fileExtension = '.json';

  render(result: AuditResult): string {
    return JSON.stringify(result, null, 2);
  }
}
