import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';
import { DEFAULT_BRANDING } from '../../../src/report/branding.js';

it('exposes a filenamePrefix the command can use to avoid collisions', () => {
  const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5 });
  const prefix: string = r.filenamePrefix ?? 'sf-audit';
  expect(prefix).toBe('SF_Audit_Executive');
});
