import { describe, it, expect } from '@jest/globals';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import { renderProbeHtml } from '../../../src/report/probeReport.js';
import type { ProbeResult } from '../../../src/probe/types.js';

const result: ProbeResult = {
  version: 1,
  provenance: {
    tool: 'orgintel',
    toolVersion: '0.1.0',
    generatedAt: '2026-07-26T00:00:00.000Z',
    orgId: '00Dxx0000001gPZEAY',
  },
  org: {
    orgId: '00Dxx0000001gPZEAY',
    name: 'Acme <Health> & Co',
    organizationType: 'Enterprise Edition',
    isSandbox: false,
    instanceUrl: 'https://acme.my.salesforce.com',
    apiVersion: '62.0',
    namespace: null,
  },
  eventMonitoring: {
    level: 'free-tier',
    access: 'ok',
    intervals: ['Daily'],
    eventTypes: ['Login'],
    eventTypeCount: 1,
    note: 'Free daily logs.',
  },
  fieldHistory: {
    objects: [
      { object: 'Account', custom: false, historyTrackingEnabled: true, trackedFieldCount: 2, trackedFields: ['Owner', 'Name'], atCap: false },
    ],
    trackedObjectCount: 1,
    fieldAuditTrail: false,
    note: 'Standard retention applies.',
  },
  behavioralTables: {
    tables: [{ name: 'CaseHistory', access: 'ok', rowCount12mo: 1234 }],
  },
  evidenceTier: 'B',
  coverage: [{ source: 'Event Monitoring', status: 'partial', detail: 'Free daily · 1 event type(s)' }],
  recommendations: [
    { title: 'Enable field history tracking', detail: 'Turn it on for status fields.', priority: 'high' },
  ],
};

describe('renderProbeHtml', () => {
  const html = renderProbeHtml(result, DEFAULT_BRANDING);

  it('is a self-contained HTML document with the org and tier', () => {
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('Org Capability Probe');
    expect(html).toContain('Evidence tier B');
    expect(html).toContain('@font-face'); // fonts inlined via core report shell
  });

  it('escapes org-supplied strings', () => {
    expect(html).toContain('Acme &lt;Health&gt; &amp; Co');
    expect(html).not.toContain('Acme <Health>');
  });

  it('renders each section and the recommendation', () => {
    expect(html).toContain('Event Monitoring');
    expect(html).toContain('Field history');
    expect(html).toContain('Behavioral tables');
    expect(html).toContain('Enable field history tracking');
    expect(html).toContain('1,234'); // formatted row count
  });
});
