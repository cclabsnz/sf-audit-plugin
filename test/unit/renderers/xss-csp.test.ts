import { describe, it, expect } from '@jest/globals';
import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';
import { DiffHtmlRenderer } from '../../../src/renderers/DiffHtmlRenderer.js';
import { HistoryRenderer } from '../../../src/renderers/HistoryRenderer.js';
import { renderHtml as renderIncidentHtml } from '../../../src/incident/render/html.js';
import { buildEvidence } from '../../../src/incident/render/evidence.js';
import { computeDiff } from '../../../src/history/DiffEngine.js';
import { DEFAULT_BRANDING, EMPTY_METRICS } from '@cclabsnz/sf-core';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import type { IncidentResult } from '../../../src/incident/analyse/index.js';

const MALICIOUS_USER = 'admin"><img src=x onerror=alert(1)>@example.com';
const MALICIOUS_ORG = 'Acme <script>alert("org")</script>';
const MALICIOUS_UA = 'Mozilla/5.0 <script>alert("ua")</script>';

function makeAuditResult(): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: MALICIOUS_ORG,
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    instanceUrl: 'https://test.salesforce.com',
    healthScore: 75,
    grade: 'C',
    metrics: {
      ...EMPTY_METRICS,
      totalActiveUsers: 10,
    },
    findings: [
      {
        id: 'finding-1',
        checkId: 'check-1',
        category: 'Access & Sharing',
        riskLevel: 'HIGH',
        title: `Overprivileged user: ${MALICIOUS_USER}`,
        detail: `The user ${MALICIOUS_USER} has ViewAllData assigned.`,
        remediation: `Revoke ViewAllData from ${MALICIOUS_USER}.`,
        affectedItems: [
          {
            label: MALICIOUS_USER,
            url: `https://test.salesforce.com?user=${encodeURIComponent(MALICIOUS_USER)}`,
            note: `Assigned to ${MALICIOUS_USER}`,
          },
        ],
      },
    ],
    attackChains: [
      {
        id: 'chain-1',
        title: `Chain exploiting ${MALICIOUS_USER}`,
        severity: 'CRITICAL',
        confidence: 'named',
        narrative: `Adversary steals credential of ${MALICIOUS_USER}.`,
        remediation: `Isolate ${MALICIOUS_USER}.`,
        steps: [
          {
            findingId: 'finding-1',
            checkId: 'check-1',
            capability: 'priv-esc',
            title: `Compromise of ${MALICIOUS_USER}`,
            severity: 'HIGH',
          },
        ],
      },
    ],
  };
}

function makeIncidentResult(): IncidentResult {
  return {
    orgId: '00D000000000001',
    orgName: MALICIOUS_ORG,
    collectedAt: '2026-03-23T15:10:00Z',
    manifestSha256: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    globalLimits: [],
    withinBaseline: false,
    coverage: {
      logs: [],
      audit: { totalRows: 0, distinctEvents: 0, earliest: '', latest: '' },
      limits: { runningUser: 'test', profile: 'test' } as any,
      detectorAvailable: false,
      ipRanges: [],
    },
    guests: [
      {
        id15: '005000000000001',
        username: MALICIOUS_USER,
        siteNames: ['Portal'],
      },
    ],
    volumes: [
      {
        day: '2026-03-23',
        guestId15: '005000000000001',
        controllerCalls: 50,
        pageLoads: 10,
      },
    ],
    waves: [
      {
        wave: {
          id: 'W1',
          site: 'Portal',
          days: ['2026-03-23'],
        },
        classification: 'automated-scan',
        result: 'access-gained',
        spikes: [],
        limits: [],
        actors: [
          {
            id: 'A1',
            block: '192.0.2.0/24',
            ips: ['192.0.2.1'],
            firstSeen: '2026-03-23T10:00:00Z',
            lastSeen: '2026-03-23T12:00:00Z',
            controllerCalls: 50,
            steady: true,
            emptyUaShare: 0.8,
            markers: [MALICIOUS_UA],
            hostingAssessed: true,
            hosting: 'AWS',
          },
        ],
        actions: {
          byName: [],
          byClass: {},
        },
        responses: {
          dataAccessCalls: 10,
          emptySize: 100,
          emptySizeInferred: false,
          band: 5,
          returnedContent: [],
        },
        outcomes: {
          actorLogins: [],
          selfRegistrationsInActorWindow: [],
          identityLinks: [],
        },
        nextSteps: ['Rotate guest credentials'],
      },
    ],
    config: {
      periods: [],
      asymmetries: [],
    },
  } as unknown as IncidentResult;
}

describe('HARD-02: HTML report escaping & Content-Security-Policy', () => {
  it('HtmlRenderer contains CSP meta and escapes org and user inputs', () => {
    const r = makeAuditResult();
    const html = new HtmlRenderer().render(r);

    expect(html).toContain('<meta http-equiv="Content-Security-Policy"');
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<script>alert("org")</script>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).toContain('&lt;script&gt;alert(&quot;org&quot;)&lt;/script&gt;');
  });

  it('ClientReportRenderer (Executive) contains strict CSP meta and escapes inputs', () => {
    const r = makeAuditResult();
    const renderer = new ClientReportRenderer({
      branding: DEFAULT_BRANDING,
      topN: 5,
      frameworks: ['OWASP', 'SOC2'],
    });
    const html = renderer.render(r);

    expect(html).toContain('<meta http-equiv="Content-Security-Policy"');
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<script>alert("org")</script>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('DiffHtmlRenderer contains CSP meta and escapes org and finding inputs', () => {
    const base = makeAuditResult();
    const cur = makeAuditResult();
    cur.healthScore = 80;
    const diff = computeDiff(base, cur);

    const html = new DiffHtmlRenderer().render(diff);

    expect(html).toContain('<meta http-equiv="Content-Security-Policy"');
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<script>alert("org")</script>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('HistoryRenderer contains CSP meta and escapes org inputs', () => {
    const r1 = makeAuditResult();
    const r2 = makeAuditResult();
    r2.generatedAt = new Date('2026-03-24T15:10:00Z');
    const html = new HistoryRenderer().renderHtml([r1, r2]);

    expect(html).toContain('<meta http-equiv="Content-Security-Policy"');
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain('<script>alert("org")</script>');
    expect(html).toContain('&lt;script&gt;alert(&quot;org&quot;)&lt;/script&gt;');
  });

  it('Incident HTML report contains CSP meta and escapes malicious user-agent and org values', () => {
    const incident = makeIncidentResult();
    const ev = buildEvidence(incident);
    const html = renderIncidentHtml(incident, ev, DEFAULT_BRANDING);

    expect(html).toContain('<meta http-equiv="Content-Security-Policy"');
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain('<script>alert("ua")</script>');
    expect(html).not.toContain('<script>alert("org")</script>');
    expect(html).toContain('&lt;script&gt;alert(&quot;ua&quot;)&lt;/script&gt;');
  });

  it('HistoryRenderer escapes values read back from tampered history files', () => {
    const r1 = makeAuditResult();
    const r2 = makeAuditResult();
    (r2 as any).grade = '<img src=x onerror=alert(1)>';
    (r2 as any).healthScore = '</script><script>alert(2)</script>';
    const html = new HistoryRenderer().renderHtml([r1, r2]);

    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('</script><script>alert(2)');
  });
});
