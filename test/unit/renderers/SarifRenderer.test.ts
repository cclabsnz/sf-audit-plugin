import { jest } from '@jest/globals';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import type { Finding } from '../../../src/findings/Finding.js';

// A sentinel version proves the driver version comes from package metadata, not a literal
// that happens to match today's release.
jest.unstable_mockModule('../../../src/lib/packageInfo.js', () => ({
  packageInfo: () => ({ name: '@cclabsnz/sf-audit', version: '0.0.0-sarif-test' }),
}));

const { SarifRenderer, FINGERPRINT_KEY } = await import('../../../src/renderers/SarifRenderer.js');

/* eslint-disable @typescript-eslint/no-explicit-any */

const sharing: Finding = {
  id: 'apex-sharing-order-controller',
  checkId: 'apex-sharing',
  category: 'code-security',
  riskLevel: 'HIGH',
  title: 'Apex class declared without sharing',
  detail: 'A controller does not enforce record sharing.',
  remediation: 'Add the with sharing keyword to the class declaration.',
  affectedItems: [{ label: 'OrderController' }, { label: 'OrderController' }],
  complianceTags: ['OWASP-A01', 'SOC2-CC6.1'],
};

const cors: Finding = {
  id: 'cors-allowlist-wildcard',
  checkId: 'cors-allowlist',
  category: 'network',
  riskLevel: 'MEDIUM',
  title: 'CORS allowlist contains broad wildcard origin',
  detail: 'CORS pattern https://*.example.com is overly permissive.',
  remediation: 'Restrict CORS origins to exact domain names.',
  affectedItems: [{ label: 'https://*.example.com' }],
};

const passed: Finding = {
  id: 'mfa-enforcement-pass',
  checkId: 'mfa-enforcement',
  category: 'identity',
  riskLevel: 'INFO',
  title: 'MFA is enforced org-wide',
  detail: 'All users require multi-factor authentication.',
  remediation: '',
  passed: true,
};

const inconclusive: Finding = {
  id: 'guest-user-access-inconclusive',
  checkId: 'guest-user-access',
  category: 'guest',
  riskLevel: 'HIGH',
  title: 'Guest user access could not be assessed',
  detail: 'INSUFFICIENT_ACCESS on the guest profile query.',
  remediation: 'Grant the audit user View Setup and Configuration.',
  inconclusive: true,
};

function makeResult(findings: Finding[], withChain = true): AuditResult {
  return {
    generatedAt: new Date('2026-10-15T00:00:00.000Z'),
    orgId: '00D000000000001AAA',
    orgName: 'Example Production Org',
    orgType: 'Production',
    isSandbox: false,
    instance: 'NA100',
    instanceUrl: 'https://acme.my.salesforce.com',
    healthScore: 78,
    grade: 'B',
    metrics: {} as any,
    findings,
    attackChains: withChain
      ? [
          {
            id: 'forcedleak-pattern',
            title: 'Indirect prompt injection into an agent tool call',
            severity: 'CRITICAL',
            confidence: 'named',
            narrative: 'Untrusted web input reaches an agent topic which triggers an outbound callout.',
            remediation: 'Enforce prompt guardrails and disable unconfirmed outbound actions.',
            steps: [
              { findingId: 'guest-user-write-access', title: 'Guest write to CRM objects', severity: 'CRITICAL', capability: 'data-write' as any },
              { findingId: 'agent-query-reach', title: 'Agent can query CRM records', severity: 'HIGH', capability: 'data-read' as any },
              { findingId: 'agent-outbound-actions', title: 'Unconfirmed outbound action', severity: 'HIGH', capability: 'external-egress' as any },
            ],
          },
        ]
      : [],
  };
}

const render = (r: AuditResult) => JSON.parse(new SarifRenderer().render(r));
const run0 = (r: AuditResult) => render(r).runs[0];

describe('SarifRenderer', () => {
  it('is a SARIF 2.1.0 log with the driver named and versioned from package metadata', () => {
    const renderer = new SarifRenderer();
    expect(renderer.format).toBe('sarif');
    expect(renderer.fileExtension).toBe('.sarif');

    const sarif = render(makeResult([sharing]));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs[0].tool.driver.name).toBe('@cclabsnz/sf-audit');
    expect(sarif.runs[0].tool.driver.version).toBe('0.0.0-sarif-test');
  });

  it('maps severities to levels and lifts compliance tags onto the rule', () => {
    const run = run0(makeResult([sharing, cors]));
    const s = run.results.find((r: any) => r.ruleId === 'apex-sharing');
    expect(s.level).toBe('error');
    expect(s.properties.riskLevel).toBe('HIGH');
    expect(s.properties.complianceTags).toContain('OWASP-A01');
    expect(run.results.find((r: any) => r.ruleId === 'cors-allowlist').level).toBe('warning');

    const rule = run.tool.driver.rules.find((r: any) => r.id === 'apex-sharing');
    expect(rule.properties.tags).toEqual(expect.arrayContaining(['OWASP-A01', 'SOC2-CC6.1']));
    expect(rule.properties['security-severity']).toBe('8.0');
    expect(rule.defaultConfiguration.level).toBe('error');
  });

  it('gives a rule the security severity of its worst finding, whatever the order', () => {
    const low: Finding = { ...cors, id: 'cors-allowlist-low', riskLevel: 'LOW' };
    for (const order of [[cors, low], [low, cors]]) {
      const rule = run0(makeResult(order, false)).tool.driver.rules.find((r: any) => r.id === 'cors-allowlist');
      expect(rule.properties['security-severity']).toBe('5.5');
      expect(rule.defaultConfiguration.level).toBe('warning');
    }
  });

  it('never emits passed or inconclusive findings as results', () => {
    const run = run0(makeResult([passed, inconclusive], false));
    expect(run.results).toEqual([]);
  });

  it('reports inconclusive checks as notifications and marks the run not fully successful', () => {
    const [inv] = run0(makeResult([sharing, inconclusive])).invocations;
    expect(inv.executionSuccessful).toBe(false);
    expect(inv.toolExecutionNotifications).toHaveLength(1);
    expect(inv.toolExecutionNotifications[0].associatedRule.id).toBe('guest-user-access');
  });

  it('marks the run successful when every check gathered evidence', () => {
    const [inv] = run0(makeResult([sharing, passed])).invocations;
    expect(inv.executionSuccessful).toBe(true);
    expect(inv.toolExecutionNotifications).toEqual([]);
  });

  it('gives every result a synthetic physical location and the affected items as unique logical locations', () => {
    const run = run0(makeResult([sharing, cors]));
    for (const r of run.results) {
      expect(r.locations).toHaveLength(1);
      expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe(`salesforce-org/${r.ruleId}`);
    }
    const s = run.results.find((r: any) => r.ruleId === 'apex-sharing');
    expect(s.locations[0].logicalLocations).toEqual([
      { name: 'OrderController', fullyQualifiedName: 'OrderController', kind: 'resource' },
    ]);
  });

  it('fingerprints are stable across runs and independent of affected-item churn', () => {
    const a = run0(makeResult([sharing, cors]));
    const grown = { ...sharing, affectedItems: [{ label: 'OrderController' }, { label: 'InvoiceController' }] };
    const b = run0(makeResult([cors, grown]));
    const fp = (run: any, ruleId: string) =>
      run.results.find((r: any) => r.ruleId === ruleId).partialFingerprints[FINGERPRINT_KEY];
    for (const id of ['apex-sharing', 'cors-allowlist', 'attack-chain-forcedleak-pattern']) {
      expect(fp(a, id)).toMatch(/^[0-9a-f]{64}$/);
      expect(fp(b, id)).toBe(fp(a, id));
    }
    expect(fp(a, 'apex-sharing')).not.toBe(fp(a, 'cors-allowlist'));
  });

  it('distinct findings of one check get distinct fingerprints, including a repeated id', () => {
    const other = { ...sharing, id: 'apex-sharing-invoice-controller' };
    const run = run0(makeResult([sharing, other, sharing], false));
    const fps = run.results.map((r: any) => r.partialFingerprints[FINGERPRINT_KEY]);
    expect(new Set(fps).size).toBe(3);
  });

  it('renders an attack chain as a result with a code flow', () => {
    const run = run0(makeResult([sharing]));
    const chain = run.results.find((r: any) => r.ruleId === 'attack-chain-forcedleak-pattern');
    expect(chain.level).toBe('error');
    expect(chain.locations[0].logicalLocations.map((l: any) => l.name)).toEqual([
      'guest-user-write-access',
      'agent-query-reach',
      'agent-outbound-actions',
    ]);
    const flow = chain.codeFlows[0].threadFlows[0].locations;
    expect(flow).toHaveLength(3);
    expect(flow[0].location.message.text).toContain('Step 1: Guest write');
    expect(flow[2].location.message.text).toContain('Step 3: Unconfirmed outbound');
    expect(run.tool.driver.rules.find((r: any) => r.id === chain.ruleId).properties['security-severity']).toBe('9.5');
  });

  it('declares every result rule in the driver, once', () => {
    const run = run0(makeResult([sharing, cors]));
    const ids = run.tool.driver.rules.map((r: any) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const r of run.results) expect(ids).toContain(r.ruleId);
  });
});
