import { JsonRenderer } from '../../../src/renderers/JsonRenderer.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import type { AttackChain } from '../../../src/chains/AttackChain.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

const SAMPLE_CHAIN: AttackChain = {
  id: 'unauth-bulk-exfil',
  title: 'Unauthenticated bulk exfiltration',
  severity: 'CRITICAL',
  confidence: 'named',
  narrative: 'Guest foothold + guest-executable Apex without sharing leads to bulk read.',
  remediation: 'Lock down guest access and add with sharing.',
  steps: [
    { findingId: 'guest-user-read-access', checkId: 'guest-user-access', capability: 'unauth-foothold', title: 'Guest read', severity: 'HIGH' },
    { findingId: 'guest-executable-apex-unprotected', checkId: 'guest-executable-apex', capability: 'code-exec', title: 'Unprotected Apex', severity: 'CRITICAL' },
  ],
};

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-24T00:00:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    instanceUrl: 'https://test.salesforce.com',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 100,
    grade: 'A',
    attackChains: [],
    ...overrides,
  };
}

describe('JsonRenderer', () => {
  const renderer = new JsonRenderer();

  it('has format="json" and fileExtension=".json"', () => {
    expect(renderer.format).toBe('json');
    expect(renderer.fileExtension).toBe('.json');
  });

  it('renders a valid JSON string', () => {
    const output = renderer.render(makeResult());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('preserves all AuditResult fields in output', () => {
    const result = makeResult({
      findings: [
        { id: 'f1', category: 'Auth', riskLevel: 'HIGH', title: 'T', detail: 'd', remediation: 'r' },
      ],
      healthScore: 70,
      grade: 'C',
    });
    const parsed = JSON.parse(renderer.render(result));
    expect(parsed.healthScore).toBe(70);
    expect(parsed.grade).toBe('C');
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].riskLevel).toBe('HIGH');
  });

  it('includes attackChains in the JSON output', () => {
    const json = JSON.parse(new JsonRenderer().render({ ...makeResult(), attackChains: [SAMPLE_CHAIN] }));
    expect(json.attackChains).toHaveLength(1);
    expect(json.attackChains[0].id).toBe('unauth-bulk-exfil');
  });
});
