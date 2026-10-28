// Rule tests for spec/threat-taxonomy.md, phase 1: STRIDE, LINDDUN and the threat view
// (RULE-100..105, the Markdown/SARIF/JSON parts of RULE-113; INT-014).
import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { CheckEngine } from '../../../src/checks/CheckEngine.js';
import type { SecurityCheck } from '../../../src/checks/SecurityCheck.js';
import { CHECKS } from '../../../src/checks/registry.js';
import { ALL_CONTROLS } from '../../../src/compliance/catalogs/index.js';
import { CHECK_CONTROL_MAP } from '../../../src/compliance/mapping.js';
import { packFrameworks, resolveFrameworks } from '../../../src/compliance/resolve.js';
import { buildAuditResult } from '../../../src/findings/scoring.js';
import { resolveExitCode } from '../../../src/findings/exitCode.js';
import type { Finding } from '../../../src/findings/Finding.js';
import { CHECK_STRIDE_MAP } from '../../../src/threats/stride.js';
import { CHECK_LINDDUN_MAP } from '../../../src/threats/linddun.js';
import { threatsFor } from '../../../src/threats/resolve.js';
import { buildThreatView, threatRowStatusText } from '../../../src/threats/view.js';
import { LINDDUN_CATEGORIES, STRIDE_CATEGORIES } from '../../../src/threats/types.js';
import { MarkdownRenderer } from '../../../src/renderers/MarkdownRenderer.js';
import { SarifRenderer } from '../../../src/renderers/SarifRenderer.js';
import { JsonRenderer } from '../../../src/renderers/JsonRenderer.js';

const ORG = { id: 'o', name: 'n', type: 'Enterprise Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' };
const ctx = (): AuditContext =>
  ({ soql: {} as any, tooling: {} as any, rest: {} as any, orgInfo: ORG, cache: {} as any }) as any;

const f = (checkId: string, riskLevel: Finding['riskLevel'], extra: Partial<Finding> = {}): Finding => ({
  id: `${checkId}-x`, checkId, category: 'T', riskLevel, title: `${checkId} finding`, detail: 'd', remediation: 'r',
  threats: threatsFor(checkId), ...extra,
});

const THREAT_ID = /^(stride:|linddun:|T\d{4}(\.\d{3})?$)/i;

describe('RULE-100 threat categories stay out of the compliance layer (MN-058)', () => {
  it('no catalogued control, framework or mapped tag is a threat identifier', () => {
    for (const c of ALL_CONTROLS) {
      expect(c.id).not.toMatch(THREAT_ID);
      expect(c.framework).not.toMatch(/STRIDE|LINDDUN|ATTACK|MITRE/i);
    }
    for (const tags of Object.values(CHECK_CONTROL_MAP)) for (const t of tags) expect(t).not.toMatch(THREAT_ID);
    for (const pack of ['universal', 'nz', 'all'] as const) {
      for (const fw of packFrameworks(pack)) expect(fw).not.toMatch(/STRIDE|LINDDUN|ATTACK|MITRE/i);
    }
  });

  it('--frameworks accepts no threat-taxonomy alias', () => {
    for (const alias of ['stride', 'linddun', 'attack', 'mitre', 'att&ck']) expect(resolveFrameworks(alias)).toEqual([]);
  });

  it('compliance tags on a finding never pick up threat categories', async () => {
    const check: SecurityCheck = {
      id: 'audit-trail', name: 'n', category: 'c', description: 'd',
      run: jest.fn<SecurityCheck['run']>().mockResolvedValue({ findings: [f('audit-trail', 'HIGH', { threats: undefined })] }),
    };
    const r = await new CheckEngine([check], ctx()).run();
    for (const t of r.findings[0].complianceTags ?? []) expect(t).not.toMatch(THREAT_ID);
  });
});

describe('RULE-101 every check carries a STRIDE category', () => {
  const ids = CHECKS.map((c) => c.id);

  it.each(ids)('%s has one or two STRIDE categories', (id) => {
    const cats = CHECK_STRIDE_MAP[id];
    expect(cats).toBeDefined();
    expect(cats.length).toBeGreaterThanOrEqual(1);
    expect(cats.length).toBeLessThanOrEqual(2);
    expect(new Set(cats).size).toBe(cats.length);
    for (const c of cats) expect(STRIDE_CATEGORIES).toContain(c);
  });

  it('every map entry names a registered check', () => {
    for (const id of Object.keys(CHECK_STRIDE_MAP)) expect(ids).toContain(id);
  });

  it('CheckEngine tags findings from the map, and an inline list overrides it for that finding', async () => {
    const check: SecurityCheck = {
      id: 'guest-api-access', name: 'n', category: 'c', description: 'd',
      run: jest.fn<SecurityCheck['run']>().mockResolvedValue({
        findings: [
          { id: 'guest-api-access-enabled', category: 'c', riskLevel: 'HIGH', title: 't', detail: 'd', remediation: 'r' },
          { id: 'guest-api-hard-delete', category: 'c', riskLevel: 'CRITICAL', title: 't', detail: 'd', remediation: 'r', threats: { stride: ['D', 'T'] } },
        ],
      }),
    };
    const r = await new CheckEngine([check], ctx()).run();
    const byId = new Map(r.findings.map((x) => [x.id, x]));
    expect(byId.get('guest-api-access-enabled')?.threats).toMatchObject({ stride: ['I', 'T'], linddun: ['DD'] });
    // The override replaces STRIDE only; LINDDUN still comes from the map.
    expect(byId.get('guest-api-hard-delete')?.threats).toMatchObject({ stride: ['D', 'T'], linddun: ['DD'] });
  });

  it('a check that throws still carries its categories', async () => {
    const check: SecurityCheck = {
      id: 'sharing-model', name: 'n', category: 'c', description: 'd',
      run: jest.fn<SecurityCheck['run']>().mockRejectedValue(new Error('boom')),
    };
    const r = await new CheckEngine([check], ctx()).run();
    expect(r.findings[0].threats?.stride).toEqual(['I']);
  });
});

describe('RULE-102 LINDDUN is tagged only where personal data is at stake', () => {
  it('every LINDDUN entry names a registered check and valid categories', () => {
    const ids = CHECKS.map((c) => c.id);
    for (const [id, cats] of Object.entries(CHECK_LINDDUN_MAP)) {
      expect(ids).toContain(id);
      expect(cats.length).toBeGreaterThan(0);
      for (const c of cats) expect(LINDDUN_CATEGORIES).toContain(c);
    }
  });

  it.each([
    'sharing-model', 'field-level-security', 'content-links', 'data-classification', 'data-export-access',
    'field-history-tracking', 'event-monitoring', 'audit-trail', 'apex-logging', 'siem-integration', 'guest-user-access',
  ])('%s is privacy-tagged', (id) => {
    expect(CHECK_LINDDUN_MAP[id]?.length).toBeGreaterThan(0);
  });

  it.each(['api-limits', 'certificate-expiry', 'mfa-enforcement', 'release-updates', 'legacy-api-version'])(
    '%s has no privacy bearing and no default category',
    (id) => {
      expect(CHECK_LINDDUN_MAP[id]).toBeUndefined();
      expect(threatsFor(id)?.linddun).toBeUndefined();
    },
  );
});

describe('RULE-103 logging is read both ways (MN-061)', () => {
  it.each(['audit-trail', 'field-history-tracking', 'event-monitoring', 'apex-logging', 'siem-integration'])(
    '%s is STRIDE R and LINDDUN Nr or D',
    (id) => {
      expect(CHECK_STRIDE_MAP[id]).toContain('R');
      expect(CHECK_LINDDUN_MAP[id].some((c) => c === 'Nr' || c === 'D')).toBe(true);
    },
  );

  it('the view keeps the finding in both STRIDE R and the dual readings, and in its LINDDUN rows', () => {
    const missing = f('event-monitoring', 'HIGH');
    const view = buildThreatView([missing]);
    expect(view.stride.find((r) => r.category === 'R')?.findings).toContain(missing);
    expect(view.dualReadings).toContain(missing);
    expect(view.linddun?.find((r) => r.category === 'D')?.findings).toContain(missing);
  });

  it('a finding that reports sensitive data being logged is a disclosure, not a dual reading', () => {
    const leak = f('apex-logging', 'HIGH', { id: 'apex-logging-sensitive-data', threats: threatsFor('apex-logging', { stride: ['I'] }) });
    const view = buildThreatView([leak]);
    expect(view.dualReadings).not.toContain(leak);
    expect(view.linddun?.find((r) => r.category === 'DD')?.findings).toContain(leak);
  });

  it('dual readings follow a finding-level LINDDUN override', () => {
    const overridden = f('audit-trail', 'HIGH', { threats: { stride: ['R'], linddun: ['DD'] } });
    expect(buildThreatView([overridden]).dualReadings).not.toContain(overridden);
  });

  it('the Markdown report states both readings', () => {
    const md = new MarkdownRenderer().render(buildAuditResult(ctx(), [f('audit-trail', 'MEDIUM')], {}));
    expect(md).toMatch(/Logging, read both ways/);
    expect(md).toMatch(/repudiation gap \(STRIDE R\)/);
    expect(md).toMatch(/records personal data/);
  });
});

describe('RULE-104 the threat view reports coverage, not assurance (MN-058, INT-010)', () => {
  const findings = [
    f('sharing-model', 'HIGH'),                                       // I: a finding
    f('api-limits', 'LOW', { passed: true }),                         // D: assessed, clean
    f('audit-trail', 'INFO', { inconclusive: true, notAssessed: true }), // R: covering check gathered nothing
  ];
  const view = buildThreatView(findings);
  const row = (c: string) => view.stride.find((r) => r.category === c)!;

  it('lists every STRIDE category', () => {
    expect(view.stride.map((r) => r.category)).toEqual([...STRIDE_CATEGORIES]);
  });

  it('distinguishes findings, no findings, not assessed in this run, and not covered', () => {
    expect(row('I').status).toBe('findings');
    expect(threatRowStatusText(row('I'))).toBe('1 finding (from 1 check)');
    expect(row('D').status).toBe('no-findings');
    expect(threatRowStatusText(row('D'))).toBe('no findings from 1 check');
    expect(row('R').status).toBe('not-assessed-in-run');
    expect(threatRowStatusText(row('R'))).toBe('not assessed in this run');
    expect(row('S').status).toBe('not-covered');
    expect(threatRowStatusText(row('S'))).toBe('not assessed by this tool');
  });

  it('counts only covering checks that gathered evidence', () => {
    expect(row('R').coveringChecks).toBe(1);
    expect(row('R').assessedChecks).toBe(0);
  });

  it('passed, inconclusive and waived findings are not listed as findings', () => {
    const v = buildThreatView([f('sharing-model', 'HIGH', { waived: true }), f('field-level-security', 'LOW', { passed: true })]);
    expect(v.stride.find((r) => r.category === 'I')?.findings).toEqual([]);
  });

  it('shows LINDDUN only when a privacy-tagged check ran', () => {
    expect(buildThreatView([f('api-limits', 'LOW')]).linddun).toBeUndefined();
    expect(buildThreatView([f('sharing-model', 'LOW')]).linddun?.map((r) => r.category)).toEqual([...LINDDUN_CATEGORIES]);
  });

  it('never reads as a pass', () => {
    const md = new MarkdownRenderer().render(buildAuditResult(ctx(), findings, {}));
    const start = md.indexOf('## Threat View');
    const section = md.slice(start, md.indexOf('\n---\n', start));
    expect(section).toMatch(/### STRIDE/);
    expect(section).not.toMatch(/\b(pass|passed|compliant|no threats)\b/i);
  });
});

describe('RULE-105 threat tags carry no weight (MN-062)', () => {
  const tagged = [f('sharing-model', 'CRITICAL'), f('audit-trail', 'HIGH'), f('api-limits', 'LOW', { passed: true })];
  const untagged = tagged.map(({ threats: _t, ...rest }) => rest as Finding);

  it('score, grade and exit code are the same with and without tags', () => {
    const a = buildAuditResult(ctx(), tagged, {});
    const b = buildAuditResult(ctx(), untagged, {});
    expect(a.healthScore).toBe(b.healthScore);
    expect(a.grade).toBe(b.grade);
    expect(a.gradeReason).toBe(b.gradeReason);
    expect(resolveExitCode(tagged, { failOn: 'HIGH' })).toBe(resolveExitCode(untagged, { failOn: 'HIGH' }));
  });

  it('SARIF security-severity is the same with and without tags', () => {
    const sev = (fs: Finding[]) => {
      const sarif = JSON.parse(new SarifRenderer().render(buildAuditResult(ctx(), fs, {})));
      return sarif.runs[0].tool.driver.rules.map((r: any) => [r.id, r.properties['security-severity']]);
    };
    expect(sev(tagged)).toEqual(sev(untagged));
  });
});

describe('RULE-113 outputs carry the taxonomy (Markdown, SARIF, JSON)', () => {
  const result = () => buildAuditResult(ctx(), [f('sharing-model', 'HIGH')], {});

  it('JSON carries threats on each finding', () => {
    const json = JSON.parse(new JsonRenderer().render(result()));
    expect(json.findings[0].threats).toEqual({ stride: ['I'], linddun: ['DD', 'L'] });
  });

  it('SARIF rules gain stride: and linddun: tags', () => {
    const sarif = JSON.parse(new SarifRenderer().render(result()));
    const rule = sarif.runs[0].tool.driver.rules.find((r: any) => r.id === 'sharing-model');
    expect(rule.properties.tags).toEqual(expect.arrayContaining(['stride:I', 'linddun:DD', 'linddun:L']));
  });

  it('Markdown shows threat tags beside compliance tags and a threat view after the findings', () => {
    const md = new MarkdownRenderer().render(result());
    expect(md).toMatch(/\*\*Threats:\*\* STRIDE I \| LINDDUN DD · L/);
    expect(md.indexOf('## Threat View')).toBeGreaterThan(md.indexOf('## Findings'));
  });
});
