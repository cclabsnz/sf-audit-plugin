// IST visible rule tests for spec/live-org-queries.md (RULE-060..062, INT-010).
// RULE-063 is proven per check by liveOrgQueries.schema.test.ts.
import { jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import type { AuditContext } from '@cclabsnz/sf-core';
import { CheckEngine } from '../../../src/checks/CheckEngine.js';
import type { SecurityCheck } from '../../../src/checks/SecurityCheck.js';

function ctx(): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'orgId', name: 'Test Org', type: 'Developer Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://test.salesforce.com' },
    cache: {},
  };
}

function throwing(id: string, err: Error, extra: Partial<SecurityCheck> = {}): SecurityCheck {
  return { id, name: `Check ${id}`, category: 'Test', description: 'd', run: () => Promise.reject(err), ...extra };
}

function apiError(code: string, message: string): Error {
  return Object.assign(new Error(message), { errorCode: code });
}

async function errorFinding(check: SecurityCheck) {
  const result = await new CheckEngine([check], ctx()).run();
  expect(result.findings).toHaveLength(1);
  return result.findings[0];
}

const REJECTIONS: Array<[string, Error]> = [
  ['INVALID_FIELD', apiError('INVALID_FIELD', "No such column 'SessionTimeout' on entity 'ConnectedApplication'.")],
  ['INVALID_TYPE', apiError('INVALID_TYPE', "sObject type 'TraceFlag' is not supported.")],
  ['MALFORMED_QUERY', apiError('MALFORMED_QUERY', 'alias is reserved: expr0')],
  ['not filterable', new Error("field 'Section' can not be filtered in a query call")],
  ['not supported, no code', new Error("sObject type 'CorsWhitelistEntry' is not supported.")],
];

describe('RULE-060 a rejected query is labelled as rejected, not as missing permissions (MN-050)', () => {
  it.each(REJECTIONS)('%s', async (_label, err) => {
    const f = await errorFinding(throwing('c', err));
    expect(f.inconclusive).toBe(true);
    expect(f.notAssessed).toBe(true);
    expect(f.title).toBe('Check c: query rejected by the org');
    expect(f.detail).toContain(err.message);
    expect(f.detail).not.toMatch(/lacks the required permissions/i);
    expect(f.remediation).not.toMatch(/grant/i);
  });
});

describe('RULE-061 an access error is still labelled as missing permissions', () => {
  it.each([
    ['INSUFFICIENT_ACCESS_RIGHTS', apiError('INSUFFICIENT_ACCESS_RIGHTS', 'insufficient access rights on object id')],
    ['INSUFFICIENT_ACCESS_OR_READONLY', apiError('INSUFFICIENT_ACCESS_OR_READONLY', 'insufficient access')],
    ['ENTITY_IS_INACCESSIBLE', apiError('ENTITY_IS_INACCESSIBLE', 'entity is inaccessible')],
    ['message only', new Error('INSUFFICIENT_ACCESS: cannot query')],
  ])('%s', async (_label, err) => {
    const f = await errorFinding(throwing('c', err));
    expect(f.inconclusive).toBe(true);
    expect(f.title).toBe('Check c: insufficient permissions');
    expect(f.remediation).toContain('PERMISSIONS.md');
    expect(f.remediation).toContain('sf audit preflight');
  });

  it('names the permission the check needs when the preflight map knows it', async () => {
    const f = await errorFinding(
      throwing('c', apiError('INSUFFICIENT_ACCESS_RIGHTS', 'insufficient access'), { populatesCache: ['eventLogSummary'] as any }),
    );
    expect(f.remediation).toContain('View Event Log Files');
  });

  it('an unrelated failure is neither a rejection nor a permissions gap', async () => {
    const f = await errorFinding(throwing('c', new Error('Network timeout')));
    expect(f.inconclusive).toBeUndefined();
    expect(f.title).toBe('Check c: check failed');
  });
});

describe('RULE-062 commands use the org API version', () => {
  it.each(['security', 'apps', 'events/pull', 'incident/collect'])('audit %s', (cmd) => {
    const src = readFileSync(new URL(`../../../src/commands/audit/${cmd}.ts`, import.meta.url), 'utf8');
    expect(src).toContain("flags['target-org'].getConnection()");
    expect(src).not.toMatch(/getConnection\(\s*'\d+\.\d+'\s*\)/);
  });
});

// Keep jest imported for parity with the other IST suites.
void jest;
