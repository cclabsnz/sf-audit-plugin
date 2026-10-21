// RULE-063 (INT-010, MN-050, MN-051) for checks whose later queries only run once earlier ones
// return rows. liveOrgQueries.schema.test.ts runs every check against empty results, so it never
// reaches these. Here earlier queries return realistic rows, and every query issued is validated
// against the captured Developer Edition schema.
import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck } from '../../../../src/checks/SecurityCheck.js';
import { SCHEMA, absentEverywhere, validate } from '../../ist/support/schemaCtx.js';
import { InternalUserMfaCheck } from '../../../../src/checks/impl/InternalUserMfaCheck.js';
import { MfaEnforcementCheck } from '../../../../src/checks/impl/MfaEnforcementCheck.js';
import { ApiClientPermissionCheck } from '../../../../src/checks/impl/ApiClientPermissionCheck.js';
import { SoapLoginApiAuthCheck } from '../../../../src/checks/impl/SoapLoginApiAuthCheck.js';
import { AuditTrailCheck } from '../../../../src/checks/impl/AuditTrailCheck.js';
import { PrivilegedAccessCheck } from '../../../../src/checks/impl/PrivilegedAccessCheck.js';
import { EscalationPermsCheck } from '../../../../src/checks/impl/EscalationPermsCheck.js';
import { FieldHistoryTrackingCheck } from '../../../../src/checks/impl/FieldHistoryTrackingCheck.js';
import { DataClassificationCheck } from '../../../../src/checks/impl/DataClassificationCheck.js';
import { EncryptionCoverageCheck } from '../../../../src/checks/impl/EncryptionCoverageCheck.js';
import { TransactionSecurityPolicyCheck } from '../../../../src/checks/impl/TransactionSecurityPolicyCheck.js';
import { RestrictionRulesIntegrityCheck } from '../../../../src/checks/impl/RestrictionRulesIntegrityCheck.js';

type Api = 'soql' | 'tooling';

/** Rows an org with one user of each kind would return, keyed by the queried object. */
function rowsFor(q: string): unknown[] {
  const from = /\bFROM\s+([A-Za-z0-9_]+)/i.exec(q)?.[1] ?? '';
  switch (from) {
    case 'User':
      return [
        { Id: '005xx0000000001AAA', Username: 'u@example.com', UserType: 'PowerPartner', Profile: { Name: 'Partner User' }, LastLoginDate: null },
      ];
    case 'LoginHistory':
      // An aggregate row for a SOAP login, so soap-login-api-auth goes on to read holders.
      return [{ UserId: '005xx0000000001AAA', Application: 'N/A', ApiType: 'SOAP Partner', logins: 3 }];
    default:
      return [];
  }
}

/**
 * validate() skips dotted relationship fields, which is where permission-field bugs live
 * (`PermissionSet.PermissionsX`). Check the relationships these queries use against the schema.
 */
const RELATIONSHIP_TARGET: Record<string, string> = { PermissionSet: 'PermissionSet', Assignee: 'User' };

function validateRelationshipFields(api: Api, q: string): void {
  for (const m of q.matchAll(/\b(PermissionSet|Assignee)\.([A-Za-z][A-Za-z0-9_]*)\b(?!\.)/g)) {
    const [, rel, field] = m;
    const target = SCHEMA[api][RELATIONSHIP_TARGET[rel]];
    if (target && !target[field]) {
      throw Object.assign(new Error(`No such column '${field}' on entity '${RELATIONSHIP_TARGET[rel]}'.`), { errorCode: 'INVALID_FIELD' });
    }
  }
}

function ctxFor(violations: string[]): AuditContext {
  const run = (api: Api, q: string) => {
    try {
      validate(api, q);
      validateRelationshipFields(api, q);
    } catch (err) {
      const object = /\bFROM\s+([A-Za-z0-9_]+)/i.exec(q)?.[1] ?? '';
      if (!absentEverywhere(object)) violations.push(`${api}: ${(err as Error).message}  <-  ${q.replace(/\s+/g, ' ').slice(0, 160)}`);
      throw err;
    }
  };
  return {
    soql: {
      query: async (q: string) => {
        run('soql', q);
        const records = rowsFor(q);
        return { records, totalSize: records.length, done: true };
      },
      queryAll: async (q: string) => {
        run('soql', q);
        return rowsFor(q);
      },
    } as any,
    tooling: {
      query: async (q: string) => {
        run('tooling', q);
        return [];
      },
      getRecord: () => Promise.reject(new Error('not found')),
    } as any,
    rest: {
      get: async (path: string) => {
        const m = /^\/?(tooling\/)?sobjects\/([A-Za-z0-9_]+)\/describe/.exec(path);
        if (!m) return {};
        const fields = SCHEMA[m[1] ? 'tooling' : 'soql'][m[2]];
        if (!fields) throw Object.assign(new Error('The requested resource does not exist'), { errorCode: 'NOT_FOUND' });
        return { fields: Object.keys(fields).map((name) => ({ name })) };
      },
    } as any,
    orgInfo: { id: '00Dxx0000000000EAA', name: 'Schema Org', type: 'Developer Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com' },
    cache: {},
  } as any;
}

const CHECKS: SecurityCheck[] = [
  new InternalUserMfaCheck(),
  new MfaEnforcementCheck(),
  new ApiClientPermissionCheck(),
  new SoapLoginApiAuthCheck(),
  new AuditTrailCheck(),
  new PrivilegedAccessCheck(),
  new EscalationPermsCheck(),
  new FieldHistoryTrackingCheck(),
  new DataClassificationCheck(),
  new EncryptionCoverageCheck(),
  new TransactionSecurityPolicyCheck(),
  new RestrictionRulesIntegrityCheck(),
];

describe('RULE-063 deeper queries are valid against the Developer Edition schema', () => {
  it.each(CHECKS.map((c) => [c.id, c] as const))('%s', async (_id, check) => {
    const violations: string[] = [];
    try {
      await check.run(ctxFor(violations));
    } catch {
      // A throw is the engine's to report; only rejected queries matter here.
    }
    expect(violations).toEqual([]);
  });

  it('reaches the holders queries it exists to cover', async () => {
    const issued: string[] = [];
    const ctx = ctxFor([]);
    const soql = ctx.soql as any;
    const wrap = (fn: (q: string) => Promise<unknown>) => async (q: string) => {
      issued.push(q);
      return fn(q);
    };
    soql.query = wrap(soql.query);
    soql.queryAll = wrap(soql.queryAll);
    for (const c of [new InternalUserMfaCheck(), new MfaEnforcementCheck(), new SoapLoginApiAuthCheck()]) await c.run(ctx);
    expect(issued.filter((q) => q.includes('PermissionsForceTwoFactor'))).toHaveLength(2);
    expect(issued.some((q) => q.includes('PermissionsUseAnyApiAuth'))).toBe(true);
  });
});
