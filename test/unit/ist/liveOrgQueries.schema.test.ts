// IST visible rule test for spec/live-org-queries.md RULE-063 (INT-010, MN-050, MN-051).
// Runs every registered check, in registry order, against a context that rejects any query the
// captured Developer Edition schema would reject. Mocked responses alone never fail a bad query.
import { CHECKS } from '../../../src/checks/registry.js';
import { schemaCtx, validate, type Violation } from './support/schemaCtx.js';

const byCheck = new Map<string, Violation[]>();

beforeAll(async () => {
  const { ctx, violations } = schemaCtx();
  for (const check of CHECKS) {
    const before = violations.length;
    try {
      await check.run(ctx);
    } catch {
      // A thrown error is the engine's to report; the recorded violations are what matter here.
    }
    byCheck.set(check.id, violations.slice(before));
  }
}, 60_000);

describe('RULE-063 checks query only what the org schema has, through the API that serves it', () => {
  it.each(CHECKS.map((c) => [c.id]))('%s', (id) => {
    const found = (byCheck.get(id) ?? []).map((v) => `${v.api}: ${v.error}  <-  ${v.query.slice(0, 160)}`);
    expect(found).toEqual([]);
  });
});

describe('the schema validator itself', () => {
  const rejects = (api: 'soql' | 'tooling', q: string, msg: RegExp) => expect(() => validate(api, q)).toThrow(msg);

  it('rejects an object on the wrong API', () => rejects('soql', 'SELECT Id FROM TraceFlag', /not supported/));
  it('rejects a missing field', () => rejects('soql', 'SELECT Id, Username FROM LoginHistory', /No such column 'Username'/));
  it('rejects an unfilterable filter', () => rejects('soql', "SELECT Id FROM LoginHistory WHERE Status = 'Success'", /can not be filtered/));
  it('rejects the reserved alias expr0', () => rejects('soql', 'SELECT COUNT(Id) expr0 FROM User', /alias is reserved/));
  it('rejects aliasing a plain field', () =>
    rejects('tooling', 'SELECT QualifiedApiName field FROM FieldDefinition', /only aggregate expressions/));
  it('rejects aggregating a non-aggregatable field', () =>
    rejects('tooling', 'SELECT COUNT(Id) c FROM FieldDefinition', /does not support aggregate/));
  it('rejects a bad field inside a semi-join', () =>
    rejects('soql', 'SELECT Id FROM User WHERE Id IN (SELECT UserId FROM UserLogin WHERE Nope = true)', /No such column 'Nope'/));
  it('rejects a bad field behind a relationship', () =>
    rejects('soql', 'SELECT Assignee.Username, PermissionSet.PermissionsNope FROM PermissionSetAssignment', /No such column 'PermissionsNope' on entity 'PermissionSet'/));
  it('rejects a bad relationship filter', () =>
    rejects('soql', 'SELECT Id FROM PermissionSetAssignment WHERE PermissionSet.PermissionsNope = true', /PermissionsNope/));
  it('rejects an unknown relationship', () =>
    rejects('soql', 'SELECT Nobody.Name FROM PermissionSetAssignment', /Didn't understand relationship 'Nobody'/));
  it('accepts a valid multi-hop path', () =>
    expect(() => validate('soql', "SELECT Assignee.Profile.Name FROM PermissionSetAssignment WHERE Assignee.IsActive = true")).not.toThrow());
  it('accepts a valid query', () =>
    expect(() =>
      validate('soql', "SELECT Id, UserId, LoginTime FROM LoginHistory WHERE LoginTime > LAST_N_DAYS:30 AND LoginType = 'Application' LIMIT 5"),
    ).not.toThrow());
});
