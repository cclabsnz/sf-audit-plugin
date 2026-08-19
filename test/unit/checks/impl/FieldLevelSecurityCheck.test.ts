import { jest } from '@jest/globals';
import { FieldLevelSecurityCheck } from '../../../../src/checks/impl/FieldLevelSecurityCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

type ToolingQ = (soql: string) => Promise<unknown[]>;
type SoqlQ = (soql: string) => Promise<{ records: unknown[] }>;

function makeCtx(opts: { tooling?: ToolingQ; query?: SoqlQ } = {}): AuditContext {
  return {
    soql: {
      queryAll: jest.fn(),
      query: (jest.fn() as any).mockImplementation((s: string) =>
        opts.query ? opts.query(s) : Promise.resolve({ records: [] }),
      ),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((s: string) =>
        opts.tooling ? opts.tooling(s) : Promise.resolve([]),
      ),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const field = (DeveloperName: string, TableEnumOrId: string, Id = '00N1') =>
  ({ Id, DeveloperName, TableEnumOrId });

/** Route tooling queries: CustomField vs EntityDefinition. */
const tooling = (o: { fields?: unknown[]; entities?: unknown[]; entityError?: boolean }): ToolingQ => (s) => {
  if (/FROM CustomField/i.test(s)) return Promise.resolve(o.fields ?? []);
  if (/FROM EntityDefinition/i.test(s)) {
    return o.entityError ? Promise.reject(new Error('no access')) : Promise.resolve(o.entities ?? []);
  }
  return Promise.resolve([]);
};

const perms = (rows: Array<{ Field: string; cnt: number }>): SoqlQ => () => Promise.resolve({ records: rows });

describe('FieldLevelSecurityCheck', () => {
  const check = new FieldLevelSecurityCheck();

  it('passes when no sensitive-looking custom fields exist', async () => {
    const r = await check.run(makeCtx({ tooling: tooling({ fields: [] }) }));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('field-level-security-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('searches for the documented sensitive name patterns', async () => {
    const seen: string[] = [];
    await check.run(makeCtx({ tooling: (s) => { seen.push(s); return Promise.resolve([]); } }));
    const q = seen.find((s) => /FROM CustomField/i.test(s))!;
    for (const pattern of ['SSN', 'CreditCard', 'BankAccount', 'DateOfBirth', 'MedicalRecord', 'Diagnosis']) {
      expect(q).toContain(pattern);
    }
  });

  it('uses TableEnumOrId directly for a standard object', async () => {
    const seen: string[] = [];
    const r = await check.run(makeCtx({
      tooling: tooling({ fields: [field('SSN', 'Account')] }),
      query: (s) => { seen.push(s); return Promise.resolve({ records: [] }); },
    }));
    // No EntityDefinition lookup is needed, and the field name is built directly.
    expect(seen[0]).toContain('Account.SSN__c');
    expect(r.findings[0].id).toBe('field-level-security-ok');
  });

  it('resolves a custom object id through EntityDefinition', async () => {
    const seen: string[] = [];
    await check.run(makeCtx({
      tooling: tooling({
        fields: [field('SSN', '01I5000000AbCdEfGh')],
        entities: [{ Id: '01I5000000AbCdEfGh', QualifiedApiName: 'Patient__c' }],
      }),
      query: (s) => { seen.push(s); return Promise.resolve({ records: [] }); },
    }));
    expect(seen[0]).toContain('Patient__c.SSN__c');
  });

  it('flags fields readable by more than 15 permission sets as HIGH', async () => {
    const r = await check.run(makeCtx({
      tooling: tooling({ fields: [field('SSN', 'Account')] }),
      query: perms([{ Field: 'Account.SSN__c', cnt: 16 }]),
    }));
    const f = r.findings.find((x) => x.id === 'field-level-security-high');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].note).toContain('16');
  });

  it('flags 10-15 permission sets as MEDIUM and leaves 10 or fewer alone', async () => {
    const medium = await check.run(makeCtx({
      tooling: tooling({ fields: [field('SSN', 'Account')] }),
      query: perms([{ Field: 'Account.SSN__c', cnt: 12 }]),
    }));
    expect(medium.findings.find((x) => x.id === 'field-level-security-medium')!.riskLevel).toBe('MEDIUM');

    const fine = await check.run(makeCtx({
      tooling: tooling({ fields: [field('SSN', 'Account')] }),
      query: perms([{ Field: 'Account.SSN__c', cnt: 10 }]),
    }));
    expect(fine.findings[0].id).toBe('field-level-security-ok');
  });

  it('reports high and medium exposure separately in one run', async () => {
    const r = await check.run(makeCtx({
      tooling: tooling({ fields: [field('SSN', 'Account'), field('DOB', 'Contact')] }),
      query: perms([
        { Field: 'Account.SSN__c', cnt: 20 },
        { Field: 'Contact.DOB__c', cnt: 11 },
      ]),
    }));
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain('field-level-security-high');
    expect(ids).toContain('field-level-security-medium');
    expect(ids).not.toContain('field-level-security-ok');
  });

  it('reports an INFO finding when the CustomField query fails', async () => {
    const r = await check.run(makeCtx({ tooling: () => Promise.reject(new Error('INSUFFICIENT_ACCESS')) }));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('field-level-security-query-error');
    expect(r.findings[0].passed).toBeUndefined();
  });

  /**
   * The three cases below pin CURRENT behaviour, which is wrong and should be changed.
   *
   * When this check cannot complete its analysis — FieldPermissions unreadable, or a custom
   * object that EntityDefinition would not resolve — it emits `field-level-security-ok` with
   * `passed: true` and the text "Sensitive custom fields appear appropriately restricted".
   * That reports a clean result for an analysis that never ran, which is the one outcome a
   * security tool must not produce. CLAUDE.md's own rule is that permission errors surface as
   * `inconclusive: true`, and SharingModelCheck does exactly that.
   *
   * These tests are deliberately named for the defect so it cannot be mistaken for intent.
   * When it is fixed, they should be inverted to assert `inconclusive: true`.
   */
  describe('known defect: unanalysable states are reported as a pass', () => {
    it('DEFECT: an unreadable FieldPermissions query yields passed:true', async () => {
      const r = await check.run(makeCtx({
        tooling: tooling({ fields: [field('SSN', 'Account')] }),
        query: () => Promise.reject(new Error('INSUFFICIENT_ACCESS')),
      }));
      expect(r.findings[0].id).toBe('field-level-security-ok');
      expect(r.findings[0].passed).toBe(true);
      expect(r.findings[0].inconclusive).toBeUndefined();
    });

    it('DEFECT: a failed EntityDefinition lookup yields passed:true', async () => {
      const r = await check.run(makeCtx({
        tooling: tooling({ fields: [field('SSN', '01I5000000AbCdEfGh')], entityError: true }),
      }));
      expect(r.findings[0].id).toBe('field-level-security-ok');
      expect(r.findings[0].passed).toBe(true);
    });

    it('DEFECT: unresolvable object ids yield passed:true rather than inconclusive', async () => {
      const r = await check.run(makeCtx({
        tooling: tooling({ fields: [field('SSN', '01I5000000AbCdEfGh')], entities: [] }),
      }));
      expect(r.findings[0].id).toBe('field-level-security-ok');
      expect(r.findings[0].passed).toBe(true);
    });
  });
});
