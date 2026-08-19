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
   * These three states are all "we could not complete the analysis". They must never render as
   * a pass: a report that says "Sensitive custom fields appear appropriately restricted" when
   * FieldPermissions was unreadable is a false assurance about SSNs and medical records.
   */
  describe('unanalysable states report what is unknown, never a pass', () => {
    it('is inconclusive when FieldPermissions cannot be read', async () => {
      const r = await check.run(makeCtx({
        tooling: tooling({ fields: [field('SSN', 'Account')] }),
        query: () => Promise.reject(new Error('INSUFFICIENT_ACCESS')),
      }));
      expect(r.findings[0].id).toBe('field-level-security-inaccessible');
      expect(r.findings[0].inconclusive).toBe(true);
      expect(r.findings[0].passed).toBeUndefined();
      // The fields it did find are still named, so the reader can check them by hand.
      expect(r.findings[0].affectedItems?.[0].label).toBe('Account.SSN__c');
    });

    it('is inconclusive when the EntityDefinition lookup fails, and says so', async () => {
      const r = await check.run(makeCtx({
        tooling: tooling({ fields: [field('SSN', '01I5000000AbCdEfGh')], entityError: true }),
      }));
      expect(r.findings[0].id).toBe('field-level-security-unresolved');
      expect(r.findings[0].inconclusive).toBe(true);
      expect(r.findings[0].detail).toContain('EntityDefinition');
    });

    it('is inconclusive when object ids resolve to nothing', async () => {
      const r = await check.run(makeCtx({
        tooling: tooling({ fields: [field('SSN', '01I5000000AbCdEfGh')], entities: [] }),
      }));
      expect(r.findings[0].id).toBe('field-level-security-unresolved');
      expect(r.findings[0].inconclusive).toBe(true);
      expect(r.findings[0].passed).toBeUndefined();
    });

    it('downgrades a clean result to inconclusive when some fields were skipped', async () => {
      // One resolvable field with acceptable exposure, one that cannot be resolved.
      const r = await check.run(makeCtx({
        tooling: tooling({
          fields: [field('SSN', 'Account'), field('DOB', '01I5000000AbCdEfGh')],
          entities: [],
        }),
        query: perms([{ Field: 'Account.SSN__c', cnt: 2 }]),
      }));
      const f = r.findings.find((x) => x.id === 'field-level-security-ok')!;
      expect(f.inconclusive).toBe(true);
      expect(f.passed).toBeUndefined();
      expect(f.title).toContain('1 could not be evaluated');
    });

    it('still passes cleanly when everything was evaluated', async () => {
      const r = await check.run(makeCtx({
        tooling: tooling({ fields: [field('SSN', 'Account')] }),
        query: perms([{ Field: 'Account.SSN__c', cnt: 2 }]),
      }));
      const f = r.findings.find((x) => x.id === 'field-level-security-ok')!;
      expect(f.passed).toBe(true);
      expect(f.inconclusive).toBeUndefined();
    });
  });
});
