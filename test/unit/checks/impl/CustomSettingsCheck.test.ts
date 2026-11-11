import { jest } from '@jest/globals';
import { CustomSettingsCheck, namesSecret } from '../../../../src/checks/impl/CustomSettingsCheck.js';
import { capabilitiesFor } from '../../../../src/chains/CapabilityRegistry.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

type Entity = { QualifiedApiName: string; NamespacePrefix?: string | null };
type Field = { object: string; QualifiedApiName: string; DataType: string; NamespacePrefix?: string | null };

function makeCtx(opts: { settings?: Entity[] | Error; mdt?: Entity[] | Error; fields?: Field[] | Error }) {
  const query = jest.fn(async (q: string) => {
    const pick = (v: unknown) => {
      if (v instanceof Error) throw v;
      return v ?? [];
    };
    if (/FROM EntityDefinition WHERE IsCustomSetting = true/.test(q)) return pick(opts.settings);
    if (/FROM EntityDefinition WHERE QualifiedApiName LIKE/.test(q)) return pick(opts.mdt);
    if (/FROM FieldDefinition/.test(q)) {
      const rows = pick(opts.fields) as Field[];
      const names = [...q.matchAll(/'([^']+)'/g)].map((m) => m[1]);
      return rows
        .filter((f) => names.includes(f.object))
        .map((f) => ({ EntityDefinition: { QualifiedApiName: f.object }, QualifiedApiName: f.QualifiedApiName, DataType: f.DataType, NamespacePrefix: f.NamespacePrefix ?? null }));
    }
    throw new Error(`unexpected query ${q}`);
  });
  const ctx = {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: { query } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {},
  } as unknown as AuditContext;
  return { ctx, query };
}

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);
const labels = (r: CheckResult, id: string) => find(r, id)?.affectedItems?.map((i) => i.label) ?? [];

describe('CustomSettingsCheck', () => {
  const check = new CustomSettingsCheck();

  it('flags a text field with a secret-like name on a custom setting, at MEDIUM', async () => {
    const { ctx } = makeCtx({
      settings: [{ QualifiedApiName: 'Integration_Settings__c' }],
      fields: [
        { object: 'Integration_Settings__c', QualifiedApiName: 'Api_Key__c', DataType: 'Text(255)' },
        { object: 'Integration_Settings__c', QualifiedApiName: 'Endpoint__c', DataType: 'URL(255)' },
      ],
    });
    const r = await check.run(ctx);
    const f = find(r, 'custom-settings-credentials')!;
    expect(f.riskLevel).toBe('MEDIUM');
    expect(labels(r, 'custom-settings-credentials')).toEqual(['Integration_Settings__c.Api_Key__c']);
  });

  it('reads custom metadata types as well as custom settings', async () => {
    const { ctx } = makeCtx({
      mdt: [{ QualifiedApiName: 'Vendor_Config__mdt' }],
      fields: [{ object: 'Vendor_Config__mdt', QualifiedApiName: 'Client_Secret__c', DataType: 'Text Area(255)' }],
    });
    const r = await check.run(ctx);
    expect(labels(r, 'custom-settings-credentials')).toEqual(['Vendor_Config__mdt.Client_Secret__c']);
  });

  // The old check flagged any object named *Setting*, *Config* or *Credential* at HIGH on its name alone.
  it('does not flag an object for its name when none of its fields looks like a secret', async () => {
    const { ctx } = makeCtx({
      settings: [{ QualifiedApiName: 'Credential_Config__c' }],
      fields: [{ object: 'Credential_Config__c', QualifiedApiName: 'Region__c', DataType: 'Text(40)' }],
    });
    const r = await check.run(ctx);
    expect(find(r, 'custom-settings-credentials')).toBeUndefined();
    expect(find(r, 'custom-settings-clean')?.passed).toBe(true);
  });

  it.each([
    ['an encrypted text field', 'Password__c', 'Text (Encrypted)(175)'],
    ['a number field', 'Token_Count__c', 'Number(18, 0)'],
    ['a checkbox', 'Use_Api_Key__c', 'Checkbox'],
    ['a field merely containing "key"', 'Key_Prefix__c', 'Text(3)'],
  ])('does not flag %s', async (_what, name, type) => {
    const { ctx } = makeCtx({
      settings: [{ QualifiedApiName: 'App_Settings__c' }],
      fields: [{ object: 'App_Settings__c', QualifiedApiName: name, DataType: type }],
    });
    expect(find(await check.run(ctx), 'custom-settings-credentials')).toBeUndefined();
  });

  // Names that describe a secret (where it lives, what it is called) or store a Named Credential's
  // name are not secrets; nor is a namespace that happens to contain a secret word.
  it.each(['Named_Credential__c', 'NamedCredential__c', 'Token_Endpoint__c', 'Secret_Name__c', 'Tokenized__c', 'Compass__c', 'Bypass_Validation__c', 'Passport_Number__c', 'pwdmgr__Region__c', 'Key__c'])(
    'does not treat %s as a secret',
    (name) => expect(namesSecret(name)).toBe(false),
  );

  it.each(['Password__c', 'Passwd__c', 'Passphrase__c', 'Access_Token__c', 'Refresh_Token__c', 'Private_Key__c', 'Client_Key__c', 'Signing_Key__c', 'Client_Secret__c', 'ApiKey__c', 'Bearer__c', 'acme__Api_Key__c', 'oauthToken__c'])(
    'flags %s',
    async (name) => {
      const { ctx } = makeCtx({
        settings: [{ QualifiedApiName: 'App_Settings__c' }],
        fields: [{ object: 'App_Settings__c', QualifiedApiName: name, DataType: 'Text(255)' }],
      });
      expect(labels(await check.run(ctx), 'custom-settings-credentials')).toEqual([`App_Settings__c.${name}`]);
    },
  );

  // A managed package's protected setting or type cannot be read from the subscriber org's API,
  // and only the vendor can change it, so a package-only match is LOW and says so.
  // A vendor's field is reported apart, LOW, under an id that feeds no attack chain: whether it is
  // readable depends on the type's visibility, which is not read.
  it('reports managed-package fields apart, LOW, and not as the chain-feeding finding', async () => {
    const { ctx } = makeCtx({
      settings: [{ QualifiedApiName: 'acme__Config__c', NamespacePrefix: 'acme' }],
      fields: [{ object: 'acme__Config__c', QualifiedApiName: 'acme__Secret__c', DataType: 'Text(255)', NamespacePrefix: 'acme' }],
    });
    const r = await check.run(ctx);
    expect(find(r, 'custom-settings-credentials')).toBeUndefined();
    const f = find(r, 'custom-settings-credentials-managed')!;
    expect(f.riskLevel).toBe('LOW');
    expect(f.affectedItems![0].note).toContain('vendor');
    expect(capabilitiesFor(f).grants ?? []).toEqual([]);
  });

  it("treats the org's own field on a managed type as the org's", async () => {
    const { ctx } = makeCtx({
      settings: [{ QualifiedApiName: 'acme__Config__c', NamespacePrefix: 'acme' }],
      fields: [{ object: 'acme__Config__c', QualifiedApiName: 'Token__c', DataType: 'Text(255)' }],
    });
    expect(find(await check.run(ctx), 'custom-settings-credentials')!.riskLevel).toBe('MEDIUM');
  });

  it('links custom settings and custom metadata types to their own Setup pages', async () => {
    const { ctx } = makeCtx({
      settings: [{ QualifiedApiName: 'A__c' }],
      mdt: [{ QualifiedApiName: 'B__mdt' }],
      fields: [
        { object: 'A__c', QualifiedApiName: 'Password__c', DataType: 'Text(80)' },
        { object: 'B__mdt', QualifiedApiName: 'Password__c', DataType: 'Text(80)' },
      ],
    });
    const urls = find(await check.run(ctx), 'custom-settings-credentials')!.affectedItems!.map((i) => i.url);
    expect(urls).toEqual(['https://x.my.salesforce.com/lightning/setup/CustomSettings/home', 'https://x.my.salesforce.com/lightning/setup/CustomMetadata/home']);
  });

  it('passes, naming how many it read, when no field looks like a secret', async () => {
    const { ctx } = makeCtx({ settings: [{ QualifiedApiName: 'A__c' }], mdt: [{ QualifiedApiName: 'B__mdt' }], fields: [] });
    const f = find(await check.run(ctx), 'custom-settings-clean')!;
    expect(f.passed).toBe(true);
    expect(f.detail).toContain('1 custom setting(s) and 1 custom metadata type(s)');
  });

  it('is inconclusive, not clean, when custom settings cannot be listed', async () => {
    const { ctx } = makeCtx({ settings: new Error('INSUFFICIENT_ACCESS') });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => [f.id, f.inconclusive])).toEqual([['custom-settings-inconclusive', true]]);
  });

  it('is inconclusive, not clean, when field definitions cannot be read', async () => {
    const { ctx } = makeCtx({ settings: [{ QualifiedApiName: 'A__c' }], fields: new Error('boom') });
    const r = await check.run(ctx);
    expect(find(r, 'custom-settings-clean')).toBeUndefined();
    expect(find(r, 'custom-settings-inconclusive')?.inconclusive).toBe(true);
  });

  it('still reads custom settings when custom metadata types cannot be listed, and says so', async () => {
    const { ctx } = makeCtx({
      settings: [{ QualifiedApiName: 'App_Settings__c' }],
      mdt: new Error('MALFORMED_QUERY'),
      fields: [{ object: 'App_Settings__c', QualifiedApiName: 'Password__c', DataType: 'Text(80)' }],
    });
    const f = find(await check.run(ctx), 'custom-settings-credentials')!;
    expect(f.detail).toContain('Custom metadata types could not be listed');
  });

  it('reads field definitions in batches', async () => {
    const settings = Array.from({ length: 120 }, (_, i) => ({ QualifiedApiName: `S${i}__c` }));
    const { ctx, query } = makeCtx({ settings, fields: [] });
    await check.run(ctx);
    const fieldQueries = query.mock.calls.map((c) => c[0] as string).filter((q) => /FROM FieldDefinition/.test(q));
    expect(fieldQueries.length).toBe(3);
  });
});
