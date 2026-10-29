import { jest } from '@jest/globals';
import { ApexRestEndpointCheck } from '../../../../src/checks/impl/ApexRestEndpointCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const REST = (name: string) => `@RestResource(urlMapping='/${name}/*') global class ${name} { @HttpGet global static void g() {} }`;

const ctxWith = (bodies: Array<{ name: string; body: string }>, versions: Record<string, number> | Error): AuditContext => ({
  soql: {
    queryAll: (jest.fn() as any).mockImplementation(async () => {
      if (versions instanceof Error) throw versions;
      return Object.entries(versions).map(([Name, ApiVersion]) => ({ Name, ApiVersion }));
    }),
  },
  tooling: {}, rest: {},
  orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
  cache: { apexBodies: bodies },
} as unknown as AuditContext);

const noDecl = (r: { findings: Array<{ id: string; affectedItems?: Array<{ label: string }> }> }) =>
  r.findings.find((f) => f.id === 'apex-rest-no-sharing-declaration')?.affectedItems?.map((i) => i.label) ?? [];

describe('ApexRestEndpointCheck', () => {
  // spec RULE-007: from API 67.0 an omitted sharing keyword means with sharing.
  it('reports a keyword-less endpoint below API 67.0 and not one at 67.0', async () => {
    const r = await new ApexRestEndpointCheck().run(ctxWith(
      [{ name: 'Old', body: REST('Old') }, { name: 'New', body: REST('New') }],
      { Old: 66, New: 67 },
    ));
    expect(noDecl(r)).toEqual(['Old']);
  });

  it('keeps reporting keyword-less endpoints when versions cannot be read', async () => {
    const r = await new ApexRestEndpointCheck().run(ctxWith([{ name: 'New', body: REST('New') }], new Error('INVALID_TYPE')));
    expect(noDecl(r)).toEqual(['New']);
  });

  // A class with no keyword takes its parent's sharing.
  it('reports an endpoint that inherits without sharing, whatever its version', async () => {
    const r = await new ApexRestEndpointCheck().run(ctxWith(
      [{ name: 'Ep', body: REST('Ep').replace('global class Ep', 'global class Ep extends Base') },
        { name: 'Base', body: 'global virtual without sharing class Base { }' }],
      { Ep: 67, Base: 67 },
    ));
    expect(r.findings.find((f) => f.id === 'apex-rest-without-sharing')!.affectedItems!.map((i) => i.label)).toEqual(['Ep']);
    expect(noDecl(r)).toEqual([]);
  });

  it('reports a 67.0 endpoint whose keyword-less parent is below 67.0', async () => {
    const r = await new ApexRestEndpointCheck().run(ctxWith(
      [{ name: 'Ep', body: REST('Ep').replace('global class Ep', 'global class Ep extends Base') },
        { name: 'Base', body: 'global virtual class Base { }' }],
      { Ep: 67, Base: 60 },
    ));
    expect(noDecl(r)).toEqual(['Ep']);
  });
});
