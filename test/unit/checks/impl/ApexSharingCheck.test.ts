import { jest } from '@jest/globals';
import { ApexSharingCheck } from '../../../../src/checks/impl/ApexSharingCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

type Body = { name: string; body: string };

function makeCtx(opts: { apexBodies?: Body[]; toolingRows?: unknown[] } = {}): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() => Promise.resolve(opts.toolingRows ?? [])),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: { apexBodies: opts.apexBodies } as any,
  } as any;
}

const cls = (name: string, body: string): Body => ({ name, body });
const summaryOf = (r: { findings: Array<{ id: string; title: string }> }) =>
  r.findings.find((f) => f.id === 'apex-sharing-summary')!.title;

describe('ApexSharingCheck', () => {
  const check = new ApexSharingCheck();

  it('declares its cache dependency', () => {
    expect(check.dependsOnCache).toEqual(expect.arrayContaining(['apexBodies']));
  });

  it.each([
    ['with sharing', 'public with sharing class A { }', '1 with sharing'],
    ['inherited sharing', 'public inherited sharing class A { }', '1 inherited'],
    ['without sharing', 'public without sharing class A { }', '1 without sharing'],
    ['no declaration', 'public class A { }', '1 no declaration'],
  ])('classifies %s', async (_label, body, expected) => {
    const r = await check.run(makeCtx({ apexBodies: [cls('A', body)] }));
    expect(summaryOf(r)).toContain(expected);
  });

  it('always emits the summary, even with nothing to classify', async () => {
    const r = await check.run(makeCtx({ apexBodies: [] }));
    expect(r.findings).toHaveLength(1);
    expect(summaryOf(r)).toContain('(0 total)');
  });

  it('skips test classes, which run as sysadmin regardless of declaration', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('T', '@IsTest public without sharing class T { }')],
    }));
    expect(summaryOf(r)).toContain('(0 total)');
    expect(r.findings.some((f) => f.id === 'apex-without-sharing')).toBe(false);
  });

  it('skips things that are not classes', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('I', 'public interface I { void go(); }'), cls('E', 'public enum E { A, B }')],
    }));
    expect(summaryOf(r)).toContain('(0 total)');
  });

  it('flags explicit "without sharing" as HIGH', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('Dangerous', 'public without sharing class Dangerous { }')],
    }));
    const f = r.findings.find((x) => x.id === 'apex-without-sharing');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('flags a missing declaration as MEDIUM', async () => {
    const r = await check.run(makeCtx({ apexBodies: [cls('Silent', 'public class Silent { }')] }));
    expect(r.findings.find((x) => x.id === 'apex-no-sharing-declaration')!.riskLevel).toBe('MEDIUM');
  });

  it('caps the listed no-declaration classes at 20 while counting them all', async () => {
    const many = Array.from({ length: 25 }, (_, i) => cls(`C${i}`, `public class C${i} { }`));
    const r = await check.run(makeCtx({ apexBodies: many }));
    const f = r.findings.find((x) => x.id === 'apex-no-sharing-declaration')!;
    expect(f.title).toContain('25 Apex class(es)');
    expect(f.affectedItems).toHaveLength(20);
  });

  // SBS-CPORTAL-001: the IDOR case. Portal-reachable code without record-level enforcement.
  it.each([
    ['@AuraEnabled without sharing', '@AuraEnabled public without sharing class P { }', 'without sharing'],
    ['@RemoteAction without sharing', '@RemoteAction public without sharing class P { }', 'without sharing'],
    ['@AuraEnabled with no declaration', '@AuraEnabled public class P { }', 'No sharing declaration'],
  ])('raises CRITICAL for %s', async (_label, body, expectedNote) => {
    const r = await check.run(makeCtx({ apexBodies: [cls('P', body)] }));
    const f = r.findings.find((x) => x.id === 'portal-exposed-apex-without-sharing');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].note).toContain(expectedNote);
  });

  it('does not raise the portal finding for @AuraEnabled with sharing', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('Safe', '@AuraEnabled public with sharing class Safe { }')],
    }));
    expect(r.findings.some((x) => x.id === 'portal-exposed-apex-without-sharing')).toBe(false);
  });

  it('does not raise the portal finding for non-portal code without sharing', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('Batch', 'public without sharing class Batch { }')],
    }));
    expect(r.findings.some((x) => x.id === 'portal-exposed-apex-without-sharing')).toBe(false);
    // ...but it is still reported at HIGH on its own merits.
    expect(r.findings.some((x) => x.id === 'apex-without-sharing')).toBe(true);
  });

  it('lists a portal class once even if both risk paths could match', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('P', '@AuraEnabled @RemoteAction public without sharing class P { }')],
    }));
    expect(r.findings.find((x) => x.id === 'portal-exposed-apex-without-sharing')!.affectedItems)
      .toHaveLength(1);
  });

  it('reports a portal class in both the CRITICAL and the HIGH finding', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('P', '@AuraEnabled public without sharing class P { }')],
    }));
    // The portal finding is the actionable one, but the class is genuinely also a
    // without-sharing class, so suppressing it there would understate the count.
    expect(r.findings.some((x) => x.id === 'portal-exposed-apex-without-sharing')).toBe(true);
    expect(r.findings.some((x) => x.id === 'apex-without-sharing')).toBe(true);
    expect(summaryOf(r)).toContain('1 without sharing');
  });

  it('falls back to querying Apex when the cache is empty', async () => {
    const ctx = makeCtx({
      toolingRows: [{ Name: 'FromQuery', NamespacePrefix: null, Body: 'public class FromQuery { }', SymbolTable: null }],
    });
    const r = await check.run(ctx);
    expect((ctx.tooling.query as any)).toHaveBeenCalled();
    expect(summaryOf(r)).toContain('(1 total)');
  });

  it('does not query when the cache is populated', async () => {
    const ctx = makeCtx({ apexBodies: [cls('A', 'public class A { }')] });
    await check.run(ctx);
    expect((ctx.tooling.query as any)).not.toHaveBeenCalled();
  });

  it('counts a realistic mix correctly', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [
        cls('A', 'public with sharing class A { }'),
        cls('B', 'public with sharing class B { }'),
        cls('C', 'public inherited sharing class C { }'),
        cls('D', 'public without sharing class D { }'),
        cls('E', 'public class E { }'),
        cls('F', '@IsTest public class F { }'),
      ],
    }));
    expect(summaryOf(r)).toContain('2 with sharing');
    expect(summaryOf(r)).toContain('1 inherited');
    expect(summaryOf(r)).toContain('1 without sharing');
    expect(summaryOf(r)).toContain('1 no declaration');
    expect(summaryOf(r)).toContain('(5 total)');
  });
});
