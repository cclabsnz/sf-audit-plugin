import { ApexLoggingCheck } from '../../../../src/checks/impl/ApexLoggingCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(opts: {
  apexBodies?: Array<{ name: string; body: string }>;
  scheduledApexClassNames?: string[];
} = {}): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {
      apexBodies: opts.apexBodies,
      scheduledApexClassNames: opts.scheduledApexClassNames,
    } as any,
  } as any;
}

const cls = (name: string, body: string) => ({ name, body });
const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('ApexLoggingCheck', () => {
  const check = new ApexLoggingCheck();

  it('declares both cache dependencies', () => {
    expect(check.dependsOnCache).toEqual(
      expect.arrayContaining(['apexBodies', 'scheduledApexClassNames']),
    );
  });

  it('is inconclusive when the Apex cache was never populated', async () => {
    const r = await check.run(makeCtx());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('apex-logging-no-bodies');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('passes when no class logs at all', async () => {
    const r = await check.run(makeCtx({ apexBodies: [cls('Quiet', 'public class Quiet { }')] }));
    expect(r.findings[0].id).toBe('apex-logging-no-debug');
    expect(r.findings[0].passed).toBe(true);
  });

  it.each([
    ['fflib_Logger', 'fflib_Logger.info("x");'],
    ['Logger.error', 'Logger.error("x");'],
    ['LoggingService', 'LoggingService.warn("x");'],
    ['Platform Events', 'EventBus.publish(new Log__e());'],
    ['custom log object', 'insert new Log__c(Message__c = "x");'],
  ])('recognises %s as a persistent logging framework', async (_label, body) => {
    const r = await check.run(makeCtx({ apexBodies: [cls('L', `public class L { ${body} }`)] }));
    const f = find(r, 'apex-logging-framework-in-use')!;
    expect(f.passed).toBe(true);
  });

  it('classifies a class as persistent even when it also uses System.debug', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('Both', 'public class Both { Logger.info("a"); System.debug("b"); }')],
    }));
    expect(find(r, 'apex-logging-framework-in-use')).toBeDefined();
    expect(find(r, 'apex-logging-debug-only')).toBeUndefined();
  });

  it('flags System.debug-only classes at LOW', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('Debuggy', 'public class Debuggy { System.debug("x"); }')],
    }));
    expect(find(r, 'apex-logging-debug-only')!.riskLevel).toBe('LOW');
  });

  // A background job with no durable log is materially worse than a UI class, because there
  // is no user watching when it fails.
  it('raises debug-only to MEDIUM when a scheduled job is affected', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('NightlyJob', 'public class NightlyJob { System.debug("x"); }')],
      scheduledApexClassNames: ['NightlyJob'],
    }));
    const f = find(r, 'apex-logging-debug-only')!;
    expect(f.riskLevel).toBe('MEDIUM');
    expect(f.affectedItems?.[0].note).toContain('scheduled/batch job');
    expect(f.detail).toContain('1 of these are scheduled');
  });

  it.each([
    ['a password', 'System.debug(password);'],
    ['a token', 'System.debug("tok: " + token);'],
    ['an api key', 'System.debug(apiKey);'],
    ['a session id', 'System.debug(UserInfo.getSessionId());'],
  ])('flags logging %s as HIGH (SBS-CODE-004)', async (_label, body) => {
    const r = await check.run(makeCtx({ apexBodies: [cls('Leaky', `public class Leaky { ${body} }`)] }));
    const f = find(r, 'apex-logging-sensitive-data')!;
    expect(f.riskLevel).toBe('HIGH');
  });

  it('does not flag ordinary debug output as sensitive', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('Fine', 'public class Fine { System.debug("record count: " + n); }')],
    }));
    expect(find(r, 'apex-logging-sensitive-data')).toBeUndefined();
    expect(find(r, 'apex-logging-debug-only')).toBeDefined();
  });

  it('excludes test classes from the scan', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [cls('T', '@IsTest public class T { System.debug(password); }')],
    }));
    expect(r.findings[0].id).toBe('apex-logging-no-debug');
  });

  it('caps the debug-only list at 30 while counting them all', async () => {
    const many = Array.from({ length: 35 }, (_, i) =>
      cls(`C${i}`, `public class C${i} { System.debug("x"); }`));
    const r = await check.run(makeCtx({ apexBodies: many }));
    const f = find(r, 'apex-logging-debug-only')!;
    expect(f.title).toContain('35 Apex class(es)');
    expect(f.affectedItems).toHaveLength(30);
  });

  it('summarises only the first five persistent-logger classes by name', async () => {
    const many = Array.from({ length: 8 }, (_, i) => cls(`L${i}`, `Logger.info("x");`));
    const r = await check.run(makeCtx({ apexBodies: many }));
    expect(find(r, 'apex-logging-framework-in-use')!.detail).toContain('+3 more');
  });

  it('reports the three concerns independently', async () => {
    const r = await check.run(makeCtx({
      apexBodies: [
        cls('Good', 'Logger.info("x");'),
        cls('Debuggy', 'System.debug("x");'),
        cls('Leaky', 'System.debug(secret);'),
      ],
    }));
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining([
      'apex-logging-framework-in-use', 'apex-logging-debug-only', 'apex-logging-sensitive-data',
    ]));
    expect(ids).not.toContain('apex-logging-no-debug');
  });
});
