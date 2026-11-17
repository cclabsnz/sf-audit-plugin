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
    // RULE-103: logging sensitive data is a disclosure, not a repudiation gap.
    expect(f.threats).toEqual({ stride: ['I'] });
    expect(f.riskLevel).toBe('HIGH');
  });

  it.each([
    ['a field on a record', 'System.debug(contact.Password__c);'],
    ['a credit card number', 'System.debug(acct.CreditCardNumber__c);'],
    ['a date of birth', 'System.debug(c.Date_Of_Birth__c);'],
    ['a value inside a nested call', 'System.debug(String.valueOf(x) + accessToken);'],
    ['a plural identifier', 'System.debug(tokens);'],
    ['a lower-case compound', 'System.debug(getpassword());'],
    ['the standard birthdate field', 'System.debug(con.Birthdate);'],
    ['a social security field', 'System.debug(p.Social_Security_Number__c);'],
    ['an NHI number field', 'System.debug(patient.NHI__c);'],
  ])('flags logging %s as sensitive', async (_label, body) => {
    const r = await check.run(makeCtx({ apexBodies: [cls('Leaky', `public class Leaky { ${body} }`)] }));
    expect(find(r, 'apex-logging-sensitive-data')).toBeDefined();
  });

  // The term has to be an identifier, or a camelCase or underscore word of one, passed to
  // System.debug. Words inside a string literal and letters inside a longer word do not count.
  it.each([
    ['a sensitive word inside a string literal', "System.debug('Token refreshed for ' + userName);"],
    ['a word that only contains a sensitive term', 'System.debug(doBulk);'],
    ['a method whose name starts with dob letters', 'System.debug(this.doBulkInsert(rows));'],
    ['a sentence that mentions passwords', "System.debug('Password policy check complete');"],
    ['an identifier that only contains the letters', 'System.debug(tokenizer.count + assessment);'],
    ['a commented-out line', '// System.debug(password);\n System.debug(n);'],
    ['a block comment', '/* System.debug(token); */ System.debug(n);'],
    ['a URL in a string literal before a debug', "String u = 'https://x.example/path'; System.debug(n);"],
  ])('does not flag %s', async (_label, body) => {
    const r = await check.run(makeCtx({ apexBodies: [cls('Fine', `public class Fine { ${body} }`)] }));
    expect(find(r, 'apex-logging-sensitive-data')).toBeUndefined();
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
