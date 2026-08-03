import { describe, it, expect } from '@jest/globals';
import { NamedCredentialsCheck } from '../../../../src/checks/impl/NamedCredentialsCheck.js';

/**
 * A named credential is matched against Apex source by building a regular expression from the
 * credential's own name. DeveloperName is constrained by the platform to word characters, but
 * MasterLabel is free text a customer types, so it can carry regex metacharacters.
 *
 * Interpolating that straight into a pattern fails three ways, and all three matter for a tool
 * that runs against orgs it has never seen:
 *
 *   - an unbalanced bracket throws, so the whole check dies rather than reporting
 *   - a balanced one silently changes the match, so "unused credential" is decided against a
 *     pattern that is not the label
 *   - a nested quantifier backtracks catastrophically; `(a+)+` took 31 seconds on 30 characters
 *
 * These exercise the check through its public interface with stub clients, so they describe
 * behaviour rather than the escaping helper's implementation.
 */
const ctx = (labels: string[], apex: string): any => ({
  orgInfo: { instanceUrl: 'https://acme.my.salesforce.com', orgId: '00Dxx0000000000EAA' },
  cache: { apexBodies: [{ name: 'Caller', body: apex }] },
  tooling: {
    query: async () =>
      labels.map((label, i) => ({
        Id: `0XA00000000000${i}`,
        MasterLabel: label,
        DeveloperName: `Cred_${i}`,
        Endpoint: 'https://example.test',
        PrincipalType: 'NamedUser',
      })),
  },
});

const unusedCount = (r: { metrics?: Record<string, unknown> }): number =>
  Number(r.metrics?.unusedNamedCredentialsCount ?? -1);

describe('NamedCredentialsCheck — labels containing regex metacharacters', () => {
  it('does not throw on an unbalanced bracket in a label', async () => {
    // Raw, this builds /callout:Billing_(Prod\b/i and throws SyntaxError.
    await expect(new NamedCredentialsCheck().run(ctx(['Billing (Prod'], 'x = callout:Cred_0;'))).resolves.toBeDefined();
  });

  it('does not throw on an unbalanced character class', async () => {
    await expect(new NamedCredentialsCheck().run(ctx(['Rate [v2'], 'x = callout:Cred_0;'))).resolves.toBeDefined();
  });

  it('treats metacharacters in a label as literal text, not as a pattern', async () => {
    // `Rate [v2]` as a pattern is a character class matching one of v or 2, so Apex mentioning
    // `callout:Rate_v` would wrongly count as a reference to this credential.
    const result = await new NamedCredentialsCheck().run(ctx(['Rate [v2]'], 'String x = callout:Rate_v;'));

    expect(unusedCount(result)).toBe(1);
  });

  it('treats a bare quantifier as literal, not as a repetition', async () => {
    // `Rate*` as a pattern is "Rat" followed by zero or more "e", so Apex mentioning
    // `callout:Rat` would satisfy it and the credential would be reported as used.
    const result = await new NamedCredentialsCheck().run(ctx(['Rate*'], 'String x = callout:Rat;'));

    expect(unusedCount(result)).toBe(1);
  });

  it('treats a dot as literal, not as any-character', async () => {
    // `Rate.v2` as a pattern matches `callout:RateXv2` for any X, so an unrelated credential
    // name in the Apex would mark this one as referenced.
    const result = await new NamedCredentialsCheck().run(ctx(['Rate.v2'], 'String x = callout:RateXv2;'));

    expect(unusedCount(result)).toBe(1);
  });

  it('still matches a label that genuinely appears in Apex', async () => {
    // The escaping must not break the ordinary case: spaces become underscores and match.
    const result = await new NamedCredentialsCheck().run(ctx(['Billing API'], 'String x = callout:Billing_API;'));

    expect(unusedCount(result)).toBe(0);
  });

  it('matches on DeveloperName as well as label', async () => {
    const result = await new NamedCredentialsCheck().run(ctx(['Anything At All'], 'String x = callout:Cred_0;'));

    expect(unusedCount(result)).toBe(0);
  });

  it('completes promptly on a label shaped for catastrophic backtracking', async () => {
    // Unescaped, `(a+)+` against a long non-matching subject backtracks exponentially.
    const started = Date.now();
    await new NamedCredentialsCheck().run(ctx(['(a+)+', 'Normal Label'], `x = callout:${'a'.repeat(40)}!;`));

    expect(Date.now() - started).toBeLessThan(2000);
  });
});
