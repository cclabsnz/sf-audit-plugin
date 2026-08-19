import { jest } from '@jest/globals';
import { SharingModelCheck } from '../../../../src/checks/impl/SharingModelCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

type Entity = { QualifiedApiName: string; InternalSharingModel: string; ExternalSharingModel: string };

function makeCtx(rows: Entity[] | Error): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation(() =>
        rows instanceof Error ? Promise.reject(rows) : Promise.resolve(rows),
      ),
      query: jest.fn(),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

/** Private/ControlledByParent on both axes unless overridden. */
const obj = (name: string, internal = 'Private', external = 'Private'): Entity => ({
  QualifiedApiName: name, InternalSharingModel: internal, ExternalSharingModel: external,
});

describe('SharingModelCheck', () => {
  const check = new SharingModelCheck();

  it('passes when every object is Private on both axes', async () => {
    const r = await check.run(makeCtx([obj('Account'), obj('Contact')]));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('sharing-model-secure');
    expect(r.findings[0].passed).toBe(true);
  });

  it('treats ControlledByParent as restrictive, not as an exposure', async () => {
    const r = await check.run(makeCtx([obj('Contact', 'ControlledByParent', 'ControlledByParent')]));
    expect(r.findings[0].id).toBe('sharing-model-secure');
  });

  // External write is the most severe: portal and guest users can modify every record.
  it.each(['ReadWrite', 'ReadWriteTransfer', 'FullAccess'])(
    'flags external OWD %s as CRITICAL',
    async (model) => {
      const r = await check.run(makeCtx([obj('Account', 'Private', model)]));
      const f = r.findings.find((x) => x.id === 'sharing-model-external-write');
      expect(f).toBeDefined();
      expect(f!.riskLevel).toBe('CRITICAL');
      expect(f!.affectedItems?.[0].note).toContain(model);
    },
  );

  it('flags external Read as HIGH', async () => {
    const r = await check.run(makeCtx([obj('Account', 'Private', 'Read')]));
    const f = r.findings.find((x) => x.id === 'sharing-model-external-read');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('flags internal write and internal read at their own severities', async () => {
    const r = await check.run(makeCtx([
      obj('Account', 'ReadWrite'),
      obj('Contact', 'Read'),
    ]));
    expect(r.findings.find((x) => x.id === 'sharing-model-internal-write')!.riskLevel).toBe('MEDIUM');
    expect(r.findings.find((x) => x.id === 'sharing-model-internal-read')!.riskLevel).toBe('LOW');
  });

  // Breadth is the signal: one permissive object is a mistake, three is a posture.
  it('escalates internal write from MEDIUM to HIGH at three or more objects', async () => {
    const two = await check.run(makeCtx([obj('Account', 'ReadWrite'), obj('Case', 'ReadWrite')]));
    expect(two.findings.find((x) => x.id === 'sharing-model-internal-write')!.riskLevel).toBe('MEDIUM');

    const three = await check.run(makeCtx([
      obj('Account', 'ReadWrite'), obj('Case', 'ReadWrite'), obj('Lead', 'ReadWrite'),
    ]));
    expect(three.findings.find((x) => x.id === 'sharing-model-internal-write')!.riskLevel).toBe('HIGH');
  });

  it('reports internal and external exposure independently for one object', async () => {
    const r = await check.run(makeCtx([obj('Account', 'ReadWrite', 'Read')]));
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain('sharing-model-internal-write');
    expect(ids).toContain('sharing-model-external-read');
    expect(ids).not.toContain('sharing-model-secure');
  });

  it('classifies each object once per axis, write taking precedence over read', async () => {
    const r = await check.run(makeCtx([obj('Account', 'ReadWrite', 'ReadWrite')]));
    expect(r.findings.some((x) => x.id === 'sharing-model-internal-read')).toBe(false);
    expect(r.findings.some((x) => x.id === 'sharing-model-external-read')).toBe(false);
  });

  it('is inconclusive, not passing, when EntityDefinition is unreadable', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('sharing-model-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
    // A permission failure must never be reported as a clean result.
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('scopes the query to the five standard objects', async () => {
    const seen: string[] = [];
    const ctx = makeCtx([]);
    (ctx.soql.queryAll as any).mockImplementation((s: string) => { seen.push(s); return Promise.resolve([]); });
    await check.run(ctx);
    for (const name of ['Account', 'Contact', 'Opportunity', 'Case', 'Lead']) {
      expect(seen[0]).toContain(`'${name}'`);
    }
  });
});
