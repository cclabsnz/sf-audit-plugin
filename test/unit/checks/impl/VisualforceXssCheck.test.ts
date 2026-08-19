import { jest } from '@jest/globals';
import { VisualforceXssCheck } from '../../../../src/checks/impl/VisualforceXssCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: {
  pages?: unknown[] | Error;
  count?: number | Error;
} = {}): AuditContext {
  return {
    soql: {
      queryAll: jest.fn(),
      query: (jest.fn() as any).mockImplementation(() =>
        opts.count instanceof Error
          ? Promise.reject(opts.count)
          : Promise.resolve({ totalSize: opts.count ?? 0, records: [] }),
      ),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() =>
        opts.pages instanceof Error ? Promise.reject(opts.pages) : Promise.resolve(opts.pages ?? []),
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

const page = (Name: string, Markup: string) => ({ Name, Markup });

describe('VisualforceXssCheck', () => {
  const check = new VisualforceXssCheck();

  it('declares the cache it populates', () => {
    expect(check.populatesCache).toEqual(expect.arrayContaining(['vfPageBodies']));
  });

  it('is inconclusive when page markup cannot be read', async () => {
    const ctx = makeCtx({ pages: new Error('INSUFFICIENT_ACCESS') });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('visualforce-xss-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
    // The cache is still initialised, so downstream checks see an empty list rather than undefined.
    expect((ctx.cache as any).vfPageBodies).toEqual([]);
  });

  it('passes when the org has no Visualforce pages', async () => {
    const r = await check.run(makeCtx({ pages: [] }));
    expect(r.findings[0].id).toBe('visualforce-xss-no-pages');
    expect(r.findings[0].passed).toBe(true);
  });

  it('caches the markup it scanned', async () => {
    const ctx = makeCtx({ pages: [page('P', '<apex:page/>')] });
    await check.run(ctx);
    expect((ctx.cache as any).vfPageBodies).toEqual([{ name: 'P', markup: '<apex:page/>' }]);
  });

  it('flags escape="false" as HIGH', async () => {
    const r = await check.run(makeCtx({
      pages: [page('Unsafe', '<apex:outputText value="{!v}" escape="false"/>')],
    }));
    const f = r.findings.find((x) => x.id === 'visualforce-xss-escape-false');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].label).toBe('Unsafe');
  });

  it('flags an unencoded merge field inside a script block as HIGH', async () => {
    const r = await check.run(makeCtx({
      pages: [page('Scripty', '<script>var x = "{!userInput}";</script>')],
    }));
    expect(r.findings.find((x) => x.id === 'visualforce-xss-js-merge-field')!.riskLevel).toBe('HIGH');
  });

  it.each(['JSENCODE', 'JSINHTMLENCODE'])('accepts %s inside a script block', async (fn) => {
    const r = await check.run(makeCtx({
      pages: [page('Safe', `<script>var x = "{!${fn}(userInput)}";</script>`)],
    }));
    expect(r.findings.some((x) => x.id === 'visualforce-xss-js-merge-field')).toBe(false);
  });

  it.each(['href', 'src', 'action', 'onclick'])(
    'flags an unencoded merge field in a %s attribute as MEDIUM',
    async (attr) => {
      const r = await check.run(makeCtx({
        pages: [page('Linky', `<a ${attr}="{!target}">go</a>`)],
      }));
      const f = r.findings.find((x) => x.id === 'visualforce-xss-attr-merge-field');
      expect(f).toBeDefined();
      expect(f!.riskLevel).toBe('MEDIUM');
    },
  );

  it.each(['HTMLENCODE', 'JSENCODE', 'URLENCODE'])('accepts %s in a URL attribute', async (fn) => {
    const r = await check.run(makeCtx({
      pages: [page('Safe', `<a href="{!${fn}(target)}">go</a>`)],
    }));
    expect(r.findings.some((x) => x.id === 'visualforce-xss-attr-merge-field')).toBe(false);
  });

  it('passes a page with no XSS pattern', async () => {
    const r = await check.run(makeCtx({
      pages: [page('Clean', '<apex:page><apex:outputText value="{!v}"/></apex:page>')],
    }));
    expect(r.findings[0].id).toBe('visualforce-xss-ok');
    expect(r.findings[0].passed).toBe(true);
    expect(r.findings[0].title).toContain('1 Visualforce page(s)');
  });

  it('reports all three patterns independently', async () => {
    const r = await check.run(makeCtx({
      pages: [
        page('A', '<apex:outputText escape="false"/>'),
        page('B', '<script>var x = "{!v}";</script>'),
        page('C', '<a href="{!v}">x</a>'),
      ],
    }));
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining([
      'visualforce-xss-escape-false',
      'visualforce-xss-js-merge-field',
      'visualforce-xss-attr-merge-field',
    ]));
    expect(ids).not.toContain('visualforce-xss-ok');
  });

  // The script and attribute patterns are module-level regexes with /g. Without the lastIndex
  // reset the check performs, the second page would be scanned from the wrong offset and
  // silently pass.
  it('detects the same pattern on consecutive pages', async () => {
    const r = await check.run(makeCtx({
      pages: [
        page('One', '<script>var x = "{!v}";</script>'),
        page('Two', '<script>var x = "{!v}";</script>'),
      ],
    }));
    expect(r.findings.find((x) => x.id === 'visualforce-xss-js-merge-field')!.affectedItems)
      .toHaveLength(2);
  });

  it('skips a page with empty markup without throwing', async () => {
    const r = await check.run(makeCtx({ pages: [{ Name: 'Empty', Markup: '' }] }));
    expect(r.findings.some((f) => f.id === 'visualforce-xss-ok')).toBe(true);
  });

  /**
   * The Tooling API caps this query at 500 rows. Reporting on a truncated scan without saying
   * so would understate exposure, so the check declares the shortfall.
   */
  describe('truncated scans declare themselves', () => {
    const many = Array.from({ length: 500 }, (_, i) => page(`P${i}`, '<apex:page/>'));

    it('warns when the org has more pages than the API will return', async () => {
      const r = await check.run(makeCtx({ pages: many, count: 900 }));
      const f = r.findings.find((x) => x.id === 'visualforce-xss-incomplete-scan');
      expect(f).toBeDefined();
      expect(f!.inconclusive).toBe(true);
      expect(f!.title).toContain('500 of 900');
      expect(f!.detail).toContain('400');
    });

    it('does not warn when everything fitted', async () => {
      const r = await check.run(makeCtx({ pages: [page('P', '<apex:page/>')], count: 1 }));
      expect(r.findings.some((x) => x.id === 'visualforce-xss-incomplete-scan')).toBe(false);
    });

    it('falls back to the returned row count when COUNT() is unavailable', async () => {
      // 500 rows returned with no count query means truncation cannot be ruled out.
      const r = await check.run(makeCtx({ pages: many, count: new Error('no count') }));
      expect(r.findings.some((x) => x.id === 'visualforce-xss-incomplete-scan')).toBe(false);
      // 500 exactly is the boundary: not greater than the limit, so no warning is raised.
      expect(r.findings.some((x) => x.id === 'visualforce-xss-ok')).toBe(true);
    });
  });
});
