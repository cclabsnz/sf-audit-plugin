import { describe, it, expect } from '@jest/globals';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OrgIntelCache, contentHash } from '../../../src/lib/cache.js';

describe('OrgIntelCache', () => {
  it('memoizes analysis by content hash (per component)', async () => {
    const base = mkdtempSync(join(tmpdir(), 'orgintel-cache-'));
    const cache = new OrgIntelCache('00Dxxx', base);
    let calls = 0;

    const v1 = await cache.memoize('flow', 'source-A', () => {
      calls++;
      return { touched: ['Case'] };
    });
    const v2 = await cache.memoize('flow', 'source-A', () => {
      calls++;
      return { touched: ['DIFFERENT'] };
    });

    expect(v1).toEqual({ touched: ['Case'] });
    expect(v2).toEqual({ touched: ['Case'] }); // served from cache, analyze() not re-run
    expect(calls).toBe(1);

    const v3 = await cache.memoize('flow', 'source-B', () => {
      calls++;
      return { touched: ['WorkOrder'] };
    });
    expect(v3).toEqual({ touched: ['WorkOrder'] });
    expect(calls).toBe(2); // changed content -> re-analyzed
  });

  it('contentHash is stable and content-sensitive', () => {
    expect(contentHash('abc')).toBe(contentHash('abc'));
    expect(contentHash('abc')).not.toBe(contentHash('abd'));
  });
});
