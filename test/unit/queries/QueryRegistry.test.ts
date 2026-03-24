import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { jest } from '@jest/globals';
import { QueryRegistry } from '../../../src/queries/QueryRegistry.js';

function makeTempConfig(soql: Record<string, unknown>, tooling: Record<string, unknown>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qr-test-'));
  const queryDir = path.join(dir, 'config', 'queries');
  fs.mkdirSync(queryDir, { recursive: true });
  fs.writeFileSync(path.join(queryDir, 'soql.json'), JSON.stringify(soql));
  fs.writeFileSync(path.join(queryDir, 'tooling.json'), JSON.stringify(tooling));
  return dir;
}

const VALID_SOQL = {
  activeUsers: {
    api: 'soql',
    soql: 'SELECT Id FROM User WHERE IsActive = true',
    description: 'Active users',
  },
  profileIpRanges: {
    api: 'soql',
    soql: 'SELECT ProfileId FROM ProfileLoginIpRange',
    description: 'IP ranges',
    fallbackOnError: true,
  },
};

const VALID_TOOLING = {
  apexClasses: {
    api: 'tooling',
    soql: 'SELECT Id, Name, Body FROM ApexClass',
    description: 'Apex classes',
  },
};

describe('QueryRegistry', () => {
  describe('load()', () => {
    it('loads valid JSON files without error', () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      expect(() => QueryRegistry.load(configDir)).not.toThrow();
    });

    it('throws on invalid query entry (missing description)', () => {
      const bad = { q1: { api: 'soql', soql: 'SELECT Id FROM User' } };
      const configDir = makeTempConfig(bad, {});
      expect(() => QueryRegistry.load(configDir)).toThrow(/QueryRegistry/);
    });

    it('throws on duplicate key across files', () => {
      const dup = { activeUsers: { api: 'tooling', soql: 'SELECT Id FROM User', description: 'd' } };
      const configDir = makeTempConfig(VALID_SOQL, dup);
      expect(() => QueryRegistry.load(configDir)).toThrow(/duplicate key/);
    });
  });

  describe('get()', () => {
    it('returns the query definition for a known key', () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const def = registry.get('activeUsers');
      expect(def.api).toBe('soql');
      expect(def.soql).toContain('IsActive');
    });

    it('throws a named error for an unknown key', () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      expect(() => registry.get('nonExistentKey')).toThrow("unknown query key 'nonExistentKey'");
    });
  });

  describe('execute()', () => {
    it('calls ctx.soql.queryAll for api=soql entries', async () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const queryAllFn: any = jest.fn();
      queryAllFn.mockResolvedValue([{ Id: '001' }]);
      const mockCtx: any = { soql: { queryAll: queryAllFn } };

      const result = await registry.execute('activeUsers', mockCtx);

      expect(queryAllFn).toHaveBeenCalledWith(
        'SELECT Id FROM User WHERE IsActive = true'
      );
      expect(result).toEqual([{ Id: '001' }]);
    });

    it('calls ctx.tooling.query for api=tooling entries', async () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const toolingQueryFn: any = jest.fn();
      toolingQueryFn.mockResolvedValue([]);
      const mockCtx: any = { tooling: { query: toolingQueryFn } };

      await registry.execute('apexClasses', mockCtx);

      expect(toolingQueryFn).toHaveBeenCalled();
    });

    it('returns null (not throws) when fallbackOnError=true and query fails', async () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const queryAllFn: any = jest.fn();
      queryAllFn.mockImplementation(() => Promise.reject(new Error('UNSUPPORTED')));
      const mockCtx: any = { soql: { queryAll: queryAllFn } };

      const result = await registry.execute('profileIpRanges', mockCtx);

      expect(result).toBeNull();
    });

    it('throws when fallbackOnError=false and query fails', async () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const queryAllFn: any = jest.fn();
      queryAllFn.mockImplementation(() => Promise.reject(new Error('API_ERROR')));
      const mockCtx: any = { soql: { queryAll: queryAllFn } };

      await expect(registry.execute('activeUsers', mockCtx)).rejects.toThrow('API_ERROR');
    });

    it('throws for api=rest entries (caller must use ctx.rest.get() directly)', async () => {
      const restEntry = {
        orgLimits: { api: 'rest', path: '/limits', description: 'Org limits' },
      };
      const configDir = makeTempConfig(restEntry, {});
      const registry = QueryRegistry.load(configDir);

      await expect(registry.execute('orgLimits', {} as any)).rejects.toThrow(/rest/);
    });
  });
});
