import { existsSync, statSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { ApiLogListingError, assessLogCoverage, downloadApiLogs } from '../../../src/apps/apiLogSource.js';

const REST_CSV = 'EVENT_TYPE,CONNECTED_APP_ID,ENTITY_NAME,METHOD\nRestApi,0H4000000000001,Account,GET';

function deps(opts: { listing?: () => Promise<unknown[]>; fail?: Set<string> } = {}) {
  const seenDirs: string[] = [];
  return {
    seenDirs,
    soql: { queryAll: opts.listing ?? (async () => []) } as any,
    rest: {
      getRawToFile: async (path: string, dest: string) => {
        seenDirs.push(dirname(dest));
        const id = /EventLogFile\/(\w+)\//.exec(path)![1];
        if (opts.fail?.has(id)) throw new Error('HTTP 403 INSUFFICIENT_ACCESS');
        writeFileSync(dest, REST_CSV);
      },
    } as any,
  };
}

describe('downloadApiLogs', () => {
  it('throws (never returns empty) when the EventLogFile listing fails on permissions', async () => {
    const d = deps({ listing: async () => { throw new Error('INSUFFICIENT_ACCESS: sObject type EventLogFile is not supported'); } });
    const err = await downloadApiLogs(d, 7).catch((e) => e);
    expect(err).toBeInstanceOf(ApiLogListingError);
    expect(err.permission).toBe(true);
    expect(err.message).toMatch(/View Event Log Files/);
  });

  it('throws on a non-permission listing failure too', async () => {
    const d = deps({ listing: async () => { throw new Error('socket hang up'); } });
    await expect(downloadApiLogs(d, 7)).rejects.toThrow(/Cannot list API event logs: socket hang up/);
  });

  it('records per-file download failures instead of dropping them', async () => {
    const d = deps({
      listing: async () => [{ Id: 'ELF1', EventType: 'RestApi' }, { Id: 'ELF2', EventType: 'RestApi' }],
      fail: new Set(['ELF2']),
    });
    const logs = await downloadApiLogs(d, 7);
    expect(logs.listed).toBe(2);
    expect(logs.failed).toEqual([{ id: 'ELF2', eventType: 'RestApi', error: 'HTTP 403 INSUFFICIENT_ACCESS' }]);
    expect(logs.csv.RestApi).toContain('Account');
  });

  it('stages raw logs in a private temp dir and removes it', async () => {
    const d = deps({ listing: async () => [{ Id: 'ELF1', EventType: 'BulkApi2' }] });
    let mode = 0;
    const orig = d.rest.getRawToFile;
    d.rest.getRawToFile = async (p: string, dest: string) => {
      mode = statSync(dirname(dest)).mode & 0o777;
      await orig(p, dest);
    };
    const logs = await downloadApiLogs(d, 7);
    expect(logs.csv.BulkApi2).toContain('Account');
    expect(mode).toBe(0o700);
    expect(existsSync(d.seenDirs[0])).toBe(false);
  });
});

describe('assessLogCoverage', () => {
  const logs = (listed: number, failed: number) => ({
    csv: { RestApi: '', BulkApi2: '', GraphQlQueryExecution: '', AuraRequest: '' },
    listed,
    failed: Array.from({ length: failed }, (_, i) => ({ id: `ELF${i}`, eventType: 'RestApi', error: 'HTTP 403' })),
  });

  it('is fatal when every file failed', () => {
    expect(assessLogCoverage(logs(3, 3), 7).fatal).toMatch(/None of the 3/);
  });
  it('flags partial failure as incomplete', () => {
    expect(assessLogCoverage(logs(3, 1), 7)).toEqual({ incomplete: '1 of 3 API log file(s) could not be downloaded' });
  });
  it('is clean when every file downloaded', () => {
    expect(assessLogCoverage(logs(3, 0), 7)).toEqual({});
  });
  it('reports an empty window without treating it as an error', () => {
    expect(assessLogCoverage(logs(0, 0), 7).empty).toMatch(/No API EventLogFiles/);
  });
});
