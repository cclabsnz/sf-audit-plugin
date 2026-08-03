import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { jest } from '@jest/globals';
import { buildEventLogQuery, sanitizeTypes, toLogDate } from '@cclabsnz/sf-core';
import { pullEventLogs } from '@cclabsnz/sf-core';
import { EventBaselineStore } from '@cclabsnz/sf-core';

describe('buildEventLogQuery', () => {
  it('builds the default daily window query (since 1, no types)', () => {
    const soql = buildEventLogQuery({ since: 1 });
    expect(soql).toContain('SELECT Id, EventType, LogDate, LogFileLength, Interval, LogFileFieldNames');
    expect(soql).toContain('FROM EventLogFile');
    expect(soql).toContain("Interval = 'Daily'");
    expect(soql).toContain('LogDate = LAST_N_DAYS:1');
    expect(soql).toContain('ORDER BY LogDate');
    expect(soql).not.toContain('EventType IN');
  });

  it('honours the since window', () => {
    expect(buildEventLogQuery({ since: 7 })).toContain('LogDate = LAST_N_DAYS:7');
  });

  it('adds an EventType IN clause when types are given', () => {
    const soql = buildEventLogQuery({ since: 1, types: ['Login', 'ApiTotalUsage'] });
    expect(soql).toContain("AND EventType IN ('Login', 'ApiTotalUsage')");
  });

  it('omits the IN clause for an empty types array', () => {
    expect(buildEventLogQuery({ since: 1, types: [] })).not.toContain('EventType IN');
  });
});

describe('sanitizeTypes', () => {
  it('trims, strips non-alphanumeric characters, and drops empties', () => {
    expect(sanitizeTypes(' Login , Api_Total*Usage ,, ')).toEqual(['Login', 'ApiTotalUsage']);
  });

  it('returns an empty array for undefined or blank input', () => {
    expect(sanitizeTypes(undefined)).toEqual([]);
    expect(sanitizeTypes('   ')).toEqual([]);
  });
});

describe('toLogDate', () => {
  it('reduces a Salesforce datetime to YYYY-MM-DD', () => {
    expect(toLogDate('2026-07-07T00:00:00.000+0000')).toBe('2026-07-07');
  });

  it('passes through an already date-only value', () => {
    expect(toLogDate('2026-07-07')).toBe('2026-07-07');
  });
});

describe('pullEventLogs', () => {
  const ORG = '00Dxx000000000';
  const CSV_A = 'EVENT_TYPE,TIMESTAMP\nLogin,20260707T101500.000Z\n';
  const CSV_B = 'EVENT_TYPE,TIMESTAMP\nApi,20260707T101600.000Z\n';
  const ROWS = [
    { Id: '0AT0001', EventType: 'Login', LogDate: '2026-07-07T00:00:00.000+0000', LogFileLength: 40, Interval: 'Daily' },
    { Id: '0AT0002', EventType: 'ApiTotalUsage', LogDate: '2026-07-07T00:00:00.000+0000', LogFileLength: 40, Interval: 'Daily' },
  ];

  let tmpDir: string;
  let store: EventBaselineStore;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-event-pull-test-'));
    store = new EventBaselineStore(tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function restReturning(map: Record<string, string>) {
    // Mirrors RestClientImpl.getRawToFile: streams the body to destPath and returns byte count.
    const getRawToFile = jest.fn(async (p: any, dest: any) => {
      const id = String(p).split('/')[3]; // /sobjects/EventLogFile/{id}/LogFile
      const body = map[id] ?? '';
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, body, 'utf-8');
      return Buffer.byteLength(body, 'utf-8');
    });
    return { getRawToFile } as any;
  }

  it('downloads every row, saves CSV verbatim, and returns a summary + manifest', async () => {
    const soql = { queryAll: jest.fn(async () => ROWS) } as any;
    const rest = restReturning({ '0AT0001': CSV_A, '0AT0002': CSV_B });

    const result = await pullEventLogs({ soql, rest, store, orgId: ORG }, { since: 1 });

    expect(result.found).toBe(2);
    expect(result.downloaded).toBe(2);
    expect(result.skipped).toBe(0);
    expect(result.totalBytes).toBe(CSV_A.length + CSV_B.length);
    expect(result.storagePath).toBe(path.join(tmpDir, ORG));
    expect(result.manifestPath).toBeDefined();

    const loginFile = path.join(tmpDir, ORG, 'Login', '2026-07-07-0AT0001.csv');
    expect(fs.readFileSync(loginFile, 'utf-8')).toBe(CSV_A);
    expect(rest.getRawToFile).toHaveBeenCalledWith('/sobjects/EventLogFile/0AT0001/LogFile', loginFile);
  });

  it('skips rows already on disk and does not re-download them (dedup / idempotency)', async () => {
    const soql = { queryAll: jest.fn(async () => ROWS) } as any;
    const rest = restReturning({ '0AT0001': CSV_A, '0AT0002': CSV_B });

    await pullEventLogs({ soql, rest, store, orgId: ORG }, { since: 1 });
    rest.getRawToFile.mockClear();

    const second = await pullEventLogs({ soql, rest, store, orgId: ORG }, { since: 1 });
    expect(second.found).toBe(2);
    expect(second.skipped).toBe(2);
    expect(second.downloaded).toBe(0);
    expect(rest.getRawToFile).not.toHaveBeenCalled();
  });

  it('returns found: 0 with no download attempts for an empty result set (no throw)', async () => {
    const soql = { queryAll: jest.fn(async () => []) } as any;
    const rest = restReturning({});

    const result = await pullEventLogs({ soql, rest, store, orgId: ORG }, { since: 1 });
    expect(result.found).toBe(0);
    expect(result.downloaded).toBe(0);
    expect(rest.getRawToFile).not.toHaveBeenCalled();

    // A run that captured nothing still writes its coverage manifest. This assertion used to
    // be the opposite, and the opposite is the more dangerous behaviour: with no manifest, a
    // later reader cannot tell "we looked and the hour was empty" from "we never looked at
    // that hour". `sf audit timeline` branches on exactly that distinction before it reports
    // an absence, so the empty run is the one whose record matters most.
    expect(result.manifestPath).toBeDefined();
    const coverage = JSON.parse(fs.readFileSync(result.manifestPath!, 'utf-8'));
    expect(coverage.orgId).toBe(ORG);
    expect(coverage.elf.captured).toEqual([]);
    expect(coverage.elf.failed).toEqual([]);
  });

  it('classifies a permission failure instead of throwing', async () => {
    const err = Object.assign(new Error('INSUFFICIENT_ACCESS_RIGHTS'), {
      errorCode: 'INSUFFICIENT_ACCESS_RIGHTS',
      statusCode: 403,
    });
    const soql = { queryAll: jest.fn(async () => { throw err; }) } as any;
    const rest = restReturning({});

    const result = await pullEventLogs({ soql, rest, store, orgId: ORG }, { since: 1 });
    expect(result.found).toBe(0);
    expect(result.accessError).toBe('no-permission');
    expect(rest.getRawToFile).not.toHaveBeenCalled();
  });
});
