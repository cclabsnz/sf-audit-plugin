// test/unit/incident/collectBundle.test.ts
import { describe, it, expect, jest } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { followUpIps } from '../../../src/incident/collect/followUp.js';
import { collectBundle } from '../../../src/incident/collect/collectBundle.js';
import { loadBundle, BundleIncompleteError } from '../../../src/incident/bundleIo.js';
import { csvLine } from '../../../src/incident/csv.js';

describe('followUpIps', () => {
  it('queries LoginHistory by an IN list with no date bound, in chunks, and sanitises IPs', async () => {
    const qs: string[] = [];
    const soql = { query: jest.fn(), queryAll: jest.fn(async (q: string) => { qs.push(q); return []; }) } as any;
    const ips = Array.from({ length: 150 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}`).concat(["192.0.2.4' OR 'x"]);
    await followUpIps(soql, ips);
    const loginQs = qs.filter((q) => q.includes('FROM LoginHistory'));
    expect(loginQs).toHaveLength(2);
    expect(loginQs.every((q) => !/LoginTime/.test(q.split('WHERE')[1]))).toBe(true);
    expect(qs.join(' ')).not.toContain("OR 'x");
  });
});

describe('followUpIps truncation (I4)', () => {
  it('marks the follow-up truncated when a chunk returns the 10,000-row cap', async () => {
    const row = { LoginTime: '2026-09-20T00:00:00.000+0000', UserId: '005xx000000tstUAAA', SourceIp: '203.0.113.9', Status: 'Failed' };
    const full = { query: jest.fn(), queryAll: jest.fn(async (q: string) => (q.includes('FROM LoginHistory') ? Array.from({ length: 10_000 }, () => row) : [])) } as any;
    expect((await followUpIps(full, ['203.0.113.9'])).truncated).toBe(true);
    const few = { query: jest.fn(), queryAll: jest.fn(async (q: string) => (q.includes('FROM LoginHistory') ? [row] : [])) } as any;
    expect((await followUpIps(few, ['203.0.113.9'])).truncated).toBeFalsy();
  });
});

describe('collectBundle', () => {
  it('writes a bundle that loadBundle accepts, with follow-up for detected actor IPs', async () => {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-cb-'));
    const day = (o: number) => new Date(Date.parse('2026-09-15T00:00:00Z') + o * 86_400_000).toISOString().slice(0, 10);
    const soql = {
      query: jest.fn(),
      queryAll: jest.fn(async (q: string) => {
        if (q.includes('GuestUserAnomalyEventStore')) return [{ EventIdentifier: 'e1', EventDate: '2026-09-15T04:04:34.000+0000', Score: 1, Username: 'a@example.com', UserId: '005xx000000gstAAAA', SourceIp: '203.0.113.9' }];
        if (q.includes("UserType = 'Guest'")) return [{ Id: '005xx000000gstAAAA', Username: 'a@example.com', Name: 'Site A Guest User', Profile: { Name: 'Site A Guest Profile' }, IsActive: true }];
        if (q.includes('FROM Site')) return [{ Name: 'Site A', GuestUserId: '005xx000000gstAAAA' }];
        if (q.includes('UserPermissionAccess')) return [{ PermissionsQueryAllFiles: true, PermissionsViewAllData: true }];
        if (q.includes('FROM EventLogFile')) return [-1, 0, 1].map((o, i) => ({ Id: `0ATxx000000000${i}`, EventType: 'AuraRequest', LogDate: `${day(o)}T00:00:00.000+0000` }));
        if (q.includes('FROM LoginHistory WHERE SourceIp IN')) return [{ LoginTime: '2026-09-20T00:00:00.000+0000', UserId: '005xx000000tstUAAA', SourceIp: '203.0.113.9', Status: 'Success' }];
        if (q.includes('FROM User WHERE Id IN')) return [{ Id: '005xx000000tstUAAA', Name: 'Test Tester', Email: 'test.tester@example.com', CreatedDate: '2026-09-19T00:00:00.000+0000', CreatedById: '005xx000000gstAAAA', Profile: { Name: 'Member' }, IsActive: true }];
        return [];
      }),
    } as any;
    const rest = {
      get: jest.fn(), getRaw: jest.fn(),
      getRawToFile: jest.fn(async (_p: string, dest: string) => {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, csvLine(['TIMESTAMP_DERIVED', 'USER_ID', 'CLIENT_IP', 'REQUEST_ID', 'ACTION_MESSAGE']) + csvLine(['2026-09-15T04:00:00.000Z', '005xx000000gstA', '203.0.113.9', 'r1', '1$apex://X/ACTION$getItems=1']));
        return 1;
      }),
    } as any;
    const { dir, manifest } = await collectBundle({ soql, rest, orgId: '00Dxx0000000000EAA', orgName: 'Test' }, { sinceDays: 30, ipRangeFiles: [], outputDir: out, warn: () => {} });
    expect(manifest.waves).toHaveLength(1);
    const b = await loadBundle(dir);
    expect(b.followUp.users.map((u) => u.id15)).toEqual(['005xx000000tstU']);
    expect(fs.existsSync(path.join(dir, '.tmp'))).toBe(false);

    // Resume: a second run into the same directory reuses intact logs and re-downloads a changed one.
    const firstDownloads = rest.getRawToFile.mock.calls.length;
    await collectBundle({ soql, rest, orgId: '00Dxx0000000000EAA', orgName: 'Test' }, { sinceDays: 30, ipRangeFiles: [], outputDir: out, warn: () => {} });
    expect(rest.getRawToFile.mock.calls.length).toBe(firstDownloads);
    fs.appendFileSync(path.join(dir, 'logs/AuraRequest/2026-09-15.csv'), csvLine(['tampered', '', '', '']));
    await collectBundle({ soql, rest, orgId: '00Dxx0000000000EAA', orgName: 'Test' }, { sinceDays: 30, ipRangeFiles: [], outputDir: out, warn: () => {} });
    expect(rest.getRawToFile.mock.calls.length).toBe(firstDownloads + 1);
    await expect(loadBundle(dir)).resolves.toBeDefined();
  });
});

describe('collectBundle trust gaps', () => {
  const GUEST = '005xx000000gstAAAA';
  const day = (o: number) => new Date(Date.parse('2026-09-15T00:00:00Z') + o * 86_400_000).toISOString().slice(0, 10);
  const setup = (over: { events?: any[]; onQuery?: (q: string) => unknown } = {}) => {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-tg-'));
    const qs: string[] = [];
    const events = over.events ?? [{ EventIdentifier: 'e1', EventDate: '2026-09-15T04:04:34.000+0000', Score: 1, Username: 'a@example.com', UserId: GUEST, SourceIp: '203.0.113.9' }];
    const soql = {
      query: jest.fn(),
      queryAll: jest.fn(async (q: string) => {
        qs.push(q);
        const o = over.onQuery?.(q);
        if (o !== undefined) return o;
        if (q.includes('GuestUserAnomalyEventStore')) return events;
        if (q.includes("UserType = 'Guest'")) return [{ Id: GUEST, Username: 'a@example.com', Name: 'Site A Guest User', Profile: { Name: 'Site A Guest Profile' }, IsActive: true }];
        if (q.includes('FROM Site')) return [{ Name: 'Site A', GuestUserId: GUEST }];
        if (q.includes('UserPermissionAccess')) return [{ PermissionsQueryAllFiles: true, PermissionsViewAllData: true }];
        if (q.includes('FROM EventLogFile')) return [-1, 0, 1].map((o2, i) => ({ Id: `0ATxx000000000${i}`, EventType: 'AuraRequest', LogDate: `${day(o2)}T00:00:00.000+0000` }));
        return [];
      }),
    } as any;
    const rest = {
      get: jest.fn(), getRaw: jest.fn(),
      getRawToFile: jest.fn(async (_p: string, dest: string) => {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, csvLine(['TIMESTAMP_DERIVED', 'USER_ID', 'CLIENT_IP', 'REQUEST_ID', 'ACTION_MESSAGE']) + csvLine(['2026-09-15T04:00:00.000Z', '005xx000000gstA', '203.0.113.9', 'r1', '1$apex://X/ACTION$getItems=1']));
        return 1;
      }),
    } as any;
    const run = (orgId = '00Dxx0000000000EAA', window?: string) =>
      collectBundle({ soql, rest, orgId, orgName: 'Test' }, { sinceDays: 30, window, ipRangeFiles: [], outputDir: out, warn: () => {} });
    return { out, qs, soql, rest, run };
  };

  it('leaves an unfinished bundle that loadBundle refuses when follow-up fails', async () => {
    const t = setup({ onQuery: (q) => { if (q.includes('FROM LoginHistory WHERE SourceIp IN')) throw new Error('boom'); return undefined; } });
    await expect(t.run()).rejects.toThrow('boom');
    await expect(loadBundle(t.out)).rejects.toBeInstanceOf(BundleIncompleteError);
  });

  it('does not reuse logs collected for a different org', async () => {
    const t = setup();
    await t.run('00Dxx0000000000EAA');
    const first = t.rest.getRawToFile.mock.calls.length;
    await t.run('00Dxx0000000001EAA');
    expect(t.rest.getRawToFile.mock.calls.length).toBe(first * 2);
  });

  it('throws when a collected log file vanishes before sealing', async () => {
    const t = setup({
      onQuery: (q) => {
        if (q.includes('FROM LoginHistory WHERE LoginTime')) fs.rmSync(path.join(t.out, 'logs/AuraRequest/2026-09-15.csv'), { force: true });
        return undefined;
      },
    });
    await expect(t.run()).rejects.toThrow(/Bundle file missing at seal: logs\/AuraRequest\/2026-09-15\.csv/);
  });

  it('in window mode keeps only anomaly events for a wave guest on a wave day, and follows up their IPs', async () => {
    const ev = (id: string, date: string, ip: string) => ({ EventIdentifier: id, EventDate: date, Score: 1, Username: 'a@example.com', UserId: GUEST, SourceIp: ip });
    const t = setup({ events: [ev('in', '2026-09-15T23:59:00.000+0000', '198.51.100.5'), ev('out', '2026-09-20T01:00:00.000+0000', '198.51.100.7')] });
    const { dir } = await t.run('00Dxx0000000000EAA', '2026-09-15/2026-09-15');
    const kept = JSON.parse(fs.readFileSync(path.join(dir, 'anomalies.json'), 'utf-8')) as Array<{ eventIdentifier: string }>;
    expect(kept.map((e) => e.eventIdentifier)).toEqual(['in']);
    const joined = t.qs.filter((q) => q.includes('FROM LoginHistory WHERE SourceIp IN')).join(' ');
    expect(joined).toContain('198.51.100.5');
    expect(joined).not.toContain('198.51.100.7');
  });

  it('C1: rejects when --event matches no wave', async () => {
    const t = setup();
    await expect(collectBundle({ soql: t.soql, rest: t.rest, orgId: '00Dxx0000000000EAA', orgName: 'Test' },
      { sinceDays: 30, event: 'no-such-event', ipRangeFiles: [], outputDir: t.out, warn: () => {} })).rejects.toThrow(/--event no-such-event matches no Guest User Anomaly wave/);
  });

  it('C1: warns when discovery finds no waves', async () => {
    const t = setup({ events: [] });
    const warn = jest.fn();
    await collectBundle({ soql: t.soql, rest: t.rest, orgId: '00Dxx0000000000EAA', orgName: 'Test' }, { sinceDays: 30, ipRangeFiles: [], outputDir: t.out, warn });
    expect(warn).toHaveBeenCalledWith('No anomaly waves found in the last 30 days; widen --since or pass --window.');
  });

  it('I3: a run that dies mid-download resumes, re-downloading only the remaining files', async () => {
    const t = setup();
    const impl = t.rest.getRawToFile.getMockImplementation()!;
    let n = 0;
    t.rest.getRawToFile.mockImplementation(async (p: string, dest: string) => {
      if (++n === 3) throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
      return impl(p, dest);
    });
    await expect(t.run()).rejects.toThrow('disk full');
    expect(t.rest.getRawToFile).toHaveBeenCalledTimes(3);
    const partial = JSON.parse(fs.readFileSync(path.join(t.out, 'manifest.json'), 'utf-8'));
    expect(partial.complete).toBe(false);
    expect(partial.logs.filter((l: { status: string }) => l.status === 'collected')).toHaveLength(2);
    expect(Object.keys(partial.files)).toHaveLength(2);
    t.rest.getRawToFile.mockImplementation(impl);
    await t.run();
    expect(t.rest.getRawToFile).toHaveBeenCalledTimes(4);
    await expect(loadBundle(t.out)).resolves.toBeDefined();
  });

  it('M2: records degraded snapshot reads in the manifest', async () => {
    const t = setup({ onQuery: (q) => { if (q.includes('FROM Site')) throw new Error('INVALID_TYPE: sObject type Site is not supported'); return undefined; } });
    const { manifest } = await t.run();
    expect(manifest.snapshotWarnings).toEqual([expect.stringContaining('Could not read Site')]);
  });

  it('M3: keeps two --ip-ranges files with the same name apart', async () => {
    const src = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-ipr-'));
    for (const d of ['aws', 'gcp']) { fs.mkdirSync(path.join(src, d)); fs.writeFileSync(path.join(src, d, 'ranges.txt'), d === 'aws' ? '192.0.2.0/24' : '198.51.100.0/24'); }
    const t = setup();
    const { dir, manifest } = await collectBundle({ soql: t.soql, rest: t.rest, orgId: '00Dxx0000000000EAA', orgName: 'Test' },
      { sinceDays: 30, ipRangeFiles: [path.join(src, 'aws', 'ranges.txt'), path.join(src, 'gcp', 'ranges.txt')], outputDir: t.out, warn: () => {} });
    expect(manifest.ipRangeFiles).toEqual(['ip-ranges/0-ranges.txt', 'ip-ranges/1-ranges.txt']);
    expect(manifest.ipRangeFiles.map((f) => fs.readFileSync(path.join(dir, f), 'utf-8'))).toEqual(['192.0.2.0/24', '198.51.100.0/24']);
  });

  it('removes .tmp when log streaming throws', async () => {
    const t = setup();
    t.rest.getRawToFile.mockImplementation(async (_p: string, dest: string) => {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, 'partial');
      throw new Error('stream failed');
    });
    await t.run().catch(() => undefined);
    expect(fs.existsSync(path.join(t.out, '.tmp'))).toBe(false);
  });
});
