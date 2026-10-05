// test/unit/incident/collect.test.ts
import { describe, it, expect, jest } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { classifyOrgError } from '../../../src/incident/collect/orgErrors.js';
import { buildWaves, parseDayWindow, readAnomalies } from '../../../src/incident/collect/discoverWaves.js';
import { fetchAuditTrail, loginsByDay, snapshotGuests } from '../../../src/incident/collect/snapshotOrg.js';
import { streamGuestLogs, collectionDays } from '../../../src/incident/collect/streamGuestLogs.js';
import { csvLine } from '../../../src/incident/csv.js';
import type { GuestUser } from '../../../src/incident/model.js';

const guest = (id15: string, site: string): GuestUser => ({ id15, username: `${id15}@example.com`, name: `${site} Guest User`, profileName: `${site} Guest Profile`, permissionSetLabels: [], siteNames: [site], active: true });

describe('discoverWaves', () => {
  it('groups adjacent UTC days per guest into waves, ordered by start', () => {
    const ev = (id: string, d: string, u: string) => ({ eventIdentifier: id, eventDate: `${d}T01:00:00Z`, score: 1, userId15: u, username: u });
    const waves = buildWaves([ev('c', '2026-09-15', 'A'), ev('a', '2026-06-30', 'A'), ev('b', '2026-07-01', 'A'), ev('d', '2026-06-30', 'B')], [guest('A', 'Site A'), guest('B', 'Site B')], {});
    expect(waves.map((w) => [w.id, w.site, w.days])).toEqual([
      ['W1', 'Site A', ['2026-06-30', '2026-07-01']], ['W2', 'Site B', ['2026-06-30']], ['W3', 'Site A', ['2026-09-15']],
    ]);
    expect(buildWaves([ev('c', '2026-09-15', 'A'), ev('a', '2026-06-30', 'A')], [guest('A', 'Site A')], { event: 'c' }).map((w) => w.eventIds)).toEqual([['c']]);
  });
  it('parses day windows', () => {
    expect(parseDayWindow('2026-09-14/2026-09-16')).toEqual(['2026-09-14', '2026-09-15', '2026-09-16']);
    expect(parseDayWindow('2026-09-15/P2D')).toEqual(['2026-09-15', '2026-09-16']);
    expect(() => parseDayWindow('yesterday')).toThrow(/YYYY-MM-DD/);
  });
  it('reports the detector unavailable instead of throwing', async () => {
    const soql = { queryAll: jest.fn(async () => { throw new Error("sObject type 'GuestUserAnomalyEventStore' is not supported"); }), query: jest.fn() } as any;
    expect(await readAnomalies(soql, 30)).toEqual({ available: false, events: [] });
  });
});

describe('snapshotGuests', () => {
  it('includes inactive guests named by anomaly events so their rows are not filtered out', async () => {
    const soql = {
      query: jest.fn(),
      queryAll: jest.fn(async (q: string) => {
        if (q.includes("UserType = 'Guest'")) return [{ Id: '005xx000000gstAAAA', Username: 'a@example.com', Name: 'Site A Guest User', Profile: { Name: 'Site A Guest Profile' }, IsActive: true }];
        if (q.includes('FROM User WHERE Id IN')) return [{ Id: '005xx000000oldGAAA', Username: 'old@example.com', Name: 'Old Guest User', Profile: { Name: 'Old Guest Profile' }, IsActive: false }];
        if (q.includes('FROM Site')) return [{ Name: 'Site A', GuestUserId: '005xx000000gstAAAA' }];
        return [];
      }),
    } as any;
    const { guests: g } = await snapshotGuests(soql, ['005xx000000oldG']);
    expect(g.map((x) => [x.id15, x.active, x.siteNames])).toEqual([['005xx000000gstA', true, ['Site A']], ['005xx000000oldG', false, []]]);
  });
});

describe('fetchAuditTrail', () => {
  it('splits a window that hits the 10,000-row cap and keeps only guest-relevant rows', async () => {
    const calls: string[] = [];
    const soql = {
      query: jest.fn(),
      queryAll: jest.fn(async (q: string) => {
        calls.push(q);
        const from = /CreatedDate >= (\S+)/.exec(q)![1];
        const to = /CreatedDate < (\S+)/.exec(q)![1];
        const hours = (Date.parse(to) - Date.parse(from)) / 3_600_000;
        const n = hours > 48 ? 10_000 : 2;
        return Array.from({ length: n }, (_, i) => ({ CreatedDate: from, CreatedBy: { Name: 'Admin' }, Section: 'Manage Users', Action: 'x', Display: i === 0 ? 'Changed profile Site A Guest Profile: x' : 'Changed profile Sales: y' }));
      }),
    } as any;
    const r = await fetchAuditTrail(soql, '2026-09-01', '2026-09-05', [guest('005xx000000gstA', 'Site A')]);
    expect(calls.length).toBeGreaterThan(1);
    expect(r.rows.every((x) => x.display.includes('Site A'))).toBe(true);
    expect(r.coverage.truncatedWindows).toEqual([]);
  });
  it('marks the trail inaccessible on a permission error', async () => {
    const soql = { query: jest.fn(), queryAll: jest.fn(async () => { throw new Error('INSUFFICIENT_ACCESS_OR_READONLY'); }) } as any;
    const r = await fetchAuditTrail(soql, '2026-09-01', '2026-09-05', []);
    expect(r.coverage.inaccessible).toBe(true);
  });
});

describe('streamGuestLogs', () => {
  it('downloads, filters to guests, deletes the raw file, and marks absent days missing', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-collect-'));
    const soql = { query: jest.fn(), queryAll: jest.fn(async () => [{ Id: '0ATxx0000000001', EventType: 'AuraRequest', LogDate: '2026-09-15T00:00:00.000+0000', LogFileLength: 10 }]) } as any;
    const rest = {
      get: jest.fn(), getRaw: jest.fn(),
      getRawToFile: jest.fn(async (_p: string, dest: string) => {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, csvLine(['TIMESTAMP_DERIVED', 'USER_ID', 'CLIENT_IP', 'REQUEST_ID', 'ACTION_MESSAGE']) + csvLine(['2026-09-15T04:00:00.000Z', '005xx000000gstA', '203.0.113.1', 'r1', '']) + csvLine(['2026-09-15T04:00:01.000Z', '005xx000000othr', '10.0.0.1', 'r2', '']));
        return 1;
      }),
    } as any;
    const cov = await streamGuestLogs({ soql, rest }, dir, ['2026-09-15', '2026-09-16'], new Set(['005xx000000gstA']), () => {});
    const aura15 = cov.find((c) => c.type === 'AuraRequest' && c.day === '2026-09-15')!;
    expect(aura15).toMatchObject({ status: 'collected', totalRows: 2, guestRows: 1, guestRowsByUser: { '005xx000000gstA': 1 } });
    expect(cov.find((c) => c.type === 'AuraRequest' && c.day === '2026-09-16')!.status).toBe('missing');
    expect(fs.existsSync(path.join(dir, '.tmp'))).toBe(false);
  });
  it('computes collection days as wave days ±1', () => {
    expect(collectionDays([{ id: 'W1', guestId15: 'g', site: 's', days: ['2026-09-15'], eventIds: [] }])).toEqual(['2026-09-14', '2026-09-15', '2026-09-16']);
  });
});

describe('error classification (fix round 1)', () => {
  it('classifies org errors', () => {
    expect(classifyOrgError(new Error("sObject type 'X' is not supported"))).toBe('unavailable');
    expect(classifyOrgError(new Error('INVALID_TYPE: nope'))).toBe('unavailable');
    expect(classifyOrgError(new Error('INSUFFICIENT_ACCESS_OR_READONLY'))).toBe('no-permission');
    expect(classifyOrgError(new Error('HTTP 403 Forbidden'))).toBe('no-permission');
    expect(classifyOrgError(new Error('INVALID_SESSION_ID: Session expired'))).toBe('error');
  });
  it('readAnomalies rethrows unclassified errors', async () => {
    const soql = { query: jest.fn(), queryAll: jest.fn(async () => { throw new Error('INVALID_SESSION_ID: Session expired'); }) } as any;
    await expect(readAnomalies(soql, 30)).rejects.toThrow(/INVALID_SESSION_ID/);
  });
  it('loginsByDay rethrows generic errors and degrades on permission errors', async () => {
    const bad = { query: jest.fn(), queryAll: jest.fn(async () => { throw new Error('boom'); }) } as any;
    await expect(loginsByDay(bad, ['2026-09-15'])).rejects.toThrow('boom');
    const denied = { query: jest.fn(), queryAll: jest.fn(async () => { throw new Error('INSUFFICIENT_ACCESS'); }) } as any;
    expect(await loginsByDay(denied, ['2026-09-15'])).toEqual([]);
  });
  it('fetchAuditTrail rethrows generic errors', async () => {
    const bad = { query: jest.fn(), queryAll: jest.fn(async () => { throw new Error('boom'); }) } as any;
    await expect(fetchAuditTrail(bad, '2026-09-01', '2026-09-05', [])).rejects.toThrow('boom');
  });
  it('snapshotGuests degrades when Site is unavailable and warns', async () => {
    const soql = {
      query: jest.fn(),
      queryAll: jest.fn(async (q: string) => {
        if (q.includes("UserType = 'Guest'")) return [{ Id: '005xx000000gstAAAA', Username: 'a@example.com', Name: 'G', Profile: { Name: 'P' }, IsActive: true }];
        if (q.includes('FROM Site')) throw new Error('INVALID_TYPE: sObject type Site is not supported');
        return [];
      }),
    } as any;
    const warn = jest.fn();
    const { guests: g, warnings } = await snapshotGuests(soql, [], warn);
    expect(g.map((x) => x.siteNames)).toEqual([[]]);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('Site'));
    // M2: degraded reads are also returned, so collect can record them in the manifest.
    expect(warnings).toEqual([expect.stringContaining('Could not read Site')]);
  });
});

describe('parseDayWindow limits (fix round 1)', () => {
  it('rejects impossible, reversed and oversized windows, and accepts 31 days', () => {
    expect(() => parseDayWindow('2026-13-45/P1D')).toThrow(/exist/);
    expect(() => parseDayWindow('2026-09-16/2026-09-14')).toThrow(/before/);
    expect(() => parseDayWindow('2026-01-01/P99999D')).toThrow(/31/);
    expect(parseDayWindow('2026-01-01/2026-01-31')).toHaveLength(31);
    expect(parseDayWindow('2026-01-01/P31D')).toHaveLength(31);
  });
});

describe('streamGuestLogs safety (fix round 1)', () => {
  const file = [{ Id: '0ATxx0000000001', EventType: 'AuraRequest', LogDate: '2026-09-15T00:00:00.000+0000', LogFileLength: 10 }];
  it('removes stale .tmp contents and leaves no .tmp behind', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-collect-'));
    fs.mkdirSync(path.join(dir, '.tmp'));
    fs.writeFileSync(path.join(dir, '.tmp', 'old.csv'), 'USER_ID\n005xx000000othr\n');
    const soql = { query: jest.fn(), queryAll: jest.fn(async () => []) } as any;
    await streamGuestLogs({ soql, rest: { getRawToFile: jest.fn() } as any }, dir, ['2026-09-15'], new Set(), () => {});
    expect(fs.existsSync(path.join(dir, '.tmp'))).toBe(false);
  });
  it('rethrows ENOSPC instead of recording a failed log', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-collect-'));
    const soql = { query: jest.fn(), queryAll: jest.fn(async () => file) } as any;
    const rest = { getRawToFile: jest.fn(async () => { throw Object.assign(new Error('disk full'), { code: 'ENOSPC' }); }) } as any;
    await expect(streamGuestLogs({ soql, rest }, dir, ['2026-09-15'], new Set(), () => {})).rejects.toThrow('disk full');
  });
  it('marks every entry no-permission when EventLogFile is unavailable', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-collect-'));
    const soql = { query: jest.fn(), queryAll: jest.fn(async () => { throw new Error('INVALID_TYPE: EventLogFile'); }) } as any;
    const cov = await streamGuestLogs({ soql, rest: {} as any }, dir, ['2026-09-15'], new Set(), () => {});
    expect(cov.length).toBeGreaterThan(0);
    expect(cov.every((c) => c.status === 'no-permission' && /View Event Log Files/.test(c.detail ?? ''))).toBe(true);
  });
});

describe('collect --since (C1)', () => {
  it('defaults to 365 days, the oldest available, and caps at 365', async () => {
    const { default: Cmd } = await import('../../../src/commands/audit/incident/collect.js');
    expect(Cmd.flags.since.default).toBe(365);
    expect((Cmd.flags.since as unknown as { max: number }).max).toBe(365);
  });
});

describe('streamGuestLogs fails closed (I5, I6)', () => {
  const AURA_COLS = ['TIMESTAMP_DERIVED', 'USER_ID', 'CLIENT_IP', 'REQUEST_ID', 'ACTION_MESSAGE'];
  const row = ['2026-09-15T04:00:00.000Z', '005xx000000gstA', '203.0.113.1', 'r1', '1$apex://X/ACTION$getItems=1'];
  const run = async (body: string, files = [{ Id: '0ATxx0000000001', EventType: 'AuraRequest', LogDate: '2026-09-15T00:00:00.000+0000', LogFileLength: 10 }]) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-cols-'));
    const soql = { query: jest.fn(), queryAll: jest.fn(async () => files) } as any;
    const rest = { getRawToFile: jest.fn(async (_p: string, dest: string) => { fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.writeFileSync(dest, body); return 1; }) } as any;
    const warn = jest.fn();
    const cov = await streamGuestLogs({ soql, rest }, dir, ['2026-09-15'], new Set(['005xx000000gstA']), warn);
    return { dir, cov: cov.find((c) => c.type === 'AuraRequest' && c.day === '2026-09-15')!, warn, rest };
  };
  it('I5: collects a BOM-prefixed AuraRequest log, with the BOM stripped from the header', async () => {
    const body = '﻿' + ['USER_ID', 'TIMESTAMP_DERIVED', 'CLIENT_IP', 'REQUEST_ID', 'ACTION_MESSAGE'].join(',') + '\n' + ['005xx000000gstA', ...row.filter((_, i) => i !== 1)].join(',') + '\n';
    const { dir, cov } = await run(body);
    expect(cov).toMatchObject({ status: 'collected', totalRows: 1, guestRows: 1 });
    const out = fs.readFileSync(path.join(dir, cov.file!), 'utf-8');
    expect(out.startsWith('"USER_ID"')).toBe(true);
  });
  it('I5: marks an AuraRequest log without ACTION_MESSAGE failed, naming the missing column', async () => {
    const body = csvLine(AURA_COLS.filter((c) => c !== 'ACTION_MESSAGE')) + csvLine(row.slice(0, 4));
    const { cov, warn } = await run(body);
    expect(cov.status).toBe('failed');
    expect(cov.detail).toBe('missing columns: ACTION_MESSAGE');
    expect(cov.file).toBeUndefined();
    expect(warn).toHaveBeenCalled();
  });
  it('I5: accepts USER_ID_DERIVED in place of USER_ID, and requires one of them', async () => {
    const derived = AURA_COLS.map((c) => (c === 'USER_ID' ? 'USER_ID_DERIVED' : c));
    expect((await run(csvLine(derived) + csvLine(row))).cov.status).toBe('collected');
    const none = AURA_COLS.filter((c) => c !== 'USER_ID');
    const r = await run(csvLine(none) + csvLine(row.filter((_, i) => i !== 1)));
    expect(r.cov).toMatchObject({ status: 'failed', detail: 'missing columns: USER_ID or USER_ID_DERIVED' });
  });
  it('I5: requires REQUEST_ID and RESPONSE_SIZE on Sites', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-cols-'));
    const soql = { query: jest.fn(), queryAll: jest.fn(async () => [{ Id: '0ATxx0000000002', EventType: 'Sites', LogDate: '2026-09-15T00:00:00.000+0000', LogFileLength: 10 }]) } as any;
    const rest = { getRawToFile: jest.fn(async (_p: string, dest: string) => { fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.writeFileSync(dest, csvLine(['USER_ID', 'REQUEST_ID']) + csvLine(['005xx000000gstA', 'r1'])); return 1; }) } as any;
    const cov = await streamGuestLogs({ soql, rest }, dir, ['2026-09-15'], new Set(['005xx000000gstA']), () => {});
    expect(cov.find((c) => c.type === 'Sites')).toMatchObject({ status: 'failed', detail: 'missing columns: RESPONSE_SIZE' });
  });
  it('I6: marks a type and day with more than one Daily file failed, and downloads neither', async () => {
    const two = [
      { Id: '0ATxx0000000001', EventType: 'AuraRequest', LogDate: '2026-09-15T00:00:00.000+0000', LogFileLength: 10 },
      { Id: '0ATxx0000000002', EventType: 'AuraRequest', LogDate: '2026-09-15T00:00:00.000+0000', LogFileLength: 10 },
    ];
    const { cov, rest } = await run(csvLine(AURA_COLS) + csvLine(row), two);
    expect(cov).toMatchObject({ status: 'failed', detail: 'multiple daily log files' });
    expect(rest.getRawToFile).not.toHaveBeenCalled();
  });
});

describe('buildWaves (M1)', () => {
  it('skips an event with an empty userId15 and warns', () => {
    const warn = jest.fn();
    const ev = (id: string, u: string) => ({ eventIdentifier: id, eventDate: '2026-09-15T01:00:00Z', score: 1, userId15: u, username: 'x' });
    const waves = buildWaves([ev('a', ''), ev('b', 'A')], [guest('A', 'Site A')], { warn });
    expect(waves.map((w) => w.eventIds)).toEqual([['b']]);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('a'));
  });
});
