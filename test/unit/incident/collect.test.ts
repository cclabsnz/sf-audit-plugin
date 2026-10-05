// test/unit/incident/collect.test.ts
import { describe, it, expect, jest } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildWaves, parseDayWindow, readAnomalies } from '../../../src/incident/collect/discoverWaves.js';
import { fetchAuditTrail, snapshotGuests } from '../../../src/incident/collect/snapshotOrg.js';
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
    const g = await snapshotGuests(soql, ['005xx000000oldG']);
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
        fs.writeFileSync(dest, csvLine(['USER_ID', 'CLIENT_IP']) + csvLine(['005xx000000gstA', '203.0.113.1']) + csvLine(['005xx000000othr', '10.0.0.1']));
        return 1;
      }),
    } as any;
    const cov = await streamGuestLogs({ soql, rest }, dir, ['2026-09-15', '2026-09-16'], new Set(['005xx000000gstA']), () => {});
    const aura15 = cov.find((c) => c.type === 'AuraRequest' && c.day === '2026-09-15')!;
    expect(aura15).toMatchObject({ status: 'collected', totalRows: 2, guestRows: 1, guestRowsByUser: { '005xx000000gstA': 1 } });
    expect(cov.find((c) => c.type === 'AuraRequest' && c.day === '2026-09-16')!.status).toBe('missing');
    expect(fs.readdirSync(path.join(dir, '.tmp'))).toEqual([]);
  });
  it('computes collection days as wave days ±1', () => {
    expect(collectionDays([{ id: 'W1', guestId15: 'g', site: 's', days: ['2026-09-15'], eventIds: [] }])).toEqual(['2026-09-14', '2026-09-15', '2026-09-16']);
  });
});
