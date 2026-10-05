// test/unit/incident/collectBundle.test.ts
import { describe, it, expect, jest } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { followUpIps } from '../../../src/incident/collect/followUp.js';
import { collectBundle } from '../../../src/incident/collect/collectBundle.js';
import { loadBundle } from '../../../src/incident/bundleIo.js';
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
        fs.writeFileSync(dest, csvLine(['TIMESTAMP_DERIVED', 'USER_ID', 'CLIENT_IP', 'ACTION_MESSAGE']) + csvLine(['2026-09-15T04:00:00.000Z', '005xx000000gstA', '203.0.113.9', '1$apex://X/ACTION$getItems=1']));
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
