import { jest } from '@jest/globals';
import { GuestTrafficAnomalyCheck } from '../../../../src/checks/impl/GuestTrafficAnomalyCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const GUEST_ID18 = '005000000000001AAA'; // 15-char prefix 005000000000001

// Build a CSV: header + rows. Every field is quoted so embedded commas/braces are safe.
function csv(header: string[], rows: string[][]): string {
  const line = (cells: string[]) => cells.map((c) => `"${c.replace(/"/g, '""')}"`).join(',');
  return [line(header), ...rows.map(line)].join('\n');
}

interface FileSpec {
  Id: string;
  EventType: string;
  LogFileLength?: number;
  csv: string;
}

function makeCtx(opts: { guests?: unknown[]; guestsThrow?: boolean; filesThrow?: boolean; files?: FileSpec[]; cache?: unknown }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM User')) {
      if (opts.guestsThrow) throw new Error('no user access');
      return opts.guests ?? [];
    }
    if (soql.includes('FROM EventLogFile')) {
      if (opts.filesThrow) throw new Error('no elf access');
      return (opts.files ?? []).map((f) => ({ Id: f.Id, EventType: f.EventType, LogDate: '2026-07-01', LogFileLength: f.LogFileLength ?? 1000 }));
    }
    return [];
  });
  const get = jest.fn() as any;
  get.mockImplementation(async (path: string) => {
    const id = path.split('/')[3];
    const f = (opts.files ?? []).find((x) => x.Id === id);
    return f ? f.csv : '';
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: { get } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: opts.cache ?? {},
  } as any;
}

const GUEST = [{ Id: '005000000000001' }];
const graphqlRow = (ip: string, entity: string) => [GUEST_ID18, ip, `uiapi { query { ${entity} { totalCount } } }`];

describe('GuestTrafficAnomalyCheck', () => {
  const check = new GuestTrafficAnomalyCheck();
  const HEADER = ['USER_ID_DERIVED', 'CLIENT_IP', 'QUERY'];

  it('passes when there are no active guest users', async () => {
    const r = await check.run(makeCtx({ guests: [] }));
    expect(r.findings.some((f) => f.id === 'guest-traffic-anomaly-none' && f.passed)).toBe(true);
  });

  it('is inconclusive when guest users cannot be queried', async () => {
    const r = await check.run(makeCtx({ guestsThrow: true }));
    expect(r.findings[0].id).toBe('guest-traffic-anomaly-users-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('is inconclusive when EventLogFile cannot be queried', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, filesThrow: true }));
    expect(r.findings[0].id).toBe('guest-traffic-anomaly-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('passes (blind note) when no guest event logs exist in the window', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, files: [] }));
    expect(r.findings.some((f) => f.id === 'guest-traffic-anomaly-no-logs' && f.passed)).toBe(true);
  });

  it('flags a GraphQL totalCount recon sweep as HIGH', async () => {
    const rows = ['Account', 'Contact', 'Case', 'Lead', 'User', 'ContentVersion'].map((e) => graphqlRow('203.0.113.5', e));
    const r = await check.run(
      makeCtx({ guests: GUEST, files: [{ Id: '0AT1', EventType: 'GraphQlQueryExecution', csv: csv(HEADER, rows) }] }),
    );
    const f = r.findings.find((x) => x.id === 'guest-traffic-anomaly-recon');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].label).toContain('203.0.113.5');
  });

  it('flags a hosting/anonymizer source IP as HIGH', async () => {
    const rows = [[GUEST_ID18, '159.223.10.10', '']];
    const r = await check.run(
      makeCtx({ guests: GUEST, files: [{ Id: '0AT2', EventType: 'Sites', csv: csv(HEADER, rows) }] }),
    );
    const f = r.findings.find((x) => x.id === 'guest-traffic-anomaly-anonymizer');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('flags a high-volume single-IP burst as MEDIUM', async () => {
    const rows = Array.from({ length: 120 }, () => [GUEST_ID18, '198.51.100.7', '']);
    const r = await check.run(
      makeCtx({ guests: GUEST, files: [{ Id: '0AT3', EventType: 'Sites', csv: csv(HEADER, rows) }] }),
    );
    const f = r.findings.find((x) => x.id === 'guest-traffic-anomaly-burst');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('passes clean when guest traffic is unremarkable', async () => {
    const rows = [[GUEST_ID18, '198.51.100.7', ''], [GUEST_ID18, '198.51.100.8', '']];
    const r = await check.run(
      makeCtx({ guests: GUEST, files: [{ Id: '0AT4', EventType: 'Sites', csv: csv(HEADER, rows) }] }),
    );
    expect(r.findings.some((f) => f.id === 'guest-traffic-anomaly-clean' && f.passed)).toBe(true);
  });

  it('reports a not-enabled blind spot when the cache says Event Monitoring is off (no API call)', async () => {
    const r = await check.run(
      makeCtx({ guests: GUEST, cache: { eventLogSummary: { earliestDate: null, totalFiles: 0, eventTypes: [], accessible: false, accessError: 'not-enabled' } } }),
    );
    const f = r.findings.find((x) => x.id === 'guest-traffic-anomaly-inaccessible');
    expect(f?.inconclusive).toBe(true);
    expect(f!.title).toMatch(/not enabled/i);
  });

  it('reports a no-permission blind spot when the cache says logs are unreadable', async () => {
    const r = await check.run(
      makeCtx({ guests: GUEST, cache: { eventLogSummary: { earliestDate: null, totalFiles: 0, eventTypes: [], accessible: false, accessError: 'no-permission' } } }),
    );
    const f = r.findings.find((x) => x.id === 'guest-traffic-anomaly-inaccessible');
    expect(f?.inconclusive).toBe(true);
    expect(f!.title).toMatch(/View Event Log Files/i);
  });

  it('reports no-logs when the cache says Event Monitoring is enabled but empty', async () => {
    const r = await check.run(
      makeCtx({ guests: GUEST, cache: { eventLogSummary: { earliestDate: null, totalFiles: 0, eventTypes: [], accessible: true } } }),
    );
    expect(r.findings.some((f) => f.id === 'guest-traffic-anomaly-no-logs' && f.passed)).toBe(true);
  });

  it('passes clean without downloading when Event Monitoring captured no guest event types', async () => {
    const r = await check.run(
      makeCtx({ guests: GUEST, cache: { eventLogSummary: { earliestDate: '2026-06-01', totalFiles: 5, eventTypes: ['ApexExecution', 'Login'], accessible: true } } }),
    );
    expect(r.findings.some((f) => f.id === 'guest-traffic-anomaly-clean' && f.passed)).toBe(true);
  });

  it('still analyzes when the cache reports accessible logs with guest event types present', async () => {
    const rows = ['Account', 'Contact', 'Case', 'Lead', 'User', 'ContentVersion'].map((e) => graphqlRow('203.0.113.9', e));
    const r = await check.run(
      makeCtx({
        guests: GUEST,
        cache: { eventLogSummary: { earliestDate: '2026-06-30', totalFiles: 3, eventTypes: ['GraphQlQueryExecution'], accessible: true } },
        files: [{ Id: '0AT9', EventType: 'GraphQlQueryExecution', csv: csv(HEADER, rows) }],
      }),
    );
    expect(r.findings.some((f) => f.id === 'guest-traffic-anomaly-recon' && f.riskLevel === 'HIGH')).toBe(true);
  });

  it('ignores rows that do not belong to a guest user', async () => {
    const rows = [['005999999999999XYZ', '159.223.10.10', '']]; // non-guest id
    const r = await check.run(
      makeCtx({ guests: GUEST, files: [{ Id: '0AT5', EventType: 'Sites', csv: csv(HEADER, rows) }] }),
    );
    expect(r.findings.some((f) => f.id === 'guest-traffic-anomaly-clean' && f.passed)).toBe(true);
  });
});
