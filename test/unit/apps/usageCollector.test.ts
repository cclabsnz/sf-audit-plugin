import { collectUsage } from '../../../src/apps/usageCollector.js';

const REST = `"EVENT_TYPE","CONNECTED_APP_ID","USER_ID","METHOD","ENTITY_NAME","ROWS_PROCESSED"
"RestApi","0H4app0000001","005U1","GET","Account","10"
"RestApi","0H4app0000001","005U1","POST","Account","1"
"RestApi","0H4app0000001","005U1","GET","Contact","5"
"RestApi","","005U9","GET","Case","3"
`;

describe('collectUsage', () => {
  it('aggregates per-app objects and verbs from RestApi rows', () => {
    const r = collectUsage(REST);
    const app = r.usage.find((a) => a.appId === '0H4app0000001')!;
    const acct = app.objects.find((o) => o.object === 'Account')!;
    expect(acct.verbs.sort()).toEqual(['read', 'write']);
    expect(app.objects.map((o) => o.object).sort()).toEqual(['Account', 'Contact']);
    expect(app.userIds).toEqual(['005U1']);
    expect(app.requests).toBe(3);
    expect(app.rowsProcessed).toBe(16);
  });

  it('reports the attribution rate and ignores blank CONNECTED_APP_ID rows for app usage', () => {
    const r = collectUsage(REST);
    expect(r.totalRows).toBe(4);
    expect(r.attributedRows).toBe(3);
    expect(r.attributionRatePct).toBe(75);
  });
});
