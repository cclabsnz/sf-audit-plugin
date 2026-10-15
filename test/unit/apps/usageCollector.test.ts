import { collectUsage } from '../../../src/apps/usageCollector.js';

const REST = `"EVENT_TYPE","CONNECTED_APP_ID","USER_ID","METHOD","ENTITY_NAME","ROWS_PROCESSED"
"RestApi","0H4app0000001","005U1","GET","Account","10"
"RestApi","0H4app0000001","005U1","POST","Account","1"
"RestApi","0H4app0000001","005U1","GET","Contact","5"
"RestApi","","005U9","GET","Case","3"
`;

// Simulates two EventLogFile CSVs naively concatenated (each has its own header row).
const REST_MULTI_FILE = `"EVENT_TYPE","CONNECTED_APP_ID","USER_ID","METHOD","ENTITY_NAME","ROWS_PROCESSED"
"RestApi","0H4app0000001","005U1","GET","Account","10"
"RestApi","0H4app0000001","005U1","POST","Account","1"
"EVENT_TYPE","CONNECTED_APP_ID","USER_ID","METHOD","ENTITY_NAME","ROWS_PROCESSED"
"RestApi","0H4app0000001","005U2","GET","Contact","5"
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

  describe('multi-file concatenation (embedded header rows)', () => {
    it('does not produce a phantom app with appId === CONNECTED_APP_ID', () => {
      const r = collectUsage(REST_MULTI_FILE);
      expect(r.usage.find((a) => a.appId === 'CONNECTED_APP_ID')).toBeUndefined();
    });

    it('correctly aggregates the real app usage across both files', () => {
      const r = collectUsage(REST_MULTI_FILE);
      const app = r.usage.find((a) => a.appId === '0H4app0000001')!;
      expect(app).toBeDefined();
      expect(app.requests).toBe(3);
      expect(app.rowsProcessed).toBe(16);
      expect(app.userIds.sort()).toEqual(['005U1', '005U2']);
      expect(app.objects.map((o) => o.object).sort()).toEqual(['Account', 'Contact']);
    });

    it('excludes embedded header rows from totalRows and attribution', () => {
      const r = collectUsage(REST_MULTI_FILE);
      // 4 real data rows (3 attributed + 1 blank-app), 1 embedded header skipped
      expect(r.totalRows).toBe(4);
      expect(r.attributedRows).toBe(3);
      expect(r.attributionRatePct).toBe(75);
    });
  });

  describe('BulkApi2, GraphQL, and Aura parsing', () => {
    it('parses BulkApi2 logs with insert/update/delete operations', () => {
      const bulkCsv = `"EVENT_TYPE","CONNECTED_APP_ID","USER_ID","OPERATION","ENTITY_NAME","ROWS_PROCESSED"
"BulkApi2","0H4bulk001","005U3","insert","Lead","50"
"BulkApi2","0H4bulk001","005U3","hardDelete","Contact","10"
"BulkApi2","0H4bulk001","005U3","query","Opportunity","100"
`;
      const r = collectUsage('', { bulkApi2Csv: bulkCsv });
      const app = r.usage.find((a) => a.appId === '0H4bulk001')!;
      expect(app).toBeDefined();
      expect(app.requests).toBe(3);
      expect(app.rowsProcessed).toBe(160);

      const lead = app.objects.find((o) => o.object === 'Lead')!;
      expect(lead.verbs).toEqual(['write']);

      const contact = app.objects.find((o) => o.object === 'Contact')!;
      expect(contact.verbs).toEqual(['delete']);

      const opp = app.objects.find((o) => o.object === 'Opportunity')!;
      expect(opp.verbs).toEqual(['read']);
    });

    it('parses GraphQlQueryExecution logs with query and mutation types', () => {
      const gqlCsv = `"EVENT_TYPE","CONNECTED_APP_ID","USER_ID","OPERATION_TYPE","ENTITY_NAME","ROWS_PROCESSED"
"GraphQlQueryExecution","0H4gql001","005U4","query","Account","25"
"GraphQlQueryExecution","0H4gql001","005U4","mutation","Order","5"
`;
      const r = collectUsage('', { graphQlCsv: gqlCsv });
      const app = r.usage.find((a) => a.appId === '0H4gql001')!;
      expect(app).toBeDefined();
      const acct = app.objects.find((o) => o.object === 'Account')!;
      expect(acct.verbs).toEqual(['read']);
      const ord = app.objects.find((o) => o.object === 'Order')!;
      expect(ord.verbs).toEqual(['write']);
    });

    it('combines RestApi, BulkApi2, and GraphQL for the same app', () => {
      const rest = `"EVENT_TYPE","CONNECTED_APP_ID","USER_ID","METHOD","ENTITY_NAME","ROWS_PROCESSED"
"RestApi","0H4combo01","005U1","GET","Account","5"
`;
      const bulk = `"EVENT_TYPE","CONNECTED_APP_ID","USER_ID","OPERATION","ENTITY_NAME","ROWS_PROCESSED"
"BulkApi2","0H4combo01","005U1","insert","Account","20"
`;
      const r = collectUsage(rest, { bulkApi2Csv: bulk });
      const app = r.usage.find((a) => a.appId === '0H4combo01')!;
      expect(app).toBeDefined();
      expect(app.requests).toBe(2);
      expect(app.rowsProcessed).toBe(25);
      const acct = app.objects.find((o) => o.object === 'Account')!;
      expect(acct.verbs.sort()).toEqual(['read', 'write']);
    });
  });
});

