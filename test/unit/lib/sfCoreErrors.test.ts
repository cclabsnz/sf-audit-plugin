// Errors as sf-core 0.12 raises them: a SalesforceApiError whose errorCode is not in the message,
// with no statusCode on the Connection path, and ERROR_HTTP_<status> when the body has no code.
import { describe, it, expect, jest } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SalesforceApiError } from '@cclabsnz/sf-core';
import { classifyOrgError } from '../../../src/incident/collect/orgErrors.js';
import { streamGuestLogs } from '../../../src/incident/collect/streamGuestLogs.js';
import { downloadApiLogs } from '../../../src/apps/apiLogSource.js';
import { isMissingObjectError } from '../../../src/checks/support/missingObject.js';
import { fieldsOf } from '../../../src/checks/support/schema.js';

// Connection path: jsforce keeps no status, so only the code says what happened.
const conn = (code: string, message: string) => new SalesforceApiError(code, message);
// Download path (getRawToFile): built from the HTTP response, so the status is present.
const http = (status: number, code = `ERROR_HTTP_${status}`, message = '') => new SalesforceApiError(code, message, { statusCode: status });

describe('incident collect classifies sf-core 0.12 errors', () => {
  it('reads the errorCode, not only the message', () => {
    expect(classifyOrgError(conn('INSUFFICIENT_ACCESS', 'insufficient access rights on cross-reference id'))).toBe('no-permission');
    expect(classifyOrgError(conn('INVALID_TYPE', "sObject type 'Site' is not supported."))).toBe('unavailable');
    expect(classifyOrgError(conn('INVALID_SESSION_ID', 'Session expired or invalid'))).toBe('error');
  });

  it('treats an HTTP 403 with no Salesforce code as no-permission', () => {
    expect(classifyOrgError(http(403))).toBe('no-permission');
    expect(classifyOrgError(conn('ERROR_HTTP_403', ''))).toBe('no-permission');
  });

  describe('streamGuestLogs', () => {
    const file = [{ Id: '0ATxx0000000001', EventType: 'AuraRequest', LogDate: '2026-09-15T00:00:00.000+0000', LogFileLength: 10 }];
    const run = (err: Error) => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-errors-'));
      const soql = { query: jest.fn(), queryAll: jest.fn(async () => file) } as any;
      const rest = { getRawToFile: jest.fn(async () => { throw err; }) } as any;
      return streamGuestLogs({ soql, rest }, dir, ['2026-09-15'], new Set(), () => {});
    };

    it.each([
      ['an expired session', http(401, 'INVALID_SESSION_ID', 'Session expired or invalid')],
      ['a 401 with no Salesforce code', http(401)],
    ])('aborts on %s instead of recording a failed log', async (_name, err) => {
      await expect(run(err)).rejects.toBe(err);
    });

    it('records a 403 download with no Salesforce code as no-permission', async () => {
      const cov = await run(http(403));
      expect(cov.find((c) => c.type === 'AuraRequest')?.status).toBe('no-permission');
    });
  });
});

describe('downloadApiLogs classifies sf-core 0.12 errors', () => {
  it('reports a coded permission failure on the listing as a permission problem', async () => {
    const soql = { queryAll: async () => { throw conn('INSUFFICIENT_ACCESS', 'insufficient access rights on object id'); } } as any;
    const err = await downloadApiLogs({ soql, rest: {} as any }, 7).catch((e: unknown) => e);
    expect((err as { permission?: boolean }).permission).toBe(true);
  });
});

describe('missing-object detection reads sf-core 0.12 codes', () => {
  it('treats a Connection-path 404 with no status as a missing object', () => {
    expect(isMissingObjectError(conn('ERROR_HTTP_404', ''))).toBe(true);
    expect(isMissingObjectError(conn('NOT_FOUND', 'The requested resource does not exist'))).toBe(true);
  });

  it('still treats a query bug as a failure, never as an absent feature', () => {
    expect(isMissingObjectError(conn('MALFORMED_QUERY', 'unexpected token'))).toBe(false);
    expect(isMissingObjectError(conn('ERROR_HTTP_500', 'boom'))).toBe(false);
  });

  it('fieldsOf answers null for an object the org does not serve', async () => {
    const ctx = { rest: { get: async () => { throw conn('ERROR_HTTP_404', ''); } } } as any;
    expect(await fieldsOf(ctx, 'NoSuchObject__c')).toBeNull();
  });
});
