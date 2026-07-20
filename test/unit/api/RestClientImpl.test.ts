import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Readable } from 'node:stream';
import { jest } from '@jest/globals';
import { RestClientImpl } from '../../../src/api/RestClientImpl.js';

describe('RestClientImpl', () => {
  let fakeConn: any;
  let client: RestClientImpl;

  beforeEach(() => {
    fakeConn = {
      request: jest.fn(),
      getApiVersion: jest.fn().mockReturnValue('62.0'),
    };
    client = new RestClientImpl(fakeConn);
  });

  it('prepends /services/data/vXX.0 to a path with leading slash', async () => {
    fakeConn.request.mockResolvedValue({ limitInfo: {} });
    await client.get('/limits');
    expect(fakeConn.request).toHaveBeenCalledWith('/services/data/v62.0/limits');
  });

  it('prepends /services/data/vXX.0 and adds leading slash if missing', async () => {
    fakeConn.request.mockResolvedValue({});
    await client.get('limits');
    expect(fakeConn.request).toHaveBeenCalledWith('/services/data/v62.0/limits');
  });

  it('returns the response from conn.request', async () => {
    const mockResponse = { value: 42 };
    fakeConn.request.mockResolvedValue(mockResponse);
    const result = await client.get<typeof mockResponse>('/some/path');
    expect(result).toEqual(mockResponse);
  });

  describe('getRaw', () => {
    it('prepends /services/data/vXX.0 to the path', async () => {
      fakeConn.request.mockResolvedValue('a,b,c\n1,2,3\n');
      await client.getRaw('/sobjects/EventLogFile/0AT000000000001/LogFile');
      expect(fakeConn.request).toHaveBeenCalledWith(
        '/services/data/v62.0/sobjects/EventLogFile/0AT000000000001/LogFile'
      );
    });

    it('adds a leading slash if missing', async () => {
      fakeConn.request.mockResolvedValue('');
      await client.getRaw('sobjects/EventLogFile/ID/LogFile');
      expect(fakeConn.request).toHaveBeenCalledWith(
        '/services/data/v62.0/sobjects/EventLogFile/ID/LogFile'
      );
    });

    it('returns the raw CSV body verbatim', async () => {
      const csv = 'EVENT_TYPE,TIMESTAMP\nLogin,20260707T101500.000Z\n';
      fakeConn.request.mockResolvedValue(csv);
      const result = await client.getRaw('/sobjects/EventLogFile/ID/LogFile');
      expect(result).toBe(csv);
    });
  });

  describe('getRawToFile', () => {
    let tmp: string;
    const origFetch = global.fetch;

    beforeEach(() => {
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rest-getrawtofile-'));
      fakeConn.instanceUrl = 'https://example.my.salesforce.com';
      fakeConn.accessToken = 'TOKEN123';
    });

    afterEach(() => {
      global.fetch = origFetch;
      fs.rmSync(tmp, { recursive: true, force: true });
    });

    it('streams the body to disk (creating parent dirs) and returns the byte count', async () => {
      const csv = 'EVENT_TYPE,TIMESTAMP\nLogin,20260707T101500.000Z\n';
      const body = Readable.toWeb(Readable.from([Buffer.from(csv)]));
      global.fetch = jest.fn(async () => ({ ok: true, status: 200, body })) as any;

      const dest = path.join(tmp, 'Sites', 'out.csv'); // nested dir does not exist yet
      const bytes = await client.getRawToFile('/sobjects/EventLogFile/ID/LogFile', dest);

      expect(fs.readFileSync(dest, 'utf-8')).toBe(csv);
      expect(bytes).toBe(Buffer.byteLength(csv, 'utf-8'));
      expect(global.fetch).toHaveBeenCalledWith(
        'https://example.my.salesforce.com/services/data/v62.0/sobjects/EventLogFile/ID/LogFile',
        { headers: { Authorization: 'Bearer TOKEN123' } }
      );
    });

    it('throws and leaves no file on a non-2xx response', async () => {
      global.fetch = jest.fn(async () => ({ ok: false, status: 404, body: null })) as any;
      const dest = path.join(tmp, 'out.csv');
      await expect(client.getRawToFile('/x/LogFile', dest)).rejects.toThrow();
      expect(fs.existsSync(dest)).toBe(false);
    });
  });
});
