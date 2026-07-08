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
});
