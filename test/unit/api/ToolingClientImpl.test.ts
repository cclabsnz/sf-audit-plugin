import { jest } from '@jest/globals';
import { ToolingClientImpl } from '../../../src/api/ToolingClientImpl.js';

describe('ToolingClientImpl', () => {
  let fakeConn: any;
  let client: ToolingClientImpl;

  beforeEach(() => {
    fakeConn = {
      tooling: {
        query: jest.fn(),
        // Note: conn.tooling has no queryMore — pagination uses conn.request() directly
      },
      request: jest.fn(),
      getApiVersion: jest.fn().mockReturnValue('62.0'),
    };
    client = new ToolingClientImpl(fakeConn);
  });

  describe('query()', () => {
    it('returns records from a single page', async () => {
      fakeConn.tooling.query.mockResolvedValue({
        totalSize: 2,
        done: true,
        records: [{ Id: '001' }, { Id: '002' }],
        nextRecordsUrl: undefined,
      });

      const result = await client.query<{ Id: string }>('SELECT Id FROM ApexClass');

      expect(result).toHaveLength(2);
      expect(fakeConn.request).not.toHaveBeenCalled();
    });

    it('follows pagination via nextRecordsUrl using conn.request()', async () => {
      fakeConn.tooling.query.mockResolvedValue({
        done: false,
        records: [{ Id: '001' }],
        nextRecordsUrl: '/services/data/v62.0/tooling/query/01g-next',
      });
      // Second page comes via conn.request() (not tooling.queryMore — that doesn't exist)
      fakeConn.request.mockResolvedValueOnce({
        done: true,
        records: [{ Id: '002' }],
        nextRecordsUrl: undefined,
      });

      const result = await client.query<{ Id: string }>('SELECT Id FROM ApexClass');

      expect(result).toHaveLength(2);
      expect(fakeConn.request).toHaveBeenCalledWith('/services/data/v62.0/tooling/query/01g-next');
    });
  });

  describe('getRecord()', () => {
    it('calls conn.request with the correct tooling REST path', async () => {
      const mockRecord = { Id: 'abc', Metadata: { ipRelaxation: 'BYPASS' } };
      fakeConn.request.mockResolvedValue(mockRecord);

      const result = await client.getRecord<typeof mockRecord>('ConnectedApplication', 'abc');

      expect(fakeConn.request).toHaveBeenCalledWith(
        '/services/data/v62.0/tooling/sobjects/ConnectedApplication/abc/'
      );
      expect(result).toEqual(mockRecord);
    });
  });
});
