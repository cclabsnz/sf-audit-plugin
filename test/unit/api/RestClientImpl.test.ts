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
});
