import { jest } from '@jest/globals';
import { MetadataClientImpl } from '../../../src/api/MetadataClientImpl.js';

function connWith(readResult: unknown) {
  const read = jest.fn() as any;
  read.mockResolvedValue(readResult);
  return { metadata: { read } } as any;
}

describe('MetadataClientImpl', () => {
  it('returns the record for a populated component', async () => {
    const c = new MetadataClientImpl(connWith({ fullName: 'Security', enableAdminLoginAsAnyUser: true }));
    const r = await c.read<{ enableAdminLoginAsAnyUser: boolean }>('SecuritySettings', 'Security');
    expect(r?.enableAdminLoginAsAnyUser).toBe(true);
  });

  it('unwraps the first element when read returns an array', async () => {
    const c = new MetadataClientImpl(connWith([{ fullName: 'Security', x: 1 }]));
    const r = await c.read('SecuritySettings', 'Security');
    expect((r as any).x).toBe(1);
  });

  it('returns null for an empty/absent component (only fullName)', async () => {
    const c = new MetadataClientImpl(connWith({ fullName: 'Security' }));
    expect(await c.read('SecuritySettings', 'Security')).toBeNull();
  });

  it('returns null when read yields null', async () => {
    const c = new MetadataClientImpl(connWith(null));
    expect(await c.read('SecuritySettings', 'Security')).toBeNull();
  });
});
