import { describe, it, expect } from '@jest/globals';
import { loadIpRanges, parseIpRangeFile } from '../../../src/incident/ipRanges.js';

describe('ip ranges', () => {
  it('parses AWS, GCP, Azure and plain CIDR files', () => {
    expect(parseIpRangeFile('ip-ranges.json', JSON.stringify({ prefixes: [{ ip_prefix: '203.0.113.0/24', region: 'ap-southeast-2', service: 'EC2' }] }))[0].label).toBe('AWS ap-southeast-2 (EC2)');
    expect(parseIpRangeFile('cloud.json', JSON.stringify({ prefixes: [{ ipv4Prefix: '198.51.100.0/24', scope: 'us-east1' }] }))[0].label).toBe('GCP us-east1');
    expect(parseIpRangeFile('ServiceTags.json', JSON.stringify({ values: [{ name: 'AzureCloud.eastus', properties: { addressPrefixes: ['192.0.2.0/24', '2001:db8::/32'] } }] })).map((r) => r.label)).toEqual(['Azure AzureCloud.eastus']);
    expect(parseIpRangeFile('vps.txt', '# comment\n192.0.2.0/25\n')[0]).toEqual({ base: (192 << 24 >>> 0) + (0 << 16) + (2 << 8), bits: 25, label: 'vps.txt' });
  });
  it('looks up IPv4 and returns null for IPv6 or no match', () => {
    const set = loadIpRanges([{ name: 'vps.txt', text: '203.0.113.0/24' }]);
    expect(set.lookup('203.0.113.105')).toBe('vps.txt');
    expect(set.lookup('198.51.100.1')).toBeNull();
    expect(set.lookup('2001:db8::1')).toBeNull();
  });
  it('rejects a CIDR with an empty prefix length', () => {
    expect(parseIpRangeFile('vps.txt', '192.0.2.4/\n')).toEqual([]);
  });
});
