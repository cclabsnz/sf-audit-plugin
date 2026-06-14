// test/unit/chains/Capability.test.ts
import { SOURCE_CAPS, HIGH_IMPACT_SINKS, ALL_CAPABILITIES } from '../../../src/chains/Capability.js';

describe('Capability vocabulary', () => {
  it('has exactly 10 capabilities', () => {
    expect(ALL_CAPABILITIES).toHaveLength(10);
  });

  it('source caps are a subset of all capabilities', () => {
    for (const c of SOURCE_CAPS) expect(ALL_CAPABILITIES).toContain(c);
  });

  it('sinks include org-takeover and data-read-bulk', () => {
    expect(HIGH_IMPACT_SINKS).toContain('org-takeover');
    expect(HIGH_IMPACT_SINKS).toContain('data-read-bulk');
  });
});
