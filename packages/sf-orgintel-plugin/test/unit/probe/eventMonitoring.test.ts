import { describe, it, expect } from '@jest/globals';
import { probeEventMonitoring } from '../../../src/probe/eventMonitoring.js';
import { mockSoql } from '../helpers/mocks.js';

const elf = (records: unknown[]) => mockSoql([{ test: (q) => q.includes('FROM EventLogFile'), records }]);

describe('probeEventMonitoring', () => {
  it('classifies full EM when hourly intervals are present', async () => {
    const em = await probeEventMonitoring(
      elf([
        { EventType: 'ApiTotalUsage', Interval: 'Hourly' },
        { EventType: 'Login', Interval: 'Daily' },
      ]),
    );
    expect(em.level).toBe('full');
    expect(em.access).toBe('ok');
    expect(em.intervals).toEqual(['Daily', 'Hourly']);
    expect(em.eventTypeCount).toBe(2);
  });

  it('classifies free-tier when only daily intervals exist', async () => {
    const em = await probeEventMonitoring(
      elf([
        { EventType: 'Login', Interval: 'Daily' },
        { EventType: 'Login', Interval: 'Daily' },
      ]),
    );
    expect(em.level).toBe('free-tier');
    expect(em.eventTypes).toEqual(['Login']);
  });

  it('reports none when readable but no rows', async () => {
    const em = await probeEventMonitoring(elf([]));
    expect(em.level).toBe('none');
    expect(em.access).toBe('ok');
  });

  it('detects missing permission', async () => {
    const soql = mockSoql([
      { test: (q) => q.includes('EventLogFile'), error: new Error('INSUFFICIENT_ACCESS: no permission') },
    ]);
    const em = await probeEventMonitoring(soql);
    expect(em.level).toBe('none');
    expect(em.access).toBe('no-permission');
  });

  it('detects not-enabled edition', async () => {
    const soql = mockSoql([
      { test: (q) => q.includes('EventLogFile'), error: new Error("sObject type 'EventLogFile' is not supported") },
    ]);
    const em = await probeEventMonitoring(soql);
    expect(em.access).toBe('not-enabled');
  });
});
