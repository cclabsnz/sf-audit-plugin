import { describe, it, expect } from '@jest/globals';
import { joinKeysOf } from '../../../src/timeline/JoinKeys.js';
import { correlate } from '../../../src/timeline/CorrelationEngine.js';

/**
 * Tracing an action to its consequences, rather than to its neighbours.
 *
 * The five original join keys answer "what else was this actor doing at the time". They tie
 * concurrent activity together: same request, same session, same address. None of them says one
 * row *caused* another, so a timeline built from them alone shows an actor's activity without
 * showing what it set off.
 *
 * Two links carry causation and both are worth following:
 *
 *   TRANSACTION_ID groups a save and everything it cascaded into. Rows sharing it did not merely
 *   happen near each other; the second happened because of the first.
 *
 *   RelatedEventIdentifier points at another event's EventIdentifier. Unlike every other key it
 *   is not an equality join on the same field — following it means jumping from one field to a
 *   different one on another row, which is why the engine needs to know about it explicitly.
 */
describe('joinKeysOf — causal keys', () => {
  it('extracts a transaction id from either naming convention', () => {
    expect(joinKeysOf({ TRANSACTION_ID: 'txn-1' }).transactionId).toBe('txn-1');
    expect(joinKeysOf({ TransactionId: 'txn-1' }).transactionId).toBe('txn-1');
  });

  it('extracts the real-time event identity and the link to its cause', () => {
    const keys = joinKeysOf({ EventIdentifier: 'evt-2', RelatedEventIdentifier: 'evt-1' });

    expect(keys.eventIdentifier).toBe('evt-2');
    expect(keys.relatedEventIdentifier).toBe('evt-1');
  });

  it('accepts the underscored spellings too', () => {
    const keys = joinKeysOf({ EVENT_IDENTIFIER: 'evt-2', RELATED_EVENT_IDENTIFIER: 'evt-1' });

    expect(keys.eventIdentifier).toBe('evt-2');
    expect(keys.relatedEventIdentifier).toBe('evt-1');
  });

  it('applies the blank rule to causal keys as well', () => {
    const keys = joinKeysOf({ TRANSACTION_ID: '  ', EventIdentifier: '', RelatedEventIdentifier: null });

    expect(keys.transactionId).toBeUndefined();
    expect(keys.eventIdentifier).toBeUndefined();
    expect(keys.relatedEventIdentifier).toBeUndefined();
  });

  it('reads real-time session and user fields, which are spelled differently from ELF', () => {
    const keys = joinKeysOf({ SessionKey: 's1', LoginKey: 'l1', UserId: '005xx1' });

    expect(keys).toMatchObject({ sessionKey: 's1', loginKey: 'l1', userId: '005xx1' });
  });
});

describe('correlate — following causation', () => {
  it('reaches everything in the same transaction', () => {
    // A guest hits a page; the save it triggers cascades into a trigger and a DML row. None of
    // those carry the client address, and only the transaction ties them to the action.
    const rows = [
      { EVENT_TYPE: 'URI', CLIENT_IP: '203.0.113.50', TRANSACTION_ID: 'txn-1' },
      { EVENT_TYPE: 'ApexTrigger', TRANSACTION_ID: 'txn-1' },
      { EVENT_TYPE: 'ApexExecution', TRANSACTION_ID: 'txn-1', CLIENT_IP: '' },
      { EVENT_TYPE: 'Unrelated', TRANSACTION_ID: 'txn-9' },
    ];

    const result = correlate(rows, [{ type: 'clientIp', value: '203.0.113.50' }], {});

    expect(result.rows).toHaveLength(3);
    expect(result.rows.some((r) => r.row.EVENT_TYPE === 'Unrelated')).toBe(false);
  });

  it('follows a related-event link forward, from a cause to its consequence', () => {
    // evt-2 says it was caused by evt-1. Seeding on the actor finds evt-1; evt-2 is only
    // reachable by jumping from its RelatedEventIdentifier to evt-1's EventIdentifier.
    const rows = [
      { EVENT_TYPE: 'ApiEvent', SourceIp: '203.0.113.50', EventIdentifier: 'evt-1' },
      { EVENT_TYPE: 'ReportEvent', EventIdentifier: 'evt-2', RelatedEventIdentifier: 'evt-1' },
    ];

    const result = correlate(rows, [{ type: 'clientIp', value: '203.0.113.50' }], {});

    expect(result.rows).toHaveLength(2);
    // Attribution names the field on the row that matched, not the field it was matched
    // against. This row is here because its own RelatedEventIdentifier pointed back at the
    // seeded event — which is exactly what a reviewer needs to see to check the link.
    expect(result.rows.find((r) => r.row.EVENT_TYPE === 'ReportEvent')!.attribution).toBe('relatedEventIdentifier');
  });

  it('follows a related-event link backward, from a consequence to its cause', () => {
    // Seeded on the consequence, the cause must still be reachable — an investigator often
    // starts from the damage and works back.
    const rows = [
      { EVENT_TYPE: 'ApiEvent', EventIdentifier: 'evt-1' },
      { EVENT_TYPE: 'ReportEvent', SourceIp: '203.0.113.50', EventIdentifier: 'evt-2', RelatedEventIdentifier: 'evt-1' },
    ];

    const result = correlate(rows, [{ type: 'clientIp', value: '203.0.113.50' }], {});

    expect(result.rows).toHaveLength(2);
    expect(result.rows.find((r) => r.row.EVENT_TYPE === 'ApiEvent')).toBeDefined();
  });

  it('walks a chain of consequences, not just one hop', () => {
    const rows = [
      { EVENT_TYPE: 'Step1', SourceIp: '203.0.113.50', EventIdentifier: 'evt-1' },
      { EVENT_TYPE: 'Step2', EventIdentifier: 'evt-2', RelatedEventIdentifier: 'evt-1' },
      { EVENT_TYPE: 'Step3', EventIdentifier: 'evt-3', RelatedEventIdentifier: 'evt-2' },
    ];

    const result = correlate(rows, [{ type: 'clientIp', value: '203.0.113.50' }], {});

    expect(result.rows).toHaveLength(3);
  });

  it('still refuses a transaction shared by too many actors', () => {
    // The causal keys are subject to the same gate. A transaction id that somehow stands for
    // many actors is not a causal link, it is a bucket.
    const rows = Array.from({ length: 12 }, (_, i) => ({
      EVENT_TYPE: i === 0 ? 'Seeded' : 'Other',
      CLIENT_IP: `203.0.113.${10 + i}`,
      TRANSACTION_ID: 'shared-txn',
    }));

    const result = correlate(rows, [{ type: 'clientIp', value: '203.0.113.10' }], {});

    expect(result.rows).toHaveLength(1);
    expect(result.refusals[0]).toMatchObject({ type: 'transactionId', cardinality: 12 });
  });

  it('does not invent a link from a blank related identifier', () => {
    // Two unrelated events both with a blank RelatedEventIdentifier must not become a chain.
    const rows = [
      { EVENT_TYPE: 'A', SourceIp: '203.0.113.50', EventIdentifier: 'evt-1', RelatedEventIdentifier: '' },
      { EVENT_TYPE: 'B', EventIdentifier: 'evt-9', RelatedEventIdentifier: '' },
    ];

    const result = correlate(rows, [{ type: 'clientIp', value: '203.0.113.50' }], {});

    expect(result.rows).toHaveLength(1);
  });
});
