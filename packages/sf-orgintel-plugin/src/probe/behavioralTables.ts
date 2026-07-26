import type { SoqlClient } from '@cclabsnz/sf-core';
import type { BehavioralTable, BehavioralTablesCoverage } from './types.js';
import { countRows, classifyQueryError } from './query.js';
import { unique } from './util.js';

/** 12-month window on CreatedDate — present on all these tables. */
const WINDOW_12MO = 'CreatedDate = LAST_N_DAYS:365';

/** Behavioral tables present in every edition, independent of Event Monitoring. */
const CORE_TABLES: readonly string[] = [
  'OpportunityFieldHistory',
  'CaseHistory',
  'ProcessInstance',
  'ProcessInstanceStep',
  'FlowInterview',
  'AsyncApexJob',
  'SetupAuditTrail',
];

export async function probeBehavioralTables(
  soql: SoqlClient,
  extraHistoryTables: string[] = [],
): Promise<BehavioralTablesCoverage> {
  const names = unique([...CORE_TABLES, ...extraHistoryTables]);
  const tables: BehavioralTable[] = [];
  for (const name of names) {
    tables.push(await probeOne(soql, name));
  }
  return { tables };
}

async function probeOne(soql: SoqlClient, name: string): Promise<BehavioralTable> {
  try {
    const rowCount12mo = await countRows(soql, name, WINDOW_12MO);
    const table: BehavioralTable = { name, access: 'ok', rowCount12mo };
    if (name === 'FlowInterview') {
      const extra = await flowInterviewExtras(soql);
      if (Object.keys(extra).length > 0) table.extra = extra;
    }
    return table;
  } catch (err) {
    const reason = classifyQueryError(err);
    return {
      name,
      access: reason === 'not-present' ? 'not-present' : 'no-access',
      rowCount12mo: null,
      note:
        reason === 'not-present'
          ? 'Table not present on this org/edition.'
          : reason === 'no-access'
            ? 'Table exists but is not readable by the running user.'
            : 'Table could not be queried.',
    };
  }
}

/** Current paused/errored interview counts — a snapshot of stuck/failed automation. */
async function flowInterviewExtras(soql: SoqlClient): Promise<Record<string, number>> {
  const extra: Record<string, number> = {};
  for (const [key, status] of [
    ['paused', 'Paused'],
    ['error', 'Error'],
  ] as const) {
    try {
      extra[key] = await countRows(soql, 'FlowInterview', `InterviewStatus = '${status}'`);
    } catch {
      // Some statuses (e.g. Error) may not be a valid picklist value on every org; skip.
    }
  }
  return extra;
}
