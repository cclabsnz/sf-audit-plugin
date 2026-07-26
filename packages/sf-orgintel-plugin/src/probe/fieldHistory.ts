import type { SoqlClient } from '@cclabsnz/sf-core';
import type { FieldHistoryCoverage, ObjectHistoryCoverage } from './types.js';
import {
  type SObjectCatalog,
  KEY_STANDARD_OBJECTS,
  historyObjectName,
  customBusinessObjects,
} from './sobjectCatalog.js';
import { unique } from './util.js';

/** Standard field-history tracking cap. */
const HISTORY_FIELD_CAP = 20;
/** Bound on custom objects inspected, to keep output and query volume sane on large orgs. */
const MAX_CUSTOM_OBJECTS = 300;

export async function probeFieldHistory(
  soql: SoqlClient,
  catalog: SObjectCatalog,
): Promise<FieldHistoryCoverage> {
  const customs = customBusinessObjects(catalog);
  const inspectedCustoms = customs.slice(0, MAX_CUSTOM_OBJECTS);
  const droppedCustoms = customs.length - inspectedCustoms.length;

  const targets: Array<{ object: string; custom: boolean }> = [
    ...KEY_STANDARD_OBJECTS.filter((o) => catalog.has(o)).map((o) => ({ object: o, custom: false })),
    ...inspectedCustoms.map((s) => ({ object: s.name, custom: true })),
  ];

  const objects: ObjectHistoryCoverage[] = [];
  for (const t of targets) {
    const histName = historyObjectName(t.object, t.custom);
    const enabled = catalog.has(histName) && catalog.isQueryable(histName);
    const cov: ObjectHistoryCoverage = {
      object: t.object,
      custom: t.custom,
      historyTrackingEnabled: enabled,
      trackedFieldCount: enabled ? 0 : null,
      trackedFields: [],
      atCap: false,
    };
    if (enabled) {
      const fields = await observedTrackedFields(soql, histName);
      if (fields) {
        cov.trackedFields = fields;
        cov.trackedFieldCount = fields.length;
        cov.atCap = fields.length >= HISTORY_FIELD_CAP;
        cov.note = 'Tracked-field list is fields with recorded changes in the last 12 months (approximate lower bound).';
      } else {
        cov.trackedFieldCount = null;
        cov.note = 'History tracking is enabled; tracked-field enumeration was not permitted.';
      }
    }
    objects.push(cov);
  }

  const fieldAuditTrail = catalog.has('FieldHistoryArchive') && catalog.isQueryable('FieldHistoryArchive');
  const trackedObjectCount = objects.filter((o) => o.historyTrackingEnabled).length;

  let note = fieldAuditTrail
    ? 'Field Audit Trail (FieldHistoryArchive) is present — history is retained beyond the standard window.'
    : 'Field Audit Trail (Shield) not detected; standard field history retention applies.';
  if (droppedCustoms > 0) {
    note += ` Inspected ${MAX_CUSTOM_OBJECTS} of ${customs.length} custom objects; ${droppedCustoms} not shown.`;
  }

  return { objects, trackedObjectCount, fieldAuditTrail, note };
}

/**
 * Fields with recorded history changes on a history table over the last 12 months. Returns
 * null if the aggregate query is not permitted (caller degrades to "count unavailable").
 */
async function observedTrackedFields(soql: SoqlClient, historyTable: string): Promise<string[] | null> {
  try {
    const result = await soql.query<{ Field: string }>(
      `SELECT Field FROM ${historyTable} WHERE CreatedDate = LAST_N_DAYS:365 GROUP BY Field LIMIT 100`,
    );
    return unique(result.records.map((r) => r.Field).filter(Boolean)).sort();
  } catch {
    return null;
  }
}
