import type { RestClient } from '@cclabsnz/sf-core';
import type { StatusField } from './types.js';
import { STATUS_FIELD_PATTERN } from './scoringConfig.js';

// --- Minimal describe shape we depend on ---
export interface DescribePicklistValue {
  value: string;
  label?: string;
  active?: boolean;
}
export interface DescribeField {
  name: string;
  label: string;
  type: string;
  picklistValues?: DescribePicklistValue[];
}
export interface DescribeChildRelationship {
  childSObject: string;
  field: string;
  relationshipName?: string | null;
}
export interface ObjectDescribe {
  name: string;
  label: string;
  custom: boolean;
  fields: DescribeField[];
  childRelationships: DescribeChildRelationship[];
}

export interface ObjectInsight {
  object: string;
  label: string;
  statusField: StatusField | null;
  inboundReferences: number;
}

/** System companion child objects that should not count toward relationship centrality. */
const SYSTEM_CHILD = /(History|Share|Feed|Tag|ChangeEvent|__mdt)$/i;
const SYSTEM_CHILD_EXACT = new Set([
  'AttachedContentDocument', 'CombinedAttachment', 'ContentDocumentLink', 'EmailMessage',
  'Attachment', 'Note', 'NoteAndAttachment', 'ActivityHistory', 'OpenActivity',
  'ProcessInstance', 'ProcessInstanceHistory', 'TopicAssignment', 'EntitySubscription',
  'RecordAction', 'FlowRecordRelation', 'DuplicateRecordItem',
]);

/** Lifecycle-ish tokens used to infer a status field when the name doesn't match. */
const LIFECYCLE_TOKENS = [
  'new', 'open', 'draft', 'pending', 'in progress', 'working', 'active', 'approved',
  'rejected', 'closed', 'done', 'complete', 'completed', 'cancelled', 'canceled',
  'escalated', 'resolved', 'won', 'lost', 'qualified',
];

export async function fetchObjectDescribe(rest: RestClient, object: string): Promise<ObjectDescribe | null> {
  try {
    return await rest.get<ObjectDescribe>(`/sobjects/${object}/describe/`);
  } catch {
    return null;
  }
}

/** Pure extraction from a describe — used directly in tests. */
export function extractInsight(describe: ObjectDescribe): ObjectInsight {
  return {
    object: describe.name,
    label: describe.label,
    statusField: detectStatusField(describe.fields),
    inboundReferences: countInbound(describe.childRelationships),
  };
}

export function detectStatusField(fields: DescribeField[]): StatusField | null {
  const picklists = fields.filter((f) => f.type === 'picklist' && (f.picklistValues?.length ?? 0) > 0);

  // 1) Name match wins.
  const named = picklists.find((f) => STATUS_FIELD_PATTERN.test(f.name));
  if (named) return toStatusField(named, true);

  // 2) Otherwise infer from a value set that reads as an ordered lifecycle.
  let best: DescribeField | null = null;
  let bestScore = 0;
  for (const f of picklists) {
    const values = activeValues(f);
    const hits = values.filter((v) => LIFECYCLE_TOKENS.includes(v.toLowerCase())).length;
    if (hits >= 2 && hits > bestScore) {
      best = f;
      bestScore = hits;
    }
  }
  return best ? toStatusField(best, false) : null;
}

function toStatusField(f: DescribeField, matchedByName: boolean): StatusField {
  return { field: f.name, label: f.label, values: activeValues(f), matchedByName };
}

function activeValues(f: DescribeField): string[] {
  return (f.picklistValues ?? []).filter((p) => p.active !== false).map((p) => p.value);
}

function countInbound(children: DescribeChildRelationship[]): number {
  const distinct = new Set<string>();
  for (const c of children) {
    const child = c.childSObject;
    if (!child) continue;
    if (SYSTEM_CHILD.test(child) || SYSTEM_CHILD_EXACT.has(child)) continue;
    distinct.add(child);
  }
  return distinct.size;
}
