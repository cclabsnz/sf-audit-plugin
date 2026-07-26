import { parseXml, type XmlValue, type XmlObject } from './xml.js';
import type { FlowSummary, FlowRecordRef, FlowInitiator } from './flowTypes.js';

/** Parse Flow metadata XML into a FlowSummary. `apiName` is the flow's FullName. */
export function parseFlowXml(xml: string, apiName: string): FlowSummary {
  const doc = parseXml(xml);
  const flow = doc.Flow;
  if (!flow || typeof flow !== 'object' || Array.isArray(flow)) {
    throw new Error('XML root is not a <Flow> element');
  }
  return summarizeFlow(flow, apiName);
}

/**
 * Build a FlowSummary from a parsed flow object. Accepts either XML-parsed output or the
 * equivalent structured Metadata returned by the Tooling API `Flow.Metadata` field — both
 * share element names; single vs. repeated elements are normalised to arrays.
 */
export function summarizeFlow(flow: XmlObject, apiName: string): FlowSummary {
  const start = asObject(flow.start);
  const startConfig = {
    triggerType: str(start.triggerType),
    triggerObject: str(start.object),
    recordTriggerType: str(start.recordTriggerType),
  };

  const recordLookups = records(flow.recordLookups);
  const recordCreates = records(flow.recordCreates);
  const recordUpdates = records(flow.recordUpdates);
  const recordDeletes = records(flow.recordDeletes);

  const actionCalls = toArray(flow.actionCalls)
    .map(asObject)
    .filter((a) => (str(a.actionType) ?? '').toLowerCase() === 'apex')
    .map((a) => str(a.actionName))
    .filter((n): n is string => !!n);

  const subflows = toArray(flow.subflows)
    .map(asObject)
    .map((s) => str(s.flowName))
    .filter((n): n is string => !!n);

  const processType = str(flow.processType) ?? 'Flow';

  return {
    apiName,
    label: str(flow.label) ?? apiName,
    apiVersion: str(flow.apiVersion),
    processType,
    status: str(flow.status) ?? 'Active',
    namespace: namespaceOf(apiName),
    start: startConfig,
    initiator: deriveInitiator(processType, startConfig.triggerObject, flow),
    recordLookups,
    recordCreates,
    recordUpdates,
    recordDeletes,
    actionCalls,
    subflows,
    screenCount: toArray(flow.screens).length,
    decisionCount: toArray(flow.decisions).length,
    loopCount: toArray(flow.loops).length,
  };
}

function deriveInitiator(processType: string, triggerObject: string | null, flow: XmlObject): FlowInitiator {
  if (triggerObject) return 'record-trigger';
  const isScreen = processType.toLowerCase() === 'flow' || toArray(flow.screens).length > 0;
  return isScreen ? 'human' : 'invocable';
}

function records(v: XmlValue | XmlValue[] | undefined): FlowRecordRef[] {
  return toArray(v)
    .map(asObject)
    .map((e) => ({ name: str(e.name) ?? '', object: str(e.object) ?? '' }))
    .filter((r) => r.object.length > 0);
}

// --- helpers ---
function toArray(v: XmlValue | XmlValue[] | undefined): XmlValue[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function asObject(v: XmlValue | XmlValue[] | undefined): XmlObject {
  return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
}

function str(v: XmlValue | XmlValue[] | undefined): string | null {
  if (typeof v === 'string') return v.length > 0 ? v : null;
  return null;
}

/** Managed-namespace prefix from a FullName (`ns__Flow_Name` -> `ns`), else null. */
export function namespaceOf(apiName: string): string | null {
  const idx = apiName.indexOf('__');
  if (idx <= 0) return null;
  const prefix = apiName.slice(0, idx);
  // A namespace prefix is a single token with no further separators.
  return /^[A-Za-z][A-Za-z0-9]*$/.test(prefix) ? prefix : null;
}
