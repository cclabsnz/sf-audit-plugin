export type FlowOperation = 'read' | 'create' | 'update' | 'delete';

export interface FlowRecordRef {
  /** Element name within the flow (for traceability). */
  name: string;
  /** Target sObject API name. */
  object: string;
}

export interface FlowStartConfig {
  triggerType: string | null;
  triggerObject: string | null;
  recordTriggerType: string | null;
}

export type FlowInitiator = 'record-trigger' | 'human' | 'invocable';

export interface FlowSummary {
  apiName: string;
  label: string;
  apiVersion: string | null;
  processType: string;
  status: string;
  namespace: string | null;
  start: FlowStartConfig;
  initiator: FlowInitiator;
  recordLookups: FlowRecordRef[];
  recordCreates: FlowRecordRef[];
  recordUpdates: FlowRecordRef[];
  recordDeletes: FlowRecordRef[];
  /** Apex classes invoked via actionCalls (actionType = apex). */
  actionCalls: string[];
  /** apiNames of referenced subflows. */
  subflows: string[];
  screenCount: number;
  decisionCount: number;
  loopCount: number;
}
