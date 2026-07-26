import type { CouplingOperation, CouplingConfidence } from '@cclabsnz/sf-core';

export type { CouplingOperation, CouplingConfidence };

export interface ComponentRef {
  type: 'Flow' | 'ApexClass' | 'ApexTrigger';
  name: string;
  confidence: CouplingConfidence;
  namespace?: string | null;
}

/** An un-aggregated coupling contribution between two objects from a single component. */
export interface RawEdge {
  a: string;
  b: string;
  operations: CouplingOperation[];
  component: ComponentRef;
}
