import type { CouplingOperation } from '../types.js';

export interface SymbolTableLike {
  externalReferences?: Array<{ name?: string | null }> | null;
  [k: string]: unknown;
}

export interface ApexClassInput {
  name: string;
  namespace: string | null;
  body: string | null;
  symbolTable: SymbolTableLike | null;
}

export interface ApexTriggerInput {
  name: string;
  namespace: string | null;
  /** Source object (resolved from TableEnumOrId). */
  object: string;
  body: string | null;
  symbolTable: SymbolTableLike | null;
}

export interface ApexAnalysis {
  objects: Map<string, Set<CouplingOperation>>;
  confidence: 'high' | 'approximate';
}
