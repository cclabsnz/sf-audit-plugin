// src/chains/AttackChain.ts
import type { RiskLevel } from '../findings/RiskLevel.js';
import type { Capability } from './Capability.js';

export interface AttackChainStep {
  findingId: string;
  checkId?: string;
  /** The capability this step contributes to the chain. */
  capability: Capability;
  title?: string;
  severity?: RiskLevel;
}

export interface AttackChain {
  id: string;
  title: string;
  severity: RiskLevel;
  confidence: 'named' | 'potential';
  narrative: string;
  remediation: string;
  steps: AttackChainStep[];
}
