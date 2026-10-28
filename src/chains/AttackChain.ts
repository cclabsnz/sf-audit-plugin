// src/chains/AttackChain.ts
import type { RiskLevel } from '@cclabsnz/sf-core';
import type { Capability } from './Capability.js';

export interface AttackChainStep {
  findingId: string;
  checkId?: string;
  /** The capability this step contributes to the chain. */
  capability: Capability;
  /** The finding grants no capability; `capability` is a fallback and is not rendered (RULE-110). */
  capabilityInferred?: true;
  /** The step belongs to the named chain's break point: fixing all such steps stops the chain (RULE-111). */
  breaksChain?: true;
  /** Verified ATT&CK technique ids for `capability` as this step's finding grants it; absent when inferred (RULE-110, RULE-113). */
  techniques?: string[];
  title?: string;
  severity?: RiskLevel;
}

/** A named chain's abuse case as rendered: roles and plain language, never finding ids (RULE-112). */
export interface AttackChainAbuseCase {
  actor: string;
  goal: string;
  breakPoint: string;
}

export interface AttackChain {
  id: string;
  title: string;
  severity: RiskLevel;
  confidence: 'named' | 'potential';
  narrative: string;
  remediation: string;
  /** Named chains only; potential chains have no proven break point. */
  abuseCase?: AttackChainAbuseCase;
  steps: AttackChainStep[];
}
