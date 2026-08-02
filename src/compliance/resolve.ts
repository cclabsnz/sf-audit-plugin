import type { ControlDef, Framework, FrameworkPack } from './types.js';
import { CHECK_CONTROL_MAP } from './mapping.js';
import { getControl } from './catalogs/index.js';

const PACKS: Record<FrameworkPack, Framework[]> = {
  universal: ['OWASP', 'OWASP_LLM', 'SOC2', 'ISO27001'],
  nz: ['ISO27001', 'HISO10029', 'PRIVACY_ACT', 'NZISM'],
  all: ['OWASP', 'OWASP_LLM', 'SOC2', 'ISO27001', 'SBS', 'HISO10029', 'PRIVACY_ACT', 'NZISM', 'HIPAA', 'GDPR'],
};

export function packFrameworks(pack: FrameworkPack): Framework[] {
  return PACKS[pack];
}

export interface ResolveOptions {
  frameworks?: Framework[];   // when omitted, all frameworks the check maps to
  requireVerified?: boolean;  // default true — provenance gate
}

export function resolveControls(checkId: string, opts: ResolveOptions = {}): ControlDef[] {
  const requireVerified = opts.requireVerified ?? true;
  const ids = CHECK_CONTROL_MAP[checkId] ?? [];
  const out: ControlDef[] = [];
  for (const id of ids) {
    const c = getControl(id);
    if (!c) continue;
    if (opts.frameworks && !opts.frameworks.includes(c.framework)) continue;
    if (requireVerified && !c.verified) continue;
    out.push(c);
  }
  return out;
}

/** Backward-compatible: the bare id strings, as the old ComplianceMapping returned. */
export function getComplianceTags(checkId: string): string[] {
  return CHECK_CONTROL_MAP[checkId] ?? [];
}

const ALIAS: Record<string, Framework> = {
  owasp: 'OWASP', 'owasp-llm': 'OWASP_LLM', llm: 'OWASP_LLM',
  soc2: 'SOC2', iso: 'ISO27001', iso27001: 'ISO27001', sbs: 'SBS',
  privacy: 'PRIVACY_ACT', 'privacy-act': 'PRIVACY_ACT', hiso: 'HISO10029', nzism: 'NZISM',
  hipaa: 'HIPAA', gdpr: 'GDPR',
};

/** Resolve a --frameworks value: a pack name (universal|nz|all) or a comma list of aliases. */
export function resolveFrameworks(input: string): Framework[] {
  const v = input.trim().toLowerCase();
  if (v === 'universal' || v === 'nz' || v === 'all') return packFrameworks(v);
  const out: Framework[] = [];
  for (const part of v.split(',').map((s) => s.trim())) {
    const fw = ALIAS[part];
    if (fw && !out.includes(fw)) out.push(fw);
  }
  return out;
}
