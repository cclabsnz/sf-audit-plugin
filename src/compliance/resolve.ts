import type { ControlDef, Framework, FrameworkPack } from './types.js';
import { CHECK_CONTROL_MAP } from './mapping.js';
import { getControl } from './catalogs/index.js';

const PACKS: Record<FrameworkPack, Framework[]> = {
  universal: ['OWASP', 'SOC2', 'ISO27001'],
  nz: ['ISO27001', 'HISO10029', 'PRIVACY_ACT', 'NZISM'],
  all: ['OWASP', 'SOC2', 'ISO27001', 'SBS', 'HISO10029', 'PRIVACY_ACT', 'NZISM', 'HIPAA', 'GDPR'],
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
