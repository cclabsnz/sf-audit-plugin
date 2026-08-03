// src/chains/ChainEngine.ts
import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '@cclabsnz/sf-core';
import type { AttackChain, AttackChainStep } from './AttackChain.js';
import type { Capability } from './Capability.js';
import { SOURCE_CAPS, HIGH_IMPACT_SINKS } from './Capability.js';
import { capabilitiesFor } from './CapabilityRegistry.js';
import { NAMED_CHAINS } from './namedChains.js';

const SEVERITY_ORDER: Record<RiskLevel, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

/** Potential-chain severity by terminal sink (capped at HIGH — named chains own CRITICAL). */
const SINK_SEVERITY: Partial<Record<Capability, RiskLevel>> = {
  'org-takeover': 'HIGH',
  'data-write': 'HIGH',
  'data-read-bulk': 'HIGH',
  'credential-theft': 'MEDIUM',
};

const MAX_STEPS = 4;

export class ChainEngine {
  correlate(findings: Finding[]): AttackChain[] {
    const active = findings.filter((f) => !f.passed && !f.inconclusive);

    // Build present capability set + per-finding grants.
    const present = new Set<Capability>();
    const grantsByFinding = new Map<Finding, Capability[]>();
    for (const f of active) {
      const grants = capabilitiesFor(f).grants;
      grantsByFinding.set(f, grants);
      for (const c of grants) present.add(c);
    }

    const namedChains = this.runNamedPass(present, active, grantsByFinding);
    const covered = this.coveredSourceSinkPairs(namedChains, grantsByFinding);
    const potentialChains = this.runEmergentPass(present, active, grantsByFinding, covered);

    return [...namedChains, ...potentialChains].sort(
      (a, b) => this.rank(a) - this.rank(b),
    );
  }

  private rank(c: AttackChain): number {
    // named before potential, then by severity
    return (c.confidence === 'named' ? 0 : 100) + SEVERITY_ORDER[c.severity];
  }

  private stepFor(f: Finding, grants: Capability[]): AttackChainStep {
    return {
      findingId: f.id,
      checkId: f.checkId,
      capability: grants[0] ?? 'data-read',
      title: f.title,
      severity: f.riskLevel,
    };
  }

  private runNamedPass(
    present: Set<Capability>,
    active: Finding[],
    grantsByFinding: Map<Finding, Capability[]>,
  ): AttackChain[] {
    const out: AttackChain[] = [];
    for (const def of NAMED_CHAINS) {
      const members = def.match(present, active);
      if (!members || members.length === 0) continue;
      out.push({
        id: def.id,
        title: def.title,
        severity: def.severity,
        confidence: 'named',
        narrative: def.narrative,
        remediation: def.remediation,
        steps: members.map((f) => this.stepFor(f, grantsByFinding.get(f) ?? [])),
      });
    }
    return out;
  }

  /** Record which (source, sink) capability pairs are already explained by a named chain. */
  private coveredSourceSinkPairs(
    named: AttackChain[],
    grantsByFinding: Map<Finding, Capability[]>,
  ): Set<string> {
    const covered = new Set<string>();
    for (const chain of named) {
      const caps = new Set<Capability>();
      for (const s of chain.steps) caps.add(s.capability);
      for (const src of SOURCE_CAPS) {
        for (const sink of HIGH_IMPACT_SINKS) {
          if (caps.has(src) && caps.has(sink)) covered.add(`${src}->${sink}`);
        }
      }
    }
    // Also use the raw grants of member findings (capability per step is only the first grant).
    for (const chain of named) {
      const memberCaps = new Set<Capability>();
      for (const s of chain.steps) {
        const f = [...grantsByFinding.keys()].find((k) => k.id === s.findingId);
        if (f) for (const c of grantsByFinding.get(f) ?? []) memberCaps.add(c);
      }
      for (const src of SOURCE_CAPS) {
        for (const sink of HIGH_IMPACT_SINKS) {
          if (memberCaps.has(src) && memberCaps.has(sink)) covered.add(`${src}->${sink}`);
        }
      }
    }
    return covered;
  }

  private runEmergentPass(
    present: Set<Capability>,
    active: Finding[],
    grantsByFinding: Map<Finding, Capability[]>,
    covered: Set<string>,
  ): AttackChain[] {
    const out: AttackChain[] = [];
    const seen = new Set<string>();

    for (const src of SOURCE_CAPS) {
      if (!present.has(src)) continue;
      for (const sink of HIGH_IMPACT_SINKS) {
        if (!present.has(sink)) continue;
        const key = `${src}->${sink}`;
        if (covered.has(key) || seen.has(key)) continue;
        seen.add(key);

        // Gather the findings that grant the source and the sink (+ any code-exec bridge).
        const members: Finding[] = [];
        for (const f of active) {
          const g = grantsByFinding.get(f) ?? [];
          if (g.includes(src) || g.includes(sink) || g.includes('code-exec')) members.push(f);
          if (members.length >= MAX_STEPS) break;
        }
        if (members.length === 0) continue;

        out.push({
          id: `potential-${src}-${sink}`,
          title: `Potential attack path: ${this.label(src)} → ${this.label(sink)}`,
          severity: SINK_SEVERITY[sink] ?? 'MEDIUM',
          confidence: 'potential',
          narrative:
            `The org presents a ${this.label(src)} entry point and findings that grant ` +
            `${this.label(sink)}. Review whether these can be combined into an exploit path.`,
          remediation:
            'Treat the contributing findings as a single risk: remediating any one of them breaks the path.',
          steps: members.map((f) => this.stepFor(f, grantsByFinding.get(f) ?? [])),
        });
      }
    }
    return out;
  }

  private label(c: Capability): string {
    return c.replace(/-/g, ' ');
  }
}
