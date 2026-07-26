import type { AnchorCandidate, AnchorSignals } from './types.js';
import { type DiscoverWeights, VELOCITY_SHARE } from './scoringConfig.js';

export interface RawCandidate {
  object: string;
  label: string;
  custom: boolean;
  signals: AnchorSignals;
}

/**
 * Combine the six signals into a transparent weighted score. Each signal is min-max
 * normalised to [0,1] across the analysed objects, multiplied by its weight, and summed.
 * Deterministic: ties break on object name so the ordering is stable for a given org.
 */
export function scoreAnchors(cands: RawCandidate[], w: DiscoverWeights): AnchorCandidate[] {
  const maxAuto = maxOf(cands, (c) => c.signals.automation.total);
  const maxTotal = maxOf(cands, (c) => c.signals.totalRecords ?? 0);
  const maxVel = maxOf(cands, (c) => c.signals.created90d ?? 0);
  const maxIn = maxOf(cands, (c) => c.signals.inboundReferences);
  const maxAct = maxOf(cands, (c) => c.signals.activityAttach ?? 0);

  const scored = cands.map((c): AnchorCandidate => {
    const s = c.signals;
    const autoN = norm(s.automation.total, maxAuto);
    const statusN = s.statusField ? 1 : 0;
    const volN = VELOCITY_SHARE * norm(s.created90d ?? 0, maxVel) + (1 - VELOCITY_SHARE) * norm(s.totalRecords ?? 0, maxTotal);
    const centN = norm(s.inboundReferences, maxIn);
    const actN = norm(s.activityAttach ?? 0, maxAct);
    const histN = s.historyTracking ? 1 : 0;

    const contributions: Record<string, number> = {
      automation: round(autoN * w.automation),
      statusShaped: round(statusN * w.statusShaped),
      volumeVelocity: round(volN * w.volumeVelocity),
      centrality: round(centN * w.centrality),
      activity: round(actN * w.activity),
      history: round(histN * w.history),
    };
    const score = round(Object.values(contributions).reduce((a, b) => a + b, 0));
    return { object: c.object, label: c.label, custom: c.custom, score, contributions, signals: s, evidence: buildEvidence(c) };
  });

  scored.sort((a, b) => b.score - a.score || a.object.localeCompare(b.object));
  return scored;
}

function buildEvidence(c: RawCandidate): string[] {
  const s = c.signals;
  const lines: string[] = [];
  if (s.automation.total > 0) {
    lines.push(
      `${s.automation.total} automation(s): ${s.automation.flows} flow, ${s.automation.triggers} trigger, ${s.automation.approvals} approval, ${s.automation.workflowRules} workflow`,
    );
  }
  if (s.statusField) {
    const v = s.statusField.values;
    const shown = v.slice(0, 6).join(' → ') + (v.length > 6 ? ' → …' : '');
    lines.push(`${s.statusField.matchedByName ? 'Status' : 'Lifecycle'} field ${s.statusField.field} [${shown}]`);
  }
  if (s.created90d != null) {
    lines.push(`${fmt(s.created90d)} created/90d${s.totalRecords != null ? ` of ${fmt(s.totalRecords)} total` : ''}`);
  }
  if (s.inboundReferences > 0) lines.push(`${s.inboundReferences} inbound lookup(s)`);
  if (s.activityAttach != null) lines.push(`${fmt(s.activityAttach)} activities/90d (approx)`);
  if (s.historyTracking) lines.push('history tracking on');
  return lines;
}

function maxOf(cands: RawCandidate[], pick: (c: RawCandidate) => number): number {
  return cands.reduce((m, c) => Math.max(m, pick(c)), 0);
}

function norm(v: number, max: number): number {
  return max > 0 ? v / max : 0;
}

function round(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function fmt(n: number): string {
  return n.toLocaleString('en-US');
}
