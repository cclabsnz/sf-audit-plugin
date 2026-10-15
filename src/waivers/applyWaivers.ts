import type { Finding } from '../findings/Finding.js';
import type { EvaluatedWaiver } from './WaiverModel.js';
import type { WaiverLoader } from './WaiverLoader.js';

export interface ApplyWaiversResult {
  findings: Finding[];
  waivedFindings: Finding[];
  activeWaiverCount: number;
  expiredWaiverCount: number;
  /** Waivers that matched a CRITICAL finding without acknowledgeCritical, and so were not applied. */
  unacknowledgedCriticalCount: number;
}

type Outcome = 'waived' | 'expired' | 'critical-unacknowledged';

/**
 * Marks findings covered by an approved, unexpired waiver as `waived`, which removes them from the
 * score and from --fail-on. A finding with affected items is waived only when every item is
 * covered; otherwise each covered item is annotated and the finding stays active. A finding with
 * no affected items is matched by its own id.
 *
 * A CRITICAL finding is waived only when the waiver sets acknowledgeCritical, so accepting the
 * most severe risks is always a deliberate, visible choice. Waived findings still take part in
 * attack-chain correlation: accepting one weakness does not accept the path it forms with others.
 */
export function applyWaivers(findings: Finding[], loader: WaiverLoader): ApplyWaiversResult {
  const result: ApplyWaiversResult = {
    findings,
    waivedFindings: [],
    activeWaiverCount: 0,
    expiredWaiverCount: 0,
    unacknowledgedCriticalCount: 0,
  };
  if (loader.waivers.length === 0) return result;

  const outcome = (f: Finding, w: EvaluatedWaiver): Outcome => {
    if (w.isExpired) return 'expired';
    if (f.riskLevel === 'CRITICAL' && w.acknowledgeCritical !== true) return 'critical-unacknowledged';
    return 'waived';
  };
  const count = (o: Outcome): void => {
    if (o === 'waived') result.activeWaiverCount++;
    else if (o === 'expired') result.expiredWaiverCount++;
    else result.unacknowledgedCriticalCount++;
  };
  const tag = (o: Outcome, w: EvaluatedWaiver): string =>
    o === 'waived'
      ? `[WAIVED: ${w.reason} (approved by ${w.approvedBy}, expires ${w.expiresAt})]`
      : o === 'expired'
        ? `[WAIVER EXPIRED] (expired ${w.expiresAt})`
        : '[WAIVER NOT APPLIED: CRITICAL findings need acknowledgeCritical]';

  const processed: Finding[] = [];
  for (const f of findings) {
    if (f.passed || f.inconclusive) {
      processed.push(f);
      continue;
    }
    const checkId = f.checkId ?? '';

    if (f.affectedItems && f.affectedItems.length > 0) {
      let waivedItems = 0;
      const items = f.affectedItems.map((item) => {
        const w = loader.findMatchingWaiver(checkId, f.id, item.label);
        if (!w) return item;
        const o = outcome(f, w);
        count(o);
        if (o === 'waived') waivedItems++;
        return { ...item, note: item.note ? `${tag(o, w)} ${item.note}` : tag(o, w) };
      });
      const updated: Finding = { ...f, affectedItems: items };
      if (waivedItems === f.affectedItems.length) {
        updated.waived = true;
        result.waivedFindings.push(updated);
      }
      processed.push(updated);
      continue;
    }

    const w = loader.findMatchingWaiver(checkId, f.id, f.id);
    if (!w) {
      processed.push(f);
      continue;
    }
    const o = outcome(f, w);
    count(o);
    const updated: Finding = { ...f, detail: `${tag(o, w)} ${f.detail}` };
    if (o === 'waived') {
      updated.waived = true;
      result.waivedFindings.push(updated);
    }
    processed.push(updated);
  }

  result.findings = processed;
  return result;
}
