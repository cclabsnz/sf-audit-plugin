import type { Finding } from './Finding.js';

/**
 * Below this share of checks gathering evidence, a run cannot be graded A: too much of the org
 * went unseen for a clean result to mean the org is clean.
 */
export const MIN_COVERAGE_FOR_A = 90;

export interface EvidenceCoverage {
  /** Checks that ran (produced at least one finding). */
  checksRun: number;
  /** Checks that gathered evidence for at least one of their findings. */
  checksAssessed: number;
  /** checksAssessed / checksRun, as a whole percentage. 100 when nothing ran. */
  percent: number;
  /** Ids of the checks that gathered no evidence at all, sorted. */
  notAssessed: string[];
}

/**
 * How much of the audit actually saw the org. A check counts as not assessed when every finding
 * it produced is inconclusive or marks the check as not run (a crash, or a permission error
 * CheckEngine caught). A check with some evidence and some gaps is assessed: its gaps are already
 * visible as its own inconclusive findings.
 */
export function evidenceCoverage(findings: readonly Finding[]): EvidenceCoverage {
  const byCheck = new Map<string, boolean>();
  for (const f of findings) {
    const id = f.checkId ?? f.id;
    const sawEvidence = !(f.inconclusive || f.notAssessed);
    byCheck.set(id, (byCheck.get(id) ?? false) || sawEvidence);
  }
  const notAssessed = [...byCheck].filter(([, assessed]) => !assessed).map(([id]) => id).sort();
  const checksRun = byCheck.size;
  const checksAssessed = checksRun - notAssessed.length;
  const percent = checksRun === 0 ? 100 : Math.floor((checksAssessed / checksRun) * 100);
  return { checksRun, checksAssessed, percent, notAssessed };
}

/** One line for every output: "Evidence coverage 82% (14 of 17 checks); grade capped at B". */
export function coverageSummary(coverage: EvidenceCoverage & { gradeCapped?: boolean }): string {
  const base = `Evidence coverage ${coverage.percent}% (${coverage.checksAssessed} of ${coverage.checksRun} checks)`;
  return coverage.gradeCapped ? `${base}; grade capped at B, below the ${MIN_COVERAGE_FOR_A}% needed for an A` : base;
}

/**
 * What a reader should do about unassessed checks, or '' when every check gathered evidence.
 * Inconclusive is not one cause: each finding quotes what the org said, and only an access
 * error is fixed by granting permissions.
 */
export function coverageAdvice(coverage: EvidenceCoverage): string {
  if (coverage.notAssessed.length === 0) return '';
  return (
    'Each unassessed check has an inconclusive finding quoting what the org returned. Where the cause is access, ' +
    '`sf audit preflight` lists the permissions the audit user is missing, and PERMISSIONS.md ' +
    '(https://github.com/cclabsnz/sf-audit-plugin/blob/main/PERMISSIONS.md) has the read-only permission set to assign.'
  );
}
