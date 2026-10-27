import type { Finding } from '../findings/Finding.js';
import { CHECK_STRIDE_MAP } from './stride.js';
import { CHECK_LINDDUN_MAP } from './linddun.js';
import {
  LINDDUN_CATEGORIES, LINDDUN_NAMES, STRIDE_CATEGORIES, STRIDE_NAMES,
  type LinddunCategory, type StrideCategory,
} from './types.js';

export type ThreatRowStatus = 'findings' | 'no-findings' | 'not-assessed-in-run' | 'not-covered';

export interface ThreatRow<C extends string> {
  category: C;
  name: string;
  /** Active findings in this category: not passed, inconclusive, not assessed or waived. */
  findings: Finding[];
  /** Checks in this run whose map entry names the category. */
  coveringChecks: number;
  /** Of those, the checks that gathered evidence. */
  assessedChecks: number;
  status: ThreatRowStatus;
}

export interface ThreatView {
  stride: ThreatRow<StrideCategory>[];
  /** Present only when a privacy-tagged check ran. */
  linddun?: ThreatRow<LinddunCategory>[];
  /** Findings that are a repudiation gap and also log personal data once fixed (RULE-103). */
  dualReadings: Finding[];
}

export const PRIVACY_COST_OF_LOGGING =
  'The logging this fix adds records personal data: decide what it captures, how long it is kept and who can read it.';

const isActive = (f: Finding): boolean => !f.passed && !f.inconclusive && !f.notAssessed && !f.waived;

/** The threat view (RULE-104): coverage per category, never a pass. */
export function buildThreatView(findings: readonly Finding[]): ThreatView {
  const assessed = new Map<string, boolean>();
  for (const f of findings) {
    const id = f.checkId ?? f.id;
    assessed.set(id, (assessed.get(id) ?? false) || !(f.inconclusive || f.notAssessed));
  }
  const active = findings.filter(isActive);

  function rows<C extends string>(
    categories: readonly C[],
    names: Record<C, string>,
    map: Record<string, C[]>,
    of: (f: Finding) => C[] | undefined,
  ): ThreatRow<C>[] {
    return categories.map((category) => {
      const covering = [...assessed.keys()].filter((id) => map[id]?.includes(category));
      const assessedChecks = covering.filter((id) => assessed.get(id)).length;
      const inCategory = active.filter((f) => of(f)?.includes(category));
      const status: ThreatRowStatus =
        inCategory.length > 0 ? 'findings'
          : assessedChecks > 0 ? 'no-findings'
            : covering.length > 0 ? 'not-assessed-in-run'
              : 'not-covered';
      return { category, name: names[category], findings: inCategory, coveringChecks: covering.length, assessedChecks, status };
    });
  }

  const view: ThreatView = {
    stride: rows(STRIDE_CATEGORIES, STRIDE_NAMES, CHECK_STRIDE_MAP, (f) => f.threats?.stride),
    dualReadings: active.filter((f) => {
      const linddun = CHECK_LINDDUN_MAP[f.checkId ?? f.id] ?? [];
      return (f.threats?.stride ?? []).includes('R') && (linddun.includes('Nr') || linddun.includes('D'));
    }),
  };
  if ([...assessed.keys()].some((id) => CHECK_LINDDUN_MAP[id])) {
    view.linddun = rows(LINDDUN_CATEGORIES, LINDDUN_NAMES, CHECK_LINDDUN_MAP, (f) => f.threats?.linddun);
  }
  return view;
}

/** How a row reads in every output. Never "pass", "compliant" or "no threats". */
export function threatRowStatusText(row: ThreatRow<string>): string {
  switch (row.status) {
    case 'findings':
      return `${row.findings.length} finding${row.findings.length === 1 ? '' : 's'}`;
    case 'no-findings':
      return `no findings from ${row.assessedChecks} check${row.assessedChecks === 1 ? '' : 's'}`;
    case 'not-assessed-in-run':
      return 'not assessed in this run';
    case 'not-covered':
      return 'not assessed by this tool';
  }
}
