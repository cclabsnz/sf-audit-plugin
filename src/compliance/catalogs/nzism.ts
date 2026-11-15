import type { ControlDef } from '../types.js';
import { NZISM_SECTIONS, NZISM_SOURCE } from '../nz/citations.generated.js';

// New Zealand Information Security Manual (NZISM), GCSB/NCSC. Section-level controls: each one is
// an NZISM section (e.g. 16.7 Multi-Factor Authentication) that at least one check cites, and its
// citation lists the individual controls the Secure Controls Framework 2026.3 crosswalk maps there,
// with each control's compliance level from the manual. Which checks cite a section comes from
// scripts/compliance/derive_nz_citations.py. `verified` = the section and every listed control
// exist in the pinned manual version, which test/unit/compliance/nzCrosswalk.test.ts checks.
const V = `NZISM v${NZISM_SOURCE.version}`;

const level = (l: string): string => l.toUpperCase();

export const NZISM_CONTROLS: ControlDef[] = Object.entries(NZISM_SECTIONS).map(([section, s]) => ({
  id: `NZISM-${section}`, framework: 'NZISM', version: V, title: `${section} ${s.title}`,
  requirement: s.controls.length
    ? `Controls in section ${section} that the Secure Controls Framework maps to the checks citing it: `
      + s.controls.map((c) => `${c.id} (${level(c.level)})`).join(', ')
    : `Section ${section} as a whole (cited directly by sf-audit; no SCF crosswalk entry).`,
  sourceRef: `${V}, ${section} ${s.title}`,
  url: NZISM_SOURCE.url, verified: true,
}));
