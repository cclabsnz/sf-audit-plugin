import type { ControlDef } from '../types.js';
import {
  CHECK_NZ_CITATIONS, HISO_SOURCES, HML_REQUIREMENTS, HSUP_REQUIREMENTS,
} from '../nz/citations.generated.js';

// HISO 10029 Health Information Security Framework (HISF), Health NZ | Te Whatu Ora. HISF is built
// on the NIST Cybersecurity Framework (core document s3); ISO/IEC 27002 is one of the catalogues it
// maps to. Two parts are cited, because which applies depends on who owns the org:
//   HISO 10029.3:2023, medium to large health organisations (HML requirements)
//   HISO 10029.4:2025, suppliers to the health sector (HSUP requirements)
// Each control is one published requirement, with its statement taken verbatim from the PDF
// (CC BY 4.0). Which checks cite it comes from scripts/compliance/derive_nz_citations.py.
// `verified` = the requirement id and statement exist in the pinned PDF, which
// test/unit/compliance/nzCrosswalk.test.ts checks against data/compliance/nz-sources.json.
const cited = (key: 'hsup' | 'hml'): Set<string> =>
  new Set(Object.values(CHECK_NZ_CITATIONS).flatMap((c) => c[key].map((x) => (typeof x === 'string' ? x : x.id))));

function build(
  framework: 'HISO10029_3' | 'HISO10029_4', part: 'hiso3' | 'hiso4', version: string,
  reqs: Record<string, { area: string; statement: string }>, ids: Set<string>,
): ControlDef[] {
  return Object.entries(reqs)
    .filter(([id]) => ids.has(id))
    .map(([id, r]) => ({
      id: `HISO-${id}`, framework, version, title: `${id} ${r.area}`,
      requirement: r.statement,
      sourceRef: `${version}, ${id} (${r.area})`,
      url: HISO_SOURCES[part].url, verified: true,
    }));
}

export const HISO10029_3_CONTROLS: ControlDef[] =
  build('HISO10029_3', 'hiso3', 'HISO 10029.3:2023', HML_REQUIREMENTS, cited('hml'));
export const HISO10029_4_CONTROLS: ControlDef[] =
  build('HISO10029_4', 'hiso4', 'HISO 10029.4:2025', HSUP_REQUIREMENTS, cited('hsup'));
