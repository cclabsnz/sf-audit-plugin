// Rule tests for spec/nz-compliance-crosswalk.md (RULE-120..125, RULE-127; INT-015, MN-063..066).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  CHECK_NZ_CITATIONS, HML_REQUIREMENTS, HSUP_REQUIREMENTS, HSUP_TO_HML, NZISM_SECTIONS, NZISM_SOURCE,
} from '../../../src/compliance/nz/citations.generated.js';
import { CHECK_CONTROL_MAP, complianceTagsForFinding } from '../../../src/compliance/mapping.js';
import { getControl } from '../../../src/compliance/catalogs/index.js';
import { HISO10029_3_CONTROLS, HISO10029_4_CONTROLS } from '../../../src/compliance/catalogs/hiso10029.js';
import { NZISM_CONTROLS } from '../../../src/compliance/catalogs/nzism.js';
import { packFrameworks, resolveFrameworks } from '../../../src/compliance/resolve.js';

const ROOT = process.cwd();
const read = (p: string): any => JSON.parse(readFileSync(join(ROOT, 'data', 'compliance', p), 'utf8'));
const SOURCES = read('nz-sources.json');
const MAPPING: Record<string, any> = read('check-nz-mapping.json');

describe('RULE-120 every cited id exists in its pinned source', () => {
  it('every HSUP and HML requirement matches the extracted PDF text', () => {
    for (const [id, r] of Object.entries(HSUP_REQUIREMENTS)) {
      expect({ id, ...r }).toEqual({ id, area: SOURCES.hiso4.requirements[id].area, statement: SOURCES.hiso4.requirements[id].statement });
    }
    for (const [id, r] of Object.entries(HML_REQUIREMENTS)) {
      expect({ id, ...r }).toEqual({ id, area: SOURCES.hiso3.requirements[id].area, statement: SOURCES.hiso3.requirements[id].statement });
    }
    expect(Object.keys(HSUP_REQUIREMENTS)).toHaveLength(68);
    // Copied by hand from the published PDFs, so a parser defect cannot pass by agreeing with itself.
    expect(HSUP_REQUIREMENTS.HSUP34.statement).toBe('User accounts are authenticated and circumventing the authentication process is prevented.');
    expect(HML_REQUIREMENTS.HML39.statement).toBe('User accounts are authenticated and circumventing the authentication process is prevented.');
    expect(HML_REQUIREMENTS.HML58.statement).toBe('Organisations developing inhouse systems, applications or services are to maintain separate production and non-production environments.');
    expect(HML_REQUIREMENTS.HML05.statement).toBe('Asset management process(es) is in place.');
    for (const [id, r] of [...Object.entries(HSUP_REQUIREMENTS), ...Object.entries(HML_REQUIREMENTS)]) {
      expect({ id, complete: /[.)]$/.test(r.statement) }).toEqual({ id, complete: true });
    }
    expect(Object.keys(HML_REQUIREMENTS)).toHaveLength(75);
  });

  it('every cited NZISM section and control exists in the pinned manual, with its level', () => {
    expect(NZISM_SOURCE.version).toBe(SOURCES.nzism.version);
    for (const [section, s] of Object.entries(NZISM_SECTIONS)) {
      expect({ section, title: s.title }).toEqual({ section, title: SOURCES.nzism.sections[section] });
      for (const c of s.controls) {
        expect({ id: c.id, level: c.level }).toEqual({ id: c.id, level: SOURCES.nzism.controls[c.id] });
        expect(c.id.startsWith(`${section}.`)).toBe(true);
      }
    }
  });

  it('every HISO and NZISM id in the control map resolves to a catalogued control', () => {
    for (const [check, ids] of Object.entries(CHECK_CONTROL_MAP)) {
      for (const id of ids.filter((x) => /^(HISO|NZISM)-/.test(x))) {
        expect({ check, id, found: getControl(id) !== undefined }).toEqual({ check, id, found: true });
      }
    }
  });
});

describe('RULE-121 every citation records its basis', () => {
  it('direct citations carry a reason; scf NZISM citations list their controls', () => {
    for (const [check, c] of Object.entries(CHECK_NZ_CITATIONS)) {
      for (const h of c.hsup) {
        expect(['scf', 'direct']).toContain(h.basis);
        if (h.basis === 'direct') expect({ check, id: h.id, reason: (h.reason ?? '').length > 10 }).toEqual({ check, id: h.id, reason: true });
      }
      for (const n of c.nzism) {
        expect(['scf', 'direct']).toContain(n.basis);
        if (n.basis === 'scf') expect((n.controls ?? []).length).toBeGreaterThan(0);
        else expect({ check, section: n.section, reason: (n.reason ?? '').length > 10 }).toEqual({ check, section: n.section, reason: true });
      }
    }
  });
});

// RULE-122 (every SCF derivation cited or excluded) is enforced by derive_nz_citations.py, which needs
// the SCF workbook; SCF data is not committed (CC BY-ND 4.0). These tests check the generated file is
// the one that the committed decisions produce.
describe('RULE-122 the generated citations match the committed decisions', () => {
  const byId = (a: any[]): any[] => [...a].sort((x, y) => Number(x.id.slice(4)) - Number(y.id.slice(4)));
  it('HSUP citations, with basis, reason and scope, match the mapping data', () => {
    for (const [check, m] of Object.entries(MAPPING)) {
      expect({ check, scf: CHECK_NZ_CITATIONS[check]?.scf, hsup: CHECK_NZ_CITATIONS[check]?.hsup })
        .toEqual({ check, scf: m.scf, hsup: byId(m.hsup).map((h: any) => ({ id: h.id, basis: h.basis, ...(h.reason ? { reason: h.reason } : {}), ...(h.findings ? { findings: h.findings } : {}) })) });
    }
  });

  it('NZISM direct citations match, and excluded sections and controls are absent', () => {
    for (const [check, m] of Object.entries(MAPPING)) {
      const cites = CHECK_NZ_CITATIONS[check].nzism;
      const direct = cites.filter((n) => n.basis === 'direct').map((n) => n.section).sort();
      expect({ check, direct }).toEqual({ check, direct: (m.nzismDirect ?? []).map((d: any) => d.section).sort() });
      for (const e of m.nzismExcluded ?? []) {
        expect({ check, excluded: e.section, cited: cites.some((n) => n.section === e.section && n.basis === 'scf') }).toEqual({ check, excluded: e.section, cited: false });
      }
      for (const e of m.nzismControlsExcluded ?? []) {
        expect({ check, excluded: e.id, cited: cites.some((n) => n.basis === 'scf' && (n.controls ?? []).includes(e.id)) }).toEqual({ check, excluded: e.id, cited: false });
      }
      for (const [section, findings] of Object.entries(m.nzismScope ?? {})) {
        expect({ check, section, findings: cites.find((n) => n.section === section)?.findings }).toEqual({ check, section, findings });
      }
      for (const e of [...(m.hsupExcluded ?? []), ...(m.nzismExcluded ?? []), ...(m.nzismControlsExcluded ?? [])]) {
        expect({ check, reason: (e.reason ?? '').length > 10 }).toEqual({ check, reason: true });
      }
    }
  });
});

describe('RULE-123 HML citations follow their HSUP pair', () => {
  it('the pairing is one to one over all 68 HSUP requirements', () => {
    const hml = Object.values(HSUP_TO_HML);
    expect(hml).toHaveLength(68);
    expect(new Set(hml).size).toBe(68);
    for (const id of hml) expect(SOURCES.hiso3.requirements[id]).toBeDefined();
  });

  it('each check cites the HML pair of every HSUP it cites', () => {
    for (const [check, c] of Object.entries(CHECK_NZ_CITATIONS)) {
      expect({ check, hml: c.hml }).toEqual({ check, hml: c.hsup.map((h) => HSUP_TO_HML[h.id]) });
    }
  });

  it('catalogues hold exactly the cited requirements', () => {
    const hsup = new Set(Object.values(CHECK_NZ_CITATIONS).flatMap((c) => c.hsup.map((h) => `HISO-${h.id}`)));
    const hml = new Set(Object.values(CHECK_NZ_CITATIONS).flatMap((c) => c.hml.map((h) => `HISO-${h}`)));
    expect(new Set(HISO10029_4_CONTROLS.map((c) => c.id))).toEqual(hsup);
    expect(new Set(HISO10029_3_CONTROLS.map((c) => c.id))).toEqual(hml);
    expect(NZISM_CONTROLS.map((c) => c.id).sort()).toEqual(Object.keys(NZISM_SECTIONS).map((s) => `NZISM-${s}`).sort());
  });
});

describe('RULE-124 either HISO part can be selected alone', () => {
  it('hiso and the nz pack select both parts; the aliases select one', () => {
    expect(resolveFrameworks('hiso')).toEqual(['HISO10029_3', 'HISO10029_4']);
    expect(resolveFrameworks('hiso-provider')).toEqual(['HISO10029_3']);
    expect(resolveFrameworks('hiso-supplier')).toEqual(['HISO10029_4']);
    expect(packFrameworks('nz')).toEqual(expect.arrayContaining(['HISO10029_3', 'HISO10029_4', 'NZISM']));
  });
});

describe('RULE-125 every check has a crosswalk entry', () => {
  it('the mapping data and the control map cover the same checks', () => {
    expect(Object.keys(MAPPING).sort()).toEqual(Object.keys(CHECK_CONTROL_MAP).sort());
    expect(Object.keys(CHECK_NZ_CITATIONS).sort()).toEqual(Object.keys(CHECK_CONTROL_MAP).sort());
  });
});

describe('RULE-127 HISO and NZISM citations attach per finding', () => {
  const FEATURES = readFileSync(join(ROOT, 'docs', 'FEATURES.md'), 'utf8');
  const implOf = (check: string): string => {
    const m = FEATURES.match(new RegExp(`^\\| \`${check}\` \\|[^|]+\\|[^|]+\\| ([^|]+)\\|`, 'm'));
    return m ? m[1].trim() : '';
  };
  const emitted = (check: string): { ids: string[]; heads: string[] } => {
    const src = readFileSync(join(ROOT, implOf(check)), 'utf8');
    return {
      ids: [...src.matchAll(/\bid:\s*'([a-z0-9][a-z0-9-]*)'/g)].map((x) => x[1]),
      heads: [...src.matchAll(/\bid:\s*`([a-z0-9-]*)/g)].map((x) => x[1]).filter(Boolean),
    };
  };

  it('every finding scope matches a finding id the check can emit', () => {
    for (const [check, c] of Object.entries(CHECK_NZ_CITATIONS)) {
      const scopes = [...c.hsup, ...c.nzism].flatMap((x) => x.findings ?? []);
      if (scopes.length === 0) continue;
      const { ids, heads } = emitted(check);
      for (const p of scopes) {
        const ok = ids.some((id) => id.startsWith(p)) || heads.some((h) => h.startsWith(p) || p.startsWith(h));
        expect({ check, scope: p, emitted: ok }).toEqual({ check, scope: p, emitted: true });
      }
    }
  });

  it('an INFO finding carries no HISO or NZISM tag', () => {
    for (const check of Object.keys(CHECK_NZ_CITATIONS)) {
      const tags = complianceTagsForFinding(check, { id: `${check}-x`, riskLevel: 'INFO' });
      expect({ check, nz: tags.filter((t) => /^(HISO|NZISM)-/.test(t)) }).toEqual({ check, nz: [] });
      // every other framework still maps at check level
      expect(tags).toEqual((CHECK_CONTROL_MAP[check] ?? []).filter((t) => !/^(HISO|NZISM)-/.test(t)));
    }
  });

  it('a scoped citation attaches only to the findings it names', () => {
    for (const [check, c] of Object.entries(CHECK_NZ_CITATIONS)) {
      c.hsup.forEach((h, i) => {
        if (!h.findings) return;
        const named = complianceTagsForFinding(check, { id: h.findings[0], riskLevel: 'HIGH' });
        const other = complianceTagsForFinding(check, { id: 'zz-not-a-finding', riskLevel: 'HIGH' });
        expect({ check, id: h.id, named: named.includes(`HISO-${h.id}`), hml: named.includes(`HISO-${c.hml[i]}`) }).toEqual({ check, id: h.id, named: true, hml: true });
        const unscopedElsewhere = c.hsup.some((x) => x.id === h.id && !x.findings);
        if (!unscopedElsewhere) expect({ check, id: h.id, other: other.includes(`HISO-${h.id}`) }).toEqual({ check, id: h.id, other: false });
      });
    }
  });
});
