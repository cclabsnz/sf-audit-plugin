// Rule tests for spec/nz-compliance-crosswalk.md (RULE-120..125; INT-015, MN-063..065).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  CHECK_NZ_CITATIONS, HML_REQUIREMENTS, HSUP_REQUIREMENTS, HSUP_TO_HML, NZISM_SECTIONS, NZISM_SOURCE,
} from '../../../src/compliance/nz/citations.generated.js';
import { CHECK_CONTROL_MAP } from '../../../src/compliance/mapping.js';
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
  it('scf citations are derived by SCF; direct citations carry a reason', () => {
    for (const [check, c] of Object.entries(CHECK_NZ_CITATIONS)) {
      for (const h of c.hsup) {
        if (h.basis === 'scf') expect({ check, id: h.id, derived: c.scfDerivedHsup.includes(h.id) }).toEqual({ check, id: h.id, derived: true });
        else expect({ check, id: h.id, reason: (h.reason ?? '').length > 10 }).toEqual({ check, id: h.id, reason: true });
      }
      for (const n of c.nzism) {
        if (n.basis === 'scf') expect((n.controls ?? []).length).toBeGreaterThan(0);
        else expect({ check, section: n.section, reason: (n.reason ?? '').length > 10 }).toEqual({ check, section: n.section, reason: true });
      }
    }
  });
});

describe('RULE-122 SCF derivations are cited or excluded with a reason', () => {
  it('every SCF-derived HSUP is in exactly one of cited or excluded', () => {
    for (const [check, c] of Object.entries(CHECK_NZ_CITATIONS)) {
      const cited = new Set(c.hsup.map((h) => h.id));
      const excluded = new Map<string, string>((MAPPING[check].hsupExcluded ?? []).map((e: any) => [e.id, e.reason]));
      for (const id of c.scfDerivedHsup) {
        expect({ check, id, decided: cited.has(id) !== excluded.has(id) }).toEqual({ check, id, decided: true });
        if (excluded.has(id)) expect((excluded.get(id) ?? '').length).toBeGreaterThan(10);
      }
    }
  });

  it('the generated file matches the committed mapping decisions', () => {
    for (const [check, m] of Object.entries(MAPPING)) {
      expect({ check, scf: CHECK_NZ_CITATIONS[check]?.scf, hsup: CHECK_NZ_CITATIONS[check]?.hsup.map((h) => h.id) })
        .toEqual({ check, scf: m.scf, hsup: [...m.hsup].map((h: any) => h.id).sort((a: string, b: string) => Number(a.slice(4)) - Number(b.slice(4))) });
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
