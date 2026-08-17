import { CHECK_CONTROL_MAP } from '../../../src/compliance/mapping.js';
import { ALL_CONTROLS, getControl } from '../../../src/compliance/catalogs/index.js';
import { HIPAA_CONTROLS } from '../../../src/compliance/catalogs/hipaa.js';
import { GDPR_CONTROLS } from '../../../src/compliance/catalogs/gdpr.js';
import { resolveControls, resolveFrameworks } from '../../../src/compliance/resolve.js';
import { CHECKS } from '../../../src/checks/registry.js';

/**
 * HIPAA and GDPR were listed in the `Framework` union and in the `all` pack long before they had
 * catalogs, so `--frameworks all` and `--frameworks hipaa` resolved to zero rendered controls.
 * These tests pin the properties that made that state detectable, so it cannot recur silently.
 */

describe('HIPAA catalog', () => {
  it('pins the operative Security Rule, not the 2025 proposed rewrite', () => {
    for (const c of HIPAA_CONTROLS) {
      expect(c.framework).toBe('HIPAA');
      expect(c.version).toBe('45 CFR Part 164 Subpart C (HIPAA Security Rule, 2013 Omnibus)');
    }
  });

  it('cites a real CFR paragraph for every control', () => {
    for (const c of HIPAA_CONTROLS) {
      expect(c.sourceRef).toMatch(/^45 CFR 164\.3(08|10|12|16)\([a-e]\)/);
      expect(c.id).toBe(`HIPAA-${c.sourceRef.replace('45 CFR ', '')}`);
    }
  });

  it('keeps the Required/Addressable designation on specs that carry one', () => {
    const byId = new Map(HIPAA_CONTROLS.map((c) => [c.id, c]));
    expect(byId.get('HIPAA-164.312(a)(2)(i)')?.title).toContain('(Required)');
    expect(byId.get('HIPAA-164.312(a)(2)(iv)')?.title).toContain('(Addressable)');
    expect(byId.get('HIPAA-164.308(a)(1)(ii)(A)')?.title).toContain('(Required)');
    // Standards themselves are neither, so they must not be labelled.
    expect(byId.get('HIPAA-164.312(b)')?.title).not.toMatch(/Required|Addressable/);
  });
});

describe('GDPR catalog', () => {
  it('pins the regulation and cites an article or paragraph', () => {
    for (const c of GDPR_CONTROLS) {
      expect(c.framework).toBe('GDPR');
      expect(c.version).toBe('Regulation (EU) 2016/679');
      expect(c.sourceRef).toMatch(/^Regulation \(EU\) 2016\/679, Art\. \d+/);
    }
  });

  it('maps paragraphs, not whole articles, where the obligation is a paragraph', () => {
    const ids = GDPR_CONTROLS.map((c) => c.id);
    expect(ids).toContain('GDPR-Art5(1)(f)');
    expect(ids).toContain('GDPR-Art32(1)(a)');
    expect(ids).toContain('GDPR-Art32(1)(b)');
    expect(ids).toContain('GDPR-Art32(1)(d)');
    // Art. 32 as a bare article would be too coarse to cite against a finding.
    expect(ids).not.toContain('GDPR-Art32');
  });
});

describe('regulatory mapping', () => {
  it('maps every registered check to at least one HIPAA and one GDPR control', () => {
    const missing: string[] = [];
    for (const check of CHECKS) {
      const ids = CHECK_CONTROL_MAP[check.id] ?? [];
      if (!ids.some((i) => i.startsWith('HIPAA-'))) missing.push(`${check.id} (HIPAA)`);
      if (!ids.some((i) => i.startsWith('GDPR-'))) missing.push(`${check.id} (GDPR)`);
    }
    expect(missing).toEqual([]);
  });

  it('leaves no catalogued HIPAA/GDPR control unmapped', () => {
    const mapped = new Set(Object.values(CHECK_CONTROL_MAP).flat());
    const orphans = ALL_CONTROLS
      .filter((c) => c.framework === 'HIPAA' || c.framework === 'GDPR')
      .filter((c) => !mapped.has(c.id))
      .map((c) => c.id);
    expect(orphans).toEqual([]);
  });

  it('never lists the same control twice for one check', () => {
    for (const [check, ids] of Object.entries(CHECK_CONTROL_MAP)) {
      expect(new Set(ids).size).toBe(ids.length);
      expect(check).toMatch(/.+/);
    }
  });

  it('resolves HIPAA and GDPR through the provenance gate', () => {
    // Both catalogs are source-verified, so they must survive requireVerified.
    const hipaa = resolveControls('encryption-coverage', { frameworks: ['HIPAA'] });
    expect(hipaa.length).toBeGreaterThan(0);
    expect(hipaa.every((c) => c.verified)).toBe(true);

    const gdpr = resolveControls('sandbox-data-masking', { frameworks: ['GDPR'] });
    expect(gdpr.map((c) => c.id)).toContain('GDPR-Art32(1)(a)');
  });

  it('the hipaa and gdpr --frameworks aliases resolve', () => {
    expect(resolveFrameworks('hipaa')).toEqual(['HIPAA']);
    expect(resolveFrameworks('gdpr')).toEqual(['GDPR']);
    expect(resolveFrameworks('hipaa,gdpr')).toEqual(['HIPAA', 'GDPR']);
  });

  it('scopes the agent checks to HIPAA/GDPR even though the NZ pack has no chapter for them', () => {
    const ids = CHECK_CONTROL_MAP['agent-user-privilege'] ?? [];
    expect(ids).toContain('HIPAA-164.312(a)(1)');
    expect(ids).toContain('GDPR-Art32(1)(b)');
    expect(getControl('HIPAA-164.312(a)(1)')?.title).toBe('Access control');
  });
});
