import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import type { AuditResult } from '../../../src/findings/AuditResult.js';

function makeResult(): AuditResult {
  return {
    generatedAt: new Date('2026-06-14T00:00:00Z'),
    orgId: '00Dxx', orgName: 'Acme', orgType: 'Production', isSandbox: false,
    instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com',
    healthScore: 62, grade: 'C',
    metrics: {} as never,
    findings: [
      { id: 'f1', checkId: 'internal-user-mfa', category: 'Authentication', riskLevel: 'CRITICAL',
        title: '3 admins without MFA', detail: 'd', remediation: 'Enforce MFA', complianceTags: ['OWASP-A07'] },
      { id: 'f2', checkId: 'sharing-model', category: 'Data', riskLevel: 'HIGH',
        title: 'Loose OWD', detail: 'd', remediation: 'Tighten OWD' },
    ],
    attackChains: [
      { id: 'c1', title: 'Account takeover', severity: 'CRITICAL', confidence: 'named',
        narrative: 'Stolen password to full org access.', remediation: 'Enforce MFA',
        steps: [{ findingId: 'f1', capability: 'INITIAL_ACCESS' as never, title: '3 admins without MFA', severity: 'CRITICAL' }] },
    ],
  };
}

describe('ClientReportRenderer', () => {
  const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5, frameworks: ['OWASP'] });

  it('declares the executive format and html extension', () => {
    expect(r.format).toBe('executive');
    expect(r.fileExtension).toBe('.html');
    expect(r.filenamePrefix).toBe('SF_Audit_Executive');
  });

  it('renders a self-contained deck: summary, plan, threat model, scenarios, appendix and sign-off', () => {
    const html = r.render(makeResult());
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('CloudCounsel Limited');
    for (const kicker of ['Executive summary', 'Where to act', 'Action plan', 'Threat model · STRIDE and LINDDUN',
      'Appendix · Remediation roadmap', 'Appendix · Compliance coverage', 'Appendix · All findings', 'Issue and approval']) {
      expect({ kicker, found: html.includes(`<div class="kicker">${kicker.replace('&', '&amp;')}</div>`) }).toEqual({ kicker, found: true });
    }
    expect(html).toContain('Account takeover');
    expect(html).toContain('@font-face');
    expect(html).not.toContain('http://');
  });

  it('renders the compliance matrix for selected frameworks', () => {
    const html = r.render(makeResult());
    expect(html).toContain('OWASP-A07');
    expect(html).toContain('OWASP Top 10:2021');
  });

  it('credits the tool in the footer without naming the org', () => {
    const html = r.render(makeResult());
    const footer = html.slice(html.indexOf('<footer>'));
    expect(footer).toContain('utm_campaign=executive-report');
    expect(footer).not.toContain('acme');
  });

  it('explains a standalone action with the check\'s impact narrative', () => {
    expect(r.render(makeResult())).toContain('no second factor');
  });

  it('escapes finding titles', () => {
    const res = makeResult();
    res.findings[0].title = '<script>x</script>';
    expect(r.render(res)).not.toContain('<script>x</script>');
  });

  it('lists waived findings as accepted risks and escapes the approval text', () => {
    const result = makeResult();
    result.findings[1] = {
      ...result.findings[1],
      waived: true,
      affectedItems: [{ label: 'Account', note: '[WAIVED: <img src=x onerror=alert(1)> (approved by sec, expires 2027-01-31)]' }],
    };
    result.waivedFindings = [result.findings[1]];
    const html = r.render(result);
    expect(html).toContain('Appendix · Accepted risks');
    expect(html).toContain('1 waived as accepted risk');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });
});

// Every slide states its conclusion; the numbers in those conclusions come from the audit.
describe('ClientReportRenderer slides', () => {
  const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5, frameworks: ['OWASP'] });
  const res = (): AuditResult => {
    const base = makeResult();
    return {
      ...base,
      findings: [
        ...base.findings,
        { id: 'f3', checkId: 'x', category: 'C', riskLevel: 'LOW', title: 'Passed check', detail: 'd', remediation: 'r', passed: true },
        { id: 'f4', checkId: 'y', category: 'C', riskLevel: 'INFO', title: 'Unread check', detail: 'd', remediation: 'r', inconclusive: true },
        { id: 'f5', checkId: 'z', category: 'C', riskLevel: 'INFO', title: 'Info finding', detail: 'd', remediation: 'r' },
      ],
      attackChains: [{
        id: 'c1', title: 'Account takeover', severity: 'CRITICAL', confidence: 'named',
        narrative: 'Stolen password to full org access.', remediation: 'Enforce MFA',
        abuseCase: { actor: 'an outsider with a phished password', goal: 'take over the org', breakPoint: 'Enforce MFA for every admin: phishing-resistant factors' },
        steps: [{ findingId: 'f1', capability: 'credential-theft', title: '3 admins without MFA', severity: 'CRITICAL', breaksChain: true }],
      }],
    };
  };

  it('numbers every slide out of the total and ends on the sign-off holding the scope text', () => {
    const html = r.render(res());
    const nos = [...html.matchAll(/ · (\d+) \/ (\d+)<\/span><\/div>\n<\/section>/g)];
    expect(nos.length).toBeGreaterThan(8);
    expect(nos.map((m) => Number(m[1]))).toEqual(nos.map((_, i) => i + 1));
    expect(new Set(nos.map((m) => Number(m[2])))).toEqual(new Set([nos.length]));
    const last = html.slice(html.lastIndexOf('<section class="slide'));
    expect(last).toContain('Issue and approval');
    expect(last).toContain('<footer>');
  });

  it('turns the chain\'s break point into the first action and states it on the summary and plan', () => {
    const html = r.render(res());
    // One chain broken by one wave-1 action; one more action for the HIGH finding outside the chain.
    expect(html).toContain('One action to start now closes every critical attack path; 1 more action completes the plan');
    expect(html).toContain('Two actions break 1 of 1 named attack chain and close 2 of 3 open findings');
    const plan = html.slice(html.indexOf('<table class="plan"'));
    expect(plan.indexOf('Enforce MFA for every admin')).toBeLessThan(plan.indexOf('Tighten OWD'));
    expect(plan).toContain('<span class="ad">Phishing-resistant factors</span>');
  });

  it('says one action in the singular, and explains the grade in words', () => {
    const base = res();
    const html = r.render({ ...base, grade: 'F', gradeReason: 'F: 1 CRITICAL (1 finding) (D allows none)', findings: base.findings.filter((x) => x.id !== 'f2') });
    expect(html).toContain('One action to start now closes every critical attack path');
    expect(html).toContain('One action breaks 1 of 1 named attack chain and closes 1 of 2 open findings');
    expect(html).toContain('Graded F because 1 critical issue is open (1 finding), and a D allows none, whatever the health score.');
  });

  it('does not claim every critical path closed while a critical potential chain is open, and labels it P1', () => {
    const base = res();
    const html = r.render({ ...base, attackChains: [...base.attackChains!, {
      id: 'p', title: 'Potential path', severity: 'CRITICAL', confidence: 'potential', narrative: 'POTNARR', remediation: 'Fix any one',
      steps: [{ findingId: 'f2', capability: 'data-read', title: 'Loose OWD', severity: 'HIGH' }],
    }] });
    expect(html).not.toContain('close every critical attack path');
    expect(html).not.toContain('closes every critical attack path');
    expect(html).toContain('addresses the critical exposure');
    expect(html).toContain('>P1</td>');
    expect(html).toContain('POTNARR');
  });

  it('says a chain stays open when part of its break point is waived', () => {
    const base = res();
    base.attackChains![0].steps.push({ findingId: 'w', capability: 'data-read', title: 'Waived step', severity: 'HIGH', breaksChain: true });
    const html = r.render({ ...base, findings: [...base.findings, { id: 'w', checkId: 'w', category: 'C', riskLevel: 'HIGH', title: 'Waived step', detail: 'd', remediation: 'r', waived: true }] });
    expect(html).toContain('Account takeover: part of its break point is waived or passed, so it stays open');
    expect(html).toContain('weakens C1');
    expect(html).not.toContain('closes every critical attack path');
  });

  it('gives every finding one unique ref, open by severity first, and reuses it in the plan and chain steps', () => {
    const html = r.render(res());
    const refs = [...html.matchAll(/<td class="ref">(F-\d{3})<\/td>|<li><span class="ref">(F-\d{3})<\/span>/g)].map((m) => m[1] ?? m[2]);
    expect(refs).toEqual(['F-001', 'F-002', 'F-003', 'F-004', 'F-005']);
    expect(html).toMatch(/<li class="step cut">.*?F-001 · Critical/s);
    expect(html).toContain('<span class="ar">F-001</span>');
  });

  it('lists waived and failed checks outside "Open findings", so every open count agrees', () => {
    const base = res();
    const html = r.render({
      ...base,
      findings: [
        ...base.findings,
        { id: 'w1', checkId: 'w', category: 'C', riskLevel: 'HIGH', title: 'Waived one', detail: 'd', remediation: 'r', waived: true },
        { id: 'e1', checkId: 'e', category: 'C', riskLevel: 'INFO', title: 'Check failed', detail: 'd', remediation: 'r', notAssessed: true },
      ],
    } as AuditResult);
    expect(html).toMatch(/close \d of 3 open findings/);
    expect(html).toMatch(/<caption>Open findings <span class="muted">3<\/span>/);
    expect(html).toMatch(/<caption>Waived <span class="muted">1 · /);
    expect(html).toMatch(/<caption>Inconclusive <span class="muted">2 · /);
  });

  it('shows the threat model with counts from the findings, and says when a category has none', () => {
    const base = res();
    base.findings[0] = { ...base.findings[0], threats: { stride: ['S', 'E'] } };
    const html = r.render(base);
    const tm = html.slice(html.indexOf('Threat model · STRIDE'), html.indexOf('Attack scenario C1'));
    expect(tm).toContain('All critical risk is spoofing or elevation of privilege');
    // A second critical finding with no STRIDE category makes "all" untrue.
    const extra = r.render({ ...base, findings: [...base.findings, { id: 'u', checkId: 'u', category: 'C', riskLevel: 'CRITICAL', title: 'U', detail: 'd', remediation: 'r' }] });
    expect(extra).not.toContain('All critical risk is');
    expect(tm).toMatch(/<b>S<\/b>Spoofing<\/div><div class="c" style="background:var\(--crit\);color:#fff">1<\/div>/);
    expect(tm).toMatch(/<b>D<\/b>Denial of service<\/div><div class="none">(no findings from|not assessed)/);
  });

  it('uses the firm\'s own colours and surfaces when it set them, and the deck\'s when it did not', () => {
    const own = new ClientReportRenderer({ branding: { ...DEFAULT_BRANDING, primary: '#123456', bg: '#101010', bgAlt: '#202020', border: '#303030' }, topN: 5, frameworks: [] }).render(res());
    expect(own).toContain('--accent:#123456;');
    expect(own).toContain('--paper:#202020;--desk:#101010;');
    expect(own).toContain('--hair:#303030;');
    expect(r.render(res())).toContain('--paper:#ffffff;--desk:#eef0f1;');
  });
});

// Org data reaches the stylesheet (print page footers) and tool advice is auto-linked.
describe('ClientReportRenderer hostile input', () => {
  const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5, frameworks: ['OWASP'] });
  const styleOf = (html: string): string => html.slice(html.indexOf('<style>'), html.indexOf('</style>') + 8);

  it('cannot leave the CSS string, the @page rule or the style element through the org name', () => {
    const res = { ...makeResult(), orgName: 'Evil"}</style><script>alert(1)</script>\\\n{x;', orgId: '00D"\\' };
    const html = r.render(res);
    const style = styleOf(html);
    expect(html.match(/<\/style>/g)).toHaveLength(1);
    expect(html).not.toContain('<script>alert(1)</script>');
    for (const m of style.matchAll(/content:("(?:[^"\\]|\\[0-9a-f]+ )*")/g)) {
      expect(m[1]).not.toMatch(/[<>{};\n]/);
    }
    expect(style).toMatch(/@page s1\{@bottom-left\{content:"Evil\\22 \\7d \\3c \/style\\3e /);
  });

  // A finding can name a lapsed or attacker-held domain as "the trusted domain (https://…)"; the report
  // must never hand the reader a live link to it.
  it('never links URLs in finding text, and sets code spans apart', () => {
    const res = makeResult();
    res.findings[0] = { ...res.findings[0], detail: 'The trusted domain "lapsed.example" (https://lapsed.example) is parked. Run `sf audit`.' };
    const html = r.render(res);
    expect(html).not.toContain('href="https://lapsed.example"');
    expect(html).toContain('(https://lapsed.example)');
    expect(html).toContain('<code>sf audit</code>');
  });

  it('keeps an emoji in the org name as one code point in the print footer', () => {
    const html = r.render({ ...makeResult(), orgName: 'Acme 😀' });
    expect(html).toContain('content:"Acme \\1f600 ');
    expect(html).not.toMatch(/\\d83d /);
  });

  it('renders an org with no findings and no chains, and adds the accepted-risks page when there are waivers', () => {
    const html = r.render({ ...makeResult(), findings: [], attackChains: [] });
    expect(html).toContain('No critical or high-severity issues are open; the remaining fixes are routine hardening');
    expect(html).toContain('No check results in this run.');
    expect(html).not.toContain('<div class="kicker">Action plan</div>');
    expect(html).not.toContain('Attack scenario');
    const waived = { ...makeResult(), waivedFindings: [{ ...makeResult().findings[1], waived: true }] };
    expect(r.render(waived)).toContain('aria-label="Appendix · Accepted risks"');
  });
});
