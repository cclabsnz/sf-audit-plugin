import { renderAttackChainDagSvg, breakPointIndices } from '../../../src/renderers/AttackChainDagRenderer.js';
import type { AttackChain, AttackChainStep } from '../../../src/chains/AttackChain.js';
import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';
import { DEFAULT_BRANDING, EMPTY_METRICS } from '@cclabsnz/sf-core';
import type { AuditResult } from '../../../src/findings/AuditResult.js';

describe('AttackChainDagRenderer', () => {
  const sampleChain: AttackChain = {
    id: 'unauth-bulk-exfil',
    title: 'Unauthenticated bulk exfiltration',
    severity: 'CRITICAL',
    confidence: 'named',
    narrative: 'Guest foothold combines with Apex without sharing to exfiltrate records.',
    remediation: 'Ensure portal-exposed-apex-without-sharing is fixed and set external OWD to Private.',
    steps: [
      {
        findingId: 'guest-user-read-access',
        capability: 'unauth-foothold',
        title: 'Guest user read access',
        severity: 'HIGH',
      },
      {
        findingId: 'portal-exposed-apex-without-sharing',
        capability: 'code-exec',
        title: 'Portal exposed apex without sharing',
        severity: 'CRITICAL',
        breaksChain: true,
      },
    ],
  };

  describe('breakPointIndices (RULE-111, MN-060)', () => {
    it('marks exactly the steps the chain engine put in the break point', () => {
      expect(breakPointIndices(sampleChain)).toEqual([1]);
    });

    it('marks nothing when no step is in a break point, whatever the remediation text or severities say', () => {
      const chain: AttackChain = {
        ...sampleChain,
        confidence: 'potential',
        remediation: 'Fix guest-user-read-access first.',
        steps: sampleChain.steps.map(({ breaksChain: _b, ...s }) => s),
      };
      expect(breakPointIndices(chain)).toEqual([]);
      expect(renderAttackChainDagSvg(chain)).not.toContain('BREAK POINT');
      expect(renderAttackChainDagSvg(chain)).not.toContain('stroke-dasharray');
    });

    it('marks every step of a multi-step break point and says all must be fixed', () => {
      const chain: AttackChain = { ...sampleChain, steps: sampleChain.steps.map((s) => ({ ...s, breaksChain: true as const })) };
      expect(breakPointIndices(chain)).toEqual([0, 1]);
      expect(renderAttackChainDagSvg(chain)).toContain('Fix all 2 ✂ steps to break the chain');
    });

    it('handles empty steps gracefully', () => {
      const chain: AttackChain = { ...sampleChain, steps: [] };
      expect(breakPointIndices(chain)).toEqual([]);
      expect(renderAttackChainDagSvg(chain)).toBe('');
    });
  });

  describe('inferred capabilities (RULE-110)', () => {
    it('draws no capability pill for a step whose capability was inferred', () => {
      const chain: AttackChain = {
        ...sampleChain,
        steps: [{ ...sampleChain.steps[0], capability: 'data-read', capabilityInferred: true }, sampleChain.steps[1]],
      };
      const svg = renderAttackChainDagSvg(chain);
      expect(svg).not.toContain('grants: data-read');
      expect(svg).toContain('grants: code-exec');
    });
  });

  describe('renderAttackChainDagSvg', () => {
    it('renders pure inline SVG with markers, nodes, and arrows', () => {
      const svg = renderAttackChainDagSvg(sampleChain, { theme: 'dark' });
      expect(svg).toContain('<svg class="attack-chain-dag"');
      expect(svg).toContain('<marker id="dag-arrow-unauth-bulk-exfil-dark"');
      expect(svg).toContain('✂ BREAK POINT');
      expect(svg).toContain('stroke-dasharray="4 2"');
      expect(svg).toContain('STEP 1 · HIGH');
      expect(svg).toContain('STEP 2 · CRITICAL');
      expect(svg).toContain('grants: unauth-foothold');
      expect(svg).toContain('grants: code-exec');
      expect(svg).toContain('<path d="M');
      expect(svg).not.toContain('http://');
    });

    it('supports light theme for executive report', () => {
      const svg = renderAttackChainDagSvg(sampleChain, { theme: 'light' });
      expect(svg).toContain('dag-arrow-unauth-bulk-exfil-light');
      expect(svg).toContain('fill="#ffffff"'); // light card bg
      expect(svg).toContain('✂ BREAK POINT');
    });

    it('adheres to strict CSP by containing no script tags or javascript protocols', () => {
      const svg = renderAttackChainDagSvg(sampleChain);
      expect(svg.toLowerCase()).not.toContain('<script');
      expect(svg.toLowerCase()).not.toContain('javascript:');
      expect(svg.toLowerCase()).not.toContain('onload');
      expect(svg.toLowerCase()).not.toContain('onerror');
    });
  });

  describe('escaping (titles, capabilities, severities and ids come from org data)', () => {
    const PAYLOADS = ['<script>alert(1)</script>', `it's "quoted"`, '"><svg onload=alert(1)>'];

    function hostile(payload: string): AttackChain {
      return {
        ...sampleChain,
        id: `chain${payload}`,
        title: `Chain ${payload}`,
        remediation: 'Nothing that names a step.',
        steps: [
          { findingId: `fid${payload}`, capability: payload as never, title: payload, severity: payload as never },
          { findingId: `fid2${payload}`, capability: `cap ${payload}` as never, severity: 'HIGH' },
        ],
      };
    }

    for (const payload of PAYLOADS) {
      for (const theme of ['dark', 'light'] as const) {
        it(`escapes ${JSON.stringify(payload)} in every field (${theme})`, () => {
          const svg = renderAttackChainDagSvg(hostile(payload), { theme });
          const lower = svg.toLowerCase();
          expect(lower).not.toContain('<script');
          expect(lower).not.toContain('<svg onload');
          // Exactly one <svg ...> open tag: the payload never opens a second element.
          expect(svg.match(/<svg\b/g)).toHaveLength(1);
          // No raw quote survives inside text nodes: each '>'...'<' run is quote-free.
          for (const text of svg.match(/>[^<]*</g) ?? []) expect(text).not.toMatch(/["']/);
          // Every attribute value is well-formed (no stray quote broke out of one).
          const tags = svg.match(/<[a-zA-Z][^>]*>/g) ?? [];
          for (const tag of tags) {
            expect(tag).toMatch(/^<[a-zA-Z]+(\s+[a-zA-Z:-]+="[^"<>]*")*\s*\/?>$/);
            const attrNames = [...tag.matchAll(/\s([a-zA-Z:-]+)="[^"]*"/g)].map((m) => m[1].toLowerCase());
            expect(attrNames.filter((n) => n.startsWith('on'))).toEqual([]);
          }
        });
      }
    }

    it('escapes the severity label rather than interpolating it raw', () => {
      const svg = renderAttackChainDagSvg(hostile('<script>alert(1)</script>'));
      expect(svg).toContain('STEP 1 · &lt;scrip');
      expect(svg).not.toContain('STEP 1 · <');
    });

    it('escapes step titles and capabilities as text', () => {
      const svg = renderAttackChainDagSvg(hostile('"><svg onload=alert(1)>'), { theme: 'light' });
      expect(svg).toContain('&quot;&gt;&lt;svg onload=alert(1)&gt;');
      expect(svg).toContain('grants: cap &quot;&gt;&lt;svg onload=al');
    });

    it('falls back to a fixed colour for an unknown severity (never interpolated into fill)', () => {
      const svg = renderAttackChainDagSvg(hostile('red" onclick="x'));
      expect(svg).not.toContain('fill="red');
      expect(svg).toMatch(/fill="#[0-9a-f]{6}"/);
    });

    it('emits no external refs, scripts, handlers or foreignObject', () => {
      const svg = renderAttackChainDagSvg(hostile('<script>alert(1)</script>'));
      expect(svg).not.toMatch(/<script|<foreignObject|href=|xlink:|url\((?!#)|@import|https?:/i);
    });
  });

  describe('layout', () => {
    const step = (i: number, extra: Partial<AttackChainStep> = {}): AttackChainStep => ({
      findingId: `finding-${i}`, capability: 'data-read' as never, title: `Step ${i}`, severity: 'MEDIUM', ...extra,
    });
    const chainOf = (n: number): AttackChain => ({
      ...sampleChain, remediation: 'x', steps: Array.from({ length: n }, (_, i) => step(i)),
    });
    const viewBox = (svg: string): number[] => svg.match(/viewBox="0 0 (\d+) (\d+)"/)!.slice(1).map(Number);

    it('renders a single-step chain with no arrows', () => {
      const svg = renderAttackChainDagSvg(chainOf(1));
      expect(svg).toContain('STEP 1');
      expect(svg).not.toContain('marker-end');
      expect(viewBox(svg)).toEqual([268, 144]);
    });

    it('wraps long chains onto rows of four instead of one ever-wider strip', () => {
      const svg = renderAttackChainDagSvg(chainOf(10));
      const [w, h] = viewBox(svg);
      expect(w).toBe(24 * 2 + 4 * 220 + 3 * 52);
      expect(h).toBe(24 * 2 + 3 * 96 + 2 * 44);
      expect(svg.match(/marker-end=/g)).toHaveLength(9);
      // Every card sits inside the viewBox.
      for (const m of svg.matchAll(/<rect x="(\d+)" y="(\d+)" width="220" height="96"/g)) {
        expect(Number(m[1]) + 220).toBeLessThanOrEqual(w);
        expect(Number(m[2]) + 96).toBeLessThanOrEqual(h);
      }
    });

    it('truncates long labels with an ellipsis', () => {
      const long = 'A'.repeat(200);
      const svg = renderAttackChainDagSvg({ ...chainOf(2), steps: [step(0, { title: long, capability: long as never }), step(1)] });
      expect(svg).toContain(`>${'A'.repeat(25)}…<`);
      expect(svg).toContain(`grants: ${'A'.repeat(23)}…<`);
      expect(svg).not.toContain('A'.repeat(26));
    });

    it('does not split a surrogate pair when truncating', () => {
      const svg = renderAttackChainDagSvg({ ...chainOf(1), steps: [step(0, { title: '😀'.repeat(40) })] });
      expect(svg).toContain(`${'😀'.repeat(25)}…`);
      expect(svg).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/);
    });

    it('uses a darker severity palette on the light theme so labels stay legible on white', () => {
      const light = renderAttackChainDagSvg(chainOf(1), { theme: 'light' });
      const dark = renderAttackChainDagSvg(chainOf(1), { theme: 'dark' });
      expect(light).toContain('fill="#a16207"');
      expect(light).not.toContain('#eab308');
      expect(dark).toContain('fill="#eab308"');
    });

    it('is deterministic', () => {
      expect(renderAttackChainDagSvg(chainOf(6), { theme: 'light' })).toBe(renderAttackChainDagSvg(chainOf(6), { theme: 'light' }));
    });
  });

  describe('report integration', () => {
    const result = (): AuditResult => ({
      generatedAt: new Date('2026-06-14T00:00:00Z'),
      orgId: '00Dxx0000000000EAA', orgName: 'Acme', orgType: 'Production', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com',
      healthScore: 62, grade: 'C', metrics: { ...EMPTY_METRICS },
      findings: [],
      attackChains: [{
        ...sampleChain,
        steps: [{ ...sampleChain.steps[0], title: '"><svg onload=alert(1)>' }, sampleChain.steps[1]],
      }],
    });

    it('HtmlRenderer embeds the dark diagram inside the attack-chain card, escaped', () => {
      const html = new HtmlRenderer().render(result());
      expect(html).toContain('dag-arrow-unauth-bulk-exfil-dark');
      expect(html).not.toContain('<svg onload');
      expect(html.indexOf('<svg class="attack-chain-dag"')).toBeGreaterThan(html.indexOf('<div class="attack-chain'));
    });

    it('ClientReportRenderer embeds the light diagram in the scenario card under the strict CSP', () => {
      const html = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5, frameworks: ['OWASP'] }).render(result());
      expect(html).toContain('dag-arrow-unauth-bulk-exfil-light');
      expect(html).not.toContain('<svg onload');
      expect(html).not.toMatch(/<script|<foreignObject/i);
    });
  });
});
