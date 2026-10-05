// test/unit/incident/html.test.ts
import { describe, it, expect, beforeAll } from '@jest/globals';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import { generateScenario } from '../../fixtures/incident/generate.js';
import { analyseBundle, type IncidentResult } from '../../../src/incident/analyse/index.js';
import { buildEvidence } from '../../../src/incident/render/evidence.js';
import { renderHtml } from '../../../src/incident/render/html.js';

let r: IncidentResult;
beforeAll(async () => { r = await analyseBundle(await generateScenario()); });

describe('renderHtml', () => {
  it('is self-contained, puts verdicts and limits first, and cites evidence', () => {
    const html = renderHtml(r, buildEvidence(r), DEFAULT_BRANDING);
    expect(html).not.toMatch(/<script[^>]+src=|<link[^>]+href=["']?https?:/i);
    const first = html.indexOf('id="timeline"');
    expect(html.indexOf('Unattributed automated scan')).toBeLessThan(first);
    expect(html.indexOf("What this report can&#39;t tell you") >= 0 || html.indexOf("What this report can't tell you") >= 0).toBe(true);
    expect(html).toMatch(/\[E\d+\]/);
    expect(/\b(attack|breach)/i.test(html.replace(/<script>[\s\S]*?<\/script>/g, ''))).toBe(false);
  });
  it('escapes values from the org', () => {
    const evil = structuredClone(r);
    evil.orgName = '<img src=x onerror=alert(1)>';
    expect(renderHtml(evil, buildEvidence(evil), DEFAULT_BRANDING)).not.toContain('<img src=x');
  });
});
