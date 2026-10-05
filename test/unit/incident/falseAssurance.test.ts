// test/unit/incident/falseAssurance.test.ts
// One regression per false-assurance path from the final review. A reassuring result
// ("No evidence of access", "within baseline") must never appear unless the evidence supports it.
import { describe, it, expect } from '@jest/globals';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import { analyseBundle } from '../../../src/incident/analyse/index.js';
import { buildEvidence } from '../../../src/incident/render/evidence.js';
import { renderHtml } from '../../../src/incident/render/html.js';
import { renderMarkdown } from '../../../src/incident/render/markdown.js';
import { nullBaseline, zeroWaves } from '../../fixtures/incident/variants.js';

const NOTHING_ASSESSED = 'No Guest User Anomaly waves were found in the collected period, so nothing was assessed.';
const WITHIN_BASELINE = 'Guest traffic stayed within baseline on every collected day.';

describe('C1: zero waves or no baseline never reads as within baseline', () => {
  it('zero waves: withinBaseline is false and the summary says nothing was assessed', async () => {
    const r = await analyseBundle(await zeroWaves());
    expect(r.waves).toEqual([]);
    expect(r.withinBaseline).toBe(false);
    const ev = buildEvidence(r);
    const md = renderMarkdown(r, ev);
    const html = renderHtml(r, ev, DEFAULT_BRANDING);
    for (const text of [md, html]) {
      expect(text).toContain(NOTHING_ASSESSED);
      expect(text).not.toContain(WITHIN_BASELINE);
    }
  });
  it('zero waves: the org-wide limits still appear in the limits box', async () => {
    const r = await analyseBundle(await zeroWaves());
    expect(r.globalLimits.join(' ')).toMatch(/Query All Files/);
    const md = renderMarkdown(r, buildEvidence(r));
    const box = md.slice(md.indexOf("### What this report can't tell you"), md.indexOf('### Recommended next steps'));
    expect(box).toMatch(/Query All Files/);
    expect(box).toMatch(/Hosting provider not assessed/);
  });
  it('a wave whose baseline median is null is not within baseline', async () => {
    const r = await analyseBundle(await nullBaseline());
    expect(r.waves[0].spikes[0].baselineMedian).toBeNull();
    expect(r.withinBaseline).toBe(false);
  });
});
