// test/unit/incident/falseAssurance.test.ts
// One regression per false-assurance path from the final review. A reassuring result
// ("No evidence of access", "within baseline") must never appear unless the evidence supports it.
import { describe, it, expect } from '@jest/globals';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import { analyseBundle } from '../../../src/incident/analyse/index.js';
import { buildEvidence } from '../../../src/incident/render/evidence.js';
import { renderHtml } from '../../../src/incident/render/html.js';
import { renderMarkdown } from '../../../src/incident/render/markdown.js';
import { midnightSpill, noReferenceReplies, nullBaseline, rotatingIps, uniformNonEmptyReplies, zeroWaves } from '../../fixtures/incident/variants.js';
import { generateScenario } from '../../fixtures/incident/generate.js';

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

const w3Of = async (dir: string) => {
  const r = await analyseBundle(dir);
  return { r, w3: r.waves.find((w) => w.wave.id === 'W3')! };
};

describe('C2: a wave with no actor block is still assessed', () => {
  it('P4 rotating IPs: the 7 large replies are still flagged and the result is content-returned', async () => {
    const { r, w3 } = await w3Of(await rotatingIps());
    expect(w3.actors).toEqual([]);
    expect(w3.responses.returnedContent).toHaveLength(7);
    expect(w3.responses.returnedContent.every((x) => x.actorId === '')).toBe(true);
    expect(w3.result).toBe('content-returned');
    expect(w3.result).not.toBe('no-evidence');
    expect(w3.classification).toBe('indeterminate');
    expect(w3.limits.join(' ')).toContain('No single source block was isolated; reply sizes were assessed across all guest traffic on the wave days.');
    expect(r.withinBaseline).toBe(false);
  });
  it('P5b midnight spill: actor traffic on a baseline day does not raise its own threshold', async () => {
    const { r, w3 } = await w3Of(await midnightSpill());
    expect(w3.actors.map((a) => a.block)).toEqual(['203.0.113.0/24']);
    expect(w3.result).toBe('content-returned');
    expect(r.withinBaseline).toBe(false);
  });
  it('tags each flagged reply with the actor that sent it', async () => {
    const { w3 } = await w3Of(await generateScenario());
    expect(w3.responses.returnedContent.every((x) => x.actorId === 'W3-A1')).toBe(true);
    const ev = buildEvidence((await analyseBundle(await generateScenario())));
    expect(ev.tables.find((t) => t.key === 'W3:returned')!.columns).toContain('actor');
  });
});

describe('C4: the empty-reply size comes from a reference set, not the replies under test', () => {
  it('P8: uniform 5000-byte getItems replies are flagged against the 1861-byte login replies', async () => {
    const { r, w3 } = await w3Of(await uniformNonEmptyReplies());
    expect(w3.responses.emptySize).toBe(1861);
    expect(w3.responses.emptySizeInferred).toBe(false);
    expect(w3.responses.returnedContent).toHaveLength(198);
    expect(w3.result).toBe('content-returned');
    expect(r.withinBaseline).toBe(false);
  });
  it('P8b: with no logins and no baseline data access, the empty size is marked inferred and stated', async () => {
    const { w3 } = await w3Of(await noReferenceReplies());
    expect(w3.responses.emptySizeInferred).toBe(true);
    expect(w3.limits.join(' ')).toContain('The empty-reply size was inferred from the replies being tested; a scanner receiving identical non-empty replies would not be detected.');
  });
});
