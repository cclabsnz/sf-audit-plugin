// test/unit/incident/render.test.ts
import { describe, it, expect, beforeAll } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { generateScenario } from '../../fixtures/incident/generate.js';
import { analyseBundle, type IncidentResult } from '../../../src/incident/analyse/index.js';
import { buildEvidence, writeEvidence } from '../../../src/incident/render/evidence.js';
import { redactResult } from '../../../src/incident/render/redact.js';
import { md, renderMarkdown } from '../../../src/incident/render/markdown.js';
import { renderHtml } from '../../../src/incident/render/html.js';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';

let r: IncidentResult;
beforeAll(async () => { r = await analyseBundle(await generateScenario()); });

describe('evidence', () => {
  it('assigns stable E-numbers and writes one CSV per table', () => {
    const ev = buildEvidence(r);
    expect(ev.ref('volumes')).toBe('[E1]');
    expect(ev.ref('W3:returned')).toMatch(/^\[E\d+\]$/);
    expect(ev.ref('nope')).toBe('');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-ev-'));
    const written = writeEvidence(dir, ev.tables);
    expect(written.length).toBe(ev.tables.length);
    const returned = ev.tables.find((t) => t.key === 'W3:returned')!;
    expect(returned.rows).toHaveLength(7);
  });
});

describe('redactResult', () => {
  it('leaves no full routable IP or email address in the serialised result', () => {
    const s = JSON.stringify(redactResult(r));
    expect(s).not.toMatch(/\b(?:\d{1,3}\.){3}(?!0\/24)\d{1,3}\b/);
    expect(s).not.toMatch(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}/);
    expect(s).toContain('203.0.113.0/24');
  });
});

describe('renderMarkdown', () => {
  it('ends with the tool credit', () => {
    const out = renderMarkdown(r, buildEvidence(r)).trimEnd();
    expect(out.endsWith('Salesforce security tool.')).toBe(true);
    expect(out).toContain('utm_campaign=incident-report');
  });
  it('leads with the per-wave verdicts and the limits box, with evidence refs', () => {
    const md = renderMarkdown(r, buildEvidence(r));
    const summary = md.slice(0, md.indexOf('## Timeline'));
    expect(summary).toMatch(/W3.*Unattributed automated scan/s);
    expect(summary).toMatch(/Content returned, contents unknown/);
    expect(summary).toMatch(/What this report can't tell you/);
    expect(md).toMatch(/\[E\d+\]/);
    expect(/\b(attack|breach)/i.test(md)).toBe(false);
  });
});

describe('fix round 1', () => {
  it('redacts compressed IPv6, IPv4 followed by a slash, and leaves timestamps alone', () => {
    const c = structuredClone(r);
    const w = c.waves.find((x) => x.actors.length > 0)!;
    w.actors[0].userAgents[0] = { ua: '2001:db8::1 http://203.0.113.9/path 2001:db8:0:0:1:2:3:4 at 04:04:34', count: 1 };
    w.actors[0].ips = ['2001:db8::1'];
    c.coverage.logs[0].detail = '2001:db8::1 http://203.0.113.9/path 2001:db8:0:0:1:2:3:4 at 04:04:34';
    const red = redactResult(c);
    const ra = red.waves.find((x) => x.actors.length > 0)!.actors[0];
    expect(ra.ips).toEqual(['2001:db8:0:0::/64']);
    for (const text of [ra.userAgents[0].ua, red.coverage.logs[0].detail!]) {
      expect(text).not.toMatch(/2001:db8::1|:1:2:3:4|203\.0\.113\.9/);
      expect(text).toContain('2001:db8:0:0::/64');
      expect(text).toContain('203.0.113.0/24');
      expect(text).toContain('04:04:34');
    }
  });

  it('neutralises spreadsheet formulas in written evidence only', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-ev-'));
    const [p] = writeEvidence(dir, [{ id: 'E1', key: 'k', title: 't', columns: ['c'], rows: [['=HYPERLINK("x")']] }]);
    expect(fs.readFileSync(p, 'utf8')).toContain('"\'=HYPERLINK(""x"")"');
  });

  it('keeps Markdown intact for hostile site names', () => {
    const base = renderMarkdown(r, buildEvidence(r));
    const c = structuredClone(r);
    c.waves[0].wave.site = 'A|B\nC';
    const out = renderMarkdown(c, buildEvidence(c));
    expect(out).toContain(`### ${c.waves[0].wave.id}: A\\|B C,`);
    const rows = (t: string) => t.split('\n').filter((l) => /^\| \d{4}-/.test(l)).length;
    expect(rows(out)).toBe(rows(base));
    expect(out).toContain('### Gaps in collection');
  });
});

describe('zero-baseline spike (I1)', () => {
  it('renders a spike with a null ratio without throwing', () => {
    const c = structuredClone(r);
    const w = c.waves.find((x) => x.wave.id === 'W3')!;
    w.spikes = [{ ...w.spikes[0], baselineMedian: 0, ratio: null, isSpike: true }];
    const md = renderMarkdown(c, buildEvidence(c));
    expect(md).toContain(`5,200 guest controller calls on ${w.spikes[0].day} against a zero baseline`);
    expect(md).not.toMatch(/null|NaN|undefined×/);
  });
});

describe('self-registrations in the actor window (I9)', () => {
  const reg = { createdDate: '2026-06-30T22:50:00Z', createdBy: 'Site A Guest User', section: 'Customer Portal', action: 'createdcustomeruser', display: 'Created new Customer User Pat Visitor' };
  const withReg = () => {
    const c = structuredClone(r);
    c.waves.find((w) => w.wave.id === 'W1')!.outcomes.selfRegistrationsInActorWindow = [reg];
    return c;
  };
  it('has an evidence table per wave and lists them in the Markdown and HTML detail', () => {
    const c = withReg();
    const ev = buildEvidence(c);
    const t = ev.tables.find((x) => x.key === 'W1:selfreg')!;
    expect(t.columns).toEqual(['created_date', 'created_by', 'display']);
    expect(t.rows).toEqual([[reg.createdDate, reg.createdBy, reg.display]]);
    expect(ev.tables.find((x) => x.key === 'W3:selfreg')!.rows).toEqual([]);
    const md = renderMarkdown(c, ev);
    expect(md.slice(md.indexOf('## W1 detail'))).toContain('Pat Visitor');
    const html = renderHtml(c, ev, DEFAULT_BRANDING);
    expect(html.slice(html.indexOf('id="detail"'))).toContain('Pat Visitor');
  });
  it('is still redacted', () => {
    const red = redactResult(withReg());
    const ev = buildEvidence(red);
    expect(JSON.stringify(ev.tables)).not.toContain('Pat Visitor');
    expect(renderMarkdown(red, ev)).not.toContain('Pat Visitor');
  });
});

describe('limits box', () => {
  it('names the waves a wave-specific limit applies to, and leaves shared limits untagged', () => {
    const md = renderMarkdown(r, buildEvidence(r));
    const box = md.slice(md.indexOf("### What this report can't tell you"), md.indexOf('### Recommended next steps'));
    expect(box).toMatch(/^- Response bodies are never logged/m);
    expect(box).toMatch(/^- W1: The empty-reply size was inferred/m);
  });
});

describe('md', () => {
  it('escapes backslashes first so a trailing backslash cannot unescape a pipe', () => {
    expect(md('a\\|b')).toBe('a\\\\\\|b');
    expect(md('ends\\')).toBe('ends\\\\');
    expect(md('x|y\n<z')).toBe('x\\|y &lt;z');
  });
});
