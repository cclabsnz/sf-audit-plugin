// test/unit/incident/render.test.ts
import { describe, it, expect, beforeAll } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { generateScenario } from '../../fixtures/incident/generate.js';
import { analyseBundle, type IncidentResult } from '../../../src/incident/analyse/index.js';
import { buildEvidence, writeEvidence } from '../../../src/incident/render/evidence.js';
import { redactResult } from '../../../src/incident/render/redact.js';
import { renderMarkdown } from '../../../src/incident/render/markdown.js';

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
