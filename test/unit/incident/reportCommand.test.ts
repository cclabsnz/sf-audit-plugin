import { describe, it, expect } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import { generateScenario } from '../../fixtures/incident/generate.js';
import { writeReport, parseFormats } from '../../../src/commands/audit/incident/report.js';

describe('writeReport', () => {
  it('writes html, md, json and evidence CSVs', async () => {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-out-'));
    const written = await writeReport(await generateScenario(), { formats: ['html', 'md', 'json'], outputDir: out, redact: false, spikeRatio: 5, branding: DEFAULT_BRANDING });
    expect(written.map((p) => path.basename(p))).toEqual(expect.arrayContaining(['incident-report.html', 'incident-report.md', 'incident-report.json', 'E1.csv']));
  });
  it('redacts every output, including evidence CSVs', async () => {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-out-'));
    const written = await writeReport(await generateScenario(), { formats: ['md', 'json'], outputDir: out, redact: true, spikeRatio: 5, branding: DEFAULT_BRANDING });
    for (const p of written) expect(fs.readFileSync(p, 'utf-8')).not.toMatch(/test\.tester@example\.com|198\.51\.100\.143/);
  });
});

describe('parseFormats', () => {
  it('splits and trims', () => {
    expect(parseFormats('html,md')).toEqual(['html', 'md']);
    expect(parseFormats(' json ')).toEqual(['json']);
  });
  it('throws on unknown or empty input', () => {
    expect(() => parseFormats('pdf')).toThrow(/Unknown --format value\(s\): pdf\. Use html, md, json\./);
    expect(() => parseFormats('')).toThrow(/Use html, md, json/);
  });
});
