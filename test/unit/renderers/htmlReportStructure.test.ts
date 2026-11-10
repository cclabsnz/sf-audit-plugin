import { EMPTY_METRICS } from '@cclabsnz/sf-core';
import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import { buildActionPlan, planHeadline } from '../../../src/report/ActionPlan.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import type { AttackChain } from '../../../src/chains/AttackChain.js';
import type { Finding } from '../../../src/findings/Finding.js';

/**
 * The technical report reads top to bottom as: the fix-first plan, attack paths, findings by domain,
 * and a table of every result. Each finding's detail is drawn once, under its domain, and everything
 * else links to it.
 */

const f = (id: string, checkId: string, riskLevel: Finding['riskLevel'], extra: Partial<Finding> = {}): Finding => ({
  id,
  checkId,
  category: 'Test',
  riskLevel,
  title: `Title of ${id}`,
  detail: `Detail of ${id}`,
  remediation: `Fix ${id}`,
  ...extra,
});

const FINDINGS: Finding[] = [
  f('guest-user-write-access', 'guest-user-access', 'CRITICAL'),
  f('guest-executable-apex-unprotected', 'guest-executable-apex', 'CRITICAL'),
  f('admin-no-ip-restrictions', 'ip-restrictions', 'HIGH'),
  f('mfa-enforced', 'mfa-enforcement', 'LOW', { passed: true }),
  f('enhanced-domains-unknown', 'enhanced-domains', 'INFO', { inconclusive: true }),
  f('made-up-finding', 'not-a-registered-check', 'MEDIUM'),
];

const CHAIN: AttackChain = {
  id: 'unauth-bulk-exfil',
  title: 'Unauthenticated bulk exfiltration',
  severity: 'CRITICAL',
  confidence: 'named',
  narrative: 'Guest foothold and guest Apex without sharing.',
  remediation: 'Close guest access.',
  abuseCase: { actor: 'an anonymous visitor', goal: 'read records in bulk', breakPoint: 'Close guest access.' },
  steps: [
    { findingId: 'guest-user-write-access', checkId: 'guest-user-access', capability: 'unauth-foothold', title: 'Guest write', severity: 'CRITICAL', breaksChain: true },
    { findingId: 'guest-executable-apex-unprotected', checkId: 'guest-executable-apex', capability: 'code-exec', title: 'Guest Apex', severity: 'CRITICAL', breaksChain: true },
  ],
} as AttackChain;

const result: AuditResult = {
  generatedAt: new Date('2026-01-01'),
  orgId: 'org123',
  orgName: 'Test Org',
  orgType: 'Enterprise',
  isSandbox: false,
  instance: 'NA1',
  instanceUrl: 'https://test.salesforce.com',
  findings: FINDINGS,
  metrics: EMPTY_METRICS,
  healthScore: 60,
  grade: 'F',
  attackChains: [CHAIN],
};

const html = new HtmlRenderer().render(result);
/** From an element's id to the next closing section tag: enough for sections with none nested. */
const section = (id: string): string => {
  const start = html.indexOf(`id="${id}"`);
  return html.slice(start, html.indexOf('</section>', start));
};

describe('HTML report structure', () => {
  it('draws each finding card exactly once, with a unique anchor', () => {
    const ids = [...html.matchAll(/<details class="finding-card[^"]*" id="([^"]+)"/g)].map((m) => m[1]);
    expect(ids).toHaveLength(FINDINGS.length);
    expect(new Set(ids).size).toBe(FINDINGS.length);
  });

  it('every in-page link lands on an element that exists', () => {
    const targets = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
    const links = [...html.matchAll(/href="#([^"]+)"/g)].map((m) => m[1]);
    expect(links.length).toBeGreaterThan(0);
    expect(links.filter((l) => !targets.has(l))).toEqual([]);
  });

  it('puts the sections in reading order: plan, attack paths, domains, then every result', () => {
    const at = ['id="fix-first"', 'id="attack-paths"', 'id="by-domain"', 'id="all-results"'].map((s) => html.indexOf(s));
    expect(at.every((i) => i > 0)).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
  });

  it('opens the plan with the same headline as the executive report', () => {
    const plan = buildActionPlan(FINDINGS, [CHAIN]);
    const headline = planHeadline(plan, [CHAIN], 1);
    expect(section('fix-first')).toContain(headline);
    expect(section('fix-first')).toContain('href="#chain-1"');
  });

  it('files findings under their CHECKS.md domain, with unknown checks under "Other checks"', () => {
    const guest = html.slice(html.indexOf('id="d-guest-external-facing-access"'));
    expect(guest.slice(0, guest.indexOf('</section>'))).toContain('Title of guest-user-write-access');
    const other = html.slice(html.indexOf('id="d-other-checks"'));
    expect(other.slice(0, other.indexOf('</section>'))).toContain('Title of made-up-finding');
  });

  it('folds passed checks away under their domain, but keeps inconclusive ones in view', () => {
    const fold = /<details class="passed-fold"><summary>1 check passed<\/summary>([\s\S]*?)<\/details>\s*<\/section>/.exec(html);
    expect(fold?.[1]).toContain('Title of mfa-enforced');
    expect(fold?.[1]).not.toContain('Title of enhanced-domains-unknown');
  });

  it('never calls a domain clear when part of it could not be assessed', () => {
    const row = /<a class="dom-row" href="#d-org-health-configuration">([\s\S]*?)<\/a>/.exec(html)?.[1] ?? '';
    expect(row).toContain('PARTLY UNSEEN');
    expect(row).not.toContain('CLEAR');
    expect(row).toContain('1 result could not be assessed');
  });

  it('keeps a finding title intact when it contains a separator character', () => {
    const piped = new HtmlRenderer().render({ ...result, findings: [f('pipe', 'ip-restrictions', 'HIGH', { title: 'Admins | no IP ranges' })], attackChains: [] });
    expect(piped).toContain('<span class="worst">Worst: Admins | no IP ranges</span>');
    expect(piped).toContain('1 high open. Worst: Admins | no IP ranges</p>');
  });

  it('lists the worst domain first in the scorecard', () => {
    const rows = [...html.matchAll(/<a class="dom-row" href="#d-([^"]+)"/g)].map((m) => m[1]);
    expect(rows[0]).toBe('guest-external-facing-access');
  });

  it('has one table row per result, with passed rows hidden until asked for', () => {
    const rows = [...html.matchAll(/<tr data-sev="[^"]*"[^>]*data-st="([a-z]+)"([^>]*)>/g)];
    expect(rows).toHaveLength(FINDINGS.length);
    for (const [, st, rest] of rows) expect(rest.includes(' hidden')).toBe(st === 'passed');
  });

  it('closes every element it opens, so no section swallows the next', () => {
    // Script, style and svg bodies are not HTML structure: tags inside them are skipped by position.
    const RAW = new Set(['script', 'style', 'svg']);
    const VOID = new Set(['meta', 'br', 'img', 'input', 'link', 'hr']);
    const open: string[] = [];
    const mismatches: string[] = [];
    let skipUntil = -1;
    for (const m of html.matchAll(/<(\/?)([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>/g)) {
      const [, close, tag] = m;
      const name = tag.toLowerCase();
      if (m.index! < skipUntil) continue;
      if (!close && RAW.has(name)) {
        skipUntil = html.indexOf(`</${name}>`, m.index!) + name.length + 3;
        continue;
      }
      if (VOID.has(name)) continue;
      if (!close) open.push(name);
      else if (open.pop() !== name) mismatches.push(name);
    }
    expect(mismatches).toEqual([]);
    expect(open).toEqual([]);
  });

  it('links each attack-chain step to its finding', () => {
    expect(html).toMatch(/<li><a href="#f-guest-user-write-access"><strong>Guest write<\/strong><\/a>/);
  });
});
