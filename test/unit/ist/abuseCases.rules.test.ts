// Rule tests for spec/threat-taxonomy.md, phase 3: abuse cases on named chains
// (RULE-110..112, the chain parts of RULE-113; INT-014, MN-060).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditContext } from '@cclabsnz/sf-core';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import { ChainEngine } from '../../../src/chains/ChainEngine.js';
import { NAMED_CHAINS, inGroup, type FindingGroup, type NamedChainDef } from '../../../src/chains/namedChains.js';
import type { Finding } from '../../../src/findings/Finding.js';
import { buildAuditResult } from '../../../src/findings/scoring.js';
import { MarkdownRenderer } from '../../../src/renderers/MarkdownRenderer.js';
import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';
import { SarifRenderer } from '../../../src/renderers/SarifRenderer.js';

const ORG = { id: 'o', name: 'n', type: 'Enterprise Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' };
const ctx = (): AuditContext =>
  ({ soql: {} as any, tooling: {} as any, rest: {} as any, orgInfo: ORG, cache: {} as any }) as any;

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  id, checkId: id, category: 'T', riskLevel: 'HIGH', title: `title of ${id}`, detail: 'd', remediation: 'r', ...extra,
});

/** One finding per id, one per prefix, and one granting each capability, for every precondition group. */
function fixtureFor(def: NamedChainDef): Finding[] {
  const out = new Map<string, Finding>();
  for (const g of def.abuseCase.preconditions) {
    for (const id of g.ids ?? []) out.set(id, finding(id));
    for (const p of g.prefixes ?? []) out.set(`${p}fixture`, finding(`${p}fixture`));
    for (const c of g.capabilities ?? []) {
      out.set(`fixture-cap-${c}`, finding(`fixture-cap-${c}`, { capabilities: { grants: [c] } }));
    }
  }
  return [...out.values()];
}

const fires = (findings: Finding[], id: string) => new ChainEngine().correlate(findings).some((c) => c.id === id);
const breakGroup = (def: NamedChainDef): FindingGroup => def.abuseCase.preconditions[def.abuseCase.breakPoint];

describe('RULE-110 named chains are structured abuse cases', () => {
  it.each(NAMED_CHAINS.map((d) => [d.id, d] as const))('%s carries a complete abuse case', (_id, def) => {
    const ac = def.abuseCase;
    expect(ac.actor.trim()).not.toBe('');
    expect(ac.goal.trim()).not.toBe('');
    expect(ac.breakPointText.trim()).not.toBe('');
    expect(ac.preconditions.length).toBeGreaterThan(0);
    expect(Number.isInteger(ac.breakPoint)).toBe(true);
    expect(ac.preconditions[ac.breakPoint]).toBeDefined();
  });

  // Drift guard: every group constant a chain's match() reads must also be named in its abuse case,
  // so preconditions and breakPoint cannot fall out of step with what the chain actually matches on.
  it('every constant a match() reads is named in the same chain\'s preconditions', () => {
    const src = readFileSync(join(process.cwd(), 'src/chains/namedChains.ts'), 'utf8');
    const start = src.indexOf('export const NAMED_CHAINS');
    const chunks = src.slice(start).split(/\n  \{\n    id: '/).slice(1);
    expect(chunks.length).toBe(NAMED_CHAINS.length);
    for (const chunk of chunks) {
      const id = chunk.slice(0, chunk.indexOf("'"));
      const code = (t: string) => t.replace(/\/\/.*$/gm, '');
      const abuse = code(chunk.slice(chunk.indexOf('abuseCase: {'), chunk.indexOf('    match(')));
      const match = code(chunk.slice(chunk.indexOf('    match(')));
      const read = new Set([...match.matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/g)].map((m) => m[1]));
      const named = new Set([...abuse.matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/g)].map((m) => m[1]));
      const missing = [...read].filter((c) => !named.has(c));
      expect({ id, missing }).toEqual({ id, missing: [] });
    }
  });

  it('a named chain carries its abuse case; a potential chain carries none', () => {
    const def = NAMED_CHAINS.find((d) => d.id === 'standard-to-takeover')!;
    const chains = new ChainEngine().correlate(fixtureFor(def));
    const named = chains.find((c) => c.id === 'standard-to-takeover')!;
    expect(named.abuseCase).toEqual({
      actor: def.abuseCase.actor, goal: def.abuseCase.goal, breakPoint: def.abuseCase.breakPointText,
    });
    for (const c of chains.filter((x) => x.confidence === 'potential')) expect(c.abuseCase).toBeUndefined();
  });

  it('a step whose finding grants no capability is marked inferred, and only that step', () => {
    const def = NAMED_CHAINS.find((d) => d.id === 'insider-bulk-exfil')!;
    const chain = new ChainEngine().correlate(fixtureFor(def)).find((c) => c.id === 'insider-bulk-exfil')!;
    const blind = chain.steps.find((s) => s.findingId === 'event-monitoring-disabled')!;
    expect(blind.capabilityInferred).toBe(true);
    const export_ = chain.steps.find((s) => s.findingId === 'data-export-weekly-export')!;
    expect(export_.capabilityInferred).toBeUndefined();
  });
});

describe('RULE-111 a break point breaks the chain (MN-060)', () => {
  it.each(NAMED_CHAINS.map((d) => [d.id, d] as const))('%s fires on its full fixture and not without its break point', (id, def) => {
    const full = fixtureFor(def);
    expect(fires(full, id)).toBe(true);
    const broken = full.filter((f) => !inGroup(f, breakGroup(def)));
    expect(broken.length).toBeLessThan(full.length);
    expect(fires(broken, id)).toBe(false);
  });

  it.each(NAMED_CHAINS.map((d) => [d.id, d] as const))('%s marks exactly its break-point steps', (id, def) => {
    const chain = new ChainEngine().correlate(fixtureFor(def)).find((c) => c.id === id)!;
    for (const s of chain.steps) {
      const inBreak = inGroup(finding(s.findingId), breakGroup(def));
      expect({ step: s.findingId, breaks: s.breaksChain === true }).toEqual({ step: s.findingId, breaks: inBreak });
    }
    expect(chain.steps.some((s) => s.breaksChain)).toBe(true);
  });

  it('cred-theft-pivot needs an exposed secret among its steps, not just credential-theft somewhere', () => {
    // A session id in an outbound message grants credential-theft and egress, and two egress paths
    // exist, but no secret is exposed: that is session-id-egress territory, not this chain.
    const findings = ['outbound-messages-session-id', 'named-credentials-inventory', 'remote-sites-inventory'].map((i) => finding(i));
    expect(fires(findings, 'cred-theft-pivot')).toBe(false);
    expect(fires([...findings, finding('hardcoded-credentials-found')], 'cred-theft-pivot')).toBe(true);
  });
});

describe('RULE-112 abuse cases name roles and shapes, never client specifics', () => {
  const allRefs = NAMED_CHAINS.flatMap((d) => d.abuseCase.preconditions.flatMap((g) => [...(g.ids ?? []), ...(g.prefixes ?? [])]));

  it.each(NAMED_CHAINS.map((d) => [d.id, d] as const))('%s abuse case text holds no finding id or prefix', (_id, def) => {
    const text = [def.abuseCase.actor, def.abuseCase.goal, def.abuseCase.breakPointText].join(' ');
    for (const ref of allRefs) expect(text).not.toContain(ref);
  });

  it('the rendered abuse case uses no finding title', () => {
    const def = NAMED_CHAINS.find((d) => d.id === 'standard-to-takeover')!;
    const chain = new ChainEngine().correlate(fixtureFor(def)).find((c) => c.id === 'standard-to-takeover')!;
    const text = Object.values(chain.abuseCase!).join(' ');
    for (const s of chain.steps) expect(text).not.toContain(s.title!);
  });
});

describe('RULE-113 every output shows the break point, not the remediation, as what breaks the chain', () => {
  const def = NAMED_CHAINS.find((d) => d.id === 'standard-to-takeover')!;
  const result = () => {
    const fs = fixtureFor(def);
    const r = buildAuditResult(ctx(), fs, {}, undefined, new ChainEngine().correlate(fs));
    // Keep one named chain and one potential chain so both renderings are exercised.
    const named = r.attackChains!.find((c) => c.id === 'standard-to-takeover')!;
    const potential = { ...named, id: 'potential-x', title: 'Potential path', confidence: 'potential' as const, abuseCase: undefined,
      steps: named.steps.map(({ breaksChain: _b, ...s }) => s), remediation: 'Potential remediation text.' };
    return { ...r, attackChains: [named, potential] };
  };

  it('executive report: "Breaks the chain" is the break point; potential chains say "Recommended fixes"', () => {
    const html = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5, frameworks: ['OWASP'] }).render(result() as any);
    expect(html).toContain(`<strong>Breaks the chain:</strong> ${def.abuseCase.breakPointText}`);
    expect(html).not.toContain(`<strong>Breaks the chain:</strong> ${def.remediation}`);
    expect(html).toContain('<strong>Recommended fixes:</strong> Potential remediation text.');
    expect(html).toContain('<strong>Abuse case:</strong>');
  });

  it('HTML report and Markdown do the same', () => {
    const r = result();
    const html = new HtmlRenderer().render(r as any);
    const md = new MarkdownRenderer().render(r as any);
    for (const out of [html, md]) {
      expect(out).toContain(def.abuseCase.breakPointText);
      expect(out).toMatch(/Recommended fixes:\*?\*?(<\/strong>)? Potential remediation text\./);
    }
    expect(md).toContain('✂ _break point_');
  });

  it('SARIF carries the abuse case and marks break-point steps', () => {
    const sarif = JSON.parse(new SarifRenderer().render(result() as any));
    const res = sarif.runs[0].results.find((x: any) => x.properties?.attackChainId === 'standard-to-takeover');
    expect(res.properties.abuseCase.breakPoint).toBe(def.abuseCase.breakPointText);
    const locs = res.codeFlows[0].threadFlows[0].locations.map((l: any) => l.location.properties);
    expect(locs.some((p: any) => p.breaksChain === true)).toBe(true);
  });
});
