// Rule tests for spec/threat-taxonomy.md, phase 2: MITRE ATT&CK on granted capabilities
// (RULE-106..109, the ATT&CK parts of RULE-113; INT-014, MN-059, MN-062).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { CheckEngine } from '../../../src/checks/CheckEngine.js';
import type { SecurityCheck } from '../../../src/checks/SecurityCheck.js';
import { ALL_CAPABILITIES } from '../../../src/chains/Capability.js';
import { CAPABILITY_REGISTRY, capabilitiesFor } from '../../../src/chains/CapabilityRegistry.js';
import { ChainEngine } from '../../../src/chains/ChainEngine.js';
import type { AttackChain } from '../../../src/chains/AttackChain.js';
import { NAMED_CHAINS } from '../../../src/chains/namedChains.js';
import type { Finding } from '../../../src/findings/Finding.js';
import { buildAuditResult } from '../../../src/findings/scoring.js';
import { CHECK_STRIDE_MAP } from '../../../src/threats/stride.js';
import {
  ATTACK_OUTPUT_ENABLED, ATTACK_RELEASE, ATTACK_TACTIC_ORDER, ATTACK_TECHNIQUES, CAPABILITY_TECHNIQUES,
  DETECTION_GAP_TECHNIQUES, attackFor, capabilitiesWithoutTechnique, detectsFor, orderStepsByTactic, stepTacticRank,
  techniqueLabel, techniquesForGrant,
} from '../../../src/threats/attack.js';
import { MarkdownRenderer } from '../../../src/renderers/MarkdownRenderer.js';
import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import { SarifRenderer } from '../../../src/renderers/SarifRenderer.js';
import { JsonRenderer } from '../../../src/renderers/JsonRenderer.js';

const ROOT = process.cwd();
const ORG = { id: 'o', name: 'n', type: 'Enterprise Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' };
const ctx = (): AuditContext =>
  ({ soql: {} as any, tooling: {} as any, rest: {} as any, orgInfo: ORG, cache: {} as any }) as any;

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  id, checkId: id, category: 'T', riskLevel: 'HIGH', title: `title of ${id}`, detail: 'd', remediation: 'r', ...extra,
});

interface Extract {
  release: string;
  tacticOrder: string[];
  sha256: string;
  techniques: Record<string, { name: string; tactics: string[]; url: string; revoked: boolean; deprecated: boolean }>;
}
const EXTRACT: Extract = JSON.parse(
  readFileSync(join(ROOT, 'test', 'fixtures', 'attack', `enterprise-attack-${ATTACK_RELEASE}-extract.json`), 'utf8'),
);

/**
 * Every registry finding and every finding a named chain matches on, present at once, so every
 * chain that can fire does, including the detection-gap chains whose blind-spot steps grant nothing.
 */
function allFindings(): Finding[] {
  const ids = new Set(Object.keys(CAPABILITY_REGISTRY));
  for (const def of NAMED_CHAINS) {
    for (const g of def.abuseCase.preconditions) {
      for (const id of g.ids ?? []) ids.add(id);
      for (const p of g.prefixes ?? []) ids.add(`${p}fixture`);
    }
  }
  return [...ids].map((id) => finding(id));
}
function allChains(): AttackChain[] {
  return new ChainEngine().correlate(allFindings());
}

describe('RULE-106 ATT&CK techniques attach to granted capabilities, not checks', () => {
  it('a finding carries the techniques of every capability it grants, and only those', () => {
    for (const id of Object.keys(CAPABILITY_REGISTRY)) {
      const f = finding(id);
      const expected = new Set(capabilitiesFor(f).grants.flatMap((c) => techniquesForGrant(id, c)));
      expect(new Set(attackFor(f) ?? [])).toEqual(expected);
    }
  });

  it('the defaults land on findings as the catalog says', () => {
    expect(new Set(attackFor(finding('guest-user-write-access')))).toEqual(new Set(['T1190', 'T1565.001', 'T1213.004']));
    expect(attackFor(finding('users-super-admin-combo'))).toEqual(['T1098']);
    expect(attackFor(finding('experience-cloud-site-self-registration'))).toEqual(['T1136.003', 'T1078.004']);
    expect(attackFor(finding('sharing-model-external-read'))).toEqual(['T1078.004', 'T1213.004']);
    expect(attackFor(finding('remote-sites-inventory'))).toEqual(['T1567']);
  });

  it('a capability the finding only requires adds no technique', () => {
    expect(attackFor(finding('x', { capabilities: { requires: ['priv-esc', 'external-egress'] } }))).toBeUndefined();
  });

  it('a passed or inconclusive finding carries none', () => {
    expect(attackFor(finding('users-super-admin-combo', { passed: true }))).toBeUndefined();
    expect(attackFor(finding('users-super-admin-combo', { inconclusive: true }))).toBeUndefined();
  });

  it('a registry override replaces the default for that grant only, and an empty override means none', () => {
    expect(techniquesForGrant('oauth-device-flow-enabled', 'credential-theft')).toEqual(['T1528']);
    expect(techniquesForGrant('hardcoded-credentials-found', 'credential-theft')).toEqual(['T1552']);
    expect(techniquesForGrant('cors-wildcard-origin', 'credential-theft')).toEqual([]);
    expect(techniquesForGrant('users-author-apex', 'code-exec')).toEqual(['T1059.009']);
    expect(techniquesForGrant('users-author-apex', 'priv-esc')).toEqual(['T1648']);
  });

  it('every override is for a capability its finding grants, and names a catalogued technique', () => {
    for (const [id, entry] of Object.entries(CAPABILITY_REGISTRY)) {
      for (const [cap, ids] of Object.entries(entry.techniques ?? {})) {
        expect({ id, cap, granted: entry.grants?.includes(cap as never) }).toEqual({ id, cap, granted: true });
        for (const t of ids ?? []) expect(ATTACK_TECHNIQUES[t]).toBeDefined();
      }
    }
  });

  it('no check id maps to a technique', () => {
    for (const key of Object.keys(DETECTION_GAP_TECHNIQUES)) expect(CHECK_STRIDE_MAP[key]).toBeUndefined();
    expect(Object.keys(CAPABILITY_TECHNIQUES).sort()).toEqual([...ALL_CAPABILITIES].sort());
  });

  it('CheckEngine puts the techniques on the finding beside its STRIDE tags', async () => {
    const check: SecurityCheck = {
      id: 'oauth-device-and-asset-token-flows', name: 'n', category: 'c', description: 'd',
      run: jest.fn<SecurityCheck['run']>().mockResolvedValue({
        findings: [{ id: 'oauth-device-flow-enabled', category: 'c', riskLevel: 'HIGH', title: 't', detail: 'd', remediation: 'r' }],
      }),
    };
    const r = await new CheckEngine([check], ctx()).run();
    expect(r.findings[0].threats?.attack).toEqual(['T1528']);
  });
});

describe('RULE-107 ATT&CK techniques have provenance', () => {
  it('every catalogued technique matches the pinned release: id, name, tactics and url, not revoked', () => {
    expect(EXTRACT.release).toBe(ATTACK_RELEASE);
    for (const t of Object.values(ATTACK_TECHNIQUES)) {
      const src = EXTRACT.techniques[t.id];
      expect({ id: t.id, found: Boolean(src) }).toEqual({ id: t.id, found: true });
      expect({ id: t.id, name: t.name, tactics: t.tactics, url: t.url, release: t.release })
        .toEqual({ id: t.id, name: src.name, tactics: src.tactics, url: src.url, release: ATTACK_RELEASE });
      expect({ id: t.id, revoked: src.revoked, deprecated: src.deprecated }).toEqual({ id: t.id, revoked: false, deprecated: false });
    }
  });

  it('every verified technique is recorded as checked in the verification worksheet', () => {
    const ws = readFileSync(join(ROOT, 'docs', 'compliance', 'verification-worksheet.md'), 'utf8');
    for (const t of Object.values(ATTACK_TECHNIQUES).filter((x) => x.verified)) {
      expect({ id: t.id, recorded: new RegExp(`^\\| \\[x\\] \\| ${t.id.replace('.', '\\.')} \\|`, 'm').test(ws) })
        .toEqual({ id: t.id, recorded: true });
    }
  });

  it('an unverified technique is never rendered, and nothing is guessed in its place', () => {
    const t = ATTACK_TECHNIQUES['T1528'];
    t.verified = false;
    try {
      expect(techniquesForGrant('oauth-device-flow-enabled', 'credential-theft')).toEqual([]);
      expect(attackFor(finding('oauth-device-flow-enabled'))).toBeUndefined();
      const chains = new ChainEngine().correlate(Object.keys(CAPABILITY_REGISTRY).map((id) => finding(id)));
      for (const s of chains.flatMap((c) => c.steps)) expect(s.techniques ?? []).not.toContain('T1528');
    } finally {
      t.verified = true;
    }
  });
});

describe('RULE-108 detection gaps reference what they leave unseen', () => {
  it('a missing SIEM leaves password guessing and stolen-account use unobserved, and grants nothing', () => {
    const f = finding('siem-integration-not-detected');
    expect(detectsFor(f)).toEqual(['T1110', 'T1078.004']);
    expect(attackFor(f)).toBeUndefined();
    expect(detectsFor({ ...f, passed: true })).toBeUndefined();
  });

  it('every detection-gap key is a finding id a check emits', () => {
    const src = readFileSync(join(ROOT, 'src', 'checks', 'impl', 'SiemIntegrationCheck.ts'), 'utf8');
    for (const id of Object.keys(DETECTION_GAP_TECHNIQUES)) expect(src).toContain(`id: '${id}'`);
  });

  it('chain steps never carry a detection technique; inferred steps carry none at all', () => {
    const chains = allChains();
    const gapChains = chains.filter((c) => c.id === 'insider-bulk-exfil' || c.id === 'undetected-compromise');
    expect(gapChains.map((c) => c.id).sort()).toEqual(['insider-bulk-exfil', 'undetected-compromise']);
    expect(gapChains.some((c) => c.steps.some((s) => s.capabilityInferred))).toBe(true);
    for (const s of chains.flatMap((c) => c.steps)) {
      if (s.findingId in DETECTION_GAP_TECHNIQUES) expect(s.techniques).toBeUndefined();
      if (s.capabilityInferred) expect(s.techniques).toBeUndefined();
    }
  });
});

describe('RULE-109 every capability has a technique before ATT&CK renders', () => {
  it('output is on, so every capability has at least one verified technique', () => {
    expect(ATTACK_OUTPUT_ENABLED).toBe(true);
    expect(capabilitiesWithoutTechnique()).toEqual([]);
  });
});

describe('RULE-113 every output carries ATT&CK in its own idiom', () => {
  const chains = allChains();
  const withTechnique = chains.find((c) => c.steps.some((s) => s.techniques?.length))!;
  const step = withTechnique.steps.find((s) => s.techniques?.length)!;

  it('chain steps carry the techniques of the capability their finding grants', () => {
    for (const s of chains.flatMap((c) => c.steps)) {
      if (s.capabilityInferred) continue;
      const expected = techniquesForGrant(s.findingId, s.capability);
      expect(s.techniques ?? []).toEqual(expected);
    }
  });

  it('JSON carries technique ids on findings and chain steps', () => {
    const f = { ...finding('oauth-device-flow-enabled'), threats: { attack: attackFor(finding('oauth-device-flow-enabled')) } };
    const json = JSON.parse(new JsonRenderer().render(buildAuditResult(ctx(), [f], {}, undefined, [withTechnique])));
    expect(json.findings[0].threats.attack).toEqual(['T1528']);
    expect(json.attackChains[0].steps.find((s: any) => s.findingId === step.findingId).techniques).toEqual(step.techniques);
  });

  it('SARIF tags the chain rule attack:<id> and lists techniques on the step', () => {
    const sarif = JSON.parse(new SarifRenderer().render(buildAuditResult(ctx(), [], {}, undefined, [withTechnique])));
    const run = sarif.runs[0];
    const rule = run.tool.driver.rules.find((r: any) => r.id === `attack-chain-${withTechnique.id}`);
    for (const t of step.techniques!) expect(rule.properties.tags).toContain(`attack:${t}`);
    const locs = run.results[0].codeFlows[0].threadFlows[0].locations;
    expect(locs.some((l: any) => JSON.stringify(l.location.properties.attackTechniques) === JSON.stringify(step.techniques))).toBe(true);
  });

  it('Markdown and HTML show capability → technique on the step', () => {
    const r = buildAuditResult(ctx(), [], {}, undefined, [withTechnique]);
    const label = step.techniques!.map(techniqueLabel).join(' · ');
    expect(new MarkdownRenderer().render(r)).toContain(`grants \`${step.capability}\` → ${label}`);
    expect(new HtmlRenderer().render(r)).toContain(`grants <code>${step.capability}</code> → ${label}`);
  });

  it('Markdown shows a finding\'s techniques, and what a detection gap leaves unobserved, on its Threats line', () => {
    const fs = [
      { ...finding('oauth-device-flow-enabled'), threats: { stride: ['S' as const], attack: ['T1528'] } },
      { ...finding('siem-integration-not-detected'), threats: { stride: ['R' as const], detects: ['T1110', 'T1078.004'] } },
    ];
    const md = new MarkdownRenderer().render(buildAuditResult(ctx(), fs, {}));
    expect(md).toContain('**Threats:** STRIDE S | ATT&CK T1528');
    expect(md).toContain('**Threats:** STRIDE R | leaves unobserved: T1110 Brute Force · T1078.004 Cloud Accounts');
  });

  it('tagging changes no score or grade (MN-062)', () => {
    const fs = Object.keys(CAPABILITY_REGISTRY).slice(0, 20).map((id) => finding(id));
    const tagged = fs.map((f) => ({ ...f, threats: { attack: attackFor(f), detects: detectsFor(f) } }));
    const a = buildAuditResult(ctx(), fs, {});
    const b = buildAuditResult(ctx(), tagged, {});
    expect({ score: b.healthScore, grade: b.grade }).toEqual({ score: a.healthScore, grade: a.grade });
  });
});

/** The tactics a step is placed by: its own techniques, else its capability's default. */
function stepTactics(s: AttackChain['steps'][number]): string[] {
  if (s.capabilityInferred) return [];
  const ids = s.techniques?.length ? s.techniques : CAPABILITY_TECHNIQUES[s.capability];
  return ids.flatMap((id) => ATTACK_TECHNIQUES[id].tactics);
}

describe('RULE-116 chain steps follow the ATT&CK tactic order', () => {
  it('the tactic order is the pinned release\'s Enterprise matrix', () => {
    expect([...ATTACK_TACTIC_ORDER]).toEqual(EXTRACT.tacticOrder);
  });

  it('every chain lists its ranked steps in tactic order', () => {
    for (const c of allChains()) {
      const ranks = c.steps.map((s) => stepTacticRank(s)).filter((r): r is number => r !== undefined);
      expect({ chain: c.id, ranks }).toEqual({ chain: c.id, ranks: [...ranks].sort((a, b) => a - b) });
    }
  });

  it('potential chains are ordered too', () => {
    const c = new ChainEngine()
      .correlate(['hardcoded-credentials-found', 'guest-user-read-access'].map((id) => finding(id)))
      .find((x) => x.confidence === 'potential')!;
    expect(c.steps.map((s) => s.capability)).toEqual(['unauth-foothold', 'credential-theft']);
  });

  it('credentials come before the egress that carries them out', () => {
    const c = allChains().find((x) => x.id === 'cred-theft-pivot')!;
    const caps = c.steps.map((s) => s.capability);
    expect(caps.lastIndexOf('credential-theft')).toBeLessThan(caps.indexOf('external-egress'));
  });

  it('a step without a rank keeps its precondition group\'s place; ties keep their order', () => {
    const step = (name: string, capability: any, extra: object = {}) => ({ name, capability, ...extra });
    const steps = [
      step('exfil', 'external-egress'),
      step('gap', 'data-read', { capabilityInferred: true as const }),
      step('foothold', 'unauth-foothold'),
      step('read-a', 'data-read'),
      step('read-b', 'data-read-bulk'),
    ];
    const group: Record<string, number> = { foothold: 0, 'read-a': 1, gap: 1, 'read-b': 1, exfil: 2 };
    expect(orderStepsByTactic(steps, (s) => group[s.name]).map((s) => s.name))
      .toEqual(['foothold', 'gap', 'read-a', 'read-b', 'exfil']);
  });

  it('ordering moves steps only: the same steps, the same break point, the same chains', () => {
    const fs = allFindings();
    const chains = new ChainEngine().correlate(fs);
    for (const def of NAMED_CHAINS) {
      const c = chains.find((x) => x.id === def.id);
      if (!c) continue;
      const members = new Set(def.match(new Set(fs.flatMap((f) => capabilitiesFor(f).grants)), fs)?.map((f) => f.id));
      expect(new Set(c.steps.map((s) => s.findingId))).toEqual(members);
    }
  });

  it('a group role shows the capability the step contributes, when its finding grants it', () => {
    const c = allChains().find((x) => x.id === 'active-guest-exfil')!;
    const exposure = c.steps.find((s) => s.findingId === 'guest-object-exposure-public-owd')!;
    expect(exposure.capability).toBe('data-read-bulk');
    expect(exposure.techniques).toEqual(['T1213.004']);
  });
});

describe('RULE-117 every named chain starts and ends where its abuse case says', () => {
  const chains = allChains();
  for (const def of NAMED_CHAINS) {
    const declared = def.abuseCase.tactics;
    if (!declared) continue;
    it(`${def.id} starts at ${declared.entry ?? '—'} and reaches ${declared.goal ?? '—'}`, () => {
      const c = chains.find((x) => x.id === def.id)!;
      expect(c).toBeDefined();
      const ranked = c.steps.filter((s) => stepTacticRank(s) !== undefined);
      expect(ranked.length).toBeGreaterThan(0);
      const first = Math.min(...ranked.map((s) => stepTacticRank(s)!));
      if (declared.entry) {
        const entryTactics = ranked.filter((s) => stepTacticRank(s) === first).flatMap(stepTactics);
        expect(entryTactics).toContain(declared.entry);
      }
      if (declared.goal) expect(ranked.flatMap(stepTactics)).toContain(declared.goal);
    });
  }

  it('every declared tactic is a tactic of the pinned release', () => {
    for (const def of NAMED_CHAINS) {
      for (const t of Object.values(def.abuseCase.tactics ?? {})) expect(ATTACK_TACTIC_ORDER).toContain(t);
    }
  });

  it('a chain whose steps carry no technique declares nothing', () => {
    for (const id of ['prompt-injection-blast-radius', 'forcedleak-pattern', 'xss-to-privileged-session']) {
      expect(NAMED_CHAINS.find((d) => d.id === id)!.abuseCase.tactics).toBeUndefined();
    }
  });
});
