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
import type { Finding } from '../../../src/findings/Finding.js';
import { buildAuditResult } from '../../../src/findings/scoring.js';
import { CHECK_STRIDE_MAP } from '../../../src/threats/stride.js';
import {
  ATTACK_OUTPUT_ENABLED, ATTACK_RELEASE, ATTACK_TECHNIQUES, CAPABILITY_TECHNIQUES, DETECTION_GAP_TECHNIQUES,
  attackFor, capabilitiesWithoutTechnique, detectsFor, techniqueLabel, techniquesForGrant,
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
  sha256: string;
  techniques: Record<string, { name: string; tactics: string[]; url: string; revoked: boolean; deprecated: boolean }>;
}
const EXTRACT: Extract = JSON.parse(
  readFileSync(join(ROOT, 'test', 'fixtures', 'attack', `enterprise-attack-${ATTACK_RELEASE}-extract.json`), 'utf8'),
);

/** Every registry finding present at once: every named and potential chain that can fire, fires. */
function allChains(): AttackChain[] {
  return new ChainEngine().correlate(Object.keys(CAPABILITY_REGISTRY).map((id) => finding(id)));
}

describe('RULE-106 ATT&CK techniques attach to granted capabilities, not checks', () => {
  it('a finding carries the techniques of every capability it grants, and only those', () => {
    for (const id of Object.keys(CAPABILITY_REGISTRY)) {
      const f = finding(id);
      const expected = new Set(capabilitiesFor(f).grants.flatMap((c) => techniquesForGrant(id, c)));
      expect(new Set(attackFor(f) ?? [])).toEqual(expected);
    }
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
  it('a missing SIEM leaves log tampering unobserved, and grants nothing', () => {
    const f = finding('siem-integration-not-detected');
    expect(detectsFor(f)).toEqual(['T1685.002']);
    expect(attackFor(f)).toBeUndefined();
    expect(detectsFor({ ...f, passed: true })).toBeUndefined();
  });

  it('every detection-gap key is a finding id a check emits', () => {
    const src = readFileSync(join(ROOT, 'src', 'checks', 'impl', 'SiemIntegrationCheck.ts'), 'utf8');
    for (const id of Object.keys(DETECTION_GAP_TECHNIQUES)) expect(src).toContain(`id: '${id}'`);
  });

  it('chain steps never carry a detection technique; inferred steps carry none at all', () => {
    for (const s of allChains().flatMap((c) => c.steps)) {
      expect(s.techniques ?? []).not.toContain('T1685.002');
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
      { ...finding('siem-integration-not-detected'), threats: { stride: ['R' as const], detects: ['T1685.002'] } },
    ];
    const md = new MarkdownRenderer().render(buildAuditResult(ctx(), fs, {}));
    expect(md).toContain('**Threats:** STRIDE S | ATT&CK T1528');
    expect(md).toContain('**Threats:** STRIDE R | leaves unobserved: T1685.002 Disable or Modify Cloud Log');
  });

  it('tagging changes no score or grade (MN-062)', () => {
    const fs = Object.keys(CAPABILITY_REGISTRY).slice(0, 20).map((id) => finding(id));
    const tagged = fs.map((f) => ({ ...f, threats: { attack: attackFor(f), detects: detectsFor(f) } }));
    const a = buildAuditResult(ctx(), fs, {});
    const b = buildAuditResult(ctx(), tagged, {});
    expect({ score: b.healthScore, grade: b.grade }).toEqual({ score: a.healthScore, grade: a.grade });
  });
});
