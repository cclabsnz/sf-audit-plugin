# Attack Chain Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correlate individually-rated findings into named and emergent attack chains, surface them in a dedicated Attack Paths report section, and fold their severity into the org grade — plus add the three new checks that feed the most important chains.

**Architecture:** A deterministic post-processing pass (`ChainEngine`) runs inside `CheckEngine.run()` after all checks produce findings. It reads a central `CapabilityRegistry` (finding id → granted/required attacker capabilities), matches a curated set of named chains, then discovers emergent chains by capability coverage. Chains flow into `AuditResult.attackChains`, contribute to scoring/grading, and render first in HTML/Markdown/JSON.

**Tech Stack:** TypeScript (ESM, `.js` import specifiers), Jest (ts-jest ESM preset), Salesforce CLI plugin (`@salesforce/sf-plugins-core`).

> **Note — not a git repo:** This project is not under git. Wherever a task says **Checkpoint**, run `npm run build && npm test` and confirm green instead of committing.

> **Run tests with:** `npm test` (or a single file: `npm test -- test/unit/path/to/File.test.ts`). Build with `npm run build`.

---

## File Structure

**Create:**
- `src/chains/Capability.ts` — capability union + source/sink groupings
- `src/chains/AttackChain.ts` — `AttackChain` result interface
- `src/chains/CapabilityRegistry.ts` — finding id → `{ grants, requires }`
- `src/chains/namedChains.ts` — curated named-chain definitions
- `src/chains/ChainEngine.ts` — `correlate(findings)` → `AttackChain[]`
- `src/checks/impl/EscalationPermsCheck.ts`
- `src/checks/impl/CorsAllowlistCheck.ts`
- `src/checks/impl/GuestExecutableApexCheck.ts`
- Tests mirroring each under `test/unit/...`

**Modify:**
- `src/findings/Finding.ts` — optional inline `capabilities` field
- `src/findings/AuditResult.ts` — add `attackChains`
- `src/findings/scoring.ts` — score + grade-gate chains
- `src/checks/CheckEngine.ts` — run ChainEngine, pass chains to `buildAuditResult`
- `src/checks/registry.ts` — register 3 new checks
- `src/renderers/JsonRenderer.ts` (no change needed — serialises whole result; covered by test)
- `src/renderers/MarkdownRenderer.ts` — Attack Paths section
- `src/renderers/HtmlRenderer.ts` — Attack Paths section
- `README.md` — fix "22 checks" → real count; document Attack Paths

---

## Task 1: Capability vocabulary

**Files:**
- Create: `src/chains/Capability.ts`
- Test: `test/unit/chains/Capability.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/chains/Capability.test.ts
import { SOURCE_CAPS, HIGH_IMPACT_SINKS, ALL_CAPABILITIES } from '../../../src/chains/Capability.js';

describe('Capability vocabulary', () => {
  it('has exactly 10 capabilities', () => {
    expect(ALL_CAPABILITIES).toHaveLength(10);
  });

  it('source caps are a subset of all capabilities', () => {
    for (const c of SOURCE_CAPS) expect(ALL_CAPABILITIES).toContain(c);
  });

  it('sinks include org-takeover and data-read-bulk', () => {
    expect(HIGH_IMPACT_SINKS).toContain('org-takeover');
    expect(HIGH_IMPACT_SINKS).toContain('data-read-bulk');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/chains/Capability.test.ts`
Expected: FAIL — cannot find module `Capability.js`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/chains/Capability.ts
export type Capability =
  | 'unauth-foothold'
  | 'low-trust-authenticated'
  | 'data-read'
  | 'data-read-bulk'
  | 'data-write'
  | 'code-exec'
  | 'credential-theft'
  | 'priv-esc'
  | 'org-takeover'
  | 'external-egress';

export const ALL_CAPABILITIES: readonly Capability[] = [
  'unauth-foothold', 'low-trust-authenticated', 'data-read', 'data-read-bulk',
  'data-write', 'code-exec', 'credential-theft', 'priv-esc', 'org-takeover', 'external-egress',
];

/** Capabilities that represent an attacker entry point. */
export const SOURCE_CAPS: readonly Capability[] = ['unauth-foothold', 'low-trust-authenticated'];

/** Capabilities that represent a high-impact outcome (a chain "sink"). */
export const HIGH_IMPACT_SINKS: readonly Capability[] = [
  'org-takeover', 'data-write', 'data-read-bulk', 'credential-theft',
];
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/chains/Capability.test.ts`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `npm run build && npm test`

---

## Task 2: AttackChain interface

**Files:**
- Create: `src/chains/AttackChain.ts`
- Test: `test/unit/chains/AttackChain.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/chains/AttackChain.test.ts
import type { AttackChain } from '../../../src/chains/AttackChain.js';

describe('AttackChain type', () => {
  it('constructs a well-formed chain object', () => {
    const chain: AttackChain = {
      id: 'unauth-bulk-exfil',
      title: 'Unauthenticated bulk exfiltration',
      severity: 'CRITICAL',
      confidence: 'named',
      narrative: 'Guest foothold leads to bulk read.',
      remediation: 'Lock down guest access.',
      steps: [{ findingId: 'guest-user-read-access', checkId: 'guest-user-access', capability: 'unauth-foothold' }],
    };
    expect(chain.steps[0].findingId).toBe('guest-user-read-access');
    expect(chain.confidence).toBe('named');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/chains/AttackChain.test.ts`
Expected: FAIL — cannot find module `AttackChain.js`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/chains/AttackChain.ts
import type { RiskLevel } from '../findings/RiskLevel.js';
import type { Capability } from './Capability.js';

export interface AttackChainStep {
  findingId: string;
  checkId?: string;
  /** The capability this step contributes to the chain. */
  capability: Capability;
  title?: string;
  severity?: RiskLevel;
}

export interface AttackChain {
  id: string;
  title: string;
  severity: RiskLevel;
  confidence: 'named' | 'potential';
  narrative: string;
  remediation: string;
  steps: AttackChainStep[];
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/chains/AttackChain.test.ts`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `npm run build && npm test`

---

## Task 3: Optional inline capabilities on Finding

**Files:**
- Modify: `src/findings/Finding.ts`
- Test: covered indirectly; no new test (type-only change).

- [ ] **Step 1: Add the field**

In `src/findings/Finding.ts`, add this import at the top (after the existing `RiskLevel` import):

```ts
import type { Capability } from '../chains/Capability.js';
```

Then add this property to the `Finding` interface, immediately after the `inconclusive?` field:

```ts
  /**
   * Optional inline attacker-capability declaration for findings produced by
   * chain-aware checks. When present, it overrides the central CapabilityRegistry
   * entry for this finding id. Only honoured for active (non-passed, non-inconclusive) findings.
   */
  capabilities?: { grants?: Capability[]; requires?: Capability[] };
```

- [ ] **Step 2: Verify it compiles**

Run: `npm run build`
Expected: build succeeds (no usages yet).

- [ ] **Step 3: Checkpoint** — `npm run build && npm test`

---

## Task 4: Capability registry

**Files:**
- Create: `src/chains/CapabilityRegistry.ts`
- Test: `test/unit/chains/CapabilityRegistry.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/chains/CapabilityRegistry.test.ts
import { CAPABILITY_REGISTRY, capabilitiesFor } from '../../../src/chains/CapabilityRegistry.js';
import type { Finding } from '../../../src/findings/Finding.js';

function f(id: string, extra: Partial<Finding> = {}): Finding {
  return { id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '', ...extra };
}

describe('CapabilityRegistry', () => {
  it('maps known guest finding to unauth-foothold + data-read', () => {
    expect(CAPABILITY_REGISTRY['guest-user-read-access'].grants).toEqual(
      expect.arrayContaining(['unauth-foothold', 'data-read']),
    );
  });

  it('capabilitiesFor returns registry grants for an active finding', () => {
    expect(capabilitiesFor(f('guest-user-read-access')).grants).toContain('unauth-foothold');
  });

  it('capabilitiesFor returns nothing for passed findings', () => {
    expect(capabilitiesFor(f('guest-user-read-access', { passed: true })).grants).toEqual([]);
  });

  it('capabilitiesFor returns nothing for inconclusive findings', () => {
    expect(capabilitiesFor(f('guest-user-read-access', { inconclusive: true })).grants).toEqual([]);
  });

  it('inline capabilities override the registry', () => {
    const finding = f('some-new-finding', { capabilities: { grants: ['code-exec'] } });
    expect(capabilitiesFor(finding).grants).toEqual(['code-exec']);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/chains/CapabilityRegistry.test.ts`
Expected: FAIL — cannot find module `CapabilityRegistry.js`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/chains/CapabilityRegistry.ts
import type { Capability } from './Capability.js';
import type { Finding } from '../findings/Finding.js';

export interface CapabilityEntry {
  grants?: Capability[];
  requires?: Capability[];
}

/**
 * The full attack model lives here: finding id → attacker capabilities it grants.
 * Keep this the single source of truth so the ~75 checks stay untouched.
 * Every key MUST correspond to a finding id some check can emit (see registry-integrity test).
 */
export const CAPABILITY_REGISTRY: Record<string, CapabilityEntry> = {
  // Guest / unauthenticated foothold
  'guest-user-write-access':       { grants: ['unauth-foothold', 'data-write', 'data-read'] },
  'guest-user-read-access':        { grants: ['unauth-foothold', 'data-read'] },
  'guest-user-sharing-exposure':   { grants: ['unauth-foothold', 'data-read'] },
  'guest-user-baseline':           { grants: ['unauth-foothold'] },
  // External / portal sharing
  'sharing-model-external-write':  { grants: ['low-trust-authenticated', 'data-write', 'data-read-bulk'] },
  'sharing-model-external-read':   { grants: ['low-trust-authenticated', 'data-read-bulk'] },
  // Apex / code execution surfaces
  'portal-exposed-apex-without-sharing': { grants: ['code-exec', 'data-read', 'data-write'] },
  'soql-injection-risk':           { grants: ['code-exec', 'data-read-bulk'] },
  // Sensitive data presence
  'field-level-security-high':     { grants: ['data-read'] },
  'field-level-security-medium':   { grants: ['data-read'] },
  // Credential / secret exposure
  'hardcoded-credentials-found':           { grants: ['credential-theft'] },
  'custom-labels-credential-value-match':  { grants: ['credential-theft'] },
  'custom-labels-credential-name-match':   { grants: ['credential-theft'] },
  'debug-log-active-traces':               { grants: ['credential-theft'] },
  // Egress
  'named-credentials-inventory':     { grants: ['external-egress'] },
  'named-credentials-http-endpoint': { grants: ['external-egress'] },
  'remote-sites-inventory':          { grants: ['external-egress'] },
  // Privileged users
  'users-modify-all-data':  { grants: ['data-read-bulk', 'data-write'] },
  'users-view-all-data':    { grants: ['data-read-bulk'] },
  'users-super-admin-combo':{ grants: ['org-takeover'] },
  'users-author-apex':      { grants: ['code-exec', 'priv-esc'] },
  // New checks (Tasks 8–10)
  'guest-executable-apex-unprotected': { grants: ['code-exec', 'data-read-bulk', 'data-write'] },
  'guest-executable-apex-exposed':     { grants: ['code-exec'] },
  'cors-wildcard-origin':              { grants: ['credential-theft'] },
  'cors-broad-origin':                 { grants: ['credential-theft'] },
  'escalation-perms-found':            { grants: ['priv-esc'] },
};

/** Resolve the effective capabilities for a finding (inline overrides registry; passed/inconclusive yield nothing). */
export function capabilitiesFor(finding: Finding): { grants: Capability[]; requires: Capability[] } {
  if (finding.passed || finding.inconclusive) return { grants: [], requires: [] };
  const inline = finding.capabilities;
  if (inline && (inline.grants || inline.requires)) {
    return { grants: inline.grants ?? [], requires: inline.requires ?? [] };
  }
  const entry = CAPABILITY_REGISTRY[finding.id];
  return { grants: entry?.grants ?? [], requires: entry?.requires ?? [] };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/chains/CapabilityRegistry.test.ts`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `npm run build && npm test`

---

## Task 5: Named chains

**Files:**
- Create: `src/chains/namedChains.ts`
- Test: `test/unit/chains/namedChains.test.ts`

Named chains are small selector functions: given the present capability set and the active findings, each returns its member findings (steps) or `null` if not present.

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/chains/namedChains.test.ts
import { NAMED_CHAINS } from '../../../src/chains/namedChains.js';
import { capabilitiesFor } from '../../../src/chains/CapabilityRegistry.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { Capability } from '../../../src/chains/Capability.js';

function f(id: string): Finding {
  return { id, checkId: id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '' };
}
function present(findings: Finding[]): Set<Capability> {
  const s = new Set<Capability>();
  for (const fd of findings) for (const c of capabilitiesFor(fd).grants) s.add(c);
  return s;
}

describe('NAMED_CHAINS', () => {
  it('unauth-bulk-exfil fires for guest foothold + executable apex', () => {
    const findings = [f('guest-user-read-access'), f('guest-executable-apex-unprotected')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    const steps = chain.match(present(findings), findings);
    expect(steps).not.toBeNull();
    expect(steps!.map((s) => s.id)).toEqual(
      expect.arrayContaining(['guest-user-read-access', 'guest-executable-apex-unprotected']),
    );
  });

  it('unauth-bulk-exfil does NOT fire without a foothold', () => {
    const findings = [f('guest-executable-apex-unprotected')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'unauth-bulk-exfil')!;
    expect(chain.match(present(findings), findings)).toBeNull();
  });

  it('cred-theft-pivot fires for credential-theft + external-egress', () => {
    const findings = [f('hardcoded-credentials-found'), f('named-credentials-inventory')];
    const chain = NAMED_CHAINS.find((c) => c.id === 'cred-theft-pivot')!;
    expect(chain.match(present(findings), findings)).not.toBeNull();
  });

  it('every named chain has a CRITICAL or HIGH severity and non-empty narrative', () => {
    for (const c of NAMED_CHAINS) {
      expect(['CRITICAL', 'HIGH']).toContain(c.severity);
      expect(c.narrative.length).toBeGreaterThan(0);
      expect(c.remediation.length).toBeGreaterThan(0);
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/chains/namedChains.test.ts`
Expected: FAIL — cannot find module `namedChains.js`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/chains/namedChains.ts
import type { RiskLevel } from '../findings/RiskLevel.js';
import type { Finding } from '../findings/Finding.js';
import type { Capability } from './Capability.js';

export interface NamedChainDef {
  id: string;
  title: string;
  severity: RiskLevel;
  narrative: string;
  remediation: string;
  /** Returns the member findings (chain steps) if present in this org, else null. */
  match(present: Set<Capability>, active: Finding[]): Finding[] | null;
}

const has = (s: Set<Capability>, ...caps: Capability[]): boolean => caps.every((c) => s.has(c));
const hasAny = (s: Set<Capability>, ...caps: Capability[]): boolean => caps.some((c) => s.has(c));
const byIds = (active: Finding[], ids: string[]): Finding[] =>
  active.filter((f) => ids.includes(f.id));
const pickGranting = (
  active: Finding[],
  caps: Capability[],
  capabilitiesFor: (f: Finding) => Capability[],
): Finding[] => active.filter((f) => capabilitiesFor(f).some((c) => caps.includes(c)));

export const NAMED_CHAINS: NamedChainDef[] = [
  {
    id: 'unauth-bulk-exfil',
    title: 'Unauthenticated bulk exfiltration',
    severity: 'CRITICAL',
    narrative:
      'An unauthenticated guest foothold combines with guest-reachable code execution or public ' +
      'external sharing to read business data in bulk without any login.',
    remediation:
      'Remove guest object/sharing access, ensure no guest-invokable Apex runs without sharing, ' +
      'and set external OWD to Private. Grant portal access only via sharing sets.',
    match(present, active) {
      if (!has(present, 'unauth-foothold')) return null;
      if (!hasAny(present, 'code-exec', 'data-read-bulk', 'data-write')) return null;
      const steps = byIds(active, [
        'guest-user-read-access', 'guest-user-write-access', 'guest-user-sharing-exposure', 'guest-user-baseline',
        'guest-executable-apex-unprotected', 'guest-executable-apex-exposed',
        'portal-exposed-apex-without-sharing', 'sharing-model-external-read', 'sharing-model-external-write',
        'field-level-security-high', 'field-level-security-medium',
      ]);
      return steps.length >= 2 ? steps : null;
    },
  },
  {
    id: 'standard-to-takeover',
    title: 'Standard user → org takeover',
    severity: 'CRITICAL',
    narrative:
      'A low-trust authenticated user combines with a privilege-escalation permission ' +
      '(assign permission sets, manage users, author apex, modify metadata) to reach full org control.',
    remediation:
      'Remove escalation permissions from non-admin profiles/permission sets and review who holds them.',
    match(present, active) {
      if (!hasAny(present, 'low-trust-authenticated', 'unauth-foothold')) return null;
      if (!hasAny(present, 'priv-esc', 'org-takeover')) return null;
      const steps = byIds(active, [
        'sharing-model-external-read', 'sharing-model-external-write', 'guest-user-baseline',
        'escalation-perms-found', 'users-author-apex', 'users-super-admin-combo',
      ]);
      return steps.length >= 2 ? steps : null;
    },
  },
  {
    id: 'cred-theft-pivot',
    title: 'Credential theft → external pivot',
    severity: 'CRITICAL',
    narrative:
      'Exposed secrets (hardcoded credentials, credentials in custom labels, debug logs, or broad CORS) ' +
      'combine with an external egress path (named credential or remote site) to exfiltrate data to attacker infrastructure.',
    remediation:
      'Rotate and remove exposed secrets, tighten CORS origins, and review external callout endpoints.',
    match(present, active) {
      if (!has(present, 'credential-theft', 'external-egress')) return null;
      const steps = byIds(active, [
        'hardcoded-credentials-found', 'custom-labels-credential-value-match', 'custom-labels-credential-name-match',
        'debug-log-active-traces', 'cors-wildcard-origin', 'cors-broad-origin',
        'named-credentials-inventory', 'named-credentials-http-endpoint', 'remote-sites-inventory',
      ]);
      return steps.length >= 2 ? steps : null;
    },
  },
  {
    id: 'soql-injection-read',
    title: 'SOQL injection → mass read',
    severity: 'HIGH',
    narrative:
      'Injectable dynamic SOQL combines with bulk data readability to let an attacker extract large datasets.',
    remediation:
      'Use bind variables in all dynamic SOQL and enforce CRUD/FLS; restrict bulk read access.',
    match(present, active) {
      if (!has(present, 'code-exec')) return null;
      const inj = byIds(active, ['soql-injection-risk']);
      if (inj.length === 0) return null;
      const sink = byIds(active, [
        'sharing-model-external-read', 'sharing-model-external-write',
        'field-level-security-high', 'field-level-security-medium', 'users-view-all-data',
      ]);
      return sink.length > 0 ? [...inj, ...sink] : null;
    },
  },
  {
    id: 'mfa-bypass-admin',
    title: 'MFA bypass → privileged compromise',
    severity: 'HIGH',
    narrative:
      'Weak MFA enforcement or trusted-IP MFA bypass combines with the presence of highly-privileged ' +
      'accounts, so a credential-stuffing or phishing attacker can take over an admin without a second factor.',
    remediation:
      'Enforce MFA for all internal users, remove trusted-IP MFA bypass ranges, and minimise privileged accounts.',
    match(_present, active) {
      const weakness = byIds(active, [
        'trusted-ip-broad-ranges', 'internal-user-mfa-gaps', 'mfa-portal-users-without-enforcement',
      ]);
      const targets = byIds(active, ['users-modify-all-data', 'users-view-all-data', 'users-super-admin-combo']);
      return weakness.length > 0 && targets.length > 0 ? [...weakness, ...targets] : null;
    },
  },
];
```

> Note: `match` deliberately does not import `capabilitiesFor` to avoid a cycle; the `pickGranting` helper is exported-unused here intentionally removed — only `byIds`, `has`, `hasAny` are used. (If your linter flags `pickGranting`/`capabilitiesFor` param as unused, delete the `pickGranting` const — it is not referenced by any chain.)

- [ ] **Step 4: Remove the unused helper**

Delete the `pickGranting` const from `src/chains/namedChains.ts` (no named chain uses it). Keep `has`, `hasAny`, `byIds`.

- [ ] **Step 5: Run test to verify it passes**

Run: `npm test -- test/unit/chains/namedChains.test.ts`
Expected: PASS.

- [ ] **Step 6: Checkpoint** — `npm run build && npm test`

---

## Task 6: ChainEngine (named + emergent passes)

**Files:**
- Create: `src/chains/ChainEngine.ts`
- Test: `test/unit/chains/ChainEngine.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/chains/ChainEngine.test.ts
import { ChainEngine } from '../../../src/chains/ChainEngine.js';
import type { Finding } from '../../../src/findings/Finding.js';

function f(id: string, extra: Partial<Finding> = {}): Finding {
  return { id, checkId: id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '', ...extra };
}

describe('ChainEngine', () => {
  const engine = new ChainEngine();

  it('emits the named unauth-bulk-exfil chain', () => {
    const chains = engine.correlate([f('guest-user-read-access'), f('guest-executable-apex-unprotected')]);
    const named = chains.find((c) => c.id === 'unauth-bulk-exfil');
    expect(named).toBeDefined();
    expect(named!.confidence).toBe('named');
    expect(named!.severity).toBe('CRITICAL');
  });

  it('ignores passed and inconclusive findings when forming chains', () => {
    const chains = engine.correlate([
      f('guest-user-read-access', { passed: true }),
      f('guest-executable-apex-unprotected', { inconclusive: true }),
    ]);
    expect(chains).toHaveLength(0);
  });

  it('emits a potential chain for an uncovered source→sink pair', () => {
    // low-trust-authenticated (external read) + data-read-bulk present, but no named chain matches
    // (no priv-esc, no code-exec). Use external-read alone: it grants both low-trust-authenticated and data-read-bulk.
    const chains = engine.correlate([f('sharing-model-external-read')]);
    const potential = chains.find((c) => c.confidence === 'potential');
    expect(potential).toBeDefined();
    expect(['HIGH', 'MEDIUM']).toContain(potential!.severity);
  });

  it('suppresses a potential chain already covered by a named chain', () => {
    const chains = engine.correlate([f('hardcoded-credentials-found'), f('named-credentials-inventory')]);
    expect(chains.some((c) => c.id === 'cred-theft-pivot' && c.confidence === 'named')).toBe(true);
    // credential-theft is not a source cap, so no competing potential chain for the same pair
    expect(chains.filter((c) => c.confidence === 'potential' && c.severity === 'CRITICAL')).toHaveLength(0);
  });

  it('sorts named chains before potential, and by descending severity', () => {
    const chains = engine.correlate([
      f('guest-user-read-access'), f('guest-executable-apex-unprotected'), f('sharing-model-external-read'),
    ]);
    if (chains.length >= 2) {
      const namedIdx = chains.findIndex((c) => c.confidence === 'named');
      const potIdx = chains.findIndex((c) => c.confidence === 'potential');
      if (namedIdx !== -1 && potIdx !== -1) expect(namedIdx).toBeLessThan(potIdx);
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/chains/ChainEngine.test.ts`
Expected: FAIL — cannot find module `ChainEngine.js`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/chains/ChainEngine.ts
import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '../findings/RiskLevel.js';
import type { AttackChain, AttackChainStep } from './AttackChain.js';
import type { Capability } from './Capability.js';
import { SOURCE_CAPS, HIGH_IMPACT_SINKS } from './Capability.js';
import { capabilitiesFor } from './CapabilityRegistry.js';
import { NAMED_CHAINS } from './namedChains.js';

const SEVERITY_ORDER: Record<RiskLevel, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

/** Potential-chain severity by terminal sink (capped at HIGH — named chains own CRITICAL). */
const SINK_SEVERITY: Partial<Record<Capability, RiskLevel>> = {
  'org-takeover': 'HIGH',
  'data-write': 'HIGH',
  'data-read-bulk': 'HIGH',
  'credential-theft': 'MEDIUM',
};

const MAX_STEPS = 4;

export class ChainEngine {
  correlate(findings: Finding[]): AttackChain[] {
    const active = findings.filter((f) => !f.passed && !f.inconclusive);

    // Build present capability set + per-finding grants.
    const present = new Set<Capability>();
    const grantsByFinding = new Map<Finding, Capability[]>();
    for (const f of active) {
      const grants = capabilitiesFor(f).grants;
      grantsByFinding.set(f, grants);
      for (const c of grants) present.add(c);
    }

    const namedChains = this.runNamedPass(present, active, grantsByFinding);
    const covered = this.coveredSourceSinkPairs(namedChains, grantsByFinding);
    const potentialChains = this.runEmergentPass(present, active, grantsByFinding, covered);

    return [...namedChains, ...potentialChains].sort(
      (a, b) => this.rank(a) - this.rank(b),
    );
  }

  private rank(c: AttackChain): number {
    // named before potential, then by severity
    return (c.confidence === 'named' ? 0 : 100) + SEVERITY_ORDER[c.severity];
  }

  private stepFor(f: Finding, grants: Capability[]): AttackChainStep {
    return {
      findingId: f.id,
      checkId: f.checkId,
      capability: grants[0] ?? 'data-read',
      title: f.title,
      severity: f.riskLevel,
    };
  }

  private runNamedPass(
    present: Set<Capability>,
    active: Finding[],
    grantsByFinding: Map<Finding, Capability[]>,
  ): AttackChain[] {
    const out: AttackChain[] = [];
    for (const def of NAMED_CHAINS) {
      const members = def.match(present, active);
      if (!members || members.length === 0) continue;
      out.push({
        id: def.id,
        title: def.title,
        severity: def.severity,
        confidence: 'named',
        narrative: def.narrative,
        remediation: def.remediation,
        steps: members.map((f) => this.stepFor(f, grantsByFinding.get(f) ?? [])),
      });
    }
    return out;
  }

  /** Record which (source, sink) capability pairs are already explained by a named chain. */
  private coveredSourceSinkPairs(
    named: AttackChain[],
    grantsByFinding: Map<Finding, Capability[]>,
  ): Set<string> {
    const covered = new Set<string>();
    for (const chain of named) {
      const caps = new Set<Capability>();
      for (const s of chain.steps) caps.add(s.capability);
      for (const src of SOURCE_CAPS) {
        for (const sink of HIGH_IMPACT_SINKS) {
          if (caps.has(src) && caps.has(sink)) covered.add(`${src}->${sink}`);
        }
      }
    }
    // Also use the raw grants of member findings (capability per step is only the first grant).
    for (const chain of named) {
      const memberCaps = new Set<Capability>();
      for (const s of chain.steps) {
        const f = [...grantsByFinding.keys()].find((k) => k.id === s.findingId);
        if (f) for (const c of grantsByFinding.get(f) ?? []) memberCaps.add(c);
      }
      for (const src of SOURCE_CAPS) {
        for (const sink of HIGH_IMPACT_SINKS) {
          if (memberCaps.has(src) && memberCaps.has(sink)) covered.add(`${src}->${sink}`);
        }
      }
    }
    return covered;
  }

  private runEmergentPass(
    present: Set<Capability>,
    active: Finding[],
    grantsByFinding: Map<Finding, Capability[]>,
    covered: Set<string>,
  ): AttackChain[] {
    const out: AttackChain[] = [];
    const seen = new Set<string>();

    for (const src of SOURCE_CAPS) {
      if (!present.has(src)) continue;
      for (const sink of HIGH_IMPACT_SINKS) {
        if (!present.has(sink)) continue;
        const key = `${src}->${sink}`;
        if (covered.has(key) || seen.has(key)) continue;
        seen.add(key);

        // Gather the findings that grant the source and the sink (+ any code-exec bridge).
        const members: Finding[] = [];
        for (const f of active) {
          const g = grantsByFinding.get(f) ?? [];
          if (g.includes(src) || g.includes(sink) || g.includes('code-exec')) members.push(f);
          if (members.length >= MAX_STEPS) break;
        }
        if (members.length === 0) continue;

        out.push({
          id: `potential-${src}-${sink}`,
          title: `Potential attack path: ${this.label(src)} → ${this.label(sink)}`,
          severity: SINK_SEVERITY[sink] ?? 'MEDIUM',
          confidence: 'potential',
          narrative:
            `The org presents a ${this.label(src)} entry point and findings that grant ` +
            `${this.label(sink)}. Review whether these can be combined into an exploit path.`,
          remediation:
            'Treat the contributing findings as a single risk: remediating any one of them breaks the path.',
          steps: members.map((f) => this.stepFor(f, grantsByFinding.get(f) ?? [])),
        });
      }
    }
    return out;
  }

  private label(c: Capability): string {
    return c.replace(/-/g, ' ');
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/chains/ChainEngine.test.ts`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `npm run build && npm test`

---

## Task 7: Wire chains into AuditResult, scoring, and CheckEngine

**Files:**
- Modify: `src/findings/AuditResult.ts`
- Modify: `src/findings/scoring.ts`
- Modify: `src/checks/CheckEngine.ts`
- Test: `test/unit/findings/scoring.test.ts` (add cases)

- [ ] **Step 1: Add the failing scoring test**

Append to `test/unit/findings/scoring.test.ts` (inside the existing top-level `describe`, or add a new one). Add this import at the top if not present:

```ts
import type { AttackChain } from '../../../src/chains/AttackChain.js';
```

Then add:

```ts
describe('buildAuditResult with attack chains', () => {
  function mkCtx() {
    return {
      orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    } as any;
  }
  const cleanFinding = (id: string) => ({
    id, checkId: id, category: 'x', riskLevel: 'LOW' as const, title: id, detail: '', remediation: '', passed: true,
  });
  const criticalChain: AttackChain = {
    id: 'c1', title: 'Takeover', severity: 'CRITICAL', confidence: 'named',
    narrative: '', remediation: '', steps: [],
  };

  it('a CRITICAL chain prevents grade A even when findings are clean', () => {
    const { buildAuditResult } = require('../../../src/findings/scoring.js');
    const result = buildAuditResult(mkCtx(), [cleanFinding('a'), cleanFinding('b')], {}, undefined, [criticalChain]);
    expect(result.attackChains).toHaveLength(1);
    expect(result.grade).not.toBe('A');
  });

  it('defaults attackChains to empty when none supplied', () => {
    const { buildAuditResult } = require('../../../src/findings/scoring.js');
    const result = buildAuditResult(mkCtx(), [cleanFinding('a')], {});
    expect(result.attackChains).toEqual([]);
  });
});
```

> Note: this test uses `require` to avoid clashing with the file's existing ESM imports; if the file already imports `buildAuditResult`, use that import directly instead of `require`.

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/findings/scoring.test.ts`
Expected: FAIL — `buildAuditResult` takes 4 args / `attackChains` missing on result.

- [ ] **Step 3: Add `attackChains` to AuditResult**

In `src/findings/AuditResult.ts`, add the import and field:

```ts
import type { AttackChain } from '../chains/AttackChain.js';
```

Add to the `AuditResult` interface, after `grade`:

```ts
  attackChains: AttackChain[];
```

- [ ] **Step 4: Update `buildAuditResult` to score and gate chains**

In `src/findings/scoring.ts`:

Add the import at the top:

```ts
import type { AttackChain } from '../chains/AttackChain.js';
```

Change the signature to accept chains (append a 5th param):

```ts
export function buildAuditResult(
  ctx: AuditContext,
  findings: Finding[],
  metrics: Partial<OrgMetrics>,
  config: ScoringConfig = DEFAULT_SCORING_CONFIG,
  attackChains: AttackChain[] = [],
): AuditResult {
```

After the existing `totalScore` computation, add chain penalty and extend `maxPossible`:

```ts
  const chainScore = attackChains.reduce((sum, c) => sum + config.riskScores[c.severity], 0);
  const totalWithChains = totalScore + chainScore;
  const maxPossible = (findings.length + attackChains.length) * 10;
  const healthScore = Math.max(
    0,
    100 - Math.round((totalWithChains / Math.max(maxPossible, 1)) * 100),
  );
```

> Remove the original `const maxPossible = findings.length * 10;` and the original `healthScore` block — they are replaced by the two snippets above.

Fold chain severities into the grade-gating counts. Replace the three count lines with:

```ts
  const chainCrit = attackChains.filter((c) => c.severity === 'CRITICAL').length;
  const chainHigh = attackChains.filter((c) => c.severity === 'HIGH').length;
  const chainMed = attackChains.filter((c) => c.severity === 'MEDIUM').length;
  const criticalCount = findings.filter((f) => f.riskLevel === 'CRITICAL').length + chainCrit;
  const highCount = findings.filter((f) => f.riskLevel === 'HIGH').length + chainHigh;
  const mediumCount = findings.filter((f) => f.riskLevel === 'MEDIUM').length + chainMed;
```

Add `attackChains` to the returned object (after `grade,`):

```ts
    attackChains,
```

- [ ] **Step 5: Run ChainEngine inside CheckEngine**

In `src/checks/CheckEngine.ts`:

Add imports:

```ts
import { ChainEngine } from '../chains/ChainEngine.js';
```

At the end of `run()`, replace the final `return buildAuditResult(...)` line with:

```ts
    const attackChains = new ChainEngine().correlate(findings);
    return buildAuditResult(this.ctx, findings, metrics, this.scoringConfig, attackChains);
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `npm test -- test/unit/findings/scoring.test.ts test/unit/checks/CheckEngine.test.ts`
Expected: PASS. If `CheckEngine.test.ts` asserts on the result shape, it should still pass since `attackChains` defaults to `[]` for finding-only inputs.

- [ ] **Step 7: Checkpoint** — `npm run build && npm test`

---

## Task 8: New check — escalation-perms

**Files:**
- Create: `src/checks/impl/EscalationPermsCheck.ts`
- Test: `test/unit/checks/impl/EscalationPermsCheck.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/checks/impl/EscalationPermsCheck.test.ts
import { jest } from '@jest/globals';
import { EscalationPermsCheck } from '../../../../src/checks/impl/EscalationPermsCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(records: unknown[], throws = false): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: throws
        ? (jest.fn() as any).mockRejectedValue(Object.assign(new Error('insufficient access'), { errorCode: 'INSUFFICIENT_ACCESS_RIGHTS' }))
        : (jest.fn() as any).mockResolvedValue(records),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('EscalationPermsCheck', () => {
  const check = new EscalationPermsCheck();

  it('flags users holding escalation permissions', async () => {
    const ctx = makeCtx([
      { AssigneeId: '005a', Assignee: { Username: 'u@x.com' }, PermissionSet: {
        PermissionsManageInternalUsers: true, PermissionsAssignPermissionSets: false,
        PermissionsModifyMetadata: false, PermissionsManageAuthProviders: false,
        PermissionsManageConnectedApps: false, PermissionsManageSession: false,
        PermissionsPasswordNeverExpires: false, PermissionsViewAllUsers: false } },
    ]);
    const result = await check.run(ctx);
    const finding = result.findings.find((f) => f.id === 'escalation-perms-found');
    expect(finding).toBeDefined();
    expect(finding!.riskLevel).toBe('HIGH');
    expect(finding!.affectedItems?.[0].label).toContain('u@x.com');
  });

  it('passes when no escalation permissions are granted', async () => {
    const ctx = makeCtx([]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'escalation-perms-ok' && f.passed)).toBe(true);
  });

  it('returns an inconclusive finding when the query is blocked', async () => {
    const ctx = makeCtx([], true);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.inconclusive)).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/checks/impl/EscalationPermsCheck.test.ts`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Write the implementation**

```ts
// src/checks/impl/EscalationPermsCheck.ts
import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface AssignmentRecord {
  AssigneeId: string;
  Assignee: { Username: string };
  PermissionSet: {
    PermissionsManageInternalUsers: boolean;
    PermissionsAssignPermissionSets: boolean;
    PermissionsModifyMetadata: boolean;
    PermissionsManageAuthProviders: boolean;
    PermissionsManageConnectedApps: boolean;
    PermissionsManageSession: boolean;
    PermissionsPasswordNeverExpires: boolean;
    PermissionsViewAllUsers: boolean;
  };
}

const PERMS: Array<[keyof AssignmentRecord['PermissionSet'], string]> = [
  ['PermissionsManageInternalUsers', 'Manage Internal Users'],
  ['PermissionsAssignPermissionSets', 'Assign Permission Sets'],
  ['PermissionsModifyMetadata', 'Modify Metadata'],
  ['PermissionsManageAuthProviders', 'Manage Auth. Providers'],
  ['PermissionsManageConnectedApps', 'Manage Connected Apps'],
  ['PermissionsManageSession', 'Manage Session Permission Set Activations'],
  ['PermissionsPasswordNeverExpires', 'Password Never Expires'],
  ['PermissionsViewAllUsers', 'View All Users'],
];

export class EscalationPermsCheck implements SecurityCheck {
  readonly id = 'escalation-perms';
  readonly name = 'Privilege Escalation Permissions';
  readonly category = 'Permissions';
  readonly description =
    'Flags users holding lateral-movement/persistence permissions (Manage Internal Users, Assign Permission Sets, Modify Metadata, Manage Auth Providers, etc.)';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const permFields = PERMS.map(([f]) => `PermissionSet.${f}`).join(', ');
    const permWhere = PERMS.map(([f]) => `PermissionSet.${f} = true`).join(' OR ');

    let rows: AssignmentRecord[];
    try {
      rows = await ctx.soql.queryAll<AssignmentRecord>(
        `SELECT AssigneeId, Assignee.Username, ${permFields}
         FROM PermissionSetAssignment
         WHERE (${permWhere}) AND Assignee.IsActive = true`,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'escalation-perms-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Privilege-escalation permission check could not be completed',
        detail: `The PermissionSetAssignment query was not accessible: ${msg}`,
        remediation: 'Grant the audit user "View Setup and Configuration", then re-run the audit.',
      });
      return { findings };
    }

    const affected: Array<{ username: string; userId: string; perm: string }> = [];
    for (const row of rows) {
      for (const [field, label] of PERMS) {
        if (row.PermissionSet[field]) {
          affected.push({ username: row.Assignee?.Username ?? row.AssigneeId, userId: row.AssigneeId, perm: label });
        }
      }
    }

    if (affected.length === 0) {
      findings.push({
        id: 'escalation-perms-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No users hold privilege-escalation permissions',
        detail: 'No active users were found holding lateral-movement or persistence permissions.',
        remediation: 'Continue to review escalation permissions periodically.',
      });
      return { findings };
    }

    findings.push({
      id: 'escalation-perms-found',
      category: this.category,
      riskLevel: 'HIGH',
      title: `${affected.length} escalation-permission grant(s) across active users`,
      detail:
        'These permissions let a user create accounts, reset passwords, assign permission sets, modify metadata, ' +
        'or register auth providers — the primitives an attacker uses for lateral movement and persistence after an initial foothold.',
      remediation:
        'Remove these permissions from non-administrator profiles/permission sets and document who legitimately needs each one.',
      affectedItems: affected.map((a) => ({
        label: `${a.username} — ${a.perm}`,
        url: `${baseUrl}/${a.userId}`,
        note: 'Review and remove if not essential',
      })),
    });

    return { findings };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/checks/impl/EscalationPermsCheck.test.ts`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `npm run build && npm test`

---

## Task 9: New check — cors-allowlist

**Files:**
- Create: `src/checks/impl/CorsAllowlistCheck.ts`
- Test: `test/unit/checks/impl/CorsAllowlistCheck.test.ts`

CORS allowlist entries live in the Tooling API object `CorsWhitelistEntry` (field `UrlPattern`).

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/checks/impl/CorsAllowlistCheck.test.ts
import { jest } from '@jest/globals';
import { CorsAllowlistCheck } from '../../../../src/checks/impl/CorsAllowlistCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(records: unknown[], throws = false): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: throws
        ? (jest.fn() as any).mockRejectedValue(Object.assign(new Error('not accessible'), { errorCode: 'ENTITY_IS_INACCESSIBLE' }))
        : (jest.fn() as any).mockResolvedValue(records),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('CorsAllowlistCheck', () => {
  const check = new CorsAllowlistCheck();

  it('flags a wildcard origin as HIGH', async () => {
    const ctx = makeCtx([{ Id: '1', UrlPattern: 'https://*' }]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'cors-wildcard-origin');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('flags a broad subdomain wildcard as MEDIUM', async () => {
    const ctx = makeCtx([{ Id: '1', UrlPattern: 'https://*.example.com' }]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'cors-broad-origin');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('passes when only exact origins are allow-listed', async () => {
    const ctx = makeCtx([{ Id: '1', UrlPattern: 'https://app.example.com' }]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.passed)).toBe(true);
  });

  it('passes when no CORS entries exist', async () => {
    const ctx = makeCtx([]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'cors-allowlist-none' && f.passed)).toBe(true);
  });

  it('is inconclusive when the object is not accessible', async () => {
    const ctx = makeCtx([], true);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.inconclusive)).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/checks/impl/CorsAllowlistCheck.test.ts`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Write the implementation**

```ts
// src/checks/impl/CorsAllowlistCheck.ts
import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface CorsRecord {
  Id: string;
  UrlPattern: string;
}

export class CorsAllowlistCheck implements SecurityCheck {
  readonly id = 'cors-allowlist';
  readonly name = 'CORS Allowlist';
  readonly category = 'External Connectivity';
  readonly description =
    'Detects wildcard or overly broad CORS allowlist origins that let malicious sites make authenticated browser requests';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/CorsWhitelistEntries/home`;

    let rows: CorsRecord[];
    try {
      rows = await ctx.tooling.query<CorsRecord>('SELECT Id, UrlPattern FROM CorsWhitelistEntry');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'cors-allowlist-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'CORS allowlist could not be read',
        detail: `The CorsWhitelistEntry Tooling query was not accessible: ${msg}`,
        remediation: 'Grant the audit user "View Setup and Configuration", then re-run the audit.',
      });
      return { findings };
    }

    if (rows.length === 0) {
      findings.push({
        id: 'cors-allowlist-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No CORS allowlist entries configured',
        detail: 'No cross-origin allowlist entries exist, so browser-based cross-origin token theft via CORS is not a concern.',
        remediation: 'If CORS entries are added later, allow only exact, fully-qualified HTTPS origins.',
      });
      return { findings };
    }

    // A pattern is a bare wildcard (https://* or *) if it has no host after the scheme.
    const isFullWildcard = (p: string): boolean => /^(https?:\/\/)?\*$/i.test(p.trim());
    // A pattern is a broad subdomain wildcard (https://*.example.com).
    const isSubdomainWildcard = (p: string): boolean => /\*\./.test(p) || /\*/.test(p);

    const wildcard = rows.filter((r) => isFullWildcard(r.UrlPattern));
    const broad = rows.filter((r) => !isFullWildcard(r.UrlPattern) && isSubdomainWildcard(r.UrlPattern));

    if (wildcard.length > 0) {
      findings.push({
        id: 'cors-wildcard-origin',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${wildcard.length} CORS allowlist entry(ies) use a full wildcard origin`,
        detail:
          'A wildcard CORS origin lets ANY website make authenticated cross-origin requests to your org from a logged-in user\'s browser and read the responses — enabling session-scoped data and token theft.',
        remediation: 'Replace wildcard origins with exact, fully-qualified HTTPS origins for each trusted application.',
        affectedItems: wildcard.map((r) => ({ label: r.UrlPattern, url: setupUrl, note: 'Full wildcard — remove immediately' })),
      });
    }

    if (broad.length > 0) {
      findings.push({
        id: 'cors-broad-origin',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${broad.length} CORS allowlist entry(ies) use a broad subdomain wildcard`,
        detail:
          'Subdomain-wildcard CORS origins trust every current and future subdomain, widening the set of sites that can make authenticated cross-origin requests. A single compromised or attacker-controlled subdomain can steal session-scoped data.',
        remediation: 'Pin CORS origins to the exact subdomains that need access rather than a wildcard.',
        affectedItems: broad.map((r) => ({ label: r.UrlPattern, url: setupUrl, note: 'Broad wildcard — narrow to exact origins' })),
      });
    }

    if (wildcard.length === 0 && broad.length === 0) {
      findings.push({
        id: 'cors-allowlist-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${rows.length} CORS allowlist entry(ies) all use exact origins`,
        detail: 'All CORS allowlist entries specify exact origins with no wildcards.',
        remediation: 'Continue to avoid wildcard CORS origins.',
      });
    }

    return { findings };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/checks/impl/CorsAllowlistCheck.test.ts`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `npm run build && npm test`

---

## Task 10: New check — guest-executable-apex

**Files:**
- Create: `src/checks/impl/GuestExecutableApexCheck.ts`
- Test: `test/unit/checks/impl/GuestExecutableApexCheck.test.ts`

This check finds guest-user profiles, the Apex classes they can execute (`SetupEntityAccess` where `SetupEntityType = 'ApexClass'`), and whether those classes run `without sharing`. It reuses `ctx.cache.apexBodies` (populated by `HardcodedCredentialsCheck`) when present to classify sharing, and otherwise reports exposure only.

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/checks/impl/GuestExecutableApexCheck.test.ts
import { jest } from '@jest/globals';
import { GuestExecutableApexCheck } from '../../../../src/checks/impl/GuestExecutableApexCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

interface Mocks { guestUsers: unknown[]; setupAccess: unknown[]; apexNames: unknown[]; }

function makeCtx(m: Mocks, apexBodies?: Array<{ name: string; body: string }>): AuditContext {
  const soqlQueryAll = jest.fn() as any;
  soqlQueryAll
    .mockResolvedValueOnce(m.guestUsers)   // guest users
    .mockResolvedValueOnce(m.setupAccess); // SetupEntityAccess
  const toolingQuery = jest.fn() as any;
  toolingQuery.mockResolvedValue(m.apexNames); // ApexClass id→name
  return {
    soql: { query: jest.fn(), queryAll: soqlQueryAll } as any,
    tooling: { query: toolingQuery, getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: apexBodies ? { apexBodies } : {},
  } as any;
}

describe('GuestExecutableApexCheck', () => {
  const check = new GuestExecutableApexCheck();

  it('passes when there are no guest users', async () => {
    const ctx = makeCtx({ guestUsers: [], setupAccess: [], apexNames: [] });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'guest-executable-apex-none' && f.passed)).toBe(true);
  });

  it('flags an unprotected (without sharing) guest-executable class as CRITICAL', async () => {
    const ctx = makeCtx(
      {
        guestUsers: [{ Id: '005g', ProfileId: '00eP', Username: 'guest@site' }],
        setupAccess: [{ SetupEntityId: '01pA', ParentId: '00eP' }],
        apexNames: [{ Id: '01pA', Name: 'PublicController' }],
      },
      [{ name: 'PublicController', body: 'public without sharing class PublicController { void f(){ [SELECT Id FROM Account]; } }' }],
    );
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'guest-executable-apex-unprotected');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].label).toContain('PublicController');
  });

  it('flags guest-executable classes (no body available) as HIGH exposed', async () => {
    const ctx = makeCtx({
      guestUsers: [{ Id: '005g', ProfileId: '00eP', Username: 'guest@site' }],
      setupAccess: [{ SetupEntityId: '01pA', ParentId: '00eP' }],
      apexNames: [{ Id: '01pA', Name: 'SomeController' }],
    });
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'guest-executable-apex-exposed');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('passes when guests can execute no Apex classes', async () => {
    const ctx = makeCtx({
      guestUsers: [{ Id: '005g', ProfileId: '00eP', Username: 'guest@site' }],
      setupAccess: [],
      apexNames: [],
    });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'guest-executable-apex-ok' && f.passed)).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- test/unit/checks/impl/GuestExecutableApexCheck.test.ts`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Write the implementation**

```ts
// src/checks/impl/GuestExecutableApexCheck.ts
import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface GuestUser { Id: string; ProfileId: string; Username: string; }
interface SetupAccess { SetupEntityId: string; ParentId: string; }
interface ApexName { Id: string; Name: string; }

const WITHOUT_SHARING = /\bwithout\s+sharing\b/i;
const WITH_SHARING = /\bwith\s+sharing\b/i;

export class GuestExecutableApexCheck implements SecurityCheck {
  readonly id = 'guest-executable-apex';
  readonly name = 'Guest-Executable Apex';
  readonly category = 'Access Control';
  readonly description =
    'Finds Apex classes that unauthenticated guest profiles can execute, flagging those that run without sharing — the classic unauthenticated data-exfiltration vector';

  // Use cached Apex bodies (from HardcodedCredentialsCheck) when available to classify sharing.
  readonly dependsOnCache = ['apexBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const guests = await ctx.soql.queryAll<GuestUser>(
      "SELECT Id, ProfileId, Username FROM User WHERE UserType = 'Guest' AND IsActive = true",
    );
    if (guests.length === 0) {
      findings.push({
        id: 'guest-executable-apex-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active guest users — guest-executable Apex not a concern',
        detail: 'There are no active guest users, so no Apex class is reachable by unauthenticated visitors.',
        remediation: 'If an Experience Cloud/Sites guest user is added later, re-run this audit.',
      });
      return { findings };
    }

    const profileIds = [...new Set(guests.map((g) => g.ProfileId))];
    const profileList = profileIds.map((id) => `'${id}'`).join(', ');

    const access = await ctx.soql.queryAll<SetupAccess>(
      `SELECT SetupEntityId, ParentId FROM SetupEntityAccess
       WHERE SetupEntityType = 'ApexClass' AND ParentId IN (${profileList})`,
    );

    const classIds = [...new Set(access.map((a) => a.SetupEntityId))];
    if (classIds.length === 0) {
      findings.push({
        id: 'guest-executable-apex-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Guest profiles cannot execute any Apex classes',
        detail: 'No Apex class execution access is granted to guest user profiles.',
        remediation: 'Continue to avoid granting Apex class access to guest profiles.',
      });
      return { findings };
    }

    const idList = classIds.map((id) => `'${id}'`).join(', ');
    const names = await ctx.tooling.query<ApexName>(
      `SELECT Id, Name FROM ApexClass WHERE Id IN (${idList})`,
    );
    const nameById = new Map(names.map((n) => [n.Id, n.Name]));

    const bodies = ctx.cache.apexBodies ?? [];
    const bodyByName = new Map(bodies.map((b) => [b.name, b.body]));

    const unprotected: string[] = [];
    const exposed: string[] = [];

    for (const id of classIds) {
      const name = nameById.get(id) ?? id;
      const body = bodyByName.get(name);
      if (body && WITHOUT_SHARING.test(body)) {
        unprotected.push(name);
      } else if (body && !WITH_SHARING.test(body)) {
        // No sharing declaration in a guest-reachable class is also dangerous.
        unprotected.push(name);
      } else {
        exposed.push(name);
      }
    }

    const apexUrl = `${baseUrl}/lightning/setup/ApexClasses/home`;

    if (unprotected.length > 0) {
      findings.push({
        id: 'guest-executable-apex-unprotected',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${unprotected.length} guest-executable Apex class(es) run without "with sharing"`,
        detail:
          'These Apex classes can be invoked by unauthenticated guest users AND do not enforce record-level sharing. ' +
          'This is the classic Salesforce guest-user exploit chain: an attacker calls the class and reads or writes ' +
          'business data in bulk with no login. Object-level guest permissions do not mitigate this — the class runs in system context.',
        remediation:
          'Add "with sharing" to every guest-reachable Apex class, enforce CRUD/FLS, and remove guest execution access from any class that does not strictly need it.',
        affectedItems: unprotected.map((n) => ({ label: n, url: apexUrl, note: 'Guest-executable + without/with-no sharing — fix immediately' })),
      });
    }

    if (exposed.length > 0) {
      findings.push({
        id: 'guest-executable-apex-exposed',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${exposed.length} Apex class(es) are executable by guest users`,
        detail:
          'Guest user profiles can execute these Apex classes. Even with "with sharing", any guest-reachable Apex is ' +
          'unauthenticated attack surface and must enforce CRUD/FLS and validate all input.',
        remediation:
          'Review each class for least-privilege: confirm "with sharing", CRUD/FLS checks, and input validation. Remove guest access where unnecessary.',
        affectedItems: exposed.map((n) => ({ label: n, url: apexUrl, note: 'Guest-executable — review for least privilege' })),
      });
    }

    return { findings };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- test/unit/checks/impl/GuestExecutableApexCheck.test.ts`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `npm run build && npm test`

---

## Task 11: Register the three new checks

**Files:**
- Modify: `src/checks/registry.ts`

`GuestExecutableApexCheck` depends on `apexBodies`, which is populated by `HardcodedCredentialsCheck`. It must be registered **after** `HardcodedCredentialsCheck` (line ~81). `EscalationPermsCheck` and `CorsAllowlistCheck` have no cache deps.

- [ ] **Step 1: Add imports**

In `src/checks/registry.ts`, add after the last import (line ~61):

```ts
import { EscalationPermsCheck } from './impl/EscalationPermsCheck.js';
import { CorsAllowlistCheck } from './impl/CorsAllowlistCheck.js';
import { GuestExecutableApexCheck } from './impl/GuestExecutableApexCheck.js';
```

- [ ] **Step 2: Register the no-dep checks**

In the `CHECKS` array, after `new ReportFolderAccessCheck(),` (line ~115), add:

```ts
  new EscalationPermsCheck(),             // priv-esc permission cluster (chain ingredient)
  new CorsAllowlistCheck(),               // wildcard/broad CORS origins (chain ingredient)
```

- [ ] **Step 3: Register the cache-dependent check**

In the "Cache-dependent checks" block (after `new ApexCrudFLSCheck(),` near line ~120), add:

```ts
  new GuestExecutableApexCheck(),  // reads apexBodies — guest-reachable Apex sharing
```

- [ ] **Step 4: Verify cache ordering and tests**

Run: `npm run build && npm test`
Expected: build passes; `CheckEngine.validateCacheOrdering()` does not throw (it runs when a `CheckEngine` is constructed in tests). All green.

- [ ] **Step 5: Checkpoint** — `npm run build && npm test`

---

## Task 12: Render the Attack Paths section

**Files:**
- Modify: `src/renderers/MarkdownRenderer.ts`
- Modify: `src/renderers/HtmlRenderer.ts`
- Test: `test/unit/renderers/MarkdownRenderer.test.ts`, `test/unit/renderers/JsonRenderer.test.ts`, `test/unit/renderers/HtmlRenderer.test.ts`

JSON needs no code change (it serialises the whole result) — we only add a test asserting `attackChains` is present.

- [ ] **Step 1: Write failing renderer tests**

Add a helper + cases. First, in each of the three renderer test files, ensure the mock `AuditResult` includes `attackChains`. Add this sample chain near the top of each test file:

```ts
import type { AttackChain } from '../../../src/chains/AttackChain.js';

const SAMPLE_CHAIN: AttackChain = {
  id: 'unauth-bulk-exfil',
  title: 'Unauthenticated bulk exfiltration',
  severity: 'CRITICAL',
  confidence: 'named',
  narrative: 'Guest foothold + guest-executable Apex without sharing leads to bulk read.',
  remediation: 'Lock down guest access and add with sharing.',
  steps: [
    { findingId: 'guest-user-read-access', checkId: 'guest-user-access', capability: 'unauth-foothold', title: 'Guest read', severity: 'HIGH' },
    { findingId: 'guest-executable-apex-unprotected', checkId: 'guest-executable-apex', capability: 'code-exec', title: 'Unprotected Apex', severity: 'CRITICAL' },
  ],
};
```

In `test/unit/renderers/MarkdownRenderer.test.ts`, add a case (adapt the existing `makeResult`/result builder used in that file to include `attackChains: [SAMPLE_CHAIN]`):

```ts
it('renders an Attack Paths section before findings', () => {
  const md = new MarkdownRenderer().render({ ...baseResult, attackChains: [SAMPLE_CHAIN] } as any);
  expect(md).toContain('## Attack Paths');
  expect(md).toContain('Unauthenticated bulk exfiltration');
  expect(md.indexOf('## Attack Paths')).toBeLessThan(md.indexOf('## Findings'));
});
```

In `test/unit/renderers/JsonRenderer.test.ts`:

```ts
it('includes attackChains in the JSON output', () => {
  const json = JSON.parse(new JsonRenderer().render({ ...baseResult, attackChains: [SAMPLE_CHAIN] } as any));
  expect(json.attackChains).toHaveLength(1);
  expect(json.attackChains[0].id).toBe('unauth-bulk-exfil');
});
```

In `test/unit/renderers/HtmlRenderer.test.ts`:

```ts
it('renders an Attack Paths section with the chain title', () => {
  const html = new HtmlRenderer().render({ ...baseResult, attackChains: [SAMPLE_CHAIN] } as any);
  expect(html).toContain('Attack Paths');
  expect(html).toContain('Unauthenticated bulk exfiltration');
});
```

> Adapt `baseResult`/`makeResult` to whatever the existing test file already uses as its base `AuditResult` fixture; if those fixtures omit `attackChains`, also add `attackChains: []` to them so existing tests still type-check.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm test -- test/unit/renderers/MarkdownRenderer.test.ts test/unit/renderers/JsonRenderer.test.ts test/unit/renderers/HtmlRenderer.test.ts`
Expected: FAIL — `## Attack Paths` not found (Markdown/HTML); JSON test may already pass.

- [ ] **Step 3: Add the Markdown section**

In `src/renderers/MarkdownRenderer.ts`, inside `render()`, immediately **before** the `lines.push(\`## Findings (${result.findings.length})\`);` line, insert:

```ts
    if (result.attackChains && result.attackChains.length > 0) {
      lines.push(`## Attack Paths (${result.attackChains.length})`);
      lines.push('');
      lines.push('_Combinations of findings that together enable an exploit more severe than any single finding._');
      lines.push('');
      for (const c of result.attackChains) {
        const conf = c.confidence === 'named' ? '' : ' _(potential)_';
        lines.push(`### [${c.severity}] ${c.title}${conf}`);
        lines.push('');
        lines.push(c.narrative);
        lines.push('');
        lines.push('**Steps:**');
        lines.push('');
        c.steps.forEach((s, i) => {
          lines.push(`${i + 1}. **${s.title ?? s.findingId}** (${s.severity ?? '—'}) — grants \`${s.capability}\``);
        });
        lines.push('');
        lines.push(`**Remediation:** ${c.remediation}`);
        lines.push('');
        lines.push('---');
        lines.push('');
      }
    }
```

- [ ] **Step 4: Add the HTML section**

Open `src/renderers/HtmlRenderer.ts` and find where the findings section is assembled in `render()` (look for the heading that introduces findings, e.g. a string containing `Findings`). Immediately before that, insert a call to a new private method and define the method. Add this helper method to the class:

```ts
  private renderAttackPaths(result: AuditResult): string {
    if (!result.attackChains || result.attackChains.length === 0) return '';
    const esc = (s: string): string =>
      s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const cards = result.attackChains
      .map((c) => {
        const conf = c.confidence === 'named' ? '' : ' (potential)';
        const steps = c.steps
          .map((s, i) => `<li><strong>${esc(s.title ?? s.findingId)}</strong> (${esc(s.severity ?? '—')}) — grants <code>${esc(s.capability)}</code></li>`)
          .join('');
        return `<div class="attack-chain severity-${c.severity.toLowerCase()}">
  <h3>[${esc(c.severity)}] ${esc(c.title)}${conf}</h3>
  <p>${esc(c.narrative)}</p>
  <ol>${steps}</ol>
  <p class="remediation"><strong>Remediation:</strong> ${esc(c.remediation)}</p>
</div>`;
      })
      .join('\n');
    return `<section class="attack-paths">
  <h2>Attack Paths (${result.attackChains.length})</h2>
  <p class="subtitle">Combinations of findings that together enable an exploit more severe than any single finding.</p>
  ${cards}
</section>`;
  }
```

Then insert this line just before the findings markup is appended to the page body (where the other sections are concatenated into the returned HTML string):

```ts
    // ...inside render(), before the findings section is added to the output:
    const attackPathsHtml = this.renderAttackPaths(result);
```

and include `${attackPathsHtml}` in the template/output string immediately before the findings block. If the renderer builds the HTML via string concatenation rather than a single template literal, push/append `attackPathsHtml` to the output array at the point just before findings.

> The exact insertion point depends on the existing `HtmlRenderer.render()` structure. The requirement: `attackPathsHtml` appears in the output **before** the findings markup and only when chains exist. The test in Step 1 only asserts the section text is present, so any correct placement before findings satisfies it.

- [ ] **Step 5: Run tests to verify they pass**

Run: `npm test -- test/unit/renderers/MarkdownRenderer.test.ts test/unit/renderers/JsonRenderer.test.ts test/unit/renderers/HtmlRenderer.test.ts`
Expected: PASS.

- [ ] **Step 6: Checkpoint** — `npm run build && npm test`

---

## Task 13: Registry integrity test + README update

**Files:**
- Create: `test/unit/chains/registryIntegrity.test.ts`
- Modify: `README.md`

- [ ] **Step 1: Write the integrity test**

This guards against the central registry / named chains referencing finding ids that no check can emit. It scans the check source files for `id: '...'` literals and asserts every registry key and every named-chain referenced id is among them.

```ts
// test/unit/chains/registryIntegrity.test.ts
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CAPABILITY_REGISTRY } from '../../../src/chains/CapabilityRegistry.js';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const implDir = join(__dirname, '../../../src/checks/impl');

function allEmittableFindingIds(): Set<string> {
  const ids = new Set<string>();
  for (const file of readdirSync(implDir)) {
    if (!file.endsWith('.ts')) continue;
    const src = readFileSync(join(implDir, file), 'utf8');
    for (const m of src.matchAll(/id:\s*'([a-z0-9-]+)'/g)) ids.add(m[1]);
  }
  return ids;
}

describe('Capability registry integrity', () => {
  const emittable = allEmittableFindingIds();

  it('every registry key is a finding id some check can emit', () => {
    const orphans = Object.keys(CAPABILITY_REGISTRY).filter((id) => !emittable.has(id));
    expect(orphans).toEqual([]);
  });
});
```

- [ ] **Step 2: Run the test**

Run: `npm test -- test/unit/chains/registryIntegrity.test.ts`
Expected: PASS. If it lists orphans, those finding ids were mistyped in `CapabilityRegistry.ts` — fix them to match the real ids.

- [ ] **Step 3: Update the README**

In `README.md`:
- Replace "runs all 22 security checks" and "instead of all 22" / "the all 22" wording with the actual count. Compute it: the length of `CHECKS` in `src/checks/registry.ts` (74 after this plan). Use "74 security checks" (verify by counting `new ` entries in `registry.ts`).
- Add a short subsection after the checks description:

```markdown
### Attack Paths

Beyond individual findings, the audit correlates findings into **attack chains** —
combinations that together enable an exploit more severe than any single finding
(e.g. an active guest user + a guest-executable Apex class running `without sharing`
+ exposed sensitive fields = unauthenticated bulk data exfiltration). Discovered chains
appear in a dedicated **Attack Paths** section at the top of the report and contribute
their own severity to the health score and grade, so an org cannot score well while a
live exploit path exists.
```

- [ ] **Step 4: Verify the count**

Run: `grep -c 'new ' src/checks/registry.ts`
Expected: a number; use that exact number in the README (subtract any commented-out lines if present — there are none in the registry array).

- [ ] **Step 5: Full suite checkpoint**

Run: `npm run build && npm test`
Expected: entire suite green.

---

## Self-Review Notes (for the implementer)

- **Spec coverage:** capability model (Task 1), registry (Task 4), AttackChain (Task 2), named chains incl. all 5 seed chains (Task 5), emergent pass with guards (Task 6), scoring + grade gating (Task 7), three new checks (Tasks 8–10), registration (Task 11), Attack Paths in HTML/MD/JSON (Task 12), registry integrity test + README (Task 13). Diff/History rendering intentionally omitted (out of scope).
- **Type consistency:** `AttackChain` / `AttackChainStep` defined in Task 2 are used unchanged in Tasks 5–7 and 12. `capabilitiesFor` (Task 4) is used in Tasks 6. `buildAuditResult` 5th param `attackChains` (Task 7) matches the `CheckEngine` call site.
- **Known follow-ups (not in scope):** wiring chains into `DiffRenderer`/`HistoryRenderer`; configurable `chainWeights`; remaining gap checks (LWC/Aura XSS, inbound email, mass-export, named-cred SSRF flags, login flows).
