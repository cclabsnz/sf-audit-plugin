# SF Plugin Audit — Foundation (Sub-project 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold the `@cloudcounsel/sf-plugin-audit` TypeScript plugin, build all infrastructure layers (API clients, Query Registry, domain model, CheckEngine, renderers, CLI command), and produce a runnable `sf audit security --target-org <alias>` command that connects to Salesforce and writes an empty HTML/JSON/MD report.

**Architecture:** Classic 6-layer plugin with strict downward dependencies. TypeScript interfaces at every boundary. No security checks implemented here — that is Sub-project 2. All 9 tasks produce working, tested, committed software.

**Tech Stack:** TypeScript, `@salesforce/core`, `@salesforce/sf-plugins-core`, `@oclif/core`, `zod`, `jest` + `ts-jest`

**Project location:** New separate git repo at:
`/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit/`
(sibling to `cloudcounsel-sf-audit/`)

**Spec:** `../cloudcounsel-sf-audit/docs/superpowers/specs/2026-03-24-sf-audit-native-plugin-design.md`

---

## File Map

Files created across all tasks:

```
cloudcounsel-sf-plugin-audit/
  src/
    api/
      ApiError.ts              — ApiError interface + isApiError guard
      SoqlClient.ts            — SoqlClient interface + QueryResult<T>
      SoqlClientImpl.ts        — implements SoqlClient using @salesforce/core Connection
      ToolingClient.ts         — ToolingClient interface
      ToolingClientImpl.ts     — implements ToolingClient (pagination + per-record GET)
      RestClient.ts            — RestClient interface
      RestClientImpl.ts        — implements RestClient
      index.ts                 — re-exports all api types + impls
    queries/
      QueryDefinition.ts       — zod schema + QueryDefinition type + QueryFileSchema
      QueryRegistry.ts         — load(), get(), execute(), executeQuery(), getAll()
    context/
      OrgInfo.ts               — OrgInfo interface
      OrgMetrics.ts            — OrgMetrics interface + EMPTY_METRICS constant
      AuditCache.ts            — AuditCache interface + HealthCheckRisk + ApexClassBody types
      AuditContext.ts          — AuditContext interface
    checks/
      SecurityCheck.ts         — SecurityCheck interface + CheckResult type
      CheckEngine.ts           — run loop + validateCacheOrdering + buildErrorFinding
      registry.ts              — CHECKS array (empty in this sub-project)
    findings/
      RiskLevel.ts             — RiskLevel union type
      Finding.ts               — Finding interface
      AuditResult.ts           — AuditResult interface
      scoring.ts               — buildAuditResult() scoring + grading function
    renderers/
      AuditRenderer.ts         — AuditRenderer interface
      JsonRenderer.ts          — serialises AuditResult to JSON
      MarkdownRenderer.ts      — renders AuditResult to Markdown
      HtmlRenderer.ts          — renders AuditResult to self-contained HTML page
    commands/
      audit/
        security.ts            — sf audit security command
        wire.ts                — buildApiClients + buildAuditContext + resolveOrgInfo factories
  config/
    queries/
      soql.json                — all standard SOQL query definitions (stubs for now)
      tooling.json             — all Tooling API + rest-type query definitions (stubs for now)
  messages/
    audit.security.md          — oclif UX strings for the security command
  test/
    unit/
      api/
        SoqlClientImpl.test.ts
        ToolingClientImpl.test.ts
      queries/
        QueryRegistry.test.ts
      checks/
        CheckEngine.test.ts
      findings/
        scoring.test.ts
      renderers/
        JsonRenderer.test.ts
        MarkdownRenderer.test.ts
  jest.config.ts
  package.json                 — modified from scaffold; adds zod; switches to jest
  tsconfig.json                — from scaffold (do not modify)
```

---

## Task 1: Scaffold the plugin project

**Files:**
- Create: all of the above (scaffold + manual additions)

- [ ] **Step 1: Navigate to the sf-audit parent directory**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit"
```

- [ ] **Step 2: Run the Salesforce plugin scaffold**

> **Note for agentic executors:** This step is interactive. If running in a non-TTY context, the prompts will hang. Run this step manually in a terminal.

```bash
# Install the generator if not already present
sf plugins inspect @salesforce/plugin-generate 2>/dev/null || sf plugins install @salesforce/plugin-generate

# Run the scaffold (interactive)
sf plugins generate plugin
```

When prompted:
- **Name:** `@cloudcounsel/sf-plugin-audit`
- **Description:** `CloudCounsel Salesforce Security Audit — native sf plugin`
- **ESM / module type:** Yes / ESM (accept default)
- Let it install npm dependencies

The scaffold creates a directory. Its name depends on the generator version — check with:
```bash
ls -d */ | grep -i audit
```

Rename whatever directory was created:
```bash
# Replace <generated-name> with whatever the scaffold created (e.g. sf-plugin-audit)
mv <generated-name> cloudcounsel-sf-plugin-audit
cd cloudcounsel-sf-plugin-audit
```

Initialize git:
```bash
git init
git add .
git commit -m "chore: initial scaffold from sf plugins generate plugin"
```

- [ ] **Step 3: Verify scaffold succeeded, then delete boilerplate**

```bash
# Verify the scaffold created the expected structure before deleting anything
ls src/commands/
```

Expected: a `hello/` subdirectory (or similar example). If missing, the scaffold failed — stop and rerun Step 2.

```bash
rm -rf src/commands/hello
rm -f messages/hello.world.md
rm -rf test/commands/hello
```

- [ ] **Step 4: Add `zod` and jest dependencies**

```bash
npm install zod
npm install --save-dev jest ts-jest @types/jest
```

- [ ] **Step 5: Replace mocha with jest**

Remove mocha config and add jest. Edit `package.json` — replace the `test` script and remove mocharc references:

```json
"scripts": {
  "build": "wireit",
  "lint": "eslint src --ext .ts",
  "test": "jest",
  "test:unit": "jest test/unit"
}
```

Create `jest.config.ts` at project root:

```typescript
import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { useESM: true }],
  },
  testMatch: ['**/*.test.ts'],
};

export default config;
```

- [ ] **Step 6: Create the source directory structure**

```bash
mkdir -p src/api src/queries src/context src/checks/impl src/findings src/renderers src/commands/audit
mkdir -p config/queries
mkdir -p test/unit/api test/unit/queries test/unit/checks test/unit/findings test/unit/renderers
```

- [ ] **Step 7: Verify TypeScript compiles with empty directories**

```bash
npm run build
```

Expected: Success (no errors). If there are missing-file errors, create empty `index.ts` files as needed.

- [ ] **Step 8: Commit the scaffold cleanup**

```bash
git add -A
git commit -m "chore: clean scaffold, add jest + zod, create directory structure"
```

---

## Task 2: Domain model types

**Files:**
- Create: `src/findings/RiskLevel.ts`
- Create: `src/findings/Finding.ts`
- Create: `src/findings/AuditResult.ts`
- Create: `src/context/OrgInfo.ts`
- Create: `src/context/OrgMetrics.ts`
- Create: `src/context/AuditCache.ts`

These are pure TypeScript interfaces — no runtime logic, no tests. Correctness is verified by `tsc`.

- [ ] **Step 1: Write `src/findings/RiskLevel.ts`**

```typescript
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export const RISK_LEVELS: readonly RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
```

- [ ] **Step 2: Write `src/findings/Finding.ts`**

```typescript
import type { RiskLevel } from './RiskLevel.js';

export interface Finding {
  id: string;
  category: string;
  riskLevel: RiskLevel;
  title: string;
  detail: string;
  remediation: string;
  affectedItems?: string[];
}
```

- [ ] **Step 3: Write `src/context/OrgInfo.ts`**

```typescript
export interface OrgInfo {
  id: string;
  name: string;
  type: string;
  isSandbox: boolean;
  instance: string;
}
```

- [ ] **Step 4: Write `src/context/OrgMetrics.ts`**

```typescript
export interface OrgMetrics {
  totalActiveUsers: number;
  modifyAllDataUsersCount: number;
  viewAllDataUsersCount: number;
  permissionSetCount: number;
  profileCount: number;
  apexClassCount: number;
  apexTriggerCount: number;
  codeCoveragePercent: number;
  failedLogins30d: number;
  inactiveUsers90d: number;
  connectedAppsCount: number;
  remoteSitesCount: number;
  namedCredentialsCount: number;
  healthCheckScore: number;
}

// Used by scoring.ts to fill any metrics not populated by checks
export const EMPTY_METRICS: OrgMetrics = {
  totalActiveUsers: 0,
  modifyAllDataUsersCount: 0,
  viewAllDataUsersCount: 0,
  permissionSetCount: 0,
  profileCount: 0,
  apexClassCount: 0,
  apexTriggerCount: 0,
  codeCoveragePercent: 0,
  failedLogins30d: 0,
  inactiveUsers90d: 0,
  connectedAppsCount: 0,
  remoteSitesCount: 0,
  namedCredentialsCount: 0,
  healthCheckScore: 0,
};
```

- [ ] **Step 5: Write `src/context/AuditCache.ts`**

```typescript
// HealthCheckRisk: one row from the Salesforce Health Check API
export interface HealthCheckRisk {
  setting: string;
  riskType: string;
  value: string;
  score: number;
}

// ApexClassBody: the subset of ApexClass fields checks need for scanning
export interface ApexClassBody {
  name: string;
  body: string;
}

// AuditCache is mutable shared state passed through AuditContext.
// Keys are typed — rename any field and every check referencing it gets a compile error.
export interface AuditCache {
  healthCheckRisks?: HealthCheckRisk[];
  apexBodies?: ApexClassBody[];
  namedCredentialEndpoints?: string[];
  remoteSiteUrls?: string[];
  healthCloudInstalled?: boolean;
}
```

- [ ] **Step 6: Write `src/findings/AuditResult.ts`**

```typescript
import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';

export interface AuditResult {
  generatedAt: Date;
  orgId: string;
  orgName: string;
  orgType: string;
  isSandbox: boolean;
  instance: string;
  findings: Finding[];
  metrics: OrgMetrics;
  healthScore: number;  // 0–100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}
```

- [ ] **Step 7: Verify TypeScript compiles**

```bash
npm run build
```

Expected: Success with no type errors.

- [ ] **Step 8: Commit**

```bash
git add src/findings/RiskLevel.ts src/findings/Finding.ts src/findings/AuditResult.ts \
        src/context/OrgInfo.ts src/context/OrgMetrics.ts src/context/AuditCache.ts
git commit -m "feat: add domain model types (Finding, AuditResult, AuditCache, OrgMetrics)"
```

---

## Task 3: API clients

**Files:**
- Create: `src/api/ApiError.ts`
- Create: `src/api/SoqlClient.ts`
- Create: `src/api/SoqlClientImpl.ts`
- Create: `src/api/ToolingClient.ts`
- Create: `src/api/ToolingClientImpl.ts`
- Create: `src/api/RestClient.ts`
- Create: `src/api/RestClientImpl.ts`
- Create: `src/api/index.ts`
- Test: `test/unit/api/SoqlClientImpl.test.ts`
- Test: `test/unit/api/ToolingClientImpl.test.ts`

> **Known gap:** `RestClientImpl` has no unit test — it wraps a single `conn.request()` call with path normalisation. It will be exercised by the smoke test in Task 10.

- [ ] **Step 1: Write the failing tests**

`test/unit/api/SoqlClientImpl.test.ts`:

```typescript
import { SoqlClientImpl } from '../../../src/api/SoqlClientImpl.js';

describe('SoqlClientImpl', () => {
  let fakeConn: any;
  let client: SoqlClientImpl;

  beforeEach(() => {
    fakeConn = {
      query: jest.fn(),
      queryAll: jest.fn(),
    };
    client = new SoqlClientImpl(fakeConn);
  });

  describe('query()', () => {
    it('returns totalSize, done, and records from Connection.query', async () => {
      fakeConn.query.mockResolvedValue({
        totalSize: 2,
        done: true,
        records: [{ Id: '001' }, { Id: '002' }],
      });

      const result = await client.query<{ Id: string }>('SELECT Id FROM Account');

      expect(result.totalSize).toBe(2);
      expect(result.done).toBe(true);
      expect(result.records).toHaveLength(2);
      expect(fakeConn.query).toHaveBeenCalledWith('SELECT Id FROM Account');
    });

    it('returns empty records array when Connection returns undefined records', async () => {
      fakeConn.query.mockResolvedValue({ totalSize: 0, done: true, records: undefined });
      const result = await client.query('SELECT Id FROM Account');
      expect(result.records).toEqual([]);
    });
  });

  describe('queryAll()', () => {
    it('returns flattened records from Connection.queryAll', async () => {
      fakeConn.queryAll.mockResolvedValue({
        totalSize: 3,
        done: true,
        records: [{ Id: 'a' }, { Id: 'b' }, { Id: 'c' }],
      });

      const result = await client.queryAll<{ Id: string }>('SELECT Id FROM User');

      expect(result).toHaveLength(3);
      expect(result[0].Id).toBe('a');
    });

    it('returns empty array when no records', async () => {
      fakeConn.queryAll.mockResolvedValue({ totalSize: 0, done: true, records: undefined });
      const result = await client.queryAll('SELECT Id FROM User');
      expect(result).toEqual([]);
    });
  });
});
```

`test/unit/api/ToolingClientImpl.test.ts`:

```typescript
import { ToolingClientImpl } from '../../../src/api/ToolingClientImpl.js';

describe('ToolingClientImpl', () => {
  let fakeConn: any;
  let client: ToolingClientImpl;

  beforeEach(() => {
    fakeConn = {
      tooling: {
        query: jest.fn(),
        // Note: conn.tooling has no queryMore — pagination uses conn.request() directly
      },
      request: jest.fn(),
      getApiVersion: jest.fn().mockReturnValue('62.0'),
    };
    client = new ToolingClientImpl(fakeConn);
  });

  describe('query()', () => {
    it('returns records from a single page', async () => {
      fakeConn.tooling.query.mockResolvedValue({
        totalSize: 2,
        done: true,
        records: [{ Id: '001' }, { Id: '002' }],
        nextRecordsUrl: undefined,
      });

      const result = await client.query<{ Id: string }>('SELECT Id FROM ApexClass');

      expect(result).toHaveLength(2);
      expect(fakeConn.tooling.queryMore).not.toHaveBeenCalled();
    });

    it('follows pagination via nextRecordsUrl using conn.request()', async () => {
      fakeConn.tooling.query.mockResolvedValue({
        done: false,
        records: [{ Id: '001' }],
        nextRecordsUrl: '/services/data/v62.0/tooling/query/01g-next',
      });
      // Second page comes via conn.request() (not tooling.queryMore — that doesn't exist)
      fakeConn.request.mockResolvedValueOnce({
        done: true,
        records: [{ Id: '002' }],
        nextRecordsUrl: undefined,
      });

      const result = await client.query<{ Id: string }>('SELECT Id FROM ApexClass');

      expect(result).toHaveLength(2);
      expect(fakeConn.request).toHaveBeenCalledWith('/services/data/v62.0/tooling/query/01g-next');
    });
  });

  describe('getRecord()', () => {
    it('calls conn.request with the correct tooling REST path', async () => {
      const mockRecord = { Id: 'abc', Metadata: { ipRelaxation: 'BYPASS' } };
      fakeConn.request.mockResolvedValue(mockRecord);

      const result = await client.getRecord<typeof mockRecord>('ConnectedApplication', 'abc');

      expect(fakeConn.request).toHaveBeenCalledWith(
        '/services/data/v62.0/tooling/sobjects/ConnectedApplication/abc/'
      );
      expect(result).toEqual(mockRecord);
    });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- test/unit/api
```

Expected: FAIL — modules not found.

- [ ] **Step 3: Write `src/api/ApiError.ts`**

```typescript
export interface ApiError extends Error {
  errorCode: string;
  statusCode: number;
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof Error && 'errorCode' in err;
}
```

- [ ] **Step 4: Write `src/api/SoqlClient.ts`**

```typescript
// QueryResult mirrors @salesforce/core Connection.query() return shape
export interface QueryResult<T> {
  totalSize: number;
  done: boolean;
  records: T[];
}

export interface SoqlClient {
  // Use when totalSize matters (COUNT queries, pagination metadata)
  query<T>(soql: string): Promise<QueryResult<T>>;
  // Use when you want all records — follows nextRecordsUrl automatically
  queryAll<T>(soql: string): Promise<T[]>;
}
```

- [ ] **Step 5: Write `src/api/SoqlClientImpl.ts`**

```typescript
import type { Connection } from '@salesforce/core';
import type { QueryResult, SoqlClient } from './SoqlClient.js';

export class SoqlClientImpl implements SoqlClient {
  constructor(private readonly conn: Connection) {}

  async query<T>(soql: string): Promise<QueryResult<T>> {
    const result = await this.conn.query<T>(soql);
    return {
      totalSize: result.totalSize,
      done: result.done,
      records: result.records ?? [],
    };
  }

  async queryAll<T>(soql: string): Promise<T[]> {
    const result = await this.conn.queryAll<T>(soql);
    return result.records ?? [];
  }
}
```

- [ ] **Step 6: Write `src/api/ToolingClient.ts`**

```typescript
export interface ToolingClient {
  // Paginated Tooling SOQL query — returns all records across pages
  query<T>(soql: string): Promise<T[]>;
  // Per-record fetch: /tooling/sobjects/{type}/{id}/
  // Used by IpRestrictionsCheck to get ConnectedApplication Metadata blob
  getRecord<T>(type: string, id: string): Promise<T>;
}
```

- [ ] **Step 7: Write `src/api/ToolingClientImpl.ts`**

```typescript
import type { Connection } from '@salesforce/core';
import type { ToolingClient } from './ToolingClient.js';

export class ToolingClientImpl implements ToolingClient {
  constructor(private readonly conn: Connection) {}

  async query<T>(soql: string): Promise<T[]> {
    const result = await this.conn.tooling.query<T>(soql) as any;
    let records: T[] = result.records ?? [];
    let nextUrl: string | undefined = result.nextRecordsUrl;

    // conn.tooling does not expose queryMore — use conn.request() directly for pagination
    while (nextUrl) {
      const next = await this.conn.request<{ records: T[]; nextRecordsUrl?: string; done: boolean }>(nextUrl);
      records = records.concat(next.records ?? []);
      nextUrl = next.nextRecordsUrl;
    }

    return records;
  }

  async getRecord<T>(type: string, id: string): Promise<T> {
    const version = this.conn.getApiVersion();
    return this.conn.request<T>(
      `/services/data/v${version}/tooling/sobjects/${type}/${id}/`
    );
  }
}
```

- [ ] **Step 8: Write `src/api/RestClient.ts`**

```typescript
export interface RestClient {
  // path is relative to /services/data/vXX.0/ e.g. '/limits' or '/sobjects/Account/describe/'
  get<T>(path: string): Promise<T>;
}
```

- [ ] **Step 9: Write `src/api/RestClientImpl.ts`**

```typescript
import type { Connection } from '@salesforce/core';
import type { RestClient } from './RestClient.js';

export class RestClientImpl implements RestClient {
  constructor(private readonly conn: Connection) {}

  async get<T>(path: string): Promise<T> {
    const version = this.conn.getApiVersion();
    const normalised = path.startsWith('/') ? path : `/${path}`;
    return this.conn.request<T>(`/services/data/v${version}${normalised}`);
  }
}
```

- [ ] **Step 10: Write `src/api/index.ts`**

```typescript
export type { QueryResult, SoqlClient } from './SoqlClient.js';
export type { ToolingClient } from './ToolingClient.js';
export type { RestClient } from './RestClient.js';
export type { ApiError } from './ApiError.js';
export { isApiError } from './ApiError.js';
export { SoqlClientImpl } from './SoqlClientImpl.js';
export { ToolingClientImpl } from './ToolingClientImpl.js';
export { RestClientImpl } from './RestClientImpl.js';
```

- [ ] **Step 11: Run tests**

```bash
npm test -- test/unit/api
```

Expected: All 6 tests pass.

- [ ] **Step 12: Commit**

```bash
git add src/api/ test/unit/api/
git commit -m "feat: add API client interfaces and implementations (SoqlClient, ToolingClient, RestClient)"
```

---

## Task 4: Query Registry

**Files:**
- Create: `src/queries/QueryDefinition.ts`
- Create: `src/queries/QueryRegistry.ts`
- Create: `config/queries/soql.json`
- Create: `config/queries/tooling.json`
- Test: `test/unit/queries/QueryRegistry.test.ts`

- [ ] **Step 1: Write the failing tests**

`test/unit/queries/QueryRegistry.test.ts`:

```typescript
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { QueryRegistry } from '../../../src/queries/QueryRegistry.js';

function makeTempConfig(soql: Record<string, unknown>, tooling: Record<string, unknown>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qr-test-'));
  const queryDir = path.join(dir, 'config', 'queries');
  fs.mkdirSync(queryDir, { recursive: true });
  fs.writeFileSync(path.join(queryDir, 'soql.json'), JSON.stringify(soql));
  fs.writeFileSync(path.join(queryDir, 'tooling.json'), JSON.stringify(tooling));
  return dir;
}

const VALID_SOQL = {
  activeUsers: {
    api: 'soql',
    soql: 'SELECT Id FROM User WHERE IsActive = true',
    description: 'Active users',
  },
  profileIpRanges: {
    api: 'soql',
    soql: 'SELECT ProfileId FROM ProfileLoginIpRange',
    description: 'IP ranges',
    fallbackOnError: true,
  },
};

const VALID_TOOLING = {
  apexClasses: {
    api: 'tooling',
    soql: 'SELECT Id, Name, Body FROM ApexClass',
    description: 'Apex classes',
  },
};

describe('QueryRegistry', () => {
  describe('load()', () => {
    it('loads valid JSON files without error', () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      expect(() => QueryRegistry.load(configDir)).not.toThrow();
    });

    it('throws on invalid query entry (missing description)', () => {
      const bad = { q1: { api: 'soql', soql: 'SELECT Id FROM User' } };
      const configDir = makeTempConfig(bad, {});
      expect(() => QueryRegistry.load(configDir)).toThrow(/QueryRegistry/);
    });

    it('throws on duplicate key across files', () => {
      const dup = { activeUsers: { api: 'tooling', soql: 'SELECT Id FROM User', description: 'd' } };
      const configDir = makeTempConfig(VALID_SOQL, dup);
      expect(() => QueryRegistry.load(configDir)).toThrow(/duplicate key/);
    });
  });

  describe('get()', () => {
    it('returns the query definition for a known key', () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const def = registry.get('activeUsers');
      expect(def.api).toBe('soql');
      expect(def.soql).toContain('IsActive');
    });

    it('throws a named error for an unknown key', () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      expect(() => registry.get('nonExistentKey')).toThrow("unknown query key 'nonExistentKey'");
    });
  });

  describe('execute()', () => {
    it('calls ctx.soql.queryAll for api=soql entries', async () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const mockCtx = { soql: { queryAll: jest.fn().mockResolvedValue([{ Id: '001' }]) } } as any;

      const result = await registry.execute('activeUsers', mockCtx);

      expect(mockCtx.soql.queryAll).toHaveBeenCalledWith(
        'SELECT Id FROM User WHERE IsActive = true'
      );
      expect(result).toEqual([{ Id: '001' }]);
    });

    it('calls ctx.tooling.query for api=tooling entries', async () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const mockCtx = { tooling: { query: jest.fn().mockResolvedValue([]) } } as any;

      await registry.execute('apexClasses', mockCtx);

      expect(mockCtx.tooling.query).toHaveBeenCalled();
    });

    it('returns null (not throws) when fallbackOnError=true and query fails', async () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const mockCtx = {
        soql: { queryAll: jest.fn().mockRejectedValue(new Error('UNSUPPORTED')) },
      } as any;

      const result = await registry.execute('profileIpRanges', mockCtx);

      expect(result).toBeNull();
    });

    it('throws when fallbackOnError=false and query fails', async () => {
      const configDir = makeTempConfig(VALID_SOQL, VALID_TOOLING);
      const registry = QueryRegistry.load(configDir);
      const mockCtx = {
        soql: { queryAll: jest.fn().mockRejectedValue(new Error('API_ERROR')) },
      } as any;

      await expect(registry.execute('activeUsers', mockCtx)).rejects.toThrow('API_ERROR');
    });

    it('throws for api=rest entries (caller must use ctx.rest.get() directly)', async () => {
      const restEntry = {
        orgLimits: { api: 'rest', path: '/limits', description: 'Org limits' },
      };
      const configDir = makeTempConfig(restEntry, {});
      const registry = QueryRegistry.load(configDir);

      await expect(registry.execute('orgLimits', {} as any)).rejects.toThrow(/rest/);
    });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- test/unit/queries
```

Expected: FAIL — modules not found.

- [ ] **Step 3: Write `src/queries/QueryDefinition.ts`**

```typescript
import { z } from 'zod';

export const QueryDefinitionSchema = z.object({
  api: z.enum(['soql', 'tooling', 'rest']),
  soql: z.string().optional(),
  path: z.string().optional(),
  description: z.string(),
  fallbackOnError: z.boolean().default(false),
  minApiVersion: z.string().optional(),
});

export type QueryDefinition = z.infer<typeof QueryDefinitionSchema>;

// Used to parse an entire JSON file of query definitions
export const QueryFileSchema = z.record(z.string(), QueryDefinitionSchema);
export type QueryFile = z.infer<typeof QueryFileSchema>;
```

- [ ] **Step 4: Write `src/queries/QueryRegistry.ts`**

```typescript
import * as fs from 'node:fs';
import * as path from 'node:path';
import { QueryFileSchema, type QueryDefinition } from './QueryDefinition.js';
import type { AuditContext } from '../context/AuditContext.js';
import type { QueryResult } from '../api/SoqlClient.js';

function warnFallback(id: string, err: unknown): void {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[QueryRegistry] Query '${id}' failed (fallbackOnError): ${msg}\n`);
}

export class QueryRegistry {
  private readonly map: ReadonlyMap<string, QueryDefinition>;

  private constructor(entries: Map<string, QueryDefinition>) {
    this.map = entries;
  }

  static load(configDir: string): QueryRegistry {
    const queryDir = path.join(configDir, 'config', 'queries');
    const files = ['soql.json', 'tooling.json'];
    const entries = new Map<string, QueryDefinition>();

    for (const file of files) {
      const filePath = path.join(queryDir, file);
      let raw: unknown;
      try {
        raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      } catch (err) {
        throw new Error(
          `QueryRegistry: failed to read ${filePath}: ${(err as Error).message}`
        );
      }

      const parsed = QueryFileSchema.safeParse(raw);
      if (!parsed.success) {
        throw new Error(
          `QueryRegistry: invalid schema in ${file}:\n${parsed.error.message}`
        );
      }

      for (const [key, def] of Object.entries(parsed.data)) {
        if (entries.has(key)) {
          throw new Error(
            `QueryRegistry: duplicate key '${key}' found in ${file}`
          );
        }
        entries.set(key, def);
      }
    }

    return new QueryRegistry(entries);
  }

  get(id: string): QueryDefinition {
    const def = this.map.get(id);
    if (!def) {
      throw new Error(`QueryRegistry: unknown query key '${id}'`);
    }
    return def;
  }

  // Use for queries where you want all records (api=soql or api=tooling).
  // Returns null (instead of throwing) when fallbackOnError=true and the query fails.
  // For api=rest entries, throws — use ctx.rest.get() or ctx.tooling.getRecord() directly.
  async execute<T>(id: string, ctx: AuditContext): Promise<T[] | null> {
    const def = this.get(id);
    try {
      if (def.api === 'soql') {
        if (!def.soql) throw new Error(`Query '${id}' has api='soql' but no soql field`);
        return ctx.soql.queryAll<T>(def.soql);
      }
      if (def.api === 'tooling') {
        if (!def.soql) throw new Error(`Query '${id}' has api='tooling' but no soql field`);
        return ctx.tooling.query<T>(def.soql);
      }
      throw new Error(
        `QueryRegistry.execute: api='rest' entries cannot be executed here. ` +
        `Use ctx.rest.get() or ctx.tooling.getRecord() directly. Key: '${id}'`
      );
    } catch (err) {
      if (def.fallbackOnError) {
        warnFallback(id, err);
        return null;
      }
      throw err;
    }
  }

  // Use for SOQL queries where totalSize matters (e.g. COUNT() results).
  // Returns null when fallbackOnError=true and the query fails.
  async executeQuery<T>(id: string, ctx: AuditContext): Promise<QueryResult<T> | null> {
    const def = this.get(id);
    if (def.api !== 'soql') {
      throw new Error(`QueryRegistry.executeQuery: query '${id}' must have api='soql'`);
    }
    if (!def.soql) {
      throw new Error(`Query '${id}' has api='soql' but no soql field`);
    }
    try {
      return ctx.soql.query<T>(def.soql);
    } catch (err) {
      if (def.fallbackOnError) {
        warnFallback(id, err);
        return null;
      }
      throw err;
    }
  }

  getAll(): ReadonlyMap<string, QueryDefinition> {
    return this.map;
  }
}
```

- [ ] **Step 5: Write `config/queries/soql.json`**

These are stubs — Sub-project 2 will add the full query list as each check is ported.

```json
{
  "activeStandardUsers": {
    "api": "soql",
    "soql": "SELECT Id, Username, ProfileId FROM User WHERE IsActive = true AND UserType = 'Standard'",
    "description": "All active standard users — used by MFA, admin, and inactive checks"
  },
  "profileIpRanges": {
    "api": "soql",
    "soql": "SELECT ProfileId, StartAddress, EndAddress FROM ProfileLoginIpRange",
    "description": "Profile login IP ranges — not queryable in all org configurations",
    "fallbackOnError": true
  },
  "orgLimits": {
    "api": "rest",
    "path": "/limits",
    "description": "Org API governor limits — fetched via ctx.rest.get('/limits')"
  },
  "sobjectDescribe": {
    "api": "rest",
    "path": "/sobjects/{sobjectType}/describe/",
    "description": "SObject describe for OWD/sharing model — called per object via ctx.rest.get(). Used by SharingModelCheck.",
    "fallbackOnError": true
  }
}
```

- [ ] **Step 6: Write `config/queries/tooling.json`**

```json
{
  "apexClasses": {
    "api": "tooling",
    "soql": "SELECT Id, Name, Body, LengthWithoutComments, NamespacePrefix FROM ApexClass WHERE NamespacePrefix = null",
    "description": "All custom Apex classes — used by HardcodedCredentialsCheck (populates apexBodies cache) and ApexSharingCheck"
  },
  "activeFlows": {
    "api": "tooling",
    "soql": "SELECT Id, MasterLabel, ProcessType, Status, RunInMode FROM Flow WHERE Status = 'Active'",
    "description": "Active Flow versions — used by FlowSecurityCheck. Note: FlowDefinitionView not supported in all API versions."
  },
  "connectedAppsBasic": {
    "api": "tooling",
    "soql": "SELECT Id, Name FROM ConnectedApplication",
    "description": "Connected App ID list — used by IpRestrictionsCheck to fetch per-record Metadata blobs"
  },
  "connectedAppDetail": {
    "api": "rest",
    "path": "tooling/sobjects/ConnectedApplication/{id}/",
    "description": "Per-record Connected App metadata — ipRelaxation lives in Metadata blob, not a SOQL column. Call via ctx.tooling.getRecord('ConnectedApplication', id).",
    "fallbackOnError": true
  },
  "connectedAppsStandard": {
    "api": "soql",
    "soql": "SELECT Id, Name, Status, StartUrl FROM ConnectedApplication",
    "description": "Connected Apps basic info — used by ConnectedAppsCheck via standard SOQL. Note: lives in tooling.json alongside connectedAppsBasic for discoverability."
  }
}
```

- [ ] **Step 7: Run tests**

```bash
npm test -- test/unit/queries
```

Expected: All 8 tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/queries/ config/queries/ test/unit/queries/
git commit -m "feat: add QueryRegistry with zod validation + query JSON stubs"
```

---

## Task 5: SecurityCheck interface and AuditContext

**Files:**
- Create: `src/checks/SecurityCheck.ts`
- Create: `src/context/AuditContext.ts`

Pure interfaces — verified by `tsc`. No unit tests.

- [ ] **Step 1: Write `src/checks/SecurityCheck.ts`**

```typescript
import type { AuditContext } from '../context/AuditContext.js';
import type { Finding } from '../findings/Finding.js';
import type { AuditCache } from '../context/AuditCache.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';

// CheckResult is what every check's run() must return.
// findings: zero or more issues found.
// metrics: optional partial OrgMetrics contribution (e.g. totalActiveUsers from UsersAndAdminsCheck).
export interface CheckResult {
  findings: Finding[];
  metrics?: Partial<OrgMetrics>;
}

export interface SecurityCheck {
  readonly id: string;
  readonly name: string;
  readonly category: string;

  // Typed as keyof AuditCache — rename a cache key → compile errors here in every check
  readonly dependsOnCache?: ReadonlyArray<keyof AuditCache>;
  readonly populatesCache?: ReadonlyArray<keyof AuditCache>;

  run(ctx: AuditContext): Promise<CheckResult>;
}
```

- [ ] **Step 2: Write `src/context/AuditContext.ts`**

```typescript
import type { SoqlClient } from '../api/SoqlClient.js';
import type { ToolingClient } from '../api/ToolingClient.js';
import type { RestClient } from '../api/RestClient.js';
import type { QueryRegistry } from '../queries/QueryRegistry.js';
import type { OrgInfo } from './OrgInfo.js';
import type { AuditCache } from './AuditCache.js';

export interface AuditContext {
  readonly soql: SoqlClient;
  readonly tooling: ToolingClient;
  readonly rest: RestClient;
  readonly queries: QueryRegistry;
  readonly orgInfo: OrgInfo;
  cache: AuditCache;  // mutable — checks read and write typed keys
}
```

- [ ] **Step 3: Verify TypeScript compiles**

```bash
npm run build
```

Expected: Success.

- [ ] **Step 4: Commit**

```bash
git add src/checks/SecurityCheck.ts src/context/AuditContext.ts
git commit -m "feat: add SecurityCheck interface and AuditContext"
```

---

## Task 6: CheckEngine

**Files:**
- Create: `src/checks/CheckEngine.ts`
- Create: `src/checks/registry.ts`
- Test: `test/unit/checks/CheckEngine.test.ts`

- [ ] **Step 1: Write the failing tests**

`test/unit/checks/CheckEngine.test.ts`:

```typescript
import { CheckEngine } from '../../../src/checks/CheckEngine.js';
import type { SecurityCheck, CheckResult } from '../../../src/checks/SecurityCheck.js';
import type { AuditContext } from '../../../src/context/AuditContext.js';

function makeCtx(): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    queries: {} as any,
    orgInfo: { id: 'orgId', name: 'Test Org', type: 'Developer Edition', isSandbox: false, instance: 'NA1' },
    cache: {},
  };
}

function makeCheck(id: string, result: Partial<CheckResult> = {}): SecurityCheck {
  return {
    id,
    name: `Check ${id}`,
    category: 'Test',
    run: jest.fn().mockResolvedValue({ findings: [], ...result }),
  };
}

describe('CheckEngine', () => {
  describe('constructor — validateCacheOrdering()', () => {
    it('accepts empty check list', () => {
      expect(() => new CheckEngine([], makeCtx())).not.toThrow();
    });

    it('accepts checks where dependencies are satisfied by preceding checks', () => {
      const producer: SecurityCheck = {
        ...makeCheck('producer'),
        populatesCache: ['apexBodies'],
      };
      const consumer: SecurityCheck = {
        ...makeCheck('consumer'),
        dependsOnCache: ['apexBodies'],
      };
      expect(() => new CheckEngine([producer, consumer], makeCtx())).not.toThrow();
    });

    it('throws when a check depends on a cache key no preceding check populates', () => {
      const consumer: SecurityCheck = {
        ...makeCheck('consumer'),
        dependsOnCache: ['apexBodies'],
      };
      expect(() => new CheckEngine([consumer], makeCtx())).toThrow(
        "Check 'Check consumer' depends on cache key 'apexBodies' but no preceding check declares it in populatesCache."
      );
    });

    it('throws when the dependency is declared in a later check (wrong order)', () => {
      const consumer: SecurityCheck = {
        ...makeCheck('consumer'),
        dependsOnCache: ['apexBodies'],
      };
      const producer: SecurityCheck = {
        ...makeCheck('producer'),
        populatesCache: ['apexBodies'],
      };
      // consumer comes BEFORE producer — should throw
      expect(() => new CheckEngine([consumer, producer], makeCtx())).toThrow(/apexBodies/);
    });
  });

  describe('run()', () => {
    it('returns an AuditResult with empty findings for empty check list', async () => {
      const engine = new CheckEngine([], makeCtx());
      const result = await engine.run();
      expect(result.findings).toHaveLength(0);
      expect(result.healthScore).toBe(100);
      expect(result.grade).toBe('A');
    });

    it('collects findings from all checks', async () => {
      const check1 = makeCheck('c1', {
        findings: [
          { id: 'f1', category: 'Auth', riskLevel: 'HIGH', title: 'Issue', detail: 'd', remediation: 'r' },
        ],
      });
      const check2 = makeCheck('c2', {
        findings: [
          { id: 'f2', category: 'Apex', riskLevel: 'LOW', title: 'Minor', detail: 'd', remediation: 'r' },
        ],
      });

      const engine = new CheckEngine([check1, check2], makeCtx());
      const result = await engine.run();

      expect(result.findings).toHaveLength(2);
    });

    it('catches per-check errors and adds an INFO error finding instead of aborting', async () => {
      const failingCheck: SecurityCheck = {
        ...makeCheck('bad'),
        run: jest.fn().mockRejectedValue(new Error('SOQL error')),
      };
      const goodCheck = makeCheck('good', {
        findings: [
          { id: 'f1', category: 'Auth', riskLevel: 'LOW', title: 'T', detail: 'd', remediation: 'r' },
        ],
      });

      const engine = new CheckEngine([failingCheck, goodCheck], makeCtx());
      const result = await engine.run();

      // Should have 2 findings: 1 error finding + 1 from goodCheck
      expect(result.findings).toHaveLength(2);
      const errorFinding = result.findings.find((f) => f.id === 'bad-error');
      expect(errorFinding).toBeDefined();
      expect(errorFinding!.riskLevel).toBe('INFO');
      expect(errorFinding!.detail).toContain('SOQL error');
    });

    it('merges metrics from all checks', async () => {
      const check1 = makeCheck('c1', { metrics: { totalActiveUsers: 10 } });
      const check2 = makeCheck('c2', { metrics: { apexClassCount: 50 } });

      const engine = new CheckEngine([check1, check2], makeCtx());
      const result = await engine.run();

      expect(result.metrics.totalActiveUsers).toBe(10);
      expect(result.metrics.apexClassCount).toBe(50);
    });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- test/unit/checks
```

Expected: FAIL — module not found.

- [ ] **Step 3: Create a stub `src/findings/scoring.ts`**

`CheckEngine.ts` imports `buildAuditResult` from `scoring.ts`. The full implementation comes in Task 7, but the stub must exist now so that `tsc` does not fail during this task's build step.

```typescript
// STUB — replaced with full implementation in Task 7
import type { AuditContext } from '../context/AuditContext.js';
import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditResult } from './AuditResult.js';
import { EMPTY_METRICS } from '../context/OrgMetrics.js';

export function buildAuditResult(
  ctx: AuditContext,
  findings: Finding[],
  metrics: Partial<OrgMetrics>,
): AuditResult {
  return {
    generatedAt: new Date(),
    orgId: ctx.orgInfo.id,
    orgName: ctx.orgInfo.name,
    orgType: ctx.orgInfo.type,
    isSandbox: ctx.orgInfo.isSandbox,
    instance: ctx.orgInfo.instance,
    findings,
    metrics: { ...EMPTY_METRICS, ...metrics },
    healthScore: 100,
    grade: 'A',
  };
}
```

- [ ] **Step 4: Write `src/checks/registry.ts`**

```typescript
import type { SecurityCheck } from './SecurityCheck.js';

// Sub-project 2 adds all 23 check implementations to this array.
// Order matters: a check's dependsOnCache must be satisfied by a preceding check's populatesCache.
// CheckEngine.validateCacheOrdering() enforces this at construction time.
export const CHECKS: SecurityCheck[] = [];
```

- [ ] **Step 6: Write `src/checks/CheckEngine.ts`**

```typescript
import type { SecurityCheck } from './SecurityCheck.js';
import type { AuditContext } from '../context/AuditContext.js';
import type { AuditCache } from '../context/AuditCache.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { Finding } from '../findings/Finding.js';
import type { AuditResult } from '../findings/AuditResult.js';
import { buildAuditResult } from '../findings/scoring.js';

function buildErrorFinding(check: SecurityCheck, err: unknown): Finding {
  const msg = err instanceof Error ? err.message : String(err);
  return {
    id: `${check.id}-error`,
    category: check.category,
    riskLevel: 'INFO',
    title: `${check.name}: check failed`,
    detail: `This check encountered an error and could not complete: ${msg}`,
    remediation:
      'Review the error message and verify the running user has the required permissions.',
  };
}

export class CheckEngine {
  constructor(
    private readonly checks: SecurityCheck[],
    private readonly ctx: AuditContext,
  ) {
    this.validateCacheOrdering();
  }

  async run(): Promise<AuditResult> {
    const findings: Finding[] = [];
    let metrics: Partial<OrgMetrics> = {};

    for (const check of this.checks) {
      try {
        const result = await check.run(this.ctx);
        findings.push(...result.findings);
        if (result.metrics) {
          metrics = { ...metrics, ...result.metrics };
        }
      } catch (err) {
        findings.push(buildErrorFinding(check, err));
      }
    }

    return buildAuditResult(this.ctx, findings, metrics);
  }

  private validateCacheOrdering(): void {
    const populated = new Set<keyof AuditCache>();
    for (const check of this.checks) {
      for (const key of check.dependsOnCache ?? []) {
        if (!populated.has(key)) {
          throw new Error(
            `Check '${check.name}' depends on cache key '${key}' ` +
              `but no preceding check declares it in populatesCache.`,
          );
        }
      }
      for (const key of check.populatesCache ?? []) {
        populated.add(key);
      }
    }
  }
}
```

- [ ] **Step 7: Run tests**

```bash
npm test -- test/unit/checks
```

Expected: All 8 tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/checks/ src/findings/scoring.ts test/unit/checks/
git commit -m "feat: add CheckEngine with cache ordering validation and per-check error isolation"
```

---

## Task 7: Scoring

**Files:**
- Modify: `src/findings/scoring.ts` — replaces the stub created in Task 6 with the full implementation
- Test: `test/unit/findings/scoring.test.ts`

- [ ] **Step 1: Write the failing tests**

`test/unit/findings/scoring.test.ts`:

```typescript
import { buildAuditResult } from '../../../src/findings/scoring.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { AuditContext } from '../../../src/context/AuditContext.js';

function makeCtx(): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    queries: {} as any,
    orgInfo: { id: 'orgId', name: 'Test Org', type: 'Developer Edition', isSandbox: false, instance: 'NA1' },
    cache: {},
  };
}

function finding(riskLevel: Finding['riskLevel'], id = 'f1'): Finding {
  return { id, category: 'Test', riskLevel, title: 'T', detail: 'd', remediation: 'r' };
}

describe('buildAuditResult', () => {
  it('returns healthScore=100 and grade=A for no findings', () => {
    const result = buildAuditResult(makeCtx(), [], {});
    expect(result.healthScore).toBe(100);
    expect(result.grade).toBe('A');
  });

  it('returns grade=F when any CRITICAL finding exists', () => {
    const result = buildAuditResult(makeCtx(), [finding('CRITICAL')], {});
    expect(result.grade).toBe('F');
  });

  it('returns grade=F when healthScore < 40', () => {
    // All HIGH findings → score 7/10 each → healthScore ≈ 30
    const findings = Array.from({ length: 10 }, (_, i) => finding('HIGH', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('F');
    expect(result.healthScore).toBeLessThan(40);
  });

  it('returns grade=D when highCount > 3', () => {
    const findings = Array.from({ length: 4 }, (_, i) => finding('HIGH', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('D');
  });

  it('returns grade=C when highCount > 1', () => {
    const findings = [finding('HIGH', 'f1'), finding('HIGH', 'f2'), finding('LOW', 'f3')];
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('C');
  });

  it('returns grade=B when mediumCount > 3', () => {
    const findings = Array.from({ length: 4 }, (_, i) => finding('MEDIUM', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('B');
  });

  it('returns grade=A for only INFO findings', () => {
    const findings = Array.from({ length: 5 }, (_, i) => finding('INFO', `f${i}`));
    const result = buildAuditResult(makeCtx(), findings, {});
    expect(result.grade).toBe('A');
    expect(result.healthScore).toBe(100);
  });

  it('populates orgInfo fields from ctx.orgInfo', () => {
    const result = buildAuditResult(makeCtx(), [], {});
    expect(result.orgId).toBe('orgId');
    expect(result.orgName).toBe('Test Org');
    expect(result.isSandbox).toBe(false);
  });

  it('merges provided metrics with EMPTY_METRICS defaults', () => {
    const result = buildAuditResult(makeCtx(), [], { totalActiveUsers: 42 });
    expect(result.metrics.totalActiveUsers).toBe(42);
    expect(result.metrics.apexClassCount).toBe(0); // default
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- test/unit/findings
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/findings/scoring.ts`**

```typescript
import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditResult } from './AuditResult.js';
import type { AuditContext } from '../context/AuditContext.js';
import type { RiskLevel } from './RiskLevel.js';
import { EMPTY_METRICS } from '../context/OrgMetrics.js';

const RISK_SCORES: Record<RiskLevel, number> = {
  CRITICAL: 10,
  HIGH: 7,
  MEDIUM: 4,
  LOW: 1,
  INFO: 0,
};

export function buildAuditResult(
  ctx: AuditContext,
  findings: Finding[],
  metrics: Partial<OrgMetrics>,
): AuditResult {
  const totalScore = findings.reduce((sum, f) => sum + RISK_SCORES[f.riskLevel], 0);
  const maxPossible = findings.length * 10;
  const healthScore = Math.max(
    0,
    100 - Math.round((totalScore / Math.max(maxPossible, 1)) * 100),
  );

  const criticalCount = findings.filter((f) => f.riskLevel === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.riskLevel === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.riskLevel === 'MEDIUM').length;

  // Grade thresholds — ported exactly from Python tool's generate_markdown_report()
  let grade: AuditResult['grade'];
  if (criticalCount > 0 || healthScore < 40) grade = 'F';
  else if (highCount > 3 || healthScore < 55) grade = 'D';
  else if (highCount > 1 || healthScore < 70) grade = 'C';
  else if (mediumCount > 3 || healthScore < 85) grade = 'B';
  else grade = 'A';

  return {
    generatedAt: new Date(),
    orgId: ctx.orgInfo.id,
    orgName: ctx.orgInfo.name,
    orgType: ctx.orgInfo.type,
    isSandbox: ctx.orgInfo.isSandbox,
    instance: ctx.orgInfo.instance,
    findings,
    metrics: { ...EMPTY_METRICS, ...metrics },
    healthScore,
    grade,
  };
}
```

- [ ] **Step 4: Run tests**

```bash
npm test -- test/unit/findings
```

Expected: All 9 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/findings/scoring.ts test/unit/findings/
git commit -m "feat: add buildAuditResult scoring + grade thresholds (ported from Python)"
```

---

## Task 8: Renderers

**Files:**
- Create: `src/renderers/AuditRenderer.ts`
- Create: `src/renderers/JsonRenderer.ts`
- Create: `src/renderers/MarkdownRenderer.ts`
- Create: `src/renderers/HtmlRenderer.ts`
- Test: `test/unit/renderers/JsonRenderer.test.ts`
- Test: `test/unit/renderers/MarkdownRenderer.test.ts`

- [ ] **Step 1: Write the failing tests**

`test/unit/renderers/JsonRenderer.test.ts`:

```typescript
import { JsonRenderer } from '../../../src/renderers/JsonRenderer.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-24T00:00:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 100,
    grade: 'A',
    ...overrides,
  };
}

describe('JsonRenderer', () => {
  const renderer = new JsonRenderer();

  it('has format="json" and fileExtension=".json"', () => {
    expect(renderer.format).toBe('json');
    expect(renderer.fileExtension).toBe('.json');
  });

  it('renders a valid JSON string', () => {
    const output = renderer.render(makeResult());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('preserves all AuditResult fields in output', () => {
    const result = makeResult({
      findings: [
        { id: 'f1', category: 'Auth', riskLevel: 'HIGH', title: 'T', detail: 'd', remediation: 'r' },
      ],
      healthScore: 70,
      grade: 'C',
    });
    const parsed = JSON.parse(renderer.render(result));
    expect(parsed.healthScore).toBe(70);
    expect(parsed.grade).toBe('C');
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].riskLevel).toBe('HIGH');
  });
});
```

`test/unit/renderers/MarkdownRenderer.test.ts`:

```typescript
import { MarkdownRenderer } from '../../../src/renderers/MarkdownRenderer.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-24T00:00:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 100,
    grade: 'A',
    ...overrides,
  };
}

describe('MarkdownRenderer', () => {
  const renderer = new MarkdownRenderer();

  it('has format="md" and fileExtension=".md"', () => {
    expect(renderer.format).toBe('md');
    expect(renderer.fileExtension).toBe('.md');
  });

  it('includes org name in output', () => {
    const output = renderer.render(makeResult());
    expect(output).toContain('Test Org');
  });

  it('includes healthScore and grade', () => {
    const output = renderer.render(makeResult({ healthScore: 75, grade: 'B' }));
    expect(output).toContain('75');
    expect(output).toContain('B');
  });

  it('renders finding titles and risk levels', () => {
    const result = makeResult({
      findings: [
        { id: 'f1', category: 'Auth', riskLevel: 'CRITICAL', title: 'MFA not enforced', detail: 'd', remediation: 'r' },
      ],
    });
    const output = renderer.render(result);
    expect(output).toContain('CRITICAL');
    expect(output).toContain('MFA not enforced');
  });

  it('shows "No findings" message when findings array is empty', () => {
    const output = renderer.render(makeResult());
    expect(output).toContain('No findings');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- test/unit/renderers
```

Expected: FAIL — modules not found.

- [ ] **Step 3: Write `src/renderers/AuditRenderer.ts`**

```typescript
import type { AuditResult } from '../findings/AuditResult.js';

export interface AuditRenderer {
  readonly format: string;
  readonly fileExtension: string;
  render(result: AuditResult): string;
}
```

- [ ] **Step 4: Write `src/renderers/JsonRenderer.ts`**

```typescript
import type { AuditResult } from '../findings/AuditResult.js';
import type { AuditRenderer } from './AuditRenderer.js';

export class JsonRenderer implements AuditRenderer {
  readonly format = 'json';
  readonly fileExtension = '.json';

  render(result: AuditResult): string {
    return JSON.stringify(result, null, 2);
  }
}
```

- [ ] **Step 5: Write `src/renderers/MarkdownRenderer.ts`**

```typescript
import type { AuditResult } from '../findings/AuditResult.js';
import type { AuditRenderer } from './AuditRenderer.js';

export class MarkdownRenderer implements AuditRenderer {
  readonly format = 'md';
  readonly fileExtension = '.md';

  render(result: AuditResult): string {
    const lines: string[] = [];
    lines.push(`# Salesforce Security Audit Report`);
    lines.push(`**Org:** ${result.orgName} (${result.orgId})`);
    lines.push(`**Generated:** ${result.generatedAt.toISOString()}`);
    lines.push(`**Instance:** ${result.instance} | **Type:** ${result.orgType}${result.isSandbox ? ' (Sandbox)' : ''}`);
    lines.push(`**Health Score:** ${result.healthScore}/100 | **Grade:** ${result.grade}`);
    lines.push('');
    lines.push(`## Findings (${result.findings.length})`);
    lines.push('');

    if (result.findings.length === 0) {
      lines.push('_No findings._');
    } else {
      for (const f of result.findings) {
        lines.push(`### [${f.riskLevel}] ${f.title}`);
        lines.push(`**Category:** ${f.category}`);
        lines.push('');
        lines.push(f.detail);
        lines.push('');
        lines.push(`**Remediation:** ${f.remediation}`);
        if (f.affectedItems?.length) {
          lines.push('');
          lines.push(`**Affected items:** ${f.affectedItems.join(', ')}`);
        }
        lines.push('');
        lines.push('---');
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}
```

- [ ] **Step 6: Write `src/renderers/HtmlRenderer.ts`**

This is a minimal but functional HTML renderer. Sub-project 3 can expand it to match the Python tool's full HTML report.

```typescript
import type { AuditResult } from '../findings/AuditResult.js';
import type { AuditRenderer } from './AuditRenderer.js';

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#2563eb',
  INFO: '#64748b',
};

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export class HtmlRenderer implements AuditRenderer {
  readonly format = 'html';
  readonly fileExtension = '.html';

  render(result: AuditResult): string {
    const findingsHtml =
      result.findings.length === 0
        ? '<p style="color:#94a3b8">No findings.</p>'
        : result.findings
            .map(
              (f) => `
  <div style="background:#1a1a2e;border:1px solid #334155;border-radius:8px;padding:1rem;margin:0.75rem 0">
    <span style="background:${RISK_COLORS[f.riskLevel] ?? '#666'};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;margin-right:0.5rem">${esc(f.riskLevel)}</span>
    <strong>${esc(f.title)}</strong>
    <p style="color:#94a3b8;font-size:0.85rem;margin:0.25rem 0 0">${esc(f.category)}</p>
    <p style="margin:0.5rem 0">${esc(f.detail)}</p>
    <p style="margin:0"><strong>Remediation:</strong> ${esc(f.remediation)}</p>
    ${f.affectedItems?.length ? `<p style="margin:0.25rem 0 0;font-size:0.85rem;color:#94a3b8"><strong>Affected:</strong> ${f.affectedItems.map(esc).join(', ')}</p>` : ''}
  </div>`,
            )
            .join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Security Audit — ${esc(result.orgName)}</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background:#0f1117; color:#e2e8f0; max-width:960px; margin:2rem auto; padding:0 1rem; }
  h1 { color:#fff; font-size:1.5rem; margin:0 0 0.25rem }
  .meta { color:#94a3b8; font-size:0.875rem; margin:0 0 1.5rem }
  .score { font-size:2.5rem; font-weight:700; margin:0 0 0.25rem }
  .grade { font-size:1.1rem; color:#94a3b8 }
  h2 { color:#cbd5e1; font-size:1.1rem; margin:1.5rem 0 0.5rem }
</style>
</head>
<body>
<h1>Salesforce Security Audit</h1>
<p class="meta">
  Org: <strong>${esc(result.orgName)}</strong> (${esc(result.orgId)}) &nbsp;·&nbsp;
  Instance: ${esc(result.instance)} &nbsp;·&nbsp;
  Type: ${esc(result.orgType)}${result.isSandbox ? ' (Sandbox)' : ''} &nbsp;·&nbsp;
  Generated: ${result.generatedAt.toISOString()}
</p>
<p class="score">${result.healthScore}<span style="font-size:1rem;color:#64748b">/100</span></p>
<p class="grade">Grade: <strong>${result.grade}</strong> &nbsp;·&nbsp; ${result.findings.length} finding${result.findings.length !== 1 ? 's' : ''}</p>
<h2>Findings</h2>
${findingsHtml}
</body>
</html>`;
  }
}
```

- [ ] **Step 7: Run tests**

```bash
npm test -- test/unit/renderers
```

Expected: All 8 tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/renderers/ test/unit/renderers/
git commit -m "feat: add AuditRenderer interface and JSON/Markdown/HTML renderers"
```

---

## Task 9: CLI command and wiring

**Files:**
- Create: `src/commands/audit/wire.ts`
- Create: `src/commands/audit/security.ts`
- Create: `messages/audit.security.md`

- [ ] **Step 1: Write `messages/audit.security.md`**

oclif reads this file for UX strings. Keep it minimal.

```markdown
# Summary

Run a comprehensive security audit against a Salesforce org.

# Flags

## target-org

The org to audit. Must be authenticated via `sf org login`.

## format

Output format: html (default), md, or json.

## output

Directory to write the report file. Defaults to the current directory.

## fail-on

Exit with code 1 if any finding is at or above this severity level.
Options: CRITICAL, HIGH, MEDIUM, LOW
```

- [ ] **Step 2: Write `src/commands/audit/wire.ts`**

```typescript
import type { Connection, Org } from '@salesforce/core';
import { SoqlClientImpl } from '../../api/SoqlClientImpl.js';
import { ToolingClientImpl } from '../../api/ToolingClientImpl.js';
import { RestClientImpl } from '../../api/RestClientImpl.js';
import type { AuditContext } from '../../context/AuditContext.js';
import type { OrgInfo } from '../../context/OrgInfo.js';
import type { QueryRegistry } from '../../queries/QueryRegistry.js';

export function buildApiClients(conn: Connection) {
  return {
    soql: new SoqlClientImpl(conn),
    tooling: new ToolingClientImpl(conn),
    rest: new RestClientImpl(conn),
  };
}

export async function resolveOrgInfo(conn: Connection): Promise<OrgInfo> {
  // Select Id directly from Organization — conn.getAuthInfoFields() is not available on Connection
  type OrgRecord = { Id: string; Name: string; OrganizationType: string; IsSandbox: boolean; InstanceName: string };
  const result = await conn.query<OrgRecord>(
    'SELECT Id, Name, OrganizationType, IsSandbox, InstanceName FROM Organization LIMIT 1'
  );
  const rec = result.records[0];
  if (!rec) throw new Error('Could not retrieve Organization record');
  return {
    id: rec.Id,
    name: rec.Name,
    type: rec.OrganizationType,
    isSandbox: rec.IsSandbox,
    instance: rec.InstanceName,
  };
}

export function buildAuditContext(
  conn: Connection,
  queries: QueryRegistry,
  orgInfo: OrgInfo,
): AuditContext {
  const clients = buildApiClients(conn);
  return {
    soql: clients.soql,
    tooling: clients.tooling,
    rest: clients.rest,
    queries,
    orgInfo,
    cache: {},
  };
}
```

- [ ] **Step 3: Write `src/commands/audit/security.ts`**

```typescript
import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import type { AuditResult } from '../../findings/AuditResult.js';
import type { RiskLevel } from '../../findings/RiskLevel.js';
import { QueryRegistry } from '../../queries/QueryRegistry.js';
import { CheckEngine } from '../../checks/CheckEngine.js';
import { CHECKS } from '../../checks/registry.js';
import { JsonRenderer } from '../../renderers/JsonRenderer.js';
import { HtmlRenderer } from '../../renderers/HtmlRenderer.js';
import { MarkdownRenderer } from '../../renderers/MarkdownRenderer.js';
import type { AuditRenderer } from '../../renderers/AuditRenderer.js';
import { buildAuditContext, resolveOrgInfo } from './wire.js';

const RENDERERS: Record<string, AuditRenderer> = {
  html: new HtmlRenderer(),
  md: new MarkdownRenderer(),
  json: new JsonRenderer(),
};

export default class SecurityAuditCommand extends SfCommand<AuditResult> {
  public static summary = 'Run a comprehensive security audit against a Salesforce org';
  public static description =
    'Runs all security checks against the target org and writes a report file.';
  public static examples = [
    '<%= config.bin %> <%= command.id %> --target-org myOrg',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --format json --output ./reports',
    '<%= config.bin %> <%= command.id %> --target-org myOrg --fail-on HIGH',
  ];

  public static flags = {
    // Flags.requiredOrg is a property (not a function call) — returns an Org instance
    'target-org': Flags.requiredOrg,
    format: Flags.string({
      char: 'f',
      summary: 'Output format(s), comma-separated: html, md, json',
      default: 'html',
    }),
    // Use Flags.string (not Flags.directory) — Flags.directory validates existence at parse time
    // and may reject '.' in some environments. Path resolution is handled in run().
    output: Flags.string({
      char: 'o',
      summary: 'Directory to write the report. Defaults to current directory.',
      default: '.',
    }),
    'fail-on': Flags.string({
      summary: 'Exit with code 1 if any finding is at or above this severity.',
      options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    }),
  };

  public async run(): Promise<AuditResult> {
    const { flags } = await this.parse(SecurityAuditCommand);

    const conn = flags['target-org'].getConnection('62.0');
    const queries = QueryRegistry.load(this.config.root);
    const orgInfo = await resolveOrgInfo(conn);
    const ctx = buildAuditContext(conn, queries, orgInfo);

    this.log(`Auditing org: ${orgInfo.name} (${orgInfo.id})`);

    const engine = new CheckEngine(CHECKS, ctx);
    const result = await engine.run();

    const formats = flags.format.split(',').map((f) => f.trim());
    for (const format of formats) {
      const renderer = RENDERERS[format];
      if (!renderer) {
        this.warn(`Unknown format '${format}' — skipping. Valid formats: html, md, json`);
        continue;
      }
      const output = renderer.render(result);
      const filename = `sf-audit-${orgInfo.id}-${Date.now()}${renderer.fileExtension}`;
      const outputPath = path.join(flags.output, filename);
      fs.writeFileSync(outputPath, output, 'utf-8');
      this.log(`Report written: ${outputPath}`);
    }

    this.log(
      `\nAudit complete — ${result.findings.length} findings | Score: ${result.healthScore}/100 | Grade: ${result.grade}`,
    );

    if (flags['fail-on']) {
      this.handleFailOn(result, flags['fail-on'] as RiskLevel);
    }

    return result;
  }

  private handleFailOn(result: AuditResult, failOn: RiskLevel): void {
    const ORDER: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const threshold = ORDER.indexOf(failOn);
    const hasViolation = result.findings.some(
      (f) => ORDER.indexOf(f.riskLevel) <= threshold,
    );
    if (hasViolation) {
      this.log(`Audit failed: one or more findings at or above ${failOn} severity.`);
      this.exit(1);
    }
  }
}
```

- [ ] **Step 4: Register the command in `package.json`**

In the `oclif` section of `package.json`, ensure `commands` points to `./lib/commands` (the compiled output). The scaffold usually sets this up, but verify:

```json
"oclif": {
  "bin": "sf",
  "commands": "./lib/commands",
  "plugins": [],
  "topics": {
    "audit": {
      "description": "Salesforce security audit commands"
    }
  }
}
```

- [ ] **Step 5: Build and verify the command is registered**

```bash
npm run build
./bin/dev.js commands
```

Expected: `audit security` appears in the list.

- [ ] **Step 6: Smoke test — run against a real org**

```bash
./bin/dev.js audit security --target-org poph-gaurav
```

Expected output (with empty check registry):
```
Auditing org: <Org Name> (<Org ID>)
Report written: ./sf-audit-<orgId>-<timestamp>.html
Audit complete — 0 findings | Score: 100/100 | Grade: A
```

Open the HTML file in a browser and verify it renders correctly.

- [ ] **Step 7: Commit**

```bash
git add src/commands/ messages/audit.security.md
git commit -m "feat: add sf audit security command with HTML/MD/JSON output + --fail-on flag"
```

---

## Task 10: Final verification

- [ ] **Step 1: Run all tests**

```bash
npm test
```

Expected: All tests pass. Note exact counts.

- [ ] **Step 2: Build clean**

```bash
npm run build
```

Expected: No TypeScript errors.

- [ ] **Step 3: Verify `sf audit security --help`**

```bash
./bin/dev.js audit security --help
```

Expected: Shows flags, description, and examples.

- [ ] **Step 4: Run against org with JSON output**

```bash
./bin/dev.js audit security --target-org poph-gaurav --format html,json,md --output /tmp
```

Expected: Three files written to `/tmp/`. Open the HTML file in a browser — should show "0 findings".

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "chore: Sub-project 1 (Foundation) complete — runnable sf audit security with empty check registry"
```

---

## What comes next

**Sub-project 2 — Checks:** Port all 23 security checks from `sf_security_audit.py` to TypeScript. For each check:
1. Add its SOQL/Tooling queries to `soql.json` / `tooling.json`
2. Create `src/checks/impl/<CheckName>.ts`
3. Add it to `src/checks/registry.ts` in the correct cache-dependency order

Reference: `../cloudcounsel-sf-audit/sf_security_audit.py` for the existing Python check implementations.

**Sub-project 3 — Polish:** Full HTML report matching Python tool's design, README, npm publish config, CI pipeline.
