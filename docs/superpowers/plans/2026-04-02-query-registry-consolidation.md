# Query Registry Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move all hardcoded inline SOQL/Tooling queries from check files into `config/queries/soql.json` and `config/queries/tooling.json`, accessed via `ctx.queries.execute()` / `ctx.queries.executeQuery()`, with `{placeholder}` substitution for dynamic queries.

**Architecture:** Add `interpolate(soql, params?)` to `QueryRegistry` so `execute()` and `executeQuery()` accept an optional `params: Record<string, string>` argument. Populate config files with all queries (static and parameterised). Update every check file to call the registry instead of `ctx.soql` / `ctx.tooling` directly.

**Tech Stack:** TypeScript, Jest (ts-jest ESM), Node.js file system for config loading.

---

## File Map

| File | Change |
|------|--------|
| `src/queries/QueryRegistry.ts` | Add `interpolate()` private method; add `params?` arg to `execute()` and `executeQuery()` |
| `test/unit/queries/QueryRegistry.test.ts` | Add interpolation tests |
| `config/queries/soql.json` | Add 22 new entries (16 static, 6 parameterised) |
| `config/queries/tooling.json` | Add 11 new entries (10 static, 1 parameterised) |
| `src/checks/impl/ConnectedAppsCheck.ts` | 1 query → registry |
| `src/checks/impl/FlowsWithoutSharingCheck.ts` | 1 query → registry |
| `src/checks/impl/HardcodedCredentialsCheck.ts` | 1 query → registry |
| `src/checks/impl/ApexSharingCheck.ts` | 1 query → registry |
| `src/checks/impl/NamedCredentialsCheck.ts` | 2 queries → registry |
| `src/checks/impl/RemoteSitesCheck.ts` | 1 query → registry |
| `src/checks/impl/CustomSettingsCheck.ts` | 1 query → registry |
| `src/checks/impl/LoginSessionCheck.ts` | 1 query → registry |
| `src/checks/impl/AuditTrailCheck.ts` | 2 queries → registry |
| `src/checks/impl/HealthCheckCheck.ts` | 3 queries → registry |
| `src/checks/impl/CodeSecurityCheck.ts` | 3 queries → registry |
| `src/checks/impl/PermissionsCheck.ts` | 3 queries → registry; remove `STANDARD_PROFILE_NAMES` constant |
| `src/checks/impl/InactiveUsersCheck.ts` | 1 query → registry |
| `src/checks/impl/UsersAndAdminsCheck.ts` | 5 queries → registry |
| `src/checks/impl/IpRestrictionsCheck.ts` | 3 queries → registry |
| `src/checks/impl/ScheduledApexCheck.ts` | 2 queries → registry (1 parameterised) |
| `src/checks/impl/PublicGroupSharingCheck.ts` | 2 queries → registry (1 parameterised) |
| `src/checks/impl/FieldLevelSecurityCheck.ts` | 3 queries → registry (2 parameterised) |
| `src/checks/impl/GuestUserAccessCheck.ts` | 5 queries → registry (4 parameterised) |

---

## Task 1: Add interpolation to QueryRegistry

**Files:**
- Modify: `src/queries/QueryRegistry.ts`
- Modify: `test/unit/queries/QueryRegistry.test.ts`

- [ ] **Step 1: Write failing interpolation tests**

Append to `test/unit/queries/QueryRegistry.test.ts`, inside the `describe('QueryRegistry')` block after the `executeQuery()` describe block:

```ts
describe('interpolation', () => {
  const PARAM_SOQL = {
    userById: {
      api: 'soql',
      soql: "SELECT Id FROM User WHERE Id IN ({idList})",
      description: 'Users by ID list',
    },
    fallbackParam: {
      api: 'soql',
      soql: "SELECT COUNT() FROM {shareTable} WHERE UserOrGroupId = '{userId}'",
      description: 'Share count with fallback',
      fallbackOnError: true,
    },
  };

  it('substitutes {key} tokens when params are provided to execute()', async () => {
    const configDir = makeTempConfigWithCleanup(PARAM_SOQL, {});
    const registry = QueryRegistry.load(configDir);
    const queryAllFn: any = jest.fn().mockResolvedValue([]);
    const mockCtx: any = { soql: { queryAll: queryAllFn } };

    await registry.execute('userById', mockCtx, { idList: "'001','002'" });

    expect(queryAllFn).toHaveBeenCalledWith(
      "SELECT Id FROM User WHERE Id IN ('001','002')"
    );
  });

  it('substitutes multiple {key} tokens in a single query', async () => {
    const configDir = makeTempConfigWithCleanup(PARAM_SOQL, {});
    const registry = QueryRegistry.load(configDir);
    const queryAllFn: any = jest.fn().mockResolvedValue([]);
    const mockCtx: any = { soql: { queryAll: queryAllFn } };

    await registry.execute('fallbackParam', mockCtx, {
      shareTable: 'AccountShare',
      userId: '005abc',
    });

    expect(queryAllFn).toHaveBeenCalledWith(
      "SELECT COUNT() FROM AccountShare WHERE UserOrGroupId = '005abc'"
    );
  });

  it('throws when a required param is missing', async () => {
    const configDir = makeTempConfigWithCleanup(PARAM_SOQL, {});
    const registry = QueryRegistry.load(configDir);
    const mockCtx: any = { soql: { queryAll: jest.fn() } };

    await expect(
      registry.execute('userById', mockCtx, {})
    ).rejects.toThrow("missing param 'idList'");
  });

  it('passes SOQL unchanged when no params provided', async () => {
    const configDir = makeTempConfigWithCleanup(VALID_SOQL, VALID_TOOLING);
    const registry = QueryRegistry.load(configDir);
    const queryAllFn: any = jest.fn().mockResolvedValue([]);
    const mockCtx: any = { soql: { queryAll: queryAllFn } };

    await registry.execute('activeUsers', mockCtx);

    expect(queryAllFn).toHaveBeenCalledWith(
      'SELECT Id FROM User WHERE IsActive = true'
    );
  });

  it('substitutes {key} tokens when params are provided to executeQuery()', async () => {
    const configDir = makeTempConfigWithCleanup(PARAM_SOQL, {});
    const registry = QueryRegistry.load(configDir);
    const queryFn: any = jest.fn().mockResolvedValue({ totalSize: 0, records: [] });
    const mockCtx: any = { soql: { query: queryFn } };

    await registry.executeQuery('userById', mockCtx, { idList: "'003'" });

    expect(queryFn).toHaveBeenCalledWith(
      "SELECT Id FROM User WHERE Id IN ('003')"
    );
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && node --experimental-vm-modules node_modules/.bin/jest test/unit/queries/QueryRegistry.test.ts -t "interpolation" --no-coverage 2>&1 | tail -20
```

Expected: 5 failures — `execute is not a function` or wrong call args.

- [ ] **Step 3: Implement interpolation in QueryRegistry**

Open `src/queries/QueryRegistry.ts`. Make these changes:

Add the private method after the `constructor`:

```ts
private interpolate(soql: string, params?: Record<string, string>): string {
  if (!params) return soql;
  return soql.replace(/\{(\w+)\}/g, (_, key) => {
    if (!(key in params)) throw new Error(`QueryRegistry: missing param '${key}'`);
    return params[key];
  });
}
```

Update `execute()` signature and body — replace the existing method:

```ts
async execute<T>(id: string, ctx: AuditContext, params?: Record<string, string>): Promise<T[] | null> {
  const def = this.get(id);
  try {
    if (def.api === 'soql') {
      if (!def.soql) throw new Error(`Query '${id}' has api='soql' but no soql field`);
      return await ctx.soql.queryAll<T>(this.interpolate(def.soql, params));
    }
    if (def.api === 'tooling') {
      if (!def.soql) throw new Error(`Query '${id}' has api='tooling' but no soql field`);
      return await ctx.tooling.query<T>(this.interpolate(def.soql, params));
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
```

Update `executeQuery()` signature and body — replace the existing method:

```ts
async executeQuery<T>(id: string, ctx: AuditContext, params?: Record<string, string>): Promise<QueryResult<T> | null> {
  const def = this.get(id);
  if (def.api !== 'soql') {
    throw new Error(`QueryRegistry.executeQuery: query '${id}' must have api='soql'`);
  }
  if (!def.soql) {
    throw new Error(`Query '${id}' has api='soql' but no soql field`);
  }
  try {
    return await ctx.soql.query<T>(this.interpolate(def.soql, params));
  } catch (err) {
    if (def.fallbackOnError) {
      warnFallback(id, err);
      return null;
    }
    throw err;
  }
}
```

- [ ] **Step 4: Run all QueryRegistry tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && node --experimental-vm-modules node_modules/.bin/jest test/unit/queries/QueryRegistry.test.ts --no-coverage 2>&1 | tail -20
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/queries/QueryRegistry.ts test/unit/queries/QueryRegistry.test.ts && git commit -m "feat: add {placeholder} interpolation to QueryRegistry execute/executeQuery"
```

---

## Task 2: Add static SOQL entries to soql.json

**Files:**
- Modify: `config/queries/soql.json`

- [ ] **Step 1: Add 16 static entries**

Open `config/queries/soql.json`. The file currently has 4 entries (`activeStandardUsers`, `profileIpRanges`, `orgLimits`, `sobjectDescribe`). Add the following entries before the closing `}`:

```json
  "auditTrailRecent": {
    "api": "soql",
    "soql": "SELECT CreatedDate, CreatedBy.Username, Action, Display, Section FROM SetupAuditTrail WHERE CreatedDate > LAST_N_DAYS:7 ORDER BY CreatedDate DESC LIMIT 200",
    "description": "Setup audit trail for last 7 days — used by AuditTrailCheck"
  },
  "auditTrailLoginAs": {
    "api": "soql",
    "soql": "SELECT CreatedDate, CreatedBy.Username, Display FROM SetupAuditTrail WHERE CreatedDate > LAST_N_DAYS:7 AND Action LIKE '%loginAs%' ORDER BY CreatedDate DESC LIMIT 20",
    "description": "Login-As events in audit trail for last 7 days — used by AuditTrailCheck"
  },
  "loginHistory30d": {
    "api": "soql",
    "soql": "SELECT UserId, LoginTime, SourceIp, Status, LoginType, Application, Browser, Platform FROM LoginHistory WHERE LoginTime > LAST_N_DAYS:30 ORDER BY LoginTime DESC LIMIT 2000",
    "description": "Login history for last 30 days — used by LoginSessionCheck"
  },
  "scheduledApexJobs": {
    "api": "soql",
    "soql": "SELECT Id, ApexClass.Name, JobType, Status, CreatedById FROM AsyncApexJob WHERE JobType IN ('ScheduledApex', 'BatchApex') AND Status NOT IN ('Aborted', 'Failed', 'Completed')",
    "description": "Active scheduled and batch Apex jobs — used by ScheduledApexCheck"
  },
  "guestUsers": {
    "api": "soql",
    "soql": "SELECT Id, ProfileId, Username FROM User WHERE UserType = 'Guest' AND IsActive = true",
    "description": "Active guest users — used by GuestUserAccessCheck"
  },
  "healthCloudPackage": {
    "api": "soql",
    "soql": "SELECT NamespacePrefix FROM PackageLicense WHERE NamespacePrefix = 'HealthCloudGA'",
    "description": "Health Cloud package detection — used by HealthCheckCheck"
  },
  "adminUsersModifyAll": {
    "api": "soql",
    "soql": "SELECT Id, ProfileId, Profile.Name, Username FROM User WHERE IsActive = true AND Profile.PermissionsModifyAllData = true",
    "description": "Admin users with Modify All Data via profile — used by IpRestrictionsCheck"
  },
  "permissionSetCount": {
    "api": "soql",
    "soql": "SELECT COUNT() FROM PermissionSet WHERE IsCustom = true",
    "description": "Count of custom permission sets — used by PermissionsCheck"
  },
  "unassignedPermissionSets": {
    "api": "soql",
    "soql": "SELECT Id, Name FROM PermissionSet WHERE IsCustom = true AND Id NOT IN (SELECT PermissionSetId FROM PermissionSetAssignment) AND Id NOT IN (SELECT PermissionSetId FROM PermissionSetGroupComponent)",
    "description": "Custom permission sets not assigned to any user or group — used by PermissionsCheck"
  },
  "profileCount": {
    "api": "soql",
    "soql": "SELECT COUNT() FROM Profile WHERE Name NOT IN ('System Administrator', 'Standard User', 'Read Only', 'Solution Manager', 'Marketing User', 'Contract Manager', 'Standard Platform User', 'Standard Platform One App User', 'Chatter Free User', 'Chatter External User', 'Chatter Moderator User', 'High Volume Customer Portal User', 'Authenticated Website', 'Customer Portal Manager Standard', 'Partner App Subscription User', 'Analytics Cloud Explorer User', 'Identity User', 'Work.com Only User', 'Force.com - App Subscription User', 'Force.com - One App User', 'Force.com - Free User', 'Guest User', 'External Apps Login User', 'External Identity User', 'Minimum Access - Salesforce')",
    "description": "Count of non-standard profiles — used by PermissionsCheck"
  },
  "inactiveUsers90d": {
    "api": "soql",
    "soql": "SELECT Id, Username, Name, Profile.Name, LastLoginDate, UserType FROM User WHERE IsActive = true AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true) AND (LastLoginDate < LAST_N_DAYS:90 OR LastLoginDate = null) AND UserType = 'Standard' ORDER BY LastLoginDate ASC LIMIT 50",
    "description": "Active standard users with no login in 90+ days, excluding frozen users — used by InactiveUsersCheck"
  },
  "activeUsersCount": {
    "api": "soql",
    "soql": "SELECT COUNT() FROM User WHERE IsActive = true AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)",
    "description": "Count of active non-frozen users — used by UsersAndAdminsCheck"
  },
  "modifyAllDataUsers": {
    "api": "soql",
    "soql": "SELECT Assignee.Id, Assignee.Username, Assignee.Name, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsModifyAllData = true AND Assignee.IsActive = true AND Assignee.Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)",
    "description": "Users with Modify All Data permission, active and non-frozen — used by UsersAndAdminsCheck"
  },
  "viewAllDataUsers": {
    "api": "soql",
    "soql": "SELECT Assignee.Id, Assignee.Username, Assignee.Name, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsViewAllData = true AND Assignee.IsActive = true AND Assignee.Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)",
    "description": "Users with View All Data permission, active and non-frozen — used by UsersAndAdminsCheck"
  },
  "customizeAppUsers": {
    "api": "soql",
    "soql": "SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsCustomizeApplication = true AND Assignee.IsActive = true AND Assignee.Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)",
    "description": "Users with Customize Application permission, active and non-frozen — used by UsersAndAdminsCheck"
  },
  "authorApexUsers": {
    "api": "soql",
    "soql": "SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsAuthorApex = true AND Assignee.IsActive = true AND Assignee.Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)",
    "description": "Users with Author Apex permission, active and non-frozen — used by UsersAndAdminsCheck"
  },
  "publicGroups": {
    "api": "soql",
    "soql": "SELECT Id, Name, Type FROM Group WHERE Type = 'AllInternal'",
    "description": "All-internal public groups — used by PublicGroupSharingCheck"
  }
```

- [ ] **Step 2: Verify JSON is valid and loads**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && node -e "const fs=require('fs'); JSON.parse(fs.readFileSync('config/queries/soql.json','utf-8')); console.log('soql.json OK')"
```

Expected: `soql.json OK`

- [ ] **Step 3: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add config/queries/soql.json && git commit -m "feat: add static SOQL query entries to soql.json"
```

---

## Task 3: Add parameterised SOQL entries to soql.json

**Files:**
- Modify: `config/queries/soql.json`

- [ ] **Step 1: Add 6 parameterised entries**

Add to `config/queries/soql.json`:

```json
  "scheduledApexCreators": {
    "api": "soql",
    "soql": "SELECT Id, Username, Profile.Name FROM User WHERE Id IN ({idList})",
    "description": "User profiles for scheduled job creator IDs — used by ScheduledApexCheck with {idList} param"
  },
  "guestUserObjectPerms": {
    "api": "soql",
    "soql": "SELECT SobjectType, PermissionsCreate, PermissionsEdit, PermissionsRead FROM ObjectPermissions WHERE ParentId = '{profileId}' AND SobjectType IN ({objectList})",
    "description": "Object permissions for a guest user profile — used by GuestUserAccessCheck with {profileId} and {objectList} params",
    "fallbackOnError": true
  },
  "guestUserHealthCloudPerms": {
    "api": "soql",
    "soql": "SELECT SobjectType, PermissionsCreate, PermissionsEdit, PermissionsRead FROM ObjectPermissions WHERE ParentId = '{profileId}' AND SobjectType = '{objectType}'",
    "description": "Health Cloud object permissions for a guest user profile — used by GuestUserAccessCheck with {profileId} and {objectType} params",
    "fallbackOnError": true
  },
  "guestUserShareCount": {
    "api": "soql",
    "soql": "SELECT COUNT() FROM {shareTable} WHERE UserOrGroupId = '{userId}' AND RowCause = 'SharingRule'",
    "description": "Sharing rule count targeting a guest user on a share object — used by GuestUserAccessCheck with {shareTable} and {userId} params",
    "fallbackOnError": true
  },
  "fieldPermsByField": {
    "api": "soql",
    "soql": "SELECT Field, COUNT(ParentId) cnt FROM FieldPermissions WHERE PermissionsRead = true AND Field IN ({fieldList}) GROUP BY Field",
    "description": "Permission set read access counts per sensitive field — used by FieldLevelSecurityCheck with {fieldList} param",
    "fallbackOnError": true
  },
  "publicGroupShareCount": {
    "api": "soql",
    "soql": "SELECT COUNT() FROM {shareTable} WHERE UserOrGroupId = '{groupId}' AND RowCause = 'SharingRule'",
    "description": "Sharing rule count for a public group on a share object — used by PublicGroupSharingCheck with {shareTable} and {groupId} params",
    "fallbackOnError": true
  }
```

- [ ] **Step 2: Verify JSON is valid**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && node -e "const fs=require('fs'); JSON.parse(fs.readFileSync('config/queries/soql.json','utf-8')); console.log('soql.json OK')"
```

Expected: `soql.json OK`

- [ ] **Step 3: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add config/queries/soql.json && git commit -m "feat: add parameterised SOQL query entries to soql.json"
```

---

## Task 4: Add tooling query entries to tooling.json

**Files:**
- Modify: `config/queries/tooling.json`

- [ ] **Step 1: Add 11 new entries**

Open `config/queries/tooling.json`. It currently has 5 entries (`apexClasses`, `activeFlows`, `connectedAppsBasic`, `connectedAppDetail`, `connectedAppsStandard`). Add:

```json
  "healthCheckScore": {
    "api": "tooling",
    "soql": "SELECT Score FROM SecurityHealthCheck",
    "description": "Salesforce Security Health Check score — used by HealthCheckCheck"
  },
  "healthCheckHighRisks": {
    "api": "tooling",
    "soql": "SELECT RiskType, Setting, SettingGroup, OrgValue, StandardValue FROM SecurityHealthCheckRisks WHERE RiskType='HIGH_RISK'",
    "description": "High-risk Security Health Check items — used by HealthCheckCheck"
  },
  "healthCheckMediumRisks": {
    "api": "tooling",
    "soql": "SELECT RiskType, Setting, SettingGroup, OrgValue, StandardValue FROM SecurityHealthCheckRisks WHERE RiskType='MEDIUM_RISK'",
    "description": "Medium-risk Security Health Check items — used by HealthCheckCheck"
  },
  "apexClassCount": {
    "api": "tooling",
    "soql": "SELECT COUNT() FROM ApexClass WHERE NamespacePrefix = null",
    "description": "Count of custom Apex classes — used by CodeSecurityCheck"
  },
  "apexTriggerCount": {
    "api": "tooling",
    "soql": "SELECT COUNT() FROM ApexTrigger WHERE NamespacePrefix = null",
    "description": "Count of custom Apex triggers — used by CodeSecurityCheck"
  },
  "apexOrgWideCoverage": {
    "api": "tooling",
    "soql": "SELECT PercentCovered FROM ApexOrgWideCoverage",
    "description": "Org-wide Apex test coverage percentage — used by CodeSecurityCheck"
  },
  "sensitiveCustomFields": {
    "api": "tooling",
    "soql": "SELECT Id, DeveloperName, TableEnumOrId FROM CustomField WHERE (DeveloperName LIKE '%SSN%' OR DeveloperName LIKE '%SocialSecurity%' OR DeveloperName LIKE '%CreditCard%' OR DeveloperName LIKE '%Password%' OR DeveloperName LIKE '%Token%' OR DeveloperName LIKE '%BankAccount%' OR DeveloperName LIKE '%DOB%' OR DeveloperName LIKE '%DateOfBirth%' OR DeveloperName LIKE '%MedicalRecord%' OR DeveloperName LIKE '%Diagnosis%') LIMIT 100",
    "description": "Custom fields with sensitive names (PII/PHI/financial) — used by FieldLevelSecurityCheck",
    "fallbackOnError": true
  },
  "entityDefinitionByIds": {
    "api": "tooling",
    "soql": "SELECT Id, QualifiedApiName FROM EntityDefinition WHERE Id IN ({idList})",
    "description": "Entity definitions by ID list — used by FieldLevelSecurityCheck with {idList} param",
    "fallbackOnError": true
  },
  "namedCredentials": {
    "api": "tooling",
    "soql": "SELECT Id, MasterLabel, DeveloperName, Endpoint FROM NamedCredential",
    "description": "All named credentials — used by NamedCredentialsCheck"
  },
  "remoteSites": {
    "api": "tooling",
    "soql": "SELECT Id, SiteName, EndpointUrl, IsActive, DisableProtocolSecurity FROM RemoteProxy WHERE IsActive = true",
    "description": "Active remote site settings — used by RemoteSitesCheck"
  },
  "customSettingsObjects": {
    "api": "tooling",
    "soql": "SELECT Id, DeveloperName, Description FROM CustomObject WHERE DeveloperName LIKE '%Setting%' OR DeveloperName LIKE '%Config%' OR DeveloperName LIKE '%Credential%'",
    "description": "Custom objects with setting/config/credential names — used by CustomSettingsCheck"
  }
```

- [ ] **Step 2: Verify JSON is valid**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && node -e "const fs=require('fs'); JSON.parse(fs.readFileSync('config/queries/tooling.json','utf-8')); console.log('tooling.json OK')"
```

Expected: `tooling.json OK`

- [ ] **Step 3: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add config/queries/tooling.json && git commit -m "feat: add tooling query entries to tooling.json"
```

---

## Task 5: Migrate checks that already have registry entries

These checks have inline queries that duplicate entries already in the config files: `ConnectedAppsCheck` (duplicates `connectedAppsStandard`), `FlowsWithoutSharingCheck` (duplicates `activeFlows`), `HardcodedCredentialsCheck` (duplicates `apexClasses`), `ApexSharingCheck` (duplicates `apexClasses`), `NamedCredentialsCheck` (duplicates `apexClasses` and matches new `namedCredentials`).

**Files:**
- Modify: `src/checks/impl/ConnectedAppsCheck.ts`
- Modify: `src/checks/impl/FlowsWithoutSharingCheck.ts`
- Modify: `src/checks/impl/HardcodedCredentialsCheck.ts`
- Modify: `src/checks/impl/ApexSharingCheck.ts`
- Modify: `src/checks/impl/NamedCredentialsCheck.ts`

- [ ] **Step 1: Update ConnectedAppsCheck.ts**

Find:
```ts
const connectedApps = await ctx.soql.queryAll<ConnectedAppRecord>(
  `SELECT Id, Name, OptionsAllowAdminApprovedUsersOnly
   FROM ConnectedApplication`
);
```

Replace with:
```ts
const connectedApps = await ctx.queries.execute<ConnectedAppRecord>('connectedAppsStandard', ctx) ?? [];
```

- [ ] **Step 2: Update FlowsWithoutSharingCheck.ts**

Find:
```ts
const flows = await ctx.tooling.query<FlowRecord>(
  "SELECT Id, MasterLabel, ProcessType, Status, RunInMode FROM Flow WHERE Status = 'Active'"
);
```

Replace with:
```ts
const flows = await ctx.queries.execute<FlowRecord>('activeFlows', ctx) ?? [];
```

- [ ] **Step 3: Update HardcodedCredentialsCheck.ts**

Find (the inline tooling query — it's the one inside the `if (!ctx.cache.apexBodies)` block):
```ts
const records = await ctx.tooling.query<ApexClassRecord>(
  'SELECT Id, Name, Body, LengthWithoutComments, NamespacePrefix FROM ApexClass WHERE NamespacePrefix = null'
);
```

Replace with:
```ts
const records = await ctx.queries.execute<ApexClassRecord>('apexClasses', ctx) ?? [];
```

Note: The variable `records` is immediately used to populate `ctx.cache.apexBodies`. The return type changes from `ApexClassRecord[]` (direct) to `ApexClassRecord[] | null` — the `?? []` handles the null case.

- [ ] **Step 4: Update ApexSharingCheck.ts**

Find:
```ts
const records = await ctx.tooling.query<ApexClassRecord>(
  'SELECT Id, Name, Body, NamespacePrefix FROM ApexClass WHERE NamespacePrefix = null'
);
apexBodies = records.map((r) => ({ name: r.Name, body: r.Body }));
```

Replace with:
```ts
const records = await ctx.queries.execute<ApexClassRecord>('apexClasses', ctx) ?? [];
apexBodies = records.map((r) => ({ name: r.Name, body: r.Body }));
```

- [ ] **Step 5: Update NamedCredentialsCheck.ts**

There are two inline queries. First, the `NamedCredential` query:

Find:
```ts
const records = await ctx.tooling.query<NamedCredentialRecord>(
  'SELECT Id, MasterLabel, DeveloperName, Endpoint FROM NamedCredential'
);
```

Replace with:
```ts
const records = await ctx.queries.execute<NamedCredentialRecord>('namedCredentials', ctx) ?? [];
```

Second, the Apex class query inside the `if (records.length > 0)` block:

Find:
```ts
const apexRecords = await ctx.tooling.query<ApexClassRecord>(
  'SELECT Name, Body FROM ApexClass WHERE NamespacePrefix = null'
);
apexBodies = apexRecords.map((r) => ({ name: r.Name, body: r.Body ?? '' }));
```

Replace with:
```ts
const apexRecords = await ctx.queries.execute<ApexClassRecord>('apexClasses', ctx) ?? [];
apexBodies = apexRecords.map((r) => ({ name: r.Name, body: r.Body ?? '' }));
```

- [ ] **Step 6: Build and run tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && npm run build 2>&1 && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1 | tail -15
```

Expected: Build succeeds, all tests pass.

- [ ] **Step 7: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/checks/impl/ConnectedAppsCheck.ts src/checks/impl/FlowsWithoutSharingCheck.ts src/checks/impl/HardcodedCredentialsCheck.ts src/checks/impl/ApexSharingCheck.ts src/checks/impl/NamedCredentialsCheck.ts && git commit -m "refactor: migrate ConnectedApps, Flows, HardcodedCredentials, ApexSharing, NamedCredentials to QueryRegistry"
```

---

## Task 6: Migrate simple static-query checks

**Files:**
- Modify: `src/checks/impl/RemoteSitesCheck.ts`
- Modify: `src/checks/impl/CustomSettingsCheck.ts`
- Modify: `src/checks/impl/LoginSessionCheck.ts`
- Modify: `src/checks/impl/AuditTrailCheck.ts`

- [ ] **Step 1: Update RemoteSitesCheck.ts**

Find:
```ts
const records = await ctx.tooling.query<RemoteProxyRecord>(
  'SELECT Id, SiteName, EndpointUrl, IsActive, DisableProtocolSecurity FROM RemoteProxy WHERE IsActive = true'
);
```

Replace with:
```ts
const records = await ctx.queries.execute<RemoteProxyRecord>('remoteSites', ctx) ?? [];
```

- [ ] **Step 2: Update CustomSettingsCheck.ts**

Find:
```ts
const customObjects = await ctx.tooling.query<CustomObjectRecord>(`
  SELECT Id, DeveloperName, Description FROM CustomObject
  WHERE DeveloperName LIKE '%Setting%'
    OR DeveloperName LIKE '%Config%'
    OR DeveloperName LIKE '%Credential%'
`);
```

Replace with:
```ts
const customObjects = await ctx.queries.execute<CustomObjectRecord>('customSettingsObjects', ctx) ?? [];
```

- [ ] **Step 3: Update LoginSessionCheck.ts**

Find:
```ts
const loginRecords = await ctx.soql.queryAll<LoginHistoryRecord>(
  `SELECT UserId, LoginTime, SourceIp, Status, LoginType, Application, Browser, Platform
   FROM LoginHistory
   WHERE LoginTime > LAST_N_DAYS:30
   ORDER BY LoginTime DESC
   LIMIT 2000`
);
```

Replace with:
```ts
const loginRecords = await ctx.queries.execute<LoginHistoryRecord>('loginHistory30d', ctx) ?? [];
```

- [ ] **Step 4: Update AuditTrailCheck.ts**

Find the first query:
```ts
const auditRecords = await ctx.soql.queryAll<AuditTrailRecord>(
  `SELECT CreatedDate, CreatedBy.Username, Action, Display, Section
   FROM SetupAuditTrail
   WHERE CreatedDate > LAST_N_DAYS:7
   ORDER BY CreatedDate DESC
   LIMIT 200`
);
```

Replace with:
```ts
const auditRecords = await ctx.queries.execute<AuditTrailRecord>('auditTrailRecent', ctx) ?? [];
```

Find the second query:
```ts
const loginAsRecords = await ctx.soql.queryAll<AuditTrailRecord>(
  `SELECT CreatedDate, CreatedBy.Username, Display
   FROM SetupAuditTrail
   WHERE CreatedDate > LAST_N_DAYS:7 AND Action LIKE '%loginAs%'
   ORDER BY CreatedDate DESC
   LIMIT 20`
);
```

Replace with:
```ts
const loginAsRecords = await ctx.queries.execute<AuditTrailRecord>('auditTrailLoginAs', ctx) ?? [];
```

- [ ] **Step 5: Build and run tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && npm run build 2>&1 && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1 | tail -15
```

Expected: Build succeeds, all tests pass.

- [ ] **Step 6: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/checks/impl/RemoteSitesCheck.ts src/checks/impl/CustomSettingsCheck.ts src/checks/impl/LoginSessionCheck.ts src/checks/impl/AuditTrailCheck.ts && git commit -m "refactor: migrate RemoteSites, CustomSettings, LoginSession, AuditTrail to QueryRegistry"
```

---

## Task 7: Migrate HealthCheckCheck and CodeSecurityCheck

**Files:**
- Modify: `src/checks/impl/HealthCheckCheck.ts`
- Modify: `src/checks/impl/CodeSecurityCheck.ts`

- [ ] **Step 1: Update HealthCheckCheck.ts**

Find the Health Cloud detection query:
```ts
const pkgRows = await ctx.soql.queryAll<PackageLicenseRecord>(
  "SELECT NamespacePrefix FROM PackageLicense WHERE NamespacePrefix = 'HealthCloudGA'"
);
```

Replace with:
```ts
const pkgRows = await ctx.queries.execute<PackageLicenseRecord>('healthCloudPackage', ctx) ?? [];
```

Find the score query:
```ts
const scoreRows = await ctx.tooling.query<HealthCheckRecord>(
  'SELECT Score FROM SecurityHealthCheck'
);
```

Replace with:
```ts
const scoreRows = await ctx.queries.execute<HealthCheckRecord>('healthCheckScore', ctx) ?? [];
```

Find the high risks query:
```ts
const highRisks = await ctx.tooling.query<HealthCheckRiskRecord>(
  "SELECT RiskType, Setting, SettingGroup, OrgValue, StandardValue FROM SecurityHealthCheckRisks WHERE RiskType='HIGH_RISK'"
);
```

Replace with:
```ts
const highRisks = await ctx.queries.execute<HealthCheckRiskRecord>('healthCheckHighRisks', ctx) ?? [];
```

Find the medium risks query:
```ts
const mediumRisks = await ctx.tooling.query<HealthCheckRiskRecord>(
  "SELECT RiskType, Setting, SettingGroup, OrgValue, StandardValue FROM SecurityHealthCheckRisks WHERE RiskType='MEDIUM_RISK'"
);
```

Replace with:
```ts
const mediumRisks = await ctx.queries.execute<HealthCheckRiskRecord>('healthCheckMediumRisks', ctx) ?? [];
```

- [ ] **Step 2: Update CodeSecurityCheck.ts**

Find the class count query:
```ts
const classCountResults = await ctx.tooling.query<CountResult>(
  "SELECT COUNT() FROM ApexClass WHERE NamespacePrefix = null"
);
```

Replace with:
```ts
const classCountResults = await ctx.queries.execute<CountResult>('apexClassCount', ctx) ?? [];
```

Find the trigger count query:
```ts
const triggerCountResults = await ctx.tooling.query<CountResult>(
  'SELECT COUNT() FROM ApexTrigger WHERE NamespacePrefix = null'
);
```

Replace with:
```ts
const triggerCountResults = await ctx.queries.execute<CountResult>('apexTriggerCount', ctx) ?? [];
```

Find the coverage query:
```ts
const coverageResults = await ctx.tooling.query<ApexCoverageRecord>(
  'SELECT PercentCovered FROM ApexOrgWideCoverage'
);
```

Replace with:
```ts
const coverageResults = await ctx.queries.execute<ApexCoverageRecord>('apexOrgWideCoverage', ctx) ?? [];
```

- [ ] **Step 3: Build and run tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && npm run build 2>&1 && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1 | tail -15
```

Expected: Build succeeds, all tests pass.

- [ ] **Step 4: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/checks/impl/HealthCheckCheck.ts src/checks/impl/CodeSecurityCheck.ts && git commit -m "refactor: migrate HealthCheck and CodeSecurity checks to QueryRegistry"
```

---

## Task 8: Migrate PermissionsCheck, InactiveUsersCheck, UsersAndAdminsCheck, IpRestrictionsCheck

**Files:**
- Modify: `src/checks/impl/PermissionsCheck.ts`
- Modify: `src/checks/impl/InactiveUsersCheck.ts`
- Modify: `src/checks/impl/UsersAndAdminsCheck.ts`
- Modify: `src/checks/impl/IpRestrictionsCheck.ts`

- [ ] **Step 1: Update PermissionsCheck.ts**

Remove the `STANDARD_PROFILE_NAMES` constant (lines 9–35) and the entire `const standardProfileList` line that builds the IN clause from it.

Find:
```ts
const psCountResult = await ctx.soql.query<{ expr0: number }>(
  'SELECT COUNT() FROM PermissionSet WHERE IsCustom = true'
);
const permissionSetCount = psCountResult.totalSize;
```

Replace with:
```ts
const psCountResult = await ctx.queries.executeQuery<{ expr0: number }>('permissionSetCount', ctx);
const permissionSetCount = psCountResult?.totalSize ?? 0;
```

Find:
```ts
const unassignedResult = await ctx.soql.query<PermissionSetRecord>(
  'SELECT Id, Name FROM PermissionSet WHERE IsCustom = true AND Id NOT IN (SELECT PermissionSetId FROM PermissionSetAssignment) AND Id NOT IN (SELECT PermissionSetId FROM PermissionSetGroupComponent)'
);
const unassignedSets = unassignedResult.records;
const unassignedCount = unassignedSets.length;
```

Replace with:
```ts
const unassignedSets = await ctx.queries.execute<PermissionSetRecord>('unassignedPermissionSets', ctx) ?? [];
const unassignedCount = unassignedSets.length;
```

Find the profile count block (including the `standardProfileList` variable and the query):
```ts
// Custom profile count: exclude known standard Salesforce profiles by name.
// Profile does not expose NamespacePrefix, so managed-package profiles cannot be filtered that way.
const standardProfileList = STANDARD_PROFILE_NAMES.map((n) => `'${n}'`).join(', ');
const profileCountResult = await ctx.soql.query<{ expr0: number }>(
  `SELECT COUNT() FROM Profile WHERE Name NOT IN (${standardProfileList})`
);
const profileCount = profileCountResult.totalSize;
```

Replace with:
```ts
// Custom profile count: standard profile names baked into the registry query.
const profileCountResult = await ctx.queries.executeQuery<{ expr0: number }>('profileCount', ctx);
const profileCount = profileCountResult?.totalSize ?? 0;
```

Also remove the unused `STANDARD_PROFILE_NAMES` import/constant from the top of the file.

- [ ] **Step 2: Update InactiveUsersCheck.ts**

Find:
```ts
const inactiveUsers = await ctx.soql.queryAll<InactiveUserRecord>(`
  SELECT Id, Username, Name, Profile.Name, LastLoginDate, UserType
  FROM User
  WHERE IsActive = true
    AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)
    AND (LastLoginDate < LAST_N_DAYS:90 OR LastLoginDate = null)
    AND UserType = 'Standard'
  ORDER BY LastLoginDate ASC
  LIMIT 50
`);
```

Replace with:
```ts
const inactiveUsers = await ctx.queries.execute<InactiveUserRecord>('inactiveUsers90d', ctx) ?? [];
```

- [ ] **Step 3: Update UsersAndAdminsCheck.ts**

Find:
```ts
const activeUsersResult = await ctx.soql.query<{ expr0: number }>(
  'SELECT COUNT() FROM User WHERE IsActive = true AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)'
);
const totalActiveUsers = activeUsersResult.totalSize;
```

Replace with:
```ts
const activeUsersResult = await ctx.queries.executeQuery<{ expr0: number }>('activeUsersCount', ctx);
const totalActiveUsers = activeUsersResult?.totalSize ?? 0;
```

Find:
```ts
const modifyAllResult = await ctx.soql.query<PsaRecord>(
  'SELECT Assignee.Id, Assignee.Username, Assignee.Name, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsModifyAllData = true AND Assignee.IsActive = true AND Assignee.Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)'
);
const modifyAllUsers = modifyAllResult.records;
const modifyAllCount = modifyAllUsers.length;
```

Replace with:
```ts
const modifyAllUsers = await ctx.queries.execute<PsaRecord>('modifyAllDataUsers', ctx) ?? [];
const modifyAllCount = modifyAllUsers.length;
```

Find:
```ts
const viewAllResult = await ctx.soql.query<PsaRecord>(
  'SELECT Assignee.Id, Assignee.Username, Assignee.Name, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsViewAllData = true AND Assignee.IsActive = true AND Assignee.Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)'
);
const viewAllUsers = viewAllResult.records;
const viewAllCount = viewAllUsers.length;
```

Replace with:
```ts
const viewAllUsers = await ctx.queries.execute<PsaRecord>('viewAllDataUsers', ctx) ?? [];
const viewAllCount = viewAllUsers.length;
```

Find:
```ts
const customizeAppResult = await ctx.soql.query<PsaRecord>(
  'SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsCustomizeApplication = true AND Assignee.IsActive = true AND Assignee.Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)'
);
const customizeAppUsers = customizeAppResult.records;
const customizeAppCount = customizeAppUsers.length;
```

Replace with:
```ts
const customizeAppUsers = await ctx.queries.execute<PsaRecord>('customizeAppUsers', ctx) ?? [];
const customizeAppCount = customizeAppUsers.length;
```

Find:
```ts
const authorApexResult = await ctx.soql.query<PsaRecord>(
  'SELECT Assignee.Id, Assignee.Username, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignment WHERE PermissionSet.PermissionsAuthorApex = true AND Assignee.IsActive = true AND Assignee.Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)'
);
const authorApexUsers = authorApexResult.records;
const authorApexCount = authorApexUsers.length;
```

Replace with:
```ts
const authorApexUsers = await ctx.queries.execute<PsaRecord>('authorApexUsers', ctx) ?? [];
const authorApexCount = authorApexUsers.length;
```

- [ ] **Step 4: Update IpRestrictionsCheck.ts**

Find:
```ts
const adminUsers = await ctx.soql.queryAll<AdminUserRecord>(
  `SELECT Id, ProfileId, Profile.Name, Username FROM User
   WHERE IsActive = true AND Profile.PermissionsModifyAllData = true`
);
```

Replace with:
```ts
const adminUsers = await ctx.queries.execute<AdminUserRecord>('adminUsersModifyAll', ctx) ?? [];
```

Find the IP ranges block with its try/catch/fallback-to-tooling:
```ts
let ipRanges: IpRangeRecord[] = [];
try {
  ipRanges = await ctx.soql.queryAll<IpRangeRecord>(
    'SELECT ProfileId, StartAddress, EndAddress FROM ProfileLoginIpRange'
  );
} catch {
  try {
    ipRanges = await ctx.tooling.query<IpRangeRecord>(
      'SELECT ProfileId, StartAddress, EndAddress FROM ProfileLoginIpRange'
    );
  } catch {
    // No IP ranges configured or not accessible — treat as empty
    ipRanges = [];
  }
}
```

Replace with (the registry's `profileIpRanges` entry already has `fallbackOnError: true`):
```ts
const ipRanges = await ctx.queries.execute<IpRangeRecord>('profileIpRanges', ctx) ?? [];
```

Note: `let` becomes `const` since the value no longer needs to be reassigned.

Find:
```ts
let connectedApps: ConnectedAppBasicRecord[] = [];
try {
  connectedApps = await ctx.tooling.query<ConnectedAppBasicRecord>(
    'SELECT Id, Name FROM ConnectedApplication'
  );
} catch {
  connectedApps = [];
}
```

Replace with:
```ts
const connectedApps = await ctx.queries.execute<ConnectedAppBasicRecord>('connectedAppsBasic', ctx) ?? [];
```

- [ ] **Step 5: Build and run tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && npm run build 2>&1 && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1 | tail -15
```

Expected: Build succeeds, all tests pass.

- [ ] **Step 6: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/checks/impl/PermissionsCheck.ts src/checks/impl/InactiveUsersCheck.ts src/checks/impl/UsersAndAdminsCheck.ts src/checks/impl/IpRestrictionsCheck.ts && git commit -m "refactor: migrate Permissions, InactiveUsers, UsersAndAdmins, IpRestrictions to QueryRegistry"
```

---

## Task 9: Migrate ScheduledApexCheck (parameterised)

**Files:**
- Modify: `src/checks/impl/ScheduledApexCheck.ts`

- [ ] **Step 1: Update ScheduledApexCheck.ts**

Find the main jobs query:
```ts
const jobs = await ctx.soql.queryAll<ApexJobRecord>(`
  SELECT Id, ApexClass.Name, JobType, Status, CreatedById
  FROM AsyncApexJob
  WHERE JobType IN ('ScheduledApex', 'BatchApex')
    AND Status NOT IN ('Aborted', 'Failed', 'Completed')
`);
```

Replace with:
```ts
const jobs = await ctx.queries.execute<ApexJobRecord>('scheduledApexJobs', ctx) ?? [];
```

Find the creator lookup query and its surrounding block:
```ts
const creatorIds = [...new Set(jobs.map((j: ApexJobRecord) => j.CreatedById))];
const inClause = creatorIds.map((id) => `'${id}'`).join(',');

const creators = await ctx.soql.query<CreatorUserRecord>(`
  SELECT Id, Username, Profile.Name FROM User WHERE Id IN (${inClause})
`);

creators.records.forEach((u: CreatorUserRecord) => {
  creatorMap[u.Id] = u;
});
```

Replace with:
```ts
const creatorIds = [...new Set(jobs.map((j: ApexJobRecord) => j.CreatedById))];
const inClause = creatorIds.map((id) => `'${id}'`).join(',');

const creatorsResult = await ctx.queries.executeQuery<CreatorUserRecord>(
  'scheduledApexCreators', ctx, { idList: inClause }
);

(creatorsResult?.records ?? []).forEach((u: CreatorUserRecord) => {
  creatorMap[u.Id] = u;
});
```

- [ ] **Step 2: Build and run tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && npm run build 2>&1 && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1 | tail -15
```

Expected: Build succeeds, all tests pass.

- [ ] **Step 3: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/checks/impl/ScheduledApexCheck.ts && git commit -m "refactor: migrate ScheduledApexCheck to QueryRegistry"
```

---

## Task 10: Migrate PublicGroupSharingCheck (parameterised)

**Files:**
- Modify: `src/checks/impl/PublicGroupSharingCheck.ts`

- [ ] **Step 1: Update PublicGroupSharingCheck.ts**

Find the groups query:
```ts
const groups = await ctx.soql.queryAll<GroupRecord>(
  "SELECT Id, Name, Type FROM Group WHERE Type = 'AllInternal'"
);
```

Replace with:
```ts
const groups = await ctx.queries.execute<GroupRecord>('publicGroups', ctx) ?? [];
```

Find the share count query inside the inner loop:
```ts
const result = await ctx.soql.query<Record<string, never>>(
  `SELECT COUNT() FROM ${shareTable} WHERE UserOrGroupId = '${group.Id}' AND RowCause = 'SharingRule'`
);
if (result.totalSize > 0) {
```

Replace with:
```ts
const result = await ctx.queries.executeQuery<Record<string, never>>(
  'publicGroupShareCount', ctx, { shareTable, groupId: group.Id }
);
if ((result?.totalSize ?? 0) > 0) {
```

- [ ] **Step 2: Build and run tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && npm run build 2>&1 && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1 | tail -15
```

Expected: Build succeeds, all tests pass.

- [ ] **Step 3: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/checks/impl/PublicGroupSharingCheck.ts && git commit -m "refactor: migrate PublicGroupSharingCheck to QueryRegistry"
```

---

## Task 11: Migrate FieldLevelSecurityCheck (parameterised)

**Files:**
- Modify: `src/checks/impl/FieldLevelSecurityCheck.ts`

- [ ] **Step 1: Update the sensitive fields query**

Find:
```ts
try {
  sensitiveFields = await ctx.tooling.query<CustomFieldRecord>(
    `SELECT Id, DeveloperName, TableEnumOrId FROM CustomField
     WHERE (DeveloperName LIKE '%SSN%' OR DeveloperName LIKE '%SocialSecurity%'
       OR DeveloperName LIKE '%CreditCard%' OR DeveloperName LIKE '%Password%'
       OR DeveloperName LIKE '%Token%' OR DeveloperName LIKE '%BankAccount%'
       OR DeveloperName LIKE '%DOB%' OR DeveloperName LIKE '%DateOfBirth%'
       OR DeveloperName LIKE '%MedicalRecord%' OR DeveloperName LIKE '%Diagnosis%')
     LIMIT 100`
  );
} catch {
  findings.push({
    id: 'field-level-security-query-error',
    ...
  });
  return { findings };
}
```

First, change the variable declaration from:
```ts
let sensitiveFields: CustomFieldRecord[] = [];
```
to:
```ts
let sensitiveFields: CustomFieldRecord[] | null = null;
```

Then replace the entire try/catch block with (`fallbackOnError: true` means the registry returns `null` on error):
```ts
sensitiveFields = await ctx.queries.execute<CustomFieldRecord>('sensitiveCustomFields', ctx);
if (sensitiveFields === null) {
  findings.push({
    id: 'field-level-security-query-error',
    category: this.category,
    riskLevel: 'INFO',
    title: 'Field-level security analysis could not be completed',
    detail:
      'The CustomField query failed. This may be due to insufficient permissions or Tooling API access restrictions.',
    remediation:
      'Ensure the running user has access to the Tooling API and CustomField sobject.',
  });
  return { findings };
}
```

The `null` check detects the error case. Do not use `?? []` here — that would silently swallow the error and skip the finding.

- [ ] **Step 2: Update the entity definition query**

Find:
```ts
try {
  entityDefs = await ctx.tooling.query<EntityDefinitionRecord>(
    `SELECT Id, QualifiedApiName FROM EntityDefinition WHERE Id IN (${objectIds.map((id) => `'${id}'`).join(', ')})`
  );
} catch {
  // If entity lookup fails, fall through — field names will be unresolvable
}
```

Replace with:
```ts
const idList = objectIds.map((id) => `'${id}'`).join(', ');
entityDefs = await ctx.queries.execute<EntityDefinitionRecord>(
  'entityDefinitionByIds', ctx, { idList }
) ?? [];
```

The `fallbackOnError: true` on this registry entry handles the catch case — null is returned and `?? []` gives an empty array, which matches the original fall-through behaviour.

- [ ] **Step 3: Update the field permissions query**

Find:
```ts
try {
  const result = await ctx.soql.query<FieldPermRecord>(
    `SELECT Field, COUNT(ParentId) cnt FROM FieldPermissions
     WHERE PermissionsRead = true AND Field IN (${fieldApiNames.map((f) => `'${f}'`).join(', ')})
     GROUP BY Field`
  );
  permRecords = result.records.map((r) => ({
    Field: r.Field,
    cnt: (r as unknown as Record<string, unknown>).cnt != null
      ? Number((r as unknown as Record<string, unknown>).cnt)
      : 0,
  }));
} catch {
  findings.push({ id: 'field-level-security-ok', ... });
  return { findings };
}
```

Replace with:
```ts
const fieldList = fieldApiNames.map((f) => `'${f}'`).join(', ');
const fieldPermsResult = await ctx.queries.executeQuery<FieldPermRecord>(
  'fieldPermsByField', ctx, { fieldList }
);
if (fieldPermsResult === null) {
  findings.push({
    id: 'field-level-security-ok',
    category: this.category,
    riskLevel: 'LOW',
    title: 'Sensitive custom fields appear appropriately restricted',
    detail: 'No sensitive custom fields with excessive permission set access were found.',
    remediation:
      'Continue to apply restrictive field-level security to any new sensitive fields.',
  });
  return { findings };
}
permRecords = fieldPermsResult.records.map((r) => ({
  Field: r.Field,
  cnt: (r as unknown as Record<string, unknown>).cnt != null
    ? Number((r as unknown as Record<string, unknown>).cnt)
    : 0,
}));
```

- [ ] **Step 4: Build and run tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && npm run build 2>&1 && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1 | tail -15
```

Expected: Build succeeds, all tests pass.

- [ ] **Step 5: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/checks/impl/FieldLevelSecurityCheck.ts && git commit -m "refactor: migrate FieldLevelSecurityCheck to QueryRegistry"
```

---

## Task 12: Migrate GuestUserAccessCheck (parameterised)

**Files:**
- Modify: `src/checks/impl/GuestUserAccessCheck.ts`

- [ ] **Step 1: Update the guest users query**

Find:
```ts
const guestUsers = await ctx.soql.queryAll<UserRecord>(
  "SELECT Id, ProfileId, Username FROM User WHERE UserType = 'Guest' AND IsActive = true"
);
```

Replace with:
```ts
const guestUsers = await ctx.queries.execute<UserRecord>('guestUsers', ctx) ?? [];
```

- [ ] **Step 2: Update the standard object permissions query**

Find the try/catch block inside the `for (const profileId of profileIds)` loop:
```ts
try {
  const perms = await ctx.soql.queryAll<ObjectPermissionRecord>(
    `SELECT SobjectType, PermissionsCreate, PermissionsEdit, PermissionsRead FROM ObjectPermissions WHERE ParentId = '${profileId}' AND SobjectType IN (${standardObjectList})`
  );
  for (const perm of perms) {
    ...
  }
} catch {
  // Skip on error
}
```

Replace with (remove the try/catch — `fallbackOnError: true` in the registry handles it by returning null):
```ts
const perms = await ctx.queries.execute<ObjectPermissionRecord>(
  'guestUserObjectPerms', ctx, { profileId, objectList: standardObjectList }
) ?? [];
for (const perm of perms) {
  if (perm.PermissionsCreate || perm.PermissionsEdit) {
    for (const u of profileUsers) {
      writeViolations.push({
        userId: u.Id,
        username: u.Username,
        sobjectType: perm.SobjectType,
        canCreate: perm.PermissionsCreate,
        canEdit: perm.PermissionsEdit,
      });
    }
  }
}
```

- [ ] **Step 3: Update the Health Cloud object permissions query**

Find the inner try/catch inside the `for (const obj of HEALTH_CLOUD_OBJECTS)` loop:
```ts
try {
  const perms = await ctx.soql.queryAll<ObjectPermissionRecord>(
    `SELECT SobjectType, PermissionsCreate, PermissionsEdit, PermissionsRead FROM ObjectPermissions WHERE ParentId = '${profileId}' AND SobjectType = '${obj}'`
  );
  for (const perm of perms) {
    ...
  }
} catch {
  // Object may not exist — skip silently
}
```

Replace with:
```ts
const perms = await ctx.queries.execute<ObjectPermissionRecord>(
  'guestUserHealthCloudPerms', ctx, { profileId, objectType: obj }
) ?? [];
for (const perm of perms) {
  if (perm.PermissionsCreate || perm.PermissionsEdit) {
    for (const u of profileUsers) {
      writeViolations.push({
        userId: u.Id,
        username: u.Username,
        sobjectType: perm.SobjectType,
        canCreate: perm.PermissionsCreate,
        canEdit: perm.PermissionsEdit,
      });
    }
  }
}
```

- [ ] **Step 4: Update the share count query**

Find the inner try/catch inside the `for (const shareTable of SHARE_TABLES)` loop:
```ts
try {
  const result = await ctx.soql.query<Record<string, never>>(
    `SELECT COUNT() FROM ${shareTable} WHERE UserOrGroupId = '${user.Id}' AND RowCause = 'SharingRule'`
  );
  if (result.totalSize > 0) {
    const existing = sharingExposures.find((e) => e.shareTable === shareTable);
    if (existing) {
      existing.count += result.totalSize;
    } else {
      sharingExposures.push({ shareTable, count: result.totalSize });
    }
  }
} catch {
  // Object may not be accessible — skip silently
}
```

Replace with:
```ts
const result = await ctx.queries.executeQuery<Record<string, never>>(
  'guestUserShareCount', ctx, { shareTable, userId: user.Id }
);
if ((result?.totalSize ?? 0) > 0) {
  const existing = sharingExposures.find((e) => e.shareTable === shareTable);
  if (existing) {
    existing.count += result!.totalSize;
  } else {
    sharingExposures.push({ shareTable, count: result!.totalSize });
  }
}
```

- [ ] **Step 5: Build and run tests**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && npm run build 2>&1 && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1 | tail -15
```

Expected: Build succeeds, all tests pass.

- [ ] **Step 6: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git add src/checks/impl/GuestUserAccessCheck.ts && git commit -m "refactor: migrate GuestUserAccessCheck to QueryRegistry"
```

---

## Task 13: Final verification and push

- [ ] **Step 1: Run full test suite**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && node --experimental-vm-modules node_modules/.bin/jest --no-coverage 2>&1
```

Expected: All tests pass, 0 failures.

- [ ] **Step 2: Confirm no inline ctx.soql or ctx.tooling query calls remain in check files**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && grep -rn "ctx\.soql\.query\|ctx\.tooling\.query" src/checks/impl/
```

Expected: No output. All inline queries have been migrated.

- [ ] **Step 3: Push and publish**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/sf-audit/cloudcounsel-sf-plugin-audit" && git push && npm publish --access public 2>&1
```
