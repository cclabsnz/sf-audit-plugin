# Query Registry Consolidation

**Date:** 2026-04-02
**Status:** Approved

## Problem

Check files contain ~35 inline SOQL/Tooling queries scattered across ~20 files. A `QueryRegistry` and `config/queries/soql.json` + `tooling.json` already exist but are only used by a handful of checks. The rest call `ctx.soql.query()` / `ctx.tooling.query()` directly with hardcoded strings.

This means:
- Queries are hard to audit without reading every check file
- No single place to review what the plugin queries
- Dynamic queries (with runtime-constructed WHERE clauses) can't live in config today

## Goal

All queries live in `config/queries/soql.json` or `config/queries/tooling.json`. Check files reference queries by key via `ctx.queries.execute()` / `ctx.queries.executeQuery()`.

---

## Section 1: Architecture

Three layers of change:

1. **`QueryRegistry`** — add a private `interpolate(soql, params)` helper that replaces `{key}` tokens with caller-supplied values. `execute()` and `executeQuery()` gain an optional `params: Record<string, string>` argument passed to `interpolate()` before the query is dispatched.

2. **Config files** — all hardcoded queries move to `soql.json` or `tooling.json`. Static queries as plain strings; dynamic queries with `{placeholder}` tokens. `fallbackOnError: true` replaces existing silent `try/catch` blocks.

3. **Check files** — every `ctx.soql.query()` / `ctx.tooling.query()` inline call replaced with `ctx.queries.execute(key, ctx)` or `ctx.queries.executeQuery(key, ctx, params)`.

No changes to `AuditContext`, `QueryDefinition` schema, or any other files.

---

## Section 2: QueryRegistry Changes

### New private method

```ts
private interpolate(soql: string, params?: Record<string, string>): string {
  if (!params) return soql;
  return soql.replace(/\{(\w+)\}/g, (_, key) => {
    if (!(key in params)) throw new Error(`QueryRegistry: missing param '${key}'`);
    return params[key];
  });
}
```

Missing params throw immediately with a clear message rather than sending a broken SOQL string to Salesforce.

### Updated signatures

```ts
async execute<T>(id: string, ctx: AuditContext, params?: Record<string, string>): Promise<T[] | null>
async executeQuery<T>(id: string, ctx: AuditContext, params?: Record<string, string>): Promise<QueryResult<T> | null>
```

`interpolate()` is called on `def.soql` immediately before the query is dispatched, after the definition is retrieved.

---

## Section 3: Config File Additions

### `config/queries/soql.json` — new static entries

| Key | Check | Notes |
|-----|-------|-------|
| `auditTrailRecent` | AuditTrailCheck | SetupAuditTrail last 7 days, LIMIT 200 |
| `auditTrailLoginAs` | AuditTrailCheck | SetupAuditTrail loginAs events last 7 days |
| `loginHistory30d` | LoginSessionCheck | LoginHistory last 30 days, LIMIT 2000 |
| `scheduledApexJobs` | ScheduledApexCheck | AsyncApexJob active scheduled/batch |
| `guestUsers` | GuestUserAccessCheck | User WHERE UserType = 'Guest' AND IsActive = true |
| `healthCloudPackage` | HealthCheckCheck | PackageLicense WHERE NamespacePrefix = 'HealthCloudGA' |
| `adminUsersModifyAll` | IpRestrictionsCheck | User WHERE IsActive AND Profile.PermissionsModifyAllData = true |
| `permissionSetCount` | PermissionsCheck | COUNT() custom permission sets |
| `unassignedPermissionSets` | PermissionsCheck | Custom PS not in any assignment or group component |
| `profileCount` | PermissionsCheck | COUNT() profiles excluding known standard names (full list baked in) |
| `inactiveUsers90d` | InactiveUsersCheck | Active standard users, no login in 90+ days |
| `activeUsersCount` | UsersAndAdminsCheck | COUNT() active non-frozen users |
| `modifyAllDataUsers` | UsersAndAdminsCheck | PSA WHERE PermissionsModifyAllData, active non-frozen |
| `viewAllDataUsers` | UsersAndAdminsCheck | PSA WHERE PermissionsViewAllData, active non-frozen |
| `customizeAppUsers` | UsersAndAdminsCheck | PSA WHERE PermissionsCustomizeApplication, active non-frozen |
| `authorApexUsers` | UsersAndAdminsCheck | PSA WHERE PermissionsAuthorApex, active non-frozen |

### `config/queries/soql.json` — new parameterised entries

| Key | Placeholders | Check |
|-----|-------------|-------|
| `scheduledApexCreators` | `{idList}` | ScheduledApexCheck |
| `guestUserObjectPerms` | `{profileId}`, `{objectList}` | GuestUserAccessCheck — `fallbackOnError: true` |
| `guestUserHealthCloudPerms` | `{profileId}`, `{objectType}` | GuestUserAccessCheck — `fallbackOnError: true` |
| `guestUserShareCount` | `{shareTable}`, `{userId}` | GuestUserAccessCheck — `fallbackOnError: true` |
| `fieldPermsByField` | `{fieldList}` | FieldLevelSecurityCheck — `fallbackOnError: true` |
| `publicGroupShareCount` | `{shareTable}`, `{groupId}` | PublicGroupSharingCheck — `fallbackOnError: true` |

### `config/queries/tooling.json` — new entries

| Key | Check | Notes |
|-----|-------|-------|
| `healthCheckScore` | HealthCheckCheck | SecurityHealthCheck |
| `healthCheckHighRisks` | HealthCheckCheck | SecurityHealthCheckRisks WHERE RiskType='HIGH_RISK' |
| `healthCheckMediumRisks` | HealthCheckCheck | SecurityHealthCheckRisks WHERE RiskType='MEDIUM_RISK' |
| `apexClassCount` | CodeSecurityCheck | COUNT() ApexClass custom |
| `apexTriggerCount` | CodeSecurityCheck | COUNT() ApexTrigger custom |
| `apexOrgWideCoverage` | CodeSecurityCheck | ApexOrgWideCoverage |
| `sensitiveCustomFields` | FieldLevelSecurityCheck | CustomField LIKE sensitive names, LIMIT 100, `fallbackOnError: true` |
| `entityDefinitionByIds` | FieldLevelSecurityCheck | `{idList}` placeholder, `fallbackOnError: true` |
| `namedCredentials` | NamedCredentialsCheck | NamedCredential |
| `remoteSites` | RemoteSitesCheck | RemoteProxy |
| `customObjects` | CustomSettingsCheck | CustomObject WHERE `{whereClause}` placeholder |

Existing entries (`apexClasses`, `activeFlows`, `connectedAppsBasic`, `connectedAppsStandard`, `connectedAppDetail`) are already correct — the checks that use them just need updating to call `ctx.queries.execute()` instead of inline queries.

---

## Section 4: Check File Migration Pattern

### Static query

Before:
```ts
const jobs = await ctx.soql.queryAll<ApexJobRecord>(`
  SELECT Id, ApexClass.Name, JobType, Status, CreatedById
  FROM AsyncApexJob WHERE JobType IN ('ScheduledApex', 'BatchApex')
    AND Status NOT IN ('Aborted', 'Failed', 'Completed')
`);
```

After:
```ts
const jobs = await ctx.queries.execute<ApexJobRecord>('scheduledApexJobs', ctx) ?? [];
```

### Parameterised query

Before:
```ts
const creators = await ctx.soql.query<CreatorUserRecord>(`
  SELECT Id, Username, Profile.Name FROM User WHERE Id IN (${inClause})
`);
```

After:
```ts
const result = await ctx.queries.executeQuery<CreatorUserRecord>(
  'scheduledApexCreators', ctx, { idList: inClause }
);
const creators = result?.records ?? [];
```

### Silent error handling

Existing `try/catch` blocks that silently skip errors are replaced by setting `fallbackOnError: true` on the query definition. The registry logs to stderr and returns `null`; callers handle `null` as empty.

---

## Files Changed

| File | Change |
|------|--------|
| `src/queries/QueryRegistry.ts` | Add `interpolate()`, update `execute()` and `executeQuery()` signatures |
| `config/queries/soql.json` | Add ~22 new query entries |
| `config/queries/tooling.json` | Add ~11 new query entries |
| `src/checks/impl/AuditTrailCheck.ts` | 2 queries → registry |
| `src/checks/impl/LoginSessionCheck.ts` | 1 query → registry |
| `src/checks/impl/ScheduledApexCheck.ts` | 2 queries → registry (1 parameterised) |
| `src/checks/impl/GuestUserAccessCheck.ts` | 5 queries → registry (4 parameterised) |
| `src/checks/impl/HealthCheckCheck.ts` | 3 queries → registry |
| `src/checks/impl/CodeSecurityCheck.ts` | 3 queries → registry |
| `src/checks/impl/FieldLevelSecurityCheck.ts` | 3 queries → registry (2 parameterised) |
| `src/checks/impl/IpRestrictionsCheck.ts` | 3 queries → registry |
| `src/checks/impl/PermissionsCheck.ts` | 3 queries → registry |
| `src/checks/impl/InactiveUsersCheck.ts` | 1 query → registry |
| `src/checks/impl/UsersAndAdminsCheck.ts` | 5 queries → registry |
| `src/checks/impl/PublicGroupSharingCheck.ts` | 2 queries → registry (1 parameterised) |
| `src/checks/impl/ConnectedAppsCheck.ts` | 1 query → registry |
| `src/checks/impl/FlowsWithoutSharingCheck.ts` | 1 query → registry |
| `src/checks/impl/NamedCredentialsCheck.ts` | 2 queries → registry |
| `src/checks/impl/RemoteSitesCheck.ts` | 1 query → registry |
| `src/checks/impl/CustomSettingsCheck.ts` | 1 query → registry |
| `src/checks/impl/ApexSharingCheck.ts` | 1 query → registry |
