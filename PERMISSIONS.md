# Minimum Salesforce Permissions for `sf-audit`

`sf audit security` is **strictly read-only**. Every check issues
SOQL / Tooling / REST **GET** queries only: no DML, no Metadata API writes, no
record modification. The account running the audit needs only enough permission
to *read* security configuration, setup metadata, and audit/login data.

This document lists the **minimum** permission set required for a **complete**
audit, what each permission is for, and (importantly for a client security
team) what the tool explicitly does **not** need.

> **Key reassurance for the org owner:** the tool reads *configuration and
> metadata*, not your business record content. It checks Org-Wide Defaults via
> `EntityDefinition` (describe), not by reading Account/Contact/Opportunity
> data. It does **not** require `View All Data` to run.
>
> One check is a partial exception, and it is stated plainly rather than buried:
> **Integration Account Least Privilege** (`integration-least-privilege`) asks
> whether an integration account has ever written to an object it holds
> Create/Edit/Delete on. It does that with grouped **ownership aggregates** —
> `SELECT CreatedById, COUNT(Id) … GROUP BY CreatedById` — which return only
> owner ids and row counts. **No field value of any record is ever selected,
> read, or stored.** See ["Record visibility and the write-evidence
> probe"](#record-visibility-and-the-write-evidence-probe) below for what that
> probe can and cannot conclude without `View All Data`.

## Recommended setup

Create a dedicated **permission set** (or integration profile) named e.g.
`SF Audit (Read-Only)`, assign it to a service/audit user with exactly the
permissions below, and nothing else. A starter permission-set definition is in
[`docs/permissionset/SF_Audit_ReadOnly.permissionset-meta.xml`](docs/permissionset/SF_Audit_ReadOnly.permissionset-meta.xml).

## System (user) permissions: required

| Permission | API name | Why it's needed | If omitted |
|---|---|---|---|
| **API Enabled** | `ApiEnabled` | All access is via SOQL/Tooling/REST over the API | Audit cannot run at all |
| **View Setup and Configuration** | `ViewSetup` | Reads the bulk of the surface: `SetupAuditTrail`, `TraceFlag`, `ConnectedApplication`, `RemoteProxy`, `CorsWhitelistEntry`, `CspTrustedSite`, `NamedCredential`, `AuthConfig`, `CriticalUpdate`/release updates, `Network` (Experience sites), `ProfileLoginIpRange`, `NetworkAccess`, `Certificate`, `ExternalString` (Custom Labels), `OrgWideEmailAddress`, `EmailServicesFunction`/`EmailServicesAddress`, and Tooling metadata (`ApexClass`, `Flow`, `CustomObject`/`CustomField`, `EntityDefinition`, `FieldDefinition`, `FieldPermissions`, `ObjectPermissions`, `SetupEntityAccess`, `WorkflowOutboundMessage`, `StaticResource`) | Most setup/config checks return **inconclusive** |
| **View All Users** | `ViewAllUsers` | Enumerate every `User`, `UserLogin`, `PermissionSetAssignment`, and `TwoFactorInfo` record org-wide (not just role-hierarchy-visible users) | User/admin/MFA checks under-count and miss accounts |
| **View Health Check** | `ViewHealthCheckScreen` | Read `SecurityHealthCheck` and `SecurityHealthCheckRisks` (Tooling) | Health Check + Password/Session checks inconclusive |
| **Author Apex** | `AuthorApex` | **Read-only use:** the only standard gate that exposes `ApexClass`/`ApexTrigger`/`ApexPage` **`Body`** via the Tooling API. Used by the ~9 Apex/Visualforce code-security checks. Grants *no* ability to modify org data | The 9 code-security checks return **inconclusive**; rest of the audit is unaffected |
| **View Event Log Files** | `ViewEventLogFiles` | Read `EventLogFile` for the Event Monitoring check | Event Monitoring check inconclusive |

### Recommended (improves completeness)

| Permission | API name | Why |
|---|---|---|
| **View Roles and Role Hierarchy** | `ViewRoles` | Complete visibility of role-based sharing context |

## What the tool does **NOT** need

Grant **none** of these. They are unnecessary for a read-only audit and a client
security team is right to refuse them:

- **`View All Data`:** not required to run. Every check works without it, and no
  check reads record content. The one thing it changes is completeness of a
  single probe: without it, `integration-least-privilege` reports each object it
  cannot conclude about as **unprobed** instead of reporting an unused write
  grant (see below). Grant it only if you want that probe to be conclusive
- **`Modify All Data`** (`ModifyAllData`)
- **`Customize Application`** (`CustomizeApplication`)
- **`Manage Users`** / **`Manage Internal Users`**
- Any **Create / Edit / Delete (DML)** permission on any object
- **Metadata API** deploy/retrieve (`deployMetadata`, `modifyMetadata`)
- Password, MFA, or session **management** permissions (the tool *reads* MFA/session config, it does not change it)

## Important caveats

- **`Author Apex` naming is misleading.** It sounds like a write/dev permission,
  but for this tool it is used purely to *read* Apex source via Tooling. It does
  not let the audit account modify data or deploy code. If your security policy
  forbids it, omit it: the ~9 code-security checks will report **inconclusive**
  and every other check runs normally.
- **Feature/licence-gated checks.** The Event Monitoring and SIEM checks require
  **Event Monitoring / Shield** to be licensed in the org; the Shield
  Platform Encryption portion of Data Classification likewise. Where a feature
  isn't licensed, the relevant check reports **inconclusive** rather than failing.
- **Public `Document` visibility is folder-gated.** The Public Static Resources &
  Documents check queries `Document WHERE IsPublic = true`. `Document` records are
  visible per **folder** access rather than via `ViewSetup`, so an audit user with
  no access to a folder will not see its public documents. Grant the audit user
  read access to document folders (or assign a profile that can view all folders)
  for complete coverage; otherwise that check reports **inconclusive** for what it
  cannot read.
- **Inconclusive ≠ pass.** Any check the audit user cannot access is surfaced as
  an explicit *inconclusive* finding (never silently treated as a pass) so an
  under-permissioned run is visible in the report, not hidden.
- **`View Setup and Configuration` vs `View All Data`.** `ViewSetup` is the
  narrowest standard permission that allows SOQL against setup objects. Some
  strict org configurations may still require object-level Read FLS on the
  setup/audit objects above; grant those rather than reaching for `View All Data`.

### Record visibility and the write-evidence probe

`integration-least-privilege` is the only check that queries record data, and it
queries ownership rather than content: for each object an integration account
holds a write grant on, it runs a grouped count of records whose `CreatedById`
or `LastModifiedById` is that account. The result is a row count per owner id.
No field of any record is selected.

Like all SOQL, that aggregate runs **as the audit user with sharing enforced**.
An audit user that cannot see the records gets a successful query and zero rows
back, which is indistinguishable from "the integration has never written here" —
and reporting that as an unused grant would be a false accusation against a
working integration. So:

- The check first determines whether the audit user holds `View All Data` (or
  `Modify All Data`). It identifies the running user through the Connect API
  (`/chatter/users/me`, a read-only GET) and reads that user's own permission-set
  assignments.
- **With** `View All Data`: the probe runs, and objects with no attributed
  record are reported as write grants the integration has never exercised.
- **Without** it — or if the running user cannot be identified, e.g. Chatter is
  disabled — **no object is probed at all.** Every object is listed as
  *unprobed*, and the finding is marked **inconclusive**. The check never
  reports an unused grant it could not establish.
- Every other part of that check (escalation-grade permissions, bulk-data
  permissions, standing credentials, dormancy) is drawn from setup objects and
  is unaffected.

This is a completeness trade, not a correctness one: refusing `View All Data`
costs you one probe's conclusions and is visible in the report as such.

## Connected App (CI / automation)

To run the audit from CI (e.g. scheduled posture checks), authenticate with a
**Connected App** using least-privilege OAuth:

- OAuth scopes: `api`, `refresh_token`: **no** `full`, **no** `web`
- Apply IP restrictions to your CI runner's IP ranges if the org enforces them
- Store the credential (`sf org login sfdx-url` output) as a secret; rotate every
  90 days or on any suspected exposure
- Assign the `SF Audit (Read-Only)` permission set to the Connected App's
  run-as / integration user
