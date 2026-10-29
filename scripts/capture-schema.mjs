#!/usr/bin/env node
// Captures the schema the checks query, from an org you own, into a test fixture.
//
//   node scripts/capture-schema.mjs <org-alias> <out.json>
//
// For every object the checks name, it describes the object through the standard API and the
// Tooling API (GET requests only) and records which API serves it and each field's filterability.
// Only standard fields are kept: custom and namespaced fields (anything containing "__") are
// dropped, so a snapshot carries no client data. Use a Developer Edition org, never a client org.
import { writeFileSync } from 'node:fs';
import { Org } from '@salesforce/core';

const OBJECTS = [
  // Named in a FROM clause under src/.
  'ApexClass', 'ApexOrgWideCoverage', 'ApexPage', 'ApexTrigger', 'AppMenuItem', 'AsyncApexJob',
  'AuthConfig', 'AuthProvider', 'BotDefinition', 'BotVersion', 'Certificate', 'ConnectedApplication',
  'ContentDistribution', 'CorsWhitelistEntry', 'CriticalUpdate', 'CspTrustedSite', 'CustomField',
  'CustomObject', 'DataShareTarget', 'DataSpace', 'DelegateGroup', 'DelegateGroupMember', 'DkimKey',
  'Document', 'EmailServicesAddress', 'EmailServicesFunction', 'EmbeddedServiceConfig',
  'EmbeddedServiceDetail', 'EncryptionKey', 'EntityDefinition', 'EventLogFile',
  'ExternalAccountHierarchy', 'ExternalClientApplication', 'ExternalCredential',
  'ExternalServiceRegistration', 'ExternalString', 'FieldDefinition', 'FieldPermissions', 'Flow',
  'FlowDefinition', 'Folder', 'GenAiFunctionDefinition', 'GenAiPlannerDefinition',
  'GenAiPlannerFunctionDef', 'GenAiPluginDefinition', 'GenAiPluginFunctionDef', 'GenAiPromptTemplate',
  'Group', 'GuestUserAnomalyEventStore', 'InstalledSubscriberPackage', 'LightningMessageChannel',
  'LoginHistory', 'MessagingChannel', 'NamedCredential', 'Network', 'NetworkAccess', 'OauthToken',
  'ObjectPermissions', 'Organization', 'OrgWideEmailAddress', 'PackageLicense', 'PermissionSet',
  'PermissionSetAssignment', 'PermissionSetGroupComponent', 'PermissionSetLicenseAssign', 'Profile',
  'ProfileLoginIpRange', 'RemoteProxy', 'RestrictionRule', 'SamlSsoConfig', 'SecurityHealthCheck',
  'SecurityHealthCheckRisks', 'SetupAuditTrail', 'SetupEntityAccess', 'Site', 'StaticResource',
  'TenantSecret', 'TraceFlag', 'TransactionSecurityPolicy', 'TwoFactorInfo', 'User', 'UserLogin',
  'UserPermissionAccess', 'UserRecordAccess', 'WorkflowOutboundMessage',
  // Named only through a variable, or only in a failing query.
  'UserExternalCredential', 'LoginAnomalyEventStore', 'DebugLevel', 'Account', 'Contact', 'Case',
  'Lead', 'Opportunity', 'AccountShare', 'ContactShare', 'CaseShare', 'LeadShare',
  'OpportunityShare', 'ContentDocument', 'ContentVersion', 'Domain', 'UserRole', 'GroupMember',
  'PermissionSetGroup', 'ApiAnomalyEventStore', 'ReportAnomalyEventStore',
  'SessionHijackingEventStore', 'CredentialStuffingEventStore', 'TwoFactorMethodsInfo', 'ReleaseUpdate',
  'Profile', 'Name', 'ApexClassMember', 'Report', 'Dashboard', 'Bot', 'BotVersion', 'PermissionSetTabSetting',
];

// Picklists left without values in the snapshot (see describe below).
const GEO_LOCALE = /(?:CountryCode|StateCode)$|SidKey$|LanguageLocaleKey$|CurrencyIsoCode$|EncodingKey$/;

const [alias, out] = process.argv.slice(2);
if (!alias || !out) {
  console.error('usage: capture-schema.mjs <org-alias> <out.json>');
  process.exit(2);
}

const conn = (await Org.create({ aliasOrUsername: alias })).getConnection();
const version = conn.getApiVersion();

async function describe(path) {
  try {
    const d = await conn.request(`/services/data/v${version}${path}`);
    const fields = {};
    for (const f of d.fields ?? []) {
      if (f.name.includes('__')) continue;
      fields[f.name] = { filterable: Boolean(f.filterable), aggregatable: Boolean(f.aggregatable), type: f.type };
      // Picklist values let the schema guard flag a filter on a value the platform never writes
      // (RowCause = 'SharingRule' matched nothing, silently, and hid every sharing rule).
      // Values naming a custom or namespaced component (anything with "__") are org-specific, like
      // custom fields, and are dropped; the guard does not judge a literal containing "__".
      const values = (f.picklistValues ?? []).map((p) => p.value).filter((v) => typeof v === 'string' && !v.includes('__'));
      // Geography, locale, time zone, currency and encoding lists are thousands of values that no
      // check filters on; every other picklist is kept whole, however long.
      if (f.type === 'picklist' && values.length > 0 && !GEO_LOCALE.test(f.name)) fields[f.name].values = values.sort();
      // A lookup is queried through its relationship name (Assignee.Username); record where it points.
      const to = (f.referenceTo ?? []).filter((t) => !t.includes("__"));
      if (f.relationshipName && to.length) fields[f.name].relationship = { name: f.relationshipName, to };
    }
    return Object.fromEntries(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b)));
  } catch {
    return null; // not served by this API in this org
  }
}

const schema = { apiVersion: version, edition: 'Developer Edition', soql: {}, tooling: {} };
for (const obj of [...new Set(OBJECTS)].sort()) {
  const [s, t] = await Promise.all([describe(`/sobjects/${obj}/describe`), describe(`/tooling/sobjects/${obj}/describe`)]);
  if (s) schema.soql[obj] = s;
  if (t) schema.tooling[obj] = t;
}
writeFileSync(out, JSON.stringify(schema, null, 1) + '\n');
console.log(`API ${version}: ${Object.keys(schema.soql).length} standard-API objects, ${Object.keys(schema.tooling).length} Tooling objects -> ${out}`);
