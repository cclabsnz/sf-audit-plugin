// RULE-063, past the first empty result. The schema guard (liveOrgQueries.schema.test.ts) answers
// every valid query with no rows, so a check that starts by listing guest users or Apex classes
// stops there and its deeper queries are never validated. Here the context answers with one
// consistent org: a site guest user who can read Lead, has a group membership, and can run Apex
// classes with cached bodies. Every query each check then sends is validated against the captured
// Developer Edition schema, and the queries these paths exist for must actually be sent.
import { GuestObjectExposureCheck } from '../../../src/checks/impl/GuestObjectExposureCheck.js';
import { GuestUserAccessCheck } from '../../../src/checks/impl/GuestUserAccessCheck.js';
import { GuestUserVisibilityCheck } from '../../../src/checks/impl/GuestUserVisibilityCheck.js';
import { GuestSiteOptionsCheck } from '../../../src/checks/impl/GuestSiteOptionsCheck.js';
import { GuestExecutableApexCheck } from '../../../src/checks/impl/GuestExecutableApexCheck.js';
import { ApexSharingCheck } from '../../../src/checks/impl/ApexSharingCheck.js';
import { ApexRestEndpointCheck } from '../../../src/checks/impl/ApexRestEndpointCheck.js';
import { ApexCrudFLSCheck } from '../../../src/checks/impl/ApexCrudFLSCheck.js';
import { PublicGroupSharingCheck } from '../../../src/checks/impl/PublicGroupSharingCheck.js';
import type { SecurityCheck } from '../../../src/checks/SecurityCheck.js';
import { schemaCtx, type RowSource } from './support/schemaCtx.js';

const GUEST = '005xx0000000001AAA';
const CLASS_ID = '01pxx0000000001AAA';

const org: RowSource = (_api, q) => {
  if (/FROM User WHERE UserType = 'Guest'/.test(q)) return [{ Id: GUEST, ProfileId: '00exx0000000001AAA', Username: 'site guest' }];
  if (/FROM PermissionSetAssignment/.test(q)) {
    return [{ AssigneeId: GUEST, PermissionSetId: '0PSxx0000000001AAA', PermissionSet: { Label: 'Guest', PermissionsViewAllUsers: false } }];
  }
  if (/FROM ObjectPermissions/.test(q)) {
    return [{ ParentId: '0PSxx0000000001AAA', SobjectType: 'Lead', PermissionsRead: true, PermissionsCreate: false, PermissionsEdit: false, PermissionsDelete: false }];
  }
  if (/FROM EntityDefinition/.test(q)) {
    return [
      { QualifiedApiName: 'Lead', ExternalSharingModel: 'Private', InternalSharingModel: 'Private' },
      { QualifiedApiName: 'User', ExternalSharingModel: 'Read', InternalSharingModel: 'Read' },
    ];
  }
  if (/FROM GroupMember/.test(q)) return [{ GroupId: '00Gxx0000000001AAA' }];
  if (/FROM Group WHERE Type = 'Organization'/.test(q)) return [{ Id: '00Gxx0000000002AAA', Name: null, Type: 'Organization' }];
  // No guest-owned or guest-shared Lead, so the check goes on to sample and ask UserRecordAccess.
  if (q.startsWith('SELECT Id FROM Lead LIMIT')) return [{ Id: '00Qxx0000000001AAA' }];
  if (/FROM SetupEntityAccess/.test(q)) return [{ SetupEntityId: CLASS_ID, ParentId: '0PSxx0000000001AAA' }];
  if (/FROM ApexClass WHERE Id IN/.test(q)) return [{ Id: CLASS_ID, Name: 'SiteCtl' }];
  if (/FROM ApexClass WHERE NamespacePrefix = null/.test(q)) return [{ Name: 'SiteCtl', ApiVersion: 66 }, { Name: 'Api', ApiVersion: 66 }];
  if (/FROM Network/.test(q)) {
    return [{ Id: '0DBxx0000000001AAA', Name: 'Site', Status: 'Live', OptionsGuestFileAccessEnabled: false, OptionsGuestMemberVisibility: true }];
  }
  return undefined;
};

const BODIES = [
  { name: 'SiteCtl', body: 'public class SiteCtl { @RemoteAction public static List<Lead> go() { return [SELECT Id FROM Lead]; } }' },
  { name: 'Api', body: "@RestResource(urlMapping='/api/*') global class Api { @HttpGet global static void g() { update [SELECT Id FROM Lead]; } }" },
];

const CHECKS: SecurityCheck[] = [
  new GuestObjectExposureCheck(), new GuestUserAccessCheck(), new GuestUserVisibilityCheck(), new GuestSiteOptionsCheck(),
  new GuestExecutableApexCheck(), new ApexSharingCheck(), new ApexRestEndpointCheck(), new ApexCrudFLSCheck(),
  new PublicGroupSharingCheck(),
];

// The queries each path exists for. If a check stops sending one, the path is no longer exercised.
const EXPECTED: Array<[string, RegExp]> = [
  ['guest group memberships', /^SELECT GroupId FROM GroupMember WHERE UserOrGroupId IN/],
  ['guest user groups', /^SELECT Id FROM Group WHERE Type = 'GuestUserGroup'$/],
  ['the All Internal Users group', /^SELECT Id, Name, Type FROM Group WHERE Type = 'Organization'$/],
  ['share rows to the All Internal Users group', /FROM AccountShare WHERE .*UserOrGroupId IN \('00Gxx0000000002AAA'\)/],
  ['guest share rows on a guest-readable object', /^SELECT COUNT\(\) FROM LeadShare WHERE RowCause IN \('GuestRule', 'GuestParentImplicit', 'GuestPersonImplicit'\) OR \(UserOrGroupId IN \('005xx0000000001AAA'\) AND RowCause != 'Owner'\) OR UserOrGroupId IN \('00Gxx0000000001AAA'\)$/],
  ['guest share rows on the four standard objects', /^SELECT COUNT\(\) FROM OpportunityShare WHERE RowCause IN/],
  ['guest-owned records', /^SELECT COUNT\(\) FROM Lead WHERE OwnerId IN/],
  ['UserRecordAccess confirmation', /^SELECT RecordId, HasReadAccess FROM UserRecordAccess WHERE UserId = '005xx0000000001AAA' AND RecordId IN/],
  ['Apex class API versions', /^SELECT Name, ApiVersion FROM ApexClass WHERE NamespacePrefix = null$/],
  ['guest class access through permission sets', /FROM SetupEntityAccess WHERE SetupEntityType = 'ApexClass' AND ParentId IN/],
  ['the User external OWD', /FROM EntityDefinition WHERE QualifiedApiName = 'User'/],
];

describe('RULE-063 deep paths: queries past the first empty result are valid against the org schema', () => {
  const run = async () => {
    const { ctx, violations, queries } = schemaCtx(org);
    (ctx.cache as Record<string, unknown>).apexBodies = BODIES;
    const findings: string[] = [];
    for (const check of CHECKS) {
      const r = await check.run(ctx);
      findings.push(...r.findings.map((f) => f.id));
    }
    return { violations, queries: queries.map((q) => q.query), findings };
  };

  it('no query is rejected', async () => {
    const { violations } = await run();
    expect(violations.map((v) => `${v.api}: ${v.error}  <-  ${v.query.slice(0, 200)}`)).toEqual([]);
  });

  it.each(EXPECTED)('sends the query for %s', async (_what, re) => {
    const { queries } = await run();
    expect({ sent: queries.some((q) => re.test(q)) }).toEqual({ sent: true });
  });

  // The seeded org drives each check to a verdict, not to an inconclusive or "nothing to check".
  it('reaches the findings the seeded org implies', async () => {
    const { findings } = await run();
    expect(findings).toEqual(expect.arrayContaining([
      'guest-user-visibility-owd',
      'guest-site-options-member-visibility',
      'guest-executable-apex-unprotected',
      'apex-rest-no-sharing-declaration',
      'apex-crud-fls-missing',
    ]));
    expect(findings.filter((f) => /inaccessible|inconclusive|no-bodies/.test(f))).toEqual([]);
  });
});
