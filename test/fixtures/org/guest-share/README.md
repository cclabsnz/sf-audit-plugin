# Guest share fixture (Developer Edition only)

Exercises the guest sharing-rule path of `guest-object-exposure` against a real org: a custom
object with a Private OWD, guest Read through a permission set, and a guest user sharing rule
that shares records whose Name starts with "Public". Never deploy it to a client org.

1. Set `<guestUser>` in `force-app/main/default/sharingRules/SFA_Guest_Fixture__c.sharingRules-meta.xml`
   to your site's name (`SELECT Name FROM Site`).
2. Deploy the `force-app` folder to your Developer Edition org with the Salesforce CLI, from this folder.
3. Assign `SFA_Guest_Fixture_Read` to the site guest user (a PermissionSetAssignment record).
4. Create one record named `Public fixture record` and one named `Internal fixture record`.
5. Run `sf audit security -o <devorg> --json`: expect `guest-object-exposure-guest-shared` (HIGH)
   with `SFA_Guest_Fixture__c: 1 guest share row(s)`, and no `unauth-bulk-exfil` chain.

Observed on 2026-10-30 (API 68.0): the rule writes one share row per matching record with
`RowCause = 'GuestRule'`, naming the site's guest user group (`Group.Type = 'GuestUserGroup'`),
not the guest user.

Remove: delete the records and the PermissionSetAssignment, then the sharing rule, permission set
and object (a destructive deploy, or Setup).
