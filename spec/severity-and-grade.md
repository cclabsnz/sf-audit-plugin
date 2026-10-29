# Severity and grade

## RULE-064 Unassessed findings carry no weight in the health score
cites: INT-011, MN-054
- When a finding is inconclusive or not assessed
- then it adds nothing to the penalty and nothing to the maximum the score is measured against
- and passed findings still count towards the maximum, as before

## RULE-065 Every grade comes with its reason
cites: INT-011, MN-055
- When an audit result is built
- then it carries `gradeReason`, naming what set the grade: the CRITICAL count, the HIGH count, the score band, or the coverage cap
- and the terminal, Markdown, HTML and executive outputs print it next to the grade

## RULE-066 Modify All Data is rated on the holders the super-admin finding does not already cover
cites: INT-011, MN-052
- When users hold Modify All Data and some also hold the super-admin combination
- then `users-modify-all-data` takes its severity from the holders outside the super-admin finding (more than 5 CRITICAL, more than 3 HIGH, else LOW)
- and it still lists every holder

## RULE-067 Admin-count findings are capped at HIGH in a sandbox
cites: INT-011, MN-052
- When the org is a sandbox
- then `users-super-admin-combo` and `users-modify-all-data` are at most HIGH, and say the cap applies because the org is a sandbox and lifts if it holds production data

## RULE-068 An expiring certificate is HIGH, not CRITICAL
cites: INT-011, MN-053
- When a certificate has expired or expires within 30 days
- then `certificate-expiring-critical` is HIGH, keeping its id

## RULE-069 Externally callable Apex is CRITICAL only when it declares `without sharing`
cites: INT-011, INT-001, MN-002
- When an @AuraEnabled, @RemoteAction or @RestResource class lacks `with sharing`
- then `portal-exposed-apex-without-sharing` is CRITICAL if any such class declares `without sharing`, and HIGH if all of them only lack a declaration
- and guest-callable classes stay governed by `guest-executable-apex`, whose severities do not change

## RULE-070 Potential attack chains do not set the grade
cites: INT-011
- When an attack chain has confidence `potential`
- then it is reported, but its severity does not count towards the grade

## RULE-071 Unauthenticated bulk exfiltration needs a confirmed guest exposure
cites: INT-012, MN-056
- When the findings include no guest exposure (guest object or record access, guest-executable Apex, guest-readable records confirmed by `UserRecordAccess`, guest API access, guest user visibility, an unenforced guest record-access policy, or an unauthenticated email handler)
- then `unauth-bulk-exfil` does not fire, however many surfaces exist (`guest-user-baseline`, `classic-sites-active`)
- and when one is present, those surfaces still join the chain as steps
- and the chain fires only when one of its guest-side steps grants bulk read, write or code execution: an internal user's View All Data, an admin's Author Apex, or Apex and Flow merely running without sharing (`portal-exposed-apex-without-sharing`, `flows-*-without-sharing`) neither open it nor join it, and the potential-chain pass does not pair a guest foothold with them either
- and the chain fires only when one step shows the guest reaching records (`guest-user-sharing-exposure`, `guest-object-exposure-public-owd`, `guest-object-exposure-guest-owned`, `guest-user-visibility-view-all-users`, `guest-executable-apex-unprotected`, `guest-record-access-policy-not-enforced`): guest object permissions, guest API access, or guest-callable Apex not shown to bypass sharing reach no record on their own, and the potential-chain pass emits no guest-foothold chain without one of these either
- and no potential chain starts from a surface alone: `guest-user-baseline` and `classic-sites-active` never supply its entry point

## RULE-072 Standard user to org takeover needs a low-trust entry and an escalation a non-admin can use
cites: INT-012, MN-056
- When the findings include no low-trust entry (external users with public sharing, social sign-on, self-registration, or a confirmed guest exposure) or no escalation available to a non-admin (escalation permissions, shadow admins, separation-of-duties self-escalation, delegated admins or login-as, an over-privileged integration account)
- then `standard-to-takeover` does not fire
- and `users-super-admin-combo`, `users-author-apex` and `guest-user-baseline` join a chain that fires as evidence, but never satisfy either requirement

## RULE-075 Separation of duties is rated on users the super-admin finding does not already cover
cites: INT-011, MN-052
- When a toxic permission combination is held by users who also hold Modify All Data, View All Data and Manage Users
- then those users are left out of the `separation-of-duties-*` finding, which counts only the others and names how many super-admins it left out
- and when only super-admins hold every combination, the check passes, pointing to `users-super-admin-combo`

## RULE-076 The super-admin finding is graded on how many hold it
cites: INT-011, MN-052
- When users hold Modify All Data, View All Data and Manage Users together
- then `users-super-admin-combo` is CRITICAL above 5 holders, HIGH above 3, and LOW otherwise, asking for each holder's justification to be documented; the sandbox cap (RULE-067) still applies

## RULE-077 Escalation permissions are rated on users the super-admin finding does not cover
cites: INT-011, INT-012, MN-052, MN-056
- When users holding Modify All Data, View All Data and Manage Users also hold an escalation permission
- then `escalation-perms-found` lists only the other holders, says how many super-admins it left out, and passes when only super-admins hold them
- and only escalation primitives (Manage Internal Users, Assign Permission Sets, Modify Metadata, Manage Auth Providers, Manage Connected Apps, Manage Session Permission Set Activations) make `escalation-perms-found`; Password Never Expires and View All Users are hygiene, reported as MEDIUM `escalation-perms-hygiene`, which feeds no attack chain
- and "Administrators can log in as any user" (`login-access-policy-login-as-enabled`) is an admin power, so it joins `standard-to-takeover` as evidence only, never as its escalation

## RULE-078 A defence-in-depth gap is at most MEDIUM
cites: INT-011
- When a finding reports a missing second layer rather than an exposure: no explicit MFA permission while Salesforce enforces MFA for UI logins at org level (`internal-user-mfa-gaps`), or no field history on sensitive objects (`field-history-tracking-missing`)
- then it is MEDIUM when it is widespread and LOW otherwise, and its title says it is a second layer

## RULE-079 The HTML dashboard counts the findings the grade counts
cites: INT-011, MN-055
- When the HTML report draws its severity donut and KPI cards
- then each severity counts open findings only: passed, inconclusive, not-assessed and waived findings are left out, as the score and the executive report's severity chips do
- and the donut is captioned "open findings"
- and the grade reason and coverage note sit below the score gauge, at the panel's full width
