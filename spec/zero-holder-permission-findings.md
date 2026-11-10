# Zero-holder permission findings

Every org with an active System Administrator has users holding Modify All Data and View All
Data, so finding none means the audit could not see the assignments. It never means the org is clean.

## RULE-040 Zero holders is reported as inconclusive
cites: INT-004, MN-011
- When no active user is found holding Modify All Data (or View All Data)
- then `users-modify-all-data` (or `users-view-all-data`) is still reported, so the gap stays visible
- and it is `inconclusive: true` at INFO, titled "Could not confirm who holds …", with a remediation that says how to get a definite answer
- and it is never `passed`
- and at one holder or more it is counted, with the existing severity thresholds and count title unchanged; on a complete read the lowest band is reported as passed (RULE-074)

## RULE-041 A zero-holder finding never completes an attack chain
cites: INT-004, MN-011
- When the only View All / Modify All evidence is a zero-holder finding
- then no chain, named or emergent, includes either finding as a step, given the real check's output
- and `insider-bulk-exfil`, `mfa-bypass-admin`, `xss-to-privileged-session`, `soql-injection-read` and `inbound-email-rce` do not fire on it
- and `platform-event-priv-esc` does not list it as a target
- and the same orgs with one holder still fire them, with the holder finding as a step

## RULE-042 A partial read gives lower bounds, not passes
cites: INT-004, MN-011
- When the org returns its permission set assignments in more than one batch
- then the check counts holders across every batch, not only the first
- and when fewer rows come back than a COUNT() of the same query reports (the assignments changed between the read and the count; since sf-core 0.12 `queryAll` reads every page, so no row limit applies), or the COUNT fails, the read is partial
- and a partial read always adds the inconclusive finding `users-and-admins-read-incomplete`, saying how much was read, because counts under a reporting threshold (super-admin, Customize Application > 5, Author Apex > 3) may then not appear at all
- and on a partial read a non-zero Modify All / View All count is a definite lower bound: the finding stays active at that bound's severity, never passed even in the lowest band, titled "At least N user(s) …", with the read noted in its detail; super-admin, Customize Application and Author Apex findings that are reported carry the same title
- and on a partial read a zero count is inconclusive and says how much was read
- and a failed COUNT never fails the rest of the check, and its advice covers both visibility and re-running the audit

## RULE-043 An unknown count is never shown or compared as a number on the dashboard or in a diff
cites: INT-004, MN-011
- When a count's finding is inconclusive, a lower bound, missing because the check did not run, or an archived "0 user(s)" from v1.17 or earlier
- then the check omits that metric, the HTML dashboard shows it as "unknown" rather than a number, and the history diff reports no change for it in either direction
- and JSON output still carries the 0 default from sf-core's metrics schema; that is a known gap, not covered here
