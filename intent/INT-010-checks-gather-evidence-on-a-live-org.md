# INT-010 Checks gather evidence on a live org, and say why when they cannot

A run on a Developer Edition org as System Administrator left 41 of 101 checks unassessed. Most
were not access problems: queries named fields or objects that do not exist, used the standard API
for Tooling-only objects (or the reverse), filtered on fields Salesforce will not filter, or used
syntax Salesforce rejects. All four commands also pinned API 62.0, hiding newer fields. Every
failure was reported as "the running user lacks the required permissions", which sends an admin to
grant access that cannot help, and tells a reviewer the tool works when it does not.

The unit tests mocked every response, so a query the org would reject could never fail a test.

- MN-050: never report a query the org rejected as unknown field, unknown object or malformed as a permissions problem
- MN-051: never count a check as assessed, or as passing, when the field or object it needs is absent from the org
