# Live-org queries

## RULE-060 A rejected query is labelled as rejected, not as missing permissions
cites: INT-010, MN-050
- When a check throws `INVALID_FIELD`, `INVALID_TYPE` or `MALFORMED_QUERY`, or a message saying an sObject type is not supported or a field cannot be filtered
- then its finding is inconclusive and not assessed, titled "<check>: query rejected by the org"
- and the detail quotes the org's error, and the remediation does not tell the reader to grant permissions

## RULE-061 An access error is still labelled as missing permissions
cites: INT-010, MN-050
- When a check throws `INSUFFICIENT_ACCESS_RIGHTS`, `INSUFFICIENT_ACCESS_OR_READONLY`, `ENTITY_IS_INACCESSIBLE` or a message saying access is insufficient
- then its finding is inconclusive and titled "<check>: insufficient permissions"

## RULE-062 Commands use the org's API version
cites: INT-010, MN-051
- When `audit security`, `audit apps`, `audit events pull` or `audit incident collect` connects
- then it uses the org's own API version, not a pinned older one

## RULE-063 Checks query only what the org's schema has, through the API that serves it
cites: INT-010, MN-050, MN-051
- When any registered check runs against the captured Developer Edition schema
- then every query names an object served by the API it is sent to, selects only fields that object has, filters only on filterable fields, and uses no reserved alias such as `expr0`
- and a field that only some editions have is looked up by describe first; when it is absent the check says the feature is not available in this org, and does not count it as a pass
