# INT-013 The remediation roadmap lists work, and only work

The executive report's "Quick wins" tier on a Developer Edition org opened with real fixes, then
listed "0 failed login attempt(s) in the last 30 days", "Inactive Users: check failed", "0 active
scheduled/batch Apex job(s) found" and "No certificates found in this org". An engineering manager
handed that list cannot act on most of it, and stops trusting the rest. Two causes: the roadmap took
every finding that was not passed, including INFO inventories and crashed checks; and several checks
reported a healthy result as an open LOW finding.

- MN-057: never put a finding in the remediation roadmap that asks for no change to the org
