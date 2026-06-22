<!-- Thanks for contributing! Keep changes read-only against the org (SOQL/Tooling/REST GET only). -->

## What this changes

A short description of the change and why.

## Type

- [ ] New check
- [ ] Fix to an existing check (false positive / false negative)
- [ ] Report / renderer change
- [ ] Docs / tooling
- [ ] Other:

## Checklist

- [ ] `npm run build` is clean
- [ ] `npm test` is green; new/changed checks have unit tests with mocked clients
- [ ] Change is strictly read-only (no DML, no metadata writes)
- [ ] New checks are registered with correct cache ordering and have compliance + `CHECK_META` entries
- [ ] `README.md` check count / tables updated if user-facing behaviour changed
- [ ] No report artifacts (`sf-audit-*.{html,md,json}`) or internal files staged

## Related issues

Closes #
