# Apex access mode

## RULE-001 SYSTEM_MODE under `with sharing` is a CRUD/FLS bypass, not a sharing bypass
cites: INT-001, MN-001, MN-003
- When an @AuraEnabled, @RemoteAction or @RestResource class is declared `with sharing` and uses `WITH SYSTEM_MODE` or `AccessLevel.SYSTEM_MODE`
- then `portal-exposed-apex-without-sharing` does not list it
- and `apex-crud-fls` lists it in the finding `apex-crud-fls-system-mode`, naming SYSTEM_MODE as the cause

## RULE-002 SYSTEM_MODE never counts as CRUD/FLS enforcement
cites: INT-001, MN-003
- When a class with SOQL or DML uses `WITH SYSTEM_MODE`, `AccessLevel.SYSTEM_MODE` or `as system` DML (`insert as system rows;`), including a batch or scheduled class
- then `apex-crud-fls` lists it in `apex-crud-fls-system-mode`, even if the class also contains a CRUD/FLS check or USER_MODE elsewhere
- and `WITH USER_MODE`, `AccessLevel.USER_MODE` and `as user` DML count as enforcement, alongside explicit CRUD/FLS checks
- and only code counts: these words in a comment neither enforce nor bypass anything

## RULE-003 Guest-callable SYSTEM_MODE under `with sharing` is HIGH, not CRITICAL
cites: INT-001, MN-001, MN-003
- When a guest-executable class is declared `with sharing` and uses SYSTEM_MODE
- then it appears in a HIGH guest finding for CRUD/FLS bypass (`guest-executable-apex-system-mode`)
- and not in the CRITICAL `guest-executable-apex-unprotected`

## RULE-004 A guest-callable class calling a `without sharing` helper is unprotected
cites: INT-001, MN-002
- When a guest-executable class declared `with sharing` references, per its SymbolTable, a class whose body declares `without sharing`
- then it appears in `guest-executable-apex-unprotected`, naming the helper
- and a helper that only uses dynamic SOQL, or has no sharing keyword (and so runs with the caller's), does not make it unprotected

## RULE-005 @RestResource classes are externally exposed
cites: INT-001, MN-002
- When a class carries @RestResource and is declared `without sharing` or declares no sharing
- then `portal-exposed-apex-without-sharing` lists it, as it does @AuraEnabled and @RemoteAction classes

## RULE-006 The new findings are wired into attack-chain correlation
cites: INT-001, MN-001, MN-002
- When `guest-executable-apex-system-mode` is active
- then it grants `code-exec` and `data-read` (not `data-read-bulk`: record sharing still applies) and is a step in the `unauth-bulk-exfil` chain, like `guest-executable-apex-exposed`
- and `apex-crud-fls-system-mode` grants `data-read`, like `apex-crud-fls-missing`

## RULE-007 From API 67.0 an omitted sharing keyword means with sharing
cites: INT-001, MN-001
- When a class declares no sharing keyword and it, and every parent it inherits sharing from while none declares one, is compiled at API 67.0 or later (Salesforce Summer '26 release note "Apex Classes Enforce Sharing Rules by Default")
- then it runs with sharing: `guest-executable-apex-unprotected`, `portal-exposed-apex-without-sharing`, `apex-no-sharing-declaration` and `apex-rest-no-sharing-declaration` do not list it, and the guest check goes on to judge its helpers and SYSTEM_MODE as for a `with sharing` class
- and `apex-sharing-summary` counts it separately as "no declaration at API 67.0+"
- and a class below 67.0, or whose version (or a parent's) cannot be read, keeps the old default and is reported as before

## RULE-008 A keyword-less class entered only through @AuraEnabled methods runs with sharing
cites: INT-001, MN-001
- When a class declares no sharing keyword, has `@AuraEnabled` methods, and has no other way in (`@RemoteAction`, `@RestResource`, `@Http*`, `webservice`, or Visualforce controller use through `ApexPages` or `PageReference`)
- then, whatever its API version, it runs with sharing (the "Use with sharing for @AuraEnabled Apex Controllers with Implicit Sharing" update, enforced from Winter '21): `guest-executable-apex-unprotected` and `portal-exposed-apex-without-sharing` do not list it for its missing keyword, and the guest check goes on to judge its helpers and SYSTEM_MODE
- and `apex-no-sharing-declaration` still lists it below API 67.0, as hygiene: another caller could still enter it without sharing

## RULE-009 From API 67.0 queries and DML run in user mode by default
cites: INT-001, MN-003
- When a class with SOQL or DML is saved at API 67.0 or later and uses no SYSTEM_MODE (`WITH SYSTEM_MODE`, `AccessLevel.SYSTEM_MODE`, `as system` DML)
- then its queries and DML enforce the running user's object and field permissions, so `apex-crud-fls-missing` and `apex-crud-fls-without-sharing` do not list it
- and SYSTEM_MODE in such a class is still reported in `apex-crud-fls-system-mode` (RULE-002)
