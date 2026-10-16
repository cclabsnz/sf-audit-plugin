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

