# INT-001 Apex findings say which control is actually bypassed

An Apex class can bypass two separate controls: record sharing (which records a user may touch)
and object/field permissions, CRUD/FLS (which objects and fields). The `with sharing` /
`without sharing` / `inherited sharing` keyword governs the first; `WITH SYSTEM_MODE` and
`AccessLevel.SYSTEM_MODE` turn off only the second, and record sharing still follows the class
keyword. A report that confuses them sends a client to fix the wrong thing, or inflates a
field-exposure issue into a CRITICAL record-access one.

- MN-001: never report a class as bypassing record sharing when its sharing is enforced, for example because it uses SYSTEM_MODE inside a `with sharing` class
- MN-002: never report a guest-callable class as protected when it, or a helper it calls, is declared `without sharing`
- MN-003: never let SYSTEM_MODE in a class pass as CRUD/FLS enforcement
