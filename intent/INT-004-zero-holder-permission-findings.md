# INT-004 A permission nobody holds is not an exposure

`users-and-admins` always reports how many users hold Modify All Data and View All Data, so the
population stays visible in every report. It reported "0 user(s) have View All Data permission"
as an active finding, and attack chains read active findings as evidence. Every org therefore met
the "somebody holds View All / Modify All" ingredient, and `insider-bulk-exfil`,
`mfa-bypass-admin` and `xss-to-privileged-session` could fire with no such user in the org.

- MN-011: never count a Modify All Data or View All Data finding with zero holders as active: not in the score, not in the exit code, and not as an attack-chain step; and never report it as a pass, because zero holders means the audit could not see them
