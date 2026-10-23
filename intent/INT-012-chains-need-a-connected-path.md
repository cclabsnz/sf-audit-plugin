# INT-012 An attack chain needs a path an attacker can actually walk

"Unauthenticated bulk exfiltration" and "Standard user to org takeover" fired, both CRITICAL, on
all three orgs audited, including a Developer Edition. Each was opened by `guest-user-baseline`,
which only says a guest user with live site access exists, as it does in any org with a site.
The exfiltration chain then joined it to any flow or Apex running without sharing anywhere in the
org, guest-reachable or not; the takeover chain joined it to admins holding admin permissions. The
guest and the admins are different principals, so neither chain described a path.

- MN-056: never report an attack chain whose steps do not connect a reachable entry point to the impact it claims
