# INT-015 NZ compliance citations trace to a published source

A New Zealand health or government reviewer reads sf-audit's HISO 10029 and NZISM citations as
claims about which requirement a finding bears on. Until 1.28.0 those citations were eight HISO
"domains" and seven NZISM chapters that sf-audit made up, applied to every check in a domain, so a
guest-user finding and an inactive-user finding cited the same things. A reviewer works at the
level of the published requirement: HML39, HSUP34, NZISM 16.7.

The Secure Controls Framework (SCF) publishes crosswalks to every NZ framework sf-audit cites. Its
HISO crosswalk is coarse (each HISO requirement links to one or two broad SCF controls), so a
mapping derived only from SCF leaves most checks citing no HISO requirement. Citations therefore
come from two places, and each says which.

- MN-063: never cite a HISO requirement or NZISM section that does not exist in the pinned source edition
- MN-064: never present sf-audit's own judgement as a published crosswalk; a citation that SCF does not derive is marked direct and carries its reason
- MN-065: never drop a citation SCF's crosswalk derives for a check without recording why
- MN-066: never present a citation as a statement that the org complies with the requirement
