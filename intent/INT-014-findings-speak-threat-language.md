# INT-014 Findings speak the threat language their readers already use

Security architects review in STRIDE, privacy officers in LINDDUN, SOC teams in MITRE ATT&CK, and
assessors ask for abuse cases. Today a finding only carries compliance controls (OWASP, SOC 2, ISO and
the regional packs), so each reader re-maps the report by hand, and does it differently each time.
The attack-chain engine already models attacker capability, and the named chains already tell abuse
stories in prose, but nothing ties either to a standard vocabulary.

Threat categories and compliance controls answer different questions. A control asks "is this
requirement met?" A category asks "what kind of harm is this?" An empty compliance row means no
mapped check found anything. An empty STRIDE row means nothing either way, and must not read as
"safe".

- MN-058: never present a threat category (STRIDE, LINDDUN, ATT&CK) as a compliance control, or let an empty category read as assurance
- MN-059: never render an ATT&CK technique, or an OWASP control, that has not been verified against a pinned version of its source
- MN-060: never name a remediation as the point that breaks an attack chain unless removing it does break the chain
- MN-061: never net a privacy threat against a security control; when STRIDE and LINDDUN disagree about a setting, show both readings
- MN-062: never let threat tagging change a finding's severity, the health score or the grade
