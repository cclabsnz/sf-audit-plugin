# INT-011 A CRITICAL means a breach-grade exposure, and the grade says why

Three orgs graded F on 81, 75 and 72/100. Every F came from the rule that a D needs zero CRITICAL
findings, and the CRITICALs were not alike: guests reading every record sat beside a certificate
expiring in a sandbox, the same nine admins counted twice (super-admin, then Modify All Data), and
developers holding admin in a sandbox. Inconclusive checks also raised the score, because they sat
in its denominator. A CTO saw "81/100, grade F" with no reason; a consultant saw CRITICALs they would
not sign.

- MN-052: never count the same users twice towards the grade for the same power
- MN-053: never rate an availability problem (an expiring certificate) as a CRITICAL security finding
- MN-054: never let a check that gathered no evidence improve the health score
- MN-055: never show a grade without the reason for it
