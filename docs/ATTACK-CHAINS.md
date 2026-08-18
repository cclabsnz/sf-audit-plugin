# Attack chains

A list of findings is not a risk assessment. Three MEDIUM findings that combine into an
unauthenticated path to bulk data matter more than a lone HIGH that leads nowhere, and reading a
report severity-by-severity hides exactly that. So every audit also correlates its findings into
**attack chains**: the specific combinations that turn separate misconfigurations into a route from
an attacker's entry point to a real outcome.

Correlation runs in two passes. **Named chains** are hand-modelled scenarios — a known pattern, with
its own narrative and remediation. Where no named chain explains a combination, an **emergent pass**
reports the remaining entry-point → outcome pairs as lower-confidence "potential attack paths", so a
novel combination is still surfaced rather than missed. Every chain lists the findings that form its
steps, and remediating **any one step breaks the chain** — which is what makes this actionable
rather than alarming.

The eleven named chains:

| Chain | Severity | Fires when |
|-------|----------|-----------|
| Unauthenticated bulk exfiltration | CRITICAL | A guest foothold combines with guest-reachable code execution, public external sharing, or a guest bulk-read surface — no login required. Reached over the site's Aura endpoint (`/s/sfsites/aura`, `aura.token=null`): `RecordUiController/ACTION$executeGraphQL` for record data, or `aura.ApexAction.execute` to invoke `@AuraEnabled` Apex that runs without sharing |
| Active guest reconnaissance against an exposed data surface | CRITICAL | `AuraRequest` / `GraphQlQueryExecution` evidence shows guests probing from anonymizer IPs, or running `totalCount`-only GraphQL sweeps against `/s/sfsites/aura` to map what is readable, **and** the org exposes objects those guests can bulk-read. Reconnaissance against a confirmed surface — likely an incident already in progress |
| Standard user to org takeover | CRITICAL | A low-trust or unauthenticated entry point combines with a privilege-escalation path: escalation permissions, Author Apex, shadow admins, delegated admin, Login-As, or a toxic permission combination |
| Credential theft to external pivot | CRITICAL | Exposed secrets (hardcoded credentials, credentials in Custom Labels, debug logs, broad CORS) combine with an egress path — a named credential, remote site, or a self-provisioned connected app |
| Prompt injection blast radius | CRITICAL | A guest-reachable Agentforce channel, an over-privileged agent run-as user, and write-capable agent actions are all present, so one injected prompt can read, alter, or destroy data across the agent's reach. Reached over the messaging host (`*.my.salesforce-scrt.com`, `/iamessage/api/v2/…`), **not** the site's Aura endpoint — the API's unauthenticated access-token flow needs only the org id and the deployment's `esDeveloperName`, both public in the widget's bootstrap |
| ForcedLeak pattern | CRITICAL | Active agents + a stale or unresolvable CSP-trusted domain + no Event Monitoring capture. The Noma Security chain (Sept 2025): re-register the lapsed domain, inject an agent into sending data to it, and nothing records it |
| SOQL injection to mass read | HIGH | Injectable dynamic SOQL combines with a bulk-readable data sink (broad sharing, unencrypted sensitive fields, public report folders, View All Data) |
| MFA bypass to privileged compromise | HIGH | Weak MFA enforcement or trusted-IP MFA bypass coincides with highly-privileged accounts, so phishing or credential stuffing reaches an admin without a second factor |
| Unmasked production PII in a weakly-controlled sandbox | HIGH | A sandbox holds populated PII fields — unmasked production data — while running weaker authentication or broader sharing than the org it was refreshed from. The data is real; only the protection is not |
| Insider bulk export without monitoring | HIGH | Data is broadly readable internally, a profile or permission set can export it en masse, **and** no monitoring would record the export — the third element is what makes it unreconstructable afterwards |
| Exploitable access with no detection coverage | MEDIUM | A real capability (unauthenticated foothold, privilege escalation, org takeover) exists while two or more of threat detection, Event Monitoring, Transaction Security and SIEM forwarding are absent. Adds no exposure — reports that existing exposure would go unobserved |

Chains appear in the technical report and drive the executive report's priorities and remediation
roadmap. A chain is only reported when **every** one of its ingredients is actually present: a clean
org produces none.
