# Further reading

Deep dives on this tool and the topics it checks, from our engineering blog **[softwareinsights.dev](https://www.softwareinsights.dev)**.

**How the commands work:**

- [How sf-audit works — checks, attack chains, and compliance mapping](https://www.softwareinsights.dev/posts/sf-audit-61-checks-attack-chains-compliance-mapping/) — the design walkthrough behind `sf audit security`
- [Free Salesforce Event Monitoring: a baseline from EventLogFile without Shield](https://www.softwareinsights.dev/posts/salesforce-free-event-monitoring-eventlogfile-baseline/) — why [`sf audit events pull`](#free-event-baseline) exists and how to cron it
- [Which connected apps use less than they're granted? Ask your own logs](https://www.softwareinsights.dev/posts/salesforce-connected-app-least-privilege-granted-vs-used/) — the granted-vs-used method behind [`sf audit apps`](#connected-app-least-privilege)
- [Scanner or breach? Triage EventLogFile in one command](https://www.softwareinsights.dev/posts/salesforce-eventlogfile-guest-traffic-triage-scanner-or-breach/) — pairing an `events pull` baseline with the [sfelf-triage](https://github.com/cclabsnz/sfelf-triage) companion
- [Salesforce guest user exposure, graded by real reachability](https://www.softwareinsights.dev/posts/sf-audit-guest-user-exposure-reachability/) — the UI-API reachability tiering behind the [guest checks](#guest--external-facing-access)
- [sf-audit vs sf-cli-security-audit](https://www.softwareinsights.dev/posts/sf-audit-vs-sf-cli-security-audit/) — how this plugin differs from a configurable policy engine, and when to reach for each

**The access model the privilege checks encode** — the reasoning behind [Users, Permissions & Privilege](#users-permissions--privilege):

- [Why your developers don't need Modify All Data](https://www.softwareinsights.dev/posts/salesforce-developers-modify-all-data-what-they-need-instead/) — part 1 of a four-part series on delivery-team access; feeds Users & Admins and Privileged Access & Shadow Admins
- [The access model: tiers and roles](https://www.softwareinsights.dev/posts/salesforce-delivery-team-access-model-tiers-and-roles/) — the tiering that Separation of Duties and Privilege Escalation Permissions test against
- [Sizing the model to your team](https://www.softwareinsights.dev/posts/salesforce-access-model-sizing-internal-vs-external-admin-teams/) — internal vs external admins, and what the model costs to run
- [Deployable permission sets](https://www.softwareinsights.dev/posts/salesforce-delivery-team-deployable-permission-sets/) — the metadata and the CI identity, which the Integration / Service Accounts check inventories

**Platform changes the checks track:**

- [Hardening Agentforce against prompt injection (post-ForcedLeak)](https://www.softwareinsights.dev/posts/salesforce-agentforce-forcedleak-prompt-injection-hardening/) — feeds the Agentforce / GenAI checks
- [Audit your Agentforce footprint: every agent, agent user, and permission](https://www.softwareinsights.dev/posts/salesforce-agentforce-footprint-audit/) — the manual SOQL behind Agent Inventory
- [Agentforce agent user least privilege](https://www.softwareinsights.dev/posts/salesforce-agentforce-agent-user-least-privilege/) — feeds the Agent User Privilege check
- [Salesforce MFA enforcement: the revised 2026 dates](https://www.softwareinsights.dev/posts/salesforce-mfa-enforcement-paused-revised-dates-2026/) — feeds the MFA checks
- [The MFA enforcement admin guide](https://www.softwareinsights.dev/posts/salesforce-mfa-enforcement-2026-admin-guide/) — what the MFA Enforcement / Registration / Method Strength checks are measuring against
- [MFA lockout recovery and break-glass accounts](https://www.softwareinsights.dev/posts/salesforce-mfa-lockout-recovery-break-glass-accounts/) — the operational side of the MFA and High Assurance Session checks
- [OAuth username-password (ROPC) flow retirement in Winter '27](https://www.softwareinsights.dev/posts/salesforce-oauth-username-password-flow-retirement-winter-27/) — feeds the SSO Enforcement and Connected App OAuth Scopes checks
- [Email change verification retirement and Authorized Email Domains](https://www.softwareinsights.dev/posts/salesforce-email-change-verification-retirement-authorized-email-domains/) — feeds the Email Security check
- [Summer '26: SAML retirement & Apex secure-by-default](https://www.softwareinsights.dev/posts/salesforce-summer-26-saml-retirement-apex-secure-by-default/) — feeds the SSO / Apex checks
- [Salesforce security enforcement in 2026 — every change and date](https://www.softwareinsights.dev/posts/salesforce-security-enforcement-2026-complete-guide/) — the overall posture this tool measures
- [Report-export step-up enforcement: known issues](https://www.softwareinsights.dev/posts/salesforce-transaction-security-policy-report-export-known-issues/) — feeds the data-export / transaction-security checks

**Compliance and NZ context** — background for the [framework mappings](#compliance-frameworks):

- [Mapping Salesforce security to NZISM, the NZ Privacy Act and ISO 27001](https://www.softwareinsights.dev/posts/salesforce-security-nzism-nz-privacy-act/)
- [Data sovereignty for New Zealand Salesforce orgs](https://www.softwareinsights.dev/posts/salesforce-data-sovereignty-new-zealand/) — residency vs sovereignty, and why the `nz` framework pack exists
- [IPP 3A indirect collection notices](https://www.softwareinsights.dev/posts/salesforce-nz-privacy-ipp3a-indirect-collection-notice/) — feeds the NZ Privacy Act control mappings
- [Why Salesforce Health Cloud needs its own security review](https://www.softwareinsights.dev/posts/salesforce-health-cloud-security-review/) — the HISO 10029 context
