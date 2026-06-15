---
title: "Mapping Salesforce security findings to NZISM, HISO, ISO 27001 and OWASP"
date: 2026-06-15
author: CloudCounsel
description: "How we map every Salesforce security finding to source-verified controls across seven frameworks, including the New Zealand standards a generic scanner ignores."
---

A Salesforce security finding and a compliance control are written for different readers. "Three administrators have no MFA registered" is what an engineer fixes. "NZISM Chapter 16, Authentication and Access Controls" is what a CISO reports against and an auditor signs off. Most Salesforce security tooling stops at the first sentence. The space between the two is where audit findings sit in a backlog until someone has to explain them to a board.

Our audit tool, `@cclabsnz/sf-audit`, closes that space. Every finding it produces is mapped to the controls it implicates across seven frameworks, and the mapping is built to survive an auditor reading it line by line.

## Why the mapping has to be exact

A loose tag such as `ISO 27001` on a finding is worse than no tag. It implies a precision the tool cannot back up. The first time a CISO checks it against the standard and finds it wrong, every other mapping in the report loses credibility with it.

So the mapping is not a list of tags. It is a sourced control catalogue. Each control carries four things:

- its exact identifier, for example `NZISM-AC`, `ISO-A.8.15`, or `SBS-AUTH-004`
- the framework version it is mapped against: ISO/IEC 27001:2022, NZISM v3.8, the current editions rather than whatever was current three years ago
- the official control title, taken verbatim from the source
- a citation back to that source

A control only appears in a report after its title and reference have been confirmed against the authoritative published standard. Controls that have not been verified do not render. The report never makes a mapping claim it cannot defend.

Building the catalogue this way caught real errors before they reached a client. Our Salesforce control set had drifted to outdated identifiers; one framework was pinned to a superseded version; a handful of controls were mapped to the wrong criterion entirely. Verification against the source fixed each one. That is the point of the discipline.

## The standards we map to

Three are universal. One is specific to Salesforce. Three are specific to where our clients operate.

Universal:

- **OWASP Top 10:2021** ([owasp.org/Top10/2021](https://owasp.org/Top10/2021/)). The common language for application security risk: broken access control, injection, cryptographic failures, server-side request forgery, and the rest.
- **SOC 2, AICPA Trust Services Criteria** ([aicpa-cima.com](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)). The Common Criteria, CC6 through CC9, that most enterprise procurement asks a vendor to evidence.
- **ISO/IEC 27001:2022** ([iso.org/standard/27001](https://www.iso.org/standard/27001)). The Annex A controls, restructured in the 2022 edition into organisational, people, physical, and technological themes. The international baseline.

Salesforce-native:

- **Security Benchmark for Salesforce (SBS)** ([docs.securitybenchmark.org](https://docs.securitybenchmark.org/)). An independent, CIS-style benchmark written specifically for the platform. This is the one a generic scanner cannot reproduce, because it encodes Salesforce-specific controls: guest user record access, the "Use Any API Client" permission, connected app token policy, portal-exposed Apex.

New Zealand:

- **NZISM v3.8** ([nzism.gcsb.govt.nz](https://nzism.gcsb.govt.nz/)). The New Zealand Information Security Manual, maintained by the GCSB's National Cyber Security Centre. The baseline any agency handling government information aligns to.
- **HISO 10029:2022, Health Information Security Framework** ([tewhatuora.govt.nz](https://www.tewhatuora.govt.nz/health-services-and-programmes/cyber-hub/cyber-standards)). Health New Zealand's security framework for the health sector, built on the ISO/IEC 27002 control set.
- **NZ Privacy Act 2020, Information Privacy Principles** ([privacy.org.nz](https://privacy.org.nz/privacy-act-2020/privacy-principles/)). IPP 5 covers storage and security of personal information; IPP 12 covers disclosure outside New Zealand. This applies to every organisation that holds personal information, not only the regulated sectors.

## Why the New Zealand standards are the point

A Salesforce scanner built in the United States maps to HIPAA. HIPAA is United States health law. It does not apply to a New Zealand health provider, and putting it at the top of an audit for a Te Whatu Ora programme tells the reader the tool was never built for this market.

New Zealand health and government organisations report against NZISM, HISO 10029, and the Privacy Act. Those are the frameworks that carry weight in a New Zealand audit, and they are exactly the ones an offshore tool leaves out. Mapping to them is not a convenience. It is the difference between a report a NZ CISO forwards to their board and one they quietly set aside.

HISO is the cheaper win than it looks, because it is built on ISO/IEC 27002. Where a finding already maps to an ISO control, the HISO mapping is largely a crosswalk. NZISM takes more work: its controls have their own structure, and verifying a mapping means reading the manual chapter by chapter. We did that. The references above are the chapters we confirmed against.

## What the mapping does not claim

A control that renders "No findings detected" is not a statement of compliance. It means the checks mapped to that control surfaced no issues at the point in time the audit ran. The tool is a read-only configuration review. It is not a certification, and it is not a penetration test. It maps where findings land against a framework; it does not attest that the framework is satisfied.

Every report says this, plainly, in its scope statement. A compliance claim a tool cannot stand behind is a liability, not a feature. The value is in the traceability, not in a grade that pretends to be an audit opinion.

## One finding, six obligations

A single finding, "guest-executable Apex running without sharing," maps across the catalogue like this:

| Framework | Control |
|-----------|---------|
| OWASP Top 10:2021 | A01 Broken Access Control |
| ISO/IEC 27001:2022 | A.8.3 Information access restriction |
| Security Benchmark for Salesforce | SBS-CPORTAL-001, Prevent Parameter-Based Record Access in Portal Apex |
| NZISM v3.8 | Ch.16 Authentication and Access Controls |
| HISO 10029:2022 | Access control |
| NZ Privacy Act 2020 | IPP 5, Storage and security of information |

One engineering fix. Six framework obligations the client can now report against, each traceable to its published source.

## References

- OWASP Top 10:2021: https://owasp.org/Top10/2021/
- AICPA Trust Services Criteria (SOC 2): https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
- ISO/IEC 27001:2022: https://www.iso.org/standard/27001
- Security Benchmark for Salesforce: https://docs.securitybenchmark.org/
- NZISM (New Zealand Information Security Manual): https://nzism.gcsb.govt.nz/
- HISO 10029:2022 Health Information Security Framework: https://www.tewhatuora.govt.nz/health-services-and-programmes/cyber-hub/cyber-standards
- NZ Privacy Act 2020, Information Privacy Principles: https://privacy.org.nz/privacy-act-2020/privacy-principles/

---

The tool is published as `@cclabsnz/sf-audit`. The control catalogue and its verification status are tracked in the open at [github.com/cclabsnz/sf-audit-plugin](https://github.com/cclabsnz/sf-audit-plugin).
