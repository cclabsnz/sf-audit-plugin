# Compliance frameworks

Findings are mapped to controls across ten security and privacy frameworks. The mapping is built on a **sourced control catalog** (each control carries its framework, **pinned version**, official title, and a citation) so a finding's compliance reference ties to an exact, defensible requirement rather than a bare tag.

| Framework | Version | Notes |
|-----------|---------|-------|
| OWASP Top 10 | 2021 | Web application risk categories |
| OWASP LLM Top 10 | 2025 | LLM/GenAI application risks (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency); mapped by the AI & Agents checks |
| SOC 2 | AICPA TSC 2017 | Common Criteria (CC6–CC9) |
| ISO/IEC 27001 | 2022 | Annex A controls |
| Security Benchmark for Salesforce (SBS) | current | Salesforce-native benchmark: [docs.securitybenchmark.org](https://docs.securitybenchmark.org) |
| NZ Privacy Act | 2020 | Information Privacy Principles (IPP 5/9/12) |
| HISO 10029 | 2022 | NZ Health Information Security Framework |
| NZISM | v3.8 | NZ Information Security Manual |
| HIPAA Security Rule | 45 CFR Part 164 Subpart C (2013 Omnibus) | Administrative (164.308) and technical (164.312) safeguards, with each implementation specification's **Required / Addressable** designation preserved. Maps the **operative** rule: the HHS NPRM of 2025-01-06 that would make encryption, MFA and segmentation mandatory is still proposed, not final |
| GDPR | Regulation (EU) 2016/679 | Art. 5(1)(f), 25, 30, 32(1)(a)/(b)/(d), 33 and 44. Mapped at paragraph level, so a finding cites the specific obligation rather than "Article 32" at large |

**Provenance gate.** Each catalogued control is marked `verified` only after its title/reference is confirmed against the authoritative source. **Controls that are not verified do not render** in the compliance matrix. Nothing ships as "compliant-to-clause" on unconfirmed data. The current verification status is tracked in [`docs/compliance/verification-worksheet.md`](compliance/verification-worksheet.md).

**Framework packs.** The executive report's compliance matrix is scoped with `--frameworks`:

- `universal` *(default)*: OWASP, OWASP LLM Top 10, SOC 2, ISO 27001
- `nz`: ISO 27001, HISO 10029, NZ Privacy Act, NZISM (for NZ health/government engagements)
- `all`: every framework, including HIPAA and GDPR
- a comma list of aliases, e.g. `owasp,owasp-llm,iso,nzism` (`owasp-llm` / `llm` selects the OWASP LLM Top 10, `hipaa` the HIPAA Security Rule, `gdpr` the GDPR articles)

HIPAA and GDPR are not in either named pack, because scoping them is a jurisdictional decision rather than a default — select them explicitly for a US healthcare or EU/UK engagement:

```bash
# US healthcare engagement — HIPAA Security Rule safeguards alongside the universal set
sf audit security --target-org myOrg --format executive --frameworks owasp,soc2,iso,hipaa

# EU/UK engagement — GDPR security-of-processing obligations
sf audit security --target-org myOrg --format executive --frameworks iso,gdpr
```

> **Not an attestation.** A control rendering "No findings detected" means this audit's checks surfaced no issues mapped to it. It is **not** a statement of compliance or certification. See [Scope & Liability](#scope--liability).

**Further reading:** [Mapping Salesforce security to NZISM, the NZ Privacy Act and ISO 27001](https://www.softwareinsights.dev/posts/salesforce-security-nzism-nz-privacy-act/) and [Why Salesforce Health Cloud needs its own security review](https://www.softwareinsights.dev/posts/salesforce-health-cloud-security-review/). More in [Further reading](FURTHER-READING.md).
