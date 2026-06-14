# sf audit Blog Articles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write and commit two short blog posts (~400–600 words each) to the software-insights-blog repo, matching the existing blog's voice and frontmatter structure.

**Architecture:** Article 1 (usage guide) publishes first to hook practitioners; Article 2 (build story) publishes second to reward curious engineers. Both live in `/Users/gaurav/Documents/Personal R&D/Side Projects/software-insights-blog/posts/`. No code to compile, no tests to run — quality gate is a manual style check against the human-voice guardrails in the spec.

**Tech Stack:** Markdown, Next.js blog frontmatter (title, date, tags, excerpt, tldr, category, difficulty, readingTime, keywords)

**Spec:** `../specs/2026-03-31-sf-audit-blog-articles-design.md`

---

### Task 1: Write Article 1 — Usage Guide

**Files:**
- Create: `/Users/gaurav/Documents/Personal R&D/Side Projects/software-insights-blog/posts/salesforce-sf-audit-security-plugin-usage.md`

- [ ] **Step 1: Write the article**

Create the file with this exact content:

```markdown
---
title: "Catch Salesforce Security Gaps in One Command"
date: "2026-03-31"
tags: ["Salesforce", "Security", "CLI", "DevOps", "sf plugin"]
excerpt: "A native sf plugin that audits your org across 22 security checks and produces a scored, graded report — without leaving your terminal."
tldr: "Install @cclabsnz/sf-audit, run sf audit security --target-org myOrg, get an HTML report with a health score, a grade, and a prioritised list of findings."
category: "Salesforce Development"
difficulty: "Beginner"
readingTime: "4 min read"
keywords: ["salesforce security audit", "sf plugin", "salesforce cli", "org security", "apex security", "salesforce devops"]
---

# Catch Salesforce Security Gaps in One Command

Salesforce orgs accumulate risk quietly. A connected app that stopped being used two years ago. A profile that still has ModifyAllData because someone was in a rush during a go-live. Guest user access that made sense at the time. None of it shows up anywhere unless you go looking — and Setup is a point-in-time view, not a monitor.

We built `sf audit security` to make the looking fast.

---

## Getting started

```bash
sf plugins install @cclabsnz/sf-audit
```

That's the install. It hooks into the Salesforce CLI you already use, so there's no separate auth flow or config file to set up.

```bash
sf audit security --target-org myOrg
```

The command runs 22 checks against your org, prints a progress line for each one, then writes a report and shows a summary:

```
─────────────────────────────
  Audit Summary
─────────────────────────────
  CRITICAL       2 findings
  HIGH           4 findings
  MEDIUM         7 findings
  LOW            3 findings
─────────────────────────────
  Score: 61/100   Grade: C
─────────────────────────────

Report written: ./sf-audit-00D8t000001abc-1711234567890.html
```

---

## What it checks

The 22 checks cover six areas:

**Org Health** — Salesforce's own Health Check score and password/session policy gaps.

**Identity & Access** — who has ModifyAllData, ViewAllData, and AuthorApex; inactive users still holding active licences; failed login trends over the last 30 days.

**Data Security** — OWD settings for Account, Contact, Opportunity, Case, and Lead; field-level security on sensitive fields like SSN and credit card numbers; guest user object permissions; public group sharing rules that expose data to all internal users.

**Integration Security** — connected apps missing admin-approval restrictions; remote site registrations without Named Credential coverage; hardcoded Bearer tokens, API keys, and raw callout URLs in Apex.

**Code & Automation** — Apex classes running `without sharing` or missing a sharing declaration; active flows in system context; scheduled and batch jobs; overall test coverage percentage.

**Platform** — API limit consumption against daily and concurrent limits; setup audit trail entries for permission changes and Login-As events; custom settings with credential-like names.

---

## The flags worth knowing

`--format html,md,json` runs multiple output formats in one pass. The HTML report is interactive — you can filter findings by risk level. The JSON output is machine-readable for dashboards or further processing.

`--output ./reports` writes the report to a specific directory instead of the current one.

`--fail-on HIGH` exits with code 1 if any finding is HIGH or CRITICAL. Drop this into a CI job and your pipeline breaks before a risky change reaches production.

`--checks hardcoded-credentials,apex-sharing` runs only the checks you name. Useful when you want a fast answer to a specific question without waiting for the full audit.

---

## Score and grade

Each finding carries a weight: CRITICAL is 10, HIGH is 7, MEDIUM is 4, LOW is 1. The health score is how far below the worst-case total you are, expressed as a number from 0 to 100. A score of 85 or above with no HIGH findings earns an A. Any CRITICAL finding is an immediate F, regardless of the score.

The grade gives you a honest read on where your org sits. Most production orgs we've run this against land somewhere between B and D on first run — not because they're badly managed, but because this stuff accumulates.

---

*Want to know how the plugin is built — the cache dependency system, the layered architecture, the scoring model? [Read part two.](./salesforce-sf-audit-plugin-architecture)*
```

- [ ] **Step 2: Check against human-voice guardrails**

Read through the article and verify:
- No em dashes used for rhetorical drama
- No words: "leverage", "seamless", "robust", "streamlined", "delve", "furthermore", "notably"
- No section that ends with a tidy summary restating itself
- No rhetorical questions used as transitions
- Sentence lengths vary — some short, some longer
- Opinions are stated plainly, not hedged

Fix anything that reads like generated text before moving on.

- [ ] **Step 3: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/software-insights-blog"
git add posts/salesforce-sf-audit-security-plugin-usage.md
git commit -m "add: sf audit security plugin usage guide"
```

---

### Task 2: Write Article 2 — Build Story

**Files:**
- Create: `/Users/gaurav/Documents/Personal R&D/Side Projects/software-insights-blog/posts/salesforce-sf-audit-plugin-architecture.md`

- [ ] **Step 1: Write the article**

Create the file with this exact content:

```markdown
---
title: "How We Built a Native sf Plugin for Salesforce Security Auditing"
date: "2026-03-31"
tags: ["Salesforce", "Architecture", "TypeScript", "sf plugin", "Security", "Open Source"]
excerpt: "Why we rewrote a working Python script as a native sf plugin, and the design decisions that made 22 parallel security checks practical."
tldr: "A layered architecture, a cache dependency system to avoid redundant API calls, and a configurable scoring model. The interesting part was getting 22 checks to share data without stepping on each other."
category: "Salesforce Development"
difficulty: "Advanced"
readingTime: "5 min read"
keywords: ["salesforce sf plugin", "salesforce cli plugin development", "typescript salesforce", "oclif plugin", "salesforce security architecture"]
---

# How We Built a Native sf Plugin for Salesforce Security Auditing

We had a Python script. It connected to Salesforce, ran a set of security checks, and produced an HTML report. It worked. The problem was everything around it — separate authentication, a manual install step, documentation that started with "first, make sure you have Python 3.11". When your whole team already runs `sf`, that's the kind of friction that means the tool doesn't get used.

So we rewrote it as a native `sf` plugin. Here's what the architecture looks like and where it got interesting.

---

## Six layers, one job each

The plugin is built in TypeScript on top of `@salesforce/sf-plugins-core` and oclif. We split it into six layers with a strict downward dependency rule — each layer only knows about the one below it.

**API client** wraps the Salesforce REST and Tooling APIs. Everything talks to Salesforce through here.

**QueryRegistry** loads SOQL definitions from JSON config files at startup. Checks don't write inline queries — they request a named query and get back results. This keeps the data access layer separate from the logic that interprets it.

**AuditContext** bundles the connection, the query registry, and org info (name, ID, instance, sandbox flag) into one object. Every check receives this and nothing else.

**CheckEngine** takes the ordered list of checks and runs them, collecting findings and passing a progress callback so the CLI can print each check as it completes.

**Findings and scoring** — a `Finding` has a title, category, risk level, description, recommendation, and a list of affected items with links into Setup. Scoring is in a separate config file.

**Renderers** take an `AuditResult` and return a string. One interface, three implementations.

---

## The cache problem

22 checks against one org means the same data gets requested multiple times. Apex class bodies are a good example — both `HardcodedCredentialsCheck` and `ApexSharingCheck` need them. Without a cache, that's two full Tooling API scans of every Apex class in the org.

We solved this with a shared cache each check can read from or write to. Each check declares `populatesCache` (the keys it writes) and `dependsOnCache` (the keys it expects to already exist). CheckEngine validates the ordering at startup — before connecting to any org, it walks the check list and confirms that every declared dependency is satisfied by a preceding check. If the ordering is wrong, the command fails with a clear error before any API call is made.

In practice: `NamedCredentialsCheck` runs early and writes Apex class bodies to the cache. `HardcodedCredentialsCheck` and `ApexSharingCheck` run later and read from it. One API call, multiple consumers.

---

## Scoring without hardcoding

Risk weights live in `config/scoring.json`, not in TypeScript:

```json
{
  "riskScores": {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
  }
}
```

The health score formula is `100 - (total weight / max possible weight) * 100`. Grades run from A (score ≥ 85, no HIGH findings) down to F (any CRITICAL finding, or score below 40). The config ships with the plugin, so you can tune weights for your org's risk profile without touching TypeScript or recompiling.

---

## Renderers as a clean boundary

The `AuditRenderer` interface is one method: `render(result: AuditResult): string`. The CLI command splits `--format html,md,json` and picks which renderers to run. Adding a new output format is one new class. Nothing else changes.

The HTML renderer is the most complex — it generates a self-contained file with embedded CSS and JavaScript for client-side filtering by risk level. The Markdown renderer is about 80 lines. JSON is a single `JSON.stringify`.

---

## What we'd change

The QueryRegistry loads SOQL from JSON files on disk. It made sense as a way to separate data access from logic, but in practice it means a check's query lives in a different file from the check that uses it. As the number of checks grows, that becomes harder to navigate. We'd move the SOQL inline to each check and remove the separate config files. The abstraction isn't paying its way.

---

*Want to run this against your own org? [Start with the usage guide.](./salesforce-sf-audit-security-plugin-usage)*
```

- [ ] **Step 2: Check against human-voice guardrails**

Read through the article and verify:
- No em dashes used for rhetorical drama
- No words: "leverage", "seamless", "robust", "streamlined", "delve", "furthermore", "notably"
- No section that ends with a tidy summary restating itself
- No rhetorical questions used as transitions
- Sentence lengths vary — some short, some longer
- Opinions are stated plainly ("We'd move the SOQL inline" not "one approach worth considering")
- Specific names used throughout (HardcodedCredentialsCheck, NamedCredentialsCheck, not "certain checks")

Fix anything that reads like generated text before moving on.

- [ ] **Step 3: Commit**

```bash
cd "/Users/gaurav/Documents/Personal R&D/Side Projects/software-insights-blog"
git add posts/salesforce-sf-audit-plugin-architecture.md
git commit -m "add: sf audit plugin architecture deep-dive"
```
