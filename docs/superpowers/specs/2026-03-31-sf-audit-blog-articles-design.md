# Blog Articles Design: sf audit plugin for softwaredev.insights

**Date:** 2026-03-31
**Target publication:** softwaredev.insights (gt2985/software-insights-blog)
**Audience:** Salesforce developers and architects
**Format:** Two short punchy posts (~400–600 words each), matching existing blog style (frontmatter, TL;DR, narrative hook, code snippets, CTA)

---

## Article 1 — Usage guide (publishes first)

**File:** `posts/salesforce-sf-audit-security-plugin-usage.md`
**Title:** "Catch Salesforce Security Gaps in One Command"
**Framing:** Lead with immediate practitioner value. What can you do right now?

### Structure

1. **Hook** — Setup is manual and things slip. One `sf` command changes that.
2. **Install** — `sf plugins install @cclabsnz/sf-audit`
3. **Run it** — `sf audit security --target-org myOrg`, describe terminal output (progress, summary table, report written)
4. **What it checks** — 6 categories in prose, one sentence each:
   - Org Health, Identity & Access, Data Security, Integration Security, Code & Automation, Platform
5. **Key flags** — one line each: `--format`, `--output`, `--fail-on` (CI use case), `--checks` (targeted runs)
6. **Score & grade** — health score 0–100, grade A–F, what drives each (two sentences)
7. **CTA** — link to Article 2 ("curious how it's built?")

### Frontmatter
- category: Salesforce Development
- difficulty: Beginner
- tags: Salesforce, Security, CLI, DevOps, sf plugin
- tldr: One sf command audits your org across 22 checks and produces an HTML/MD/JSON report with a health score and grade.

---

## Article 2 — Build story (publishes second)

**File:** `posts/salesforce-sf-audit-plugin-architecture.md`
**Title:** "How We Built a Native sf Plugin for Salesforce Security Auditing"
**Framing:** Earn the technical deep-dive with Article 1's credibility. Reward curious engineers.

### Structure

1. **Hook** — We had a working Python script. So why rewrite it as a native sf plugin?
2. **The layered architecture** — 6 layers, one job each: API client → QueryRegistry → AuditContext → CheckEngine → findings/scoring → renderers. No code dumps, prose description.
3. **The cache dependency system** — The interesting design problem: 22 checks, one org, redundant API calls. Checks declare `populatesCache`/`dependsOnCache`, CheckEngine validates order at startup. Concrete example: HardcodedCredentialsCheck reads Apex bodies written earlier by NamedCredentialsCheck.
4. **Scoring model** — Risk weights (CRITICAL=10 down to INFO=0), health score formula, grade thresholds A–F. Call out `scoring.json` is configurable without recompile.
5. **Renderers as a clean seam** — One interface, three implementations (HTML, MD, JSON). `--format` picks which run. Easy to extend.
6. **What we'd do differently** — One honest reflection (keeps it from reading like a press release).
7. **CTA** — link back to Article 1 ("try it against your org")

### Frontmatter
- category: Salesforce Development
- difficulty: Advanced
- tags: Salesforce, Architecture, TypeScript, sf plugin, Security, Open Source
- tldr: We rewrote a Python audit script as a native sf plugin using a layered architecture, a cache dependency system to minimise API calls, and a configurable scoring model.

---

## Style notes (match existing blog)
- First-person plural ("we", "our")
- Narrative hook before any technical content
- Bold for key terms on first use
- Code blocks for all commands and snippets
- `---` dividers between major sections
- End with italicised follow/CTA line matching blog footer pattern

## Human voice guardrails (strict)
These patterns must not appear — they signal AI generation:

**Punctuation / formatting to avoid**
- Em dashes used as a rhetorical device (— like this — for drama)
- Bullet lists for everything — use prose where a sentence flows naturally
- Perfectly parallel sentence structures back to back

**Phrases and words to avoid**
- "delve into", "dive into", "let's explore"
- "it's worth noting", "it's important to", "notably"
- "leverage", "seamless", "robust", "streamlined", "game-changer"
- "in conclusion", "in summary", "to summarise"
- "furthermore", "moreover", "additionally" as sentence starters
- "at the end of the day", "the good news is"
- Rhetorical questions used as section transitions ("So why does this matter?")

**Structural patterns to avoid**
- Every section ending with a tidy one-line summary of itself
- Conclusions that restate every point already made
- Headers that read like a textbook table of contents

**What good looks like instead**
- Sentences that vary in length — some short. Some that carry a bit more weight and take their time.
- Opinions stated plainly without hedging ("we chose X because Y" not "one approach that may be considered is X")
- Specific details over generalities ("22 checks" not "many checks", "HardcodedCredentialsCheck reads Apex bodies" not "checks share data")
- Transitions that feel like a person thinking, not a document flowing
