import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ApexPageRecord {
  Name: string;
  Markup: string;
}

// Unescaped output in <apex:outputText> or <apex:outputField>
// escape="false" bypasses Salesforce's automatic HTML encoding
const ESCAPE_FALSE_RE = /escape\s*=\s*["']false["']/i;

// {!variable} merge fields inside <script> blocks are not HTML-encoded — they need JSENCODE/JSINHTMLENCODE
// This regex approximates: a script tag that contains a {!...} not wrapped in JSENCODE/JSINHTMLENCODE
const JS_UNENCODED_MERGE_RE = /<script[^>]*>[\s\S]*?\{!(?!JSENCODE\(|JSINHTMLENCODE\()[^}]+\}[\s\S]*?<\/script>/gi;

// href/src/action attributes with unencoded merge fields — potential open redirect or injection
const ATTR_MERGE_UNENCODED_RE = /(?:href|src|action|onclick)\s*=\s*["'][^"']*\{!(?!HTMLENCODE\(|JSENCODE\(|URLENCODE\()[^}]+\}/gi;

export class VisualforceXssCheck implements SecurityCheck {
  readonly id = 'visualforce-xss';
  readonly name = 'Visualforce XSS Patterns';
  readonly category = 'Code Security';
  readonly description = 'Scans Visualforce page markup for common XSS patterns: escape="false", unencoded merge fields in script blocks and HTML attributes';

  readonly populatesCache = ['vfPageBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/ApexPages/home`;

    // Query 1: COUNT to detect truncation before fetching markup
    let totalPageCount = 0;
    try {
      const countResult = await ctx.soql.query<Record<string, never>>(
        `SELECT COUNT() FROM ApexPage WHERE NamespacePrefix = null`,
      );
      totalPageCount = countResult.totalSize;
    } catch {
      // COUNT unavailable — proceed with markup query and detect truncation empirically
    }

    let pages: ApexPageRecord[];
    try {
      // Query 2: fetch markup (Tooling API only — regular SOQL does not expose Markup)
      pages = await ctx.tooling.query<ApexPageRecord>(
        `SELECT Name, Markup FROM ApexPage WHERE NamespacePrefix = null LIMIT 500`,
      );
    } catch {
      ctx.cache.vfPageBodies = [];
      findings.push({
        id: 'visualforce-xss-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Visualforce page markup could not be accessed: XSS check skipped',
        detail: 'The Tooling API ApexPage query was not accessible. This may indicate the audit user lacks Tooling API access.',
        remediation: 'Grant Tooling API access to the audit user and re-run.',
      });
      return { findings };
    }

    const effectiveTotal = totalPageCount > 0 ? totalPageCount : pages.length;
    if (effectiveTotal > 500) {
      findings.push({
        id: 'visualforce-xss-incomplete-scan',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `Visualforce XSS scan incomplete: only ${pages.length} of ${effectiveTotal} pages scanned (API LIMIT 500)`,
        detail: `This org has ${effectiveTotal} Visualforce pages, but the Tooling API imposes a hard LIMIT of 500 rows per query. The remaining ${effectiveTotal - pages.length} pages were not analysed for XSS patterns. Findings below reflect only the scanned subset and may understate the true exposure.`,
        remediation:
          'Use the Salesforce CLI (sf apex list page) or a dedicated SAST tool (PMD, CodeScan) to perform a complete scan of all Visualforce pages outside the 500-row API limit.',
      });
    }

    // Cache page markup for potential future checks
    ctx.cache.vfPageBodies = pages.map((p) => ({ name: p.Name, markup: p.Markup ?? '' }));

    if (pages.length === 0) {
      findings.push({
        id: 'visualforce-xss-no-pages',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No custom Visualforce pages found',
        detail: 'No Visualforce pages in the org namespace were found.',
        remediation: 'Continue monitoring as new pages are added.',
      });
      return { findings };
    }

    const escapeFalsePages: string[] = [];
    const jsUncodedPages: string[] = [];
    const attrUncodedPages: string[] = [];

    for (const { Name, Markup } of pages) {
      if (!Markup) continue;

      if (ESCAPE_FALSE_RE.test(Markup)) escapeFalsePages.push(Name);

      JS_UNENCODED_MERGE_RE.lastIndex = 0;
      if (JS_UNENCODED_MERGE_RE.test(Markup)) jsUncodedPages.push(Name);

      ATTR_MERGE_UNENCODED_RE.lastIndex = 0;
      if (ATTR_MERGE_UNENCODED_RE.test(Markup)) attrUncodedPages.push(Name);
    }

    let hasFindings = false;

    if (escapeFalsePages.length > 0) {
      hasFindings = true;
      findings.push({
        id: 'visualforce-xss-escape-false',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${escapeFalsePages.length} Visualforce page(s) use escape="false": XSS risk`,
        detail:
          `\`escape="false"\` on \`<apex:outputText>\` or similar components disables Salesforce's automatic HTML encoding. If the rendered value contains user-controlled content, an attacker can inject arbitrary JavaScript into the page, leading to stored or reflected XSS. Salesforce defaults to \`escape="true"\` specifically to prevent this.`,
        remediation:
          'Remove `escape="false"` unless the value being rendered is fully trusted (e.g., hardcoded HTML from a developer). For user-controlled content, ensure it is sanitised before storage and rely on the default escaping. Replace with HTMLENCODE() if explicit encoding is needed.',
        affectedItems: escapeFalsePages.map((name) => ({
          label: name,
          url: setupUrl,
          note: 'escape="false" found: review all output components for user-controlled content',
        })),
      });
    }

    if (jsUncodedPages.length > 0) {
      hasFindings = true;
      findings.push({
        id: 'visualforce-xss-js-merge-field',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${jsUncodedPages.length} Visualforce page(s) use merge fields inside <script> blocks without JSENCODE`,
        detail:
          `Merge fields used inside \`<script>\` tags must be wrapped with \`{!JSENCODE(variable)}\` or \`{!JSINHTMLENCODE(variable)}\`. Without encoding, an attacker who controls the value can break out of the JavaScript string context and execute arbitrary code. HTML-encoding alone (the default in VF) does NOT prevent JavaScript injection.`,
        remediation:
          'Wrap all merge fields inside `<script>` blocks with JSENCODE(): `{!JSENCODE(variable)}`. For values placed in HTML event handlers (onclick, etc.), use JSINHTMLENCODE().',
        affectedItems: jsUncodedPages.map((name) => ({
          label: name,
          url: setupUrl,
          note: '{!var} in <script> block without JSENCODE: wrap with {!JSENCODE(var)}',
        })),
      });
    }

    if (attrUncodedPages.length > 0) {
      hasFindings = true;
      findings.push({
        id: 'visualforce-xss-attr-merge-field',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${attrUncodedPages.length} Visualforce page(s) use merge fields in href/src/action attributes without encoding`,
        detail:
          `Merge fields in URL-context HTML attributes (href, src, action) without URLENCODE() or HTMLENCODE() can enable open redirects or attribute injection. An attacker may be able to manipulate the URL or inject additional attributes.`,
        remediation:
          'Wrap merge fields used in URL attributes with URLENCODE() for URL values, or HTMLENCODE() for full attribute values. Validate that URL values cannot redirect to external untrusted hosts.',
        affectedItems: attrUncodedPages.map((name) => ({
          label: name,
          url: setupUrl,
          note: '{!var} in href/src/action without URLENCODE: encode or validate',
        })),
      });
    }

    if (!hasFindings) {
      findings.push({
        id: 'visualforce-xss-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All ${pages.length} Visualforce page(s) passed XSS pattern scan`,
        detail: `No common XSS patterns (escape="false", unencoded merge fields in script blocks or URL attributes) were found in the ${pages.length} custom Visualforce pages scanned.`,
        remediation: 'Continue monitoring as new pages are developed. Consider adding a static analysis step to your CI/CD pipeline for ongoing VF XSS detection.',
      });
    }

    return { findings };
  }
}
