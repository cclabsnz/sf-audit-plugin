// src/renderers/toolCredit.ts
/**
 * One-line credit for the reports that travel beyond the person who ran the tool: the executive
 * report and the incident report. The link carries campaign tags so visits arriving from a
 * shared report can be counted. It names the report type only, never the org or the client.
 * A plain hyperlink: nothing is fetched when a report is opened.
 */
export type CreditedReport = 'executive-report' | 'incident-report';

const TOOLS_PAGE = 'https://www.softwareinsights.dev/tools/';
const CREDIT_TEXT = 'an open-source, read-only Salesforce security tool';

export function toolCreditUrl(report: CreditedReport): string {
  return `${TOOLS_PAGE}?utm_source=sf-audit&utm_medium=report&utm_campaign=${report}`;
}

export function toolCreditHtml(report: CreditedReport): string {
  return `Prepared with <a href="${toolCreditUrl(report)}">sf-audit</a>, ${CREDIT_TEXT}.`;
}

export function toolCreditMarkdown(report: CreditedReport): string {
  return `Prepared with [sf-audit](${toolCreditUrl(report)}), ${CREDIT_TEXT}.`;
}
