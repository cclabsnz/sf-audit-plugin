import { createHash } from 'node:crypto';
import type { RiskLevel } from '@cclabsnz/sf-core';
import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';
import type { AttackChain } from '../chains/AttackChain.js';
import { CHECKS } from '../checks/registry.js';
import { packageInfo } from '../lib/packageInfo.js';
import type { AuditRenderer } from './AuditRenderer.js';

/**
 * SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers.
 *
 * The audit inspects an org's configuration, not files, so there is no real source location.
 * Each result carries:
 *   - a logical location per affected item (the actual subject of the finding), and
 *   - a synthetic physical location, `salesforce-org/<ruleId>`, because GitHub code scanning
 *     only displays results that have a physicalLocation with an artifactLocation.uri. The
 *     file does not exist in the repository; it groups alerts by check in the UI.
 *
 * Results carry a `partialFingerprints` entry derived from the rule id and the finding id, so
 * the same finding on the next run updates the existing alert instead of opening a new one.
 * Finding ids are stable per subject (checks embed the user / domain / component they are
 * about), whereas affected-item lists change size between runs.
 *
 * Only actionable findings become results. Passing checks are omitted, and inconclusive
 * checks (no evidence, usually a missing permission) are reported as tool execution
 * notifications with `executionSuccessful: false`, never as error/warning alerts.
 */

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

/** Fingerprint key. Bump the version suffix if the hashed inputs ever change. */
export const FINGERPRINT_KEY = 'sfAuditFindingHash/v1';

/** Root of the synthetic artifact path every result points at. */
export const ORG_ARTIFACT_ROOT = 'salesforce-org';

const SEVERITY_ORDER: RiskLevel[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function riskToSarifLevel(level: RiskLevel): SarifLevel {
  switch (level) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
      return 'note';
  }
}

/**
 * GitHub's `security-severity` bands: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium,
 * 0.1-3.9 low. Values sit inside each band rather than on its edge. INFO has none, so an
 * advisory-only rule falls back to its `note` level instead of claiming a security severity.
 */
function riskToSecuritySeverity(level: RiskLevel): string | undefined {
  switch (level) {
    case 'CRITICAL':
      return '9.5';
    case 'HIGH':
      return '8.0';
    case 'MEDIUM':
      return '5.5';
    case 'LOW':
      return '3.0';
    case 'INFO':
      return undefined;
  }
}

function maxRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

function fingerprint(...parts: string[]): string {
  return createHash('sha256').update(parts.join('\u0000')).digest('hex');
}

/** Logical locations for the given names. SARIF requires the array's items to be unique. */
function logicalLocations(names: string[]): Array<{ name: string; fullyQualifiedName: string; kind: string }> {
  return [...new Set(names)].map((name) => ({ name, fullyQualifiedName: name, kind: 'resource' }));
}

/** The location every result points at: a synthetic per-rule artifact, plus the logical subjects. */
function orgLocation(ruleId: string, names: string[]): Record<string, unknown> {
  const logical = logicalLocations(names);
  return {
    physicalLocation: {
      artifactLocation: { uri: `${ORG_ARTIFACT_ROOT}/${encodeURIComponent(ruleId)}` },
      region: { startLine: 1 },
    },
    ...(logical.length > 0 ? { logicalLocations: logical } : {}),
  };
}

function ruleName(text: string): string {
  return text.replace(/[^a-zA-Z0-9]/g, '');
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  defaultConfiguration: { level: SarifLevel };
  properties: { tags: string[]; 'security-severity'?: string };
}

interface RuleAccumulator {
  rule: SarifRule;
  /** Highest severity among this rule's emitted results; undefined until one is emitted. */
  worst?: RiskLevel;
}

export class SarifRenderer implements AuditRenderer {
  public readonly format = 'sarif';
  public readonly fileExtension = '.sarif';
  public readonly filenamePrefix = 'sf-audit';

  public render(result: AuditResult): string {
    const pkg = packageInfo();
    const rules = new Map<string, RuleAccumulator>();

    for (const check of CHECKS) {
      rules.set(check.id, {
        rule: {
          id: check.id,
          name: ruleName(check.name),
          shortDescription: { text: check.name },
          fullDescription: { text: `${check.name} (${check.category})` },
          help: {
            text: `Each result for ${check.id} carries its own remediation.`,
            markdown: `Each result for \`${check.id}\` carries its own remediation.\n\n**Category**: \`${check.category}\``,
          },
          defaultConfiguration: { level: 'warning' },
          properties: { tags: ['security', 'salesforce', check.category] },
        },
      });
    }

    const results: unknown[] = [];
    const notifications: unknown[] = [];
    const seen = new Map<string, number>();

    for (const f of result.findings) {
      if (f.passed === true) continue;
      const ruleId = f.checkId ?? f.id;

      if (f.inconclusive === true) {
        notifications.push({
          level: 'warning',
          message: { text: `${f.title}: ${f.detail}` },
          associatedRule: { id: ruleId },
        });
        continue;
      }

      const acc = this.ruleFor(rules, ruleId, f);
      acc.worst = acc.worst ? maxRisk(acc.worst, f.riskLevel) : f.riskLevel;
      const threatTags = [
        ...(f.threats?.stride ?? []).map((c) => `stride:${c}`),
        ...(f.threats?.linddun ?? []).map((c) => `linddun:${c}`),
      ];
      for (const tag of [...(f.complianceTags ?? []), ...threatTags]) {
        if (!acc.rule.properties.tags.includes(tag)) acc.rule.properties.tags.push(tag);
      }

      // Two findings sharing an id within one run would otherwise collapse into one alert.
      const key = `${ruleId}\u0000${f.id}`;
      const n = seen.get(key) ?? 0;
      seen.set(key, n + 1);

      results.push(this.findingResult(f, ruleId, n === 0 ? fingerprint(ruleId, f.id) : fingerprint(ruleId, f.id, String(n))));
    }

    for (const chain of result.attackChains ?? []) {
      results.push(this.chainResult(rules, chain));
    }

    for (const acc of rules.values()) {
      if (!acc.worst) continue;
      acc.rule.defaultConfiguration.level = riskToSarifLevel(acc.worst);
      const sev = riskToSecuritySeverity(acc.worst);
      if (sev) acc.rule.properties['security-severity'] = sev;
    }

    const sarifLog = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: pkg.name,
              version: pkg.version,
              informationUri: 'https://github.com/cclabsnz/sf-audit-plugin',
              rules: Array.from(rules.values(), (a) => a.rule),
            },
          },
          // One category per org. GitHub code scanning closes any alert of a category that a new
          // upload no longer contains, so two orgs sharing a category would close each other's.
          automationDetails: { id: `sf-audit/${result.orgId}/` },
          results,
          invocations: [
            {
              // An inconclusive check is a partial analysis failure: the tool ran, but could
              // not establish the answer for that check.
              executionSuccessful: notifications.length === 0,
              endTimeUtc: result.generatedAt.toISOString(),
              toolExecutionNotifications: notifications,
            },
          ],
          properties: {
            orgId: result.orgId,
            orgName: result.orgName,
            healthScore: result.healthScore,
            grade: result.grade,
          },
        },
      ],
    };

    return JSON.stringify(sarifLog, null, 2);
  }

  private ruleFor(rules: Map<string, RuleAccumulator>, ruleId: string, f: Finding): RuleAccumulator {
    let acc = rules.get(ruleId);
    if (!acc) {
      acc = {
        rule: {
          id: ruleId,
          name: ruleName(ruleId),
          shortDescription: { text: f.title },
          fullDescription: { text: f.title },
          help: { text: f.remediation, markdown: `### Remediation\n\n${f.remediation}` },
          defaultConfiguration: { level: 'warning' },
          properties: { tags: ['security', 'salesforce', f.category] },
        },
      };
      rules.set(ruleId, acc);
    }
    return acc;
  }

  /**
   * One SARIF result per actionable finding. Accepted-risk waivers, when they land, attach
   * here as `suppressions` (SARIF 3.27.23) rather than by dropping the result, so consumers
   * can still see the finding and that it was waived.
   */
  private findingResult(f: Finding, ruleId: string, hash: string): unknown {
    const items = f.affectedItems ?? [];
    return {
      ruleId,
      level: riskToSarifLevel(f.riskLevel),
      message: { text: `${f.title}\n\n${f.detail}\n\nRemediation: ${f.remediation}` },
      locations: [orgLocation(ruleId, items.map((i) => i.label))],
      partialFingerprints: { [FINGERPRINT_KEY]: hash },
      properties: {
        findingId: f.id,
        riskLevel: f.riskLevel,
        category: f.category,
        remediation: f.remediation,
        complianceTags: f.complianceTags ?? [],
        affectedItems: items.map((i) => ({ label: i.label, ...(i.note ? { note: i.note } : {}) })),
      },
    };
  }

  private chainResult(rules: Map<string, RuleAccumulator>, chain: AttackChain): unknown {
    const ruleId = `attack-chain-${chain.id}`;
    let acc = rules.get(ruleId);
    if (!acc) {
      acc = {
        rule: {
          id: ruleId,
          name: ruleName(chain.title),
          shortDescription: { text: chain.title },
          fullDescription: { text: chain.narrative },
          help: {
            text: chain.remediation,
            markdown: `### Attack chain\n\n${chain.narrative}\n\n### Remediation\n\n${chain.remediation}`,
          },
          defaultConfiguration: { level: 'error' },
          properties: { tags: ['security', 'salesforce', 'attack-chain'] },
        },
      };
      rules.set(ruleId, acc);
    }
    acc.worst = acc.worst ? maxRisk(acc.worst, chain.severity) : chain.severity;

    const stepLocation = (step: AttackChain['steps'][number], idx: number) => ({
      message: { text: `Step ${idx + 1}: ${step.title ?? step.findingId} (${step.findingId})` },
      logicalLocations: logicalLocations([step.findingId]),
      properties: { capability: step.capability },
    });

    return {
      ruleId,
      level: riskToSarifLevel(chain.severity),
      message: { text: `[Attack chain] ${chain.title}: ${chain.narrative}` },
      locations: [orgLocation(ruleId, chain.steps.map((s) => s.findingId))],
      codeFlows: [
        {
          message: { text: chain.title },
          threadFlows: [{ locations: chain.steps.map((s, i) => ({ location: stepLocation(s, i) })) }],
        },
      ],
      partialFingerprints: { [FINGERPRINT_KEY]: fingerprint(ruleId, chain.id) },
      properties: {
        riskLevel: chain.severity,
        confidence: chain.confidence,
        attackChainId: chain.id,
        remediation: chain.remediation,
      },
    };
  }
}
