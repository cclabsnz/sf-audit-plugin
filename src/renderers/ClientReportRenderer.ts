import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '@cclabsnz/sf-core';
import type { AuditRenderer } from './AuditRenderer.js';
import type { Branding } from '@cclabsnz/sf-core';
import { esc, STRICT_CSP_META, DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import { toolCreditHtml } from './toolCredit.js';
import { buildRoadmap, type Roadmap } from '../report/RemediationRoadmap.js';
import type { Framework } from '../compliance/types.js';
import { buildComplianceMatrix, type FrameworkMatrix } from '../report/ComplianceMatrix.js';
import type { AttackChain, AttackChainStep } from '../chains/AttackChain.js';
import { coverageSummary, coverageAdvice } from '../findings/coverage.js';
import { techniqueLabel, ATTACK_TACTIC_ORDER } from '../threats/attack.js';
import { buildThreatView, threatRowStatusText, type ThreatRow } from '../threats/view.js';
import { buildActionPlan, type PlannedAction } from '../report/ActionPlan.js';
import { buildAttackJourney } from '../report/AttackJourney.js';
import { deckFontFaceCss } from './deckFonts.js';

// The executive report is a consulting-style deck: every slide's title states its conclusion, the
// exhibit below supports it, and a source note says where the numbers come from. Slides print one
// per landscape page; the appendix pages run as long as their content.

const CRIT = '#a3392b';
const AMBER = '#a8660f';
const SEV_COLOR: Record<RiskLevel, string> = {
  CRITICAL: CRIT, HIGH: CRIT, MEDIUM: AMBER, LOW: 'var(--muted)', INFO: '#9aa1a8',
};
const SEV_RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEVERITIES: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const EFFORT_LABEL = { quick: 'Under a day', moderate: 'Days', project: 'Weeks' } as const;
const WAVE_LABEL = { 1: 'Start now', 2: 'Next 30 days', 3: 'This quarter' } as const;
const WAVE_WHY = {
  1: 'breaks a critical chain or closes a critical finding, whatever the effort',
  2: 'high severity, days of work or less',
  3: 'high severity, weeks of work',
} as const;
const PLAN_ROWS_PER_SLIDE = 6;
const MATRIX_MAX = 10;
const TACTIC_SHORT: Record<string, string> = {
  'reconnaissance': 'Recon', 'resource-development': 'Resource dev.', 'initial-access': 'Initial access',
  'execution': 'Execution', 'persistence': 'Persistence', 'privilege-escalation': 'Privilege esc.',
  'stealth': 'Stealth', 'defense-impairment': 'Defense impair.', 'credential-access': 'Credential access',
  'discovery': 'Discovery', 'lateral-movement': 'Lateral move.', 'collection': 'Collection',
  'command-and-control': 'Command & control', 'exfiltration': 'Exfiltration', 'impact': 'Impact',
};

const FRAMEWORK_LABEL: Record<Framework, string> = {
  OWASP: 'OWASP Top 10', OWASP_LLM: 'OWASP LLM Top 10', SOC2: 'SOC 2', ISO27001: 'ISO/IEC 27001',
  SBS: 'Security Benchmark for Salesforce', PRIVACY_ACT: 'NZ Privacy Act',
  HISO10029: 'HISO 10029', NZISM: 'NZISM', HIPAA: 'HIPAA', GDPR: 'GDPR',
};

export interface ClientReportOptions {
  branding: Branding;
  topN: number;
  frameworks: Framework[];
}

interface Slide {
  kicker: string;
  /** The conclusion, as a sentence; escaped HTML. */
  title: string;
  body: string;
  source?: string;
  /** 'page' grows with its content (appendix); a slide keeps the 16:9 frame. */
  kind?: 'slide' | 'page' | 'cover';
}

/** The grade's reason in words: "F: 7 CRITICAL (4 findings, 3 attack chains) (D allows none)" reads as a sentence. */
function gradeInWords(grade: string, reason: string | undefined): string {
  if (!reason) return `Graded ${grade} from the health score.`;
  const m = /^[A-F]: (\d+) (CRITICAL|HIGH|MEDIUM)(?: \((.+?)\))? \(([A-F]) allows (none|at most \d+)\)$/.exec(reason);
  if (!m) return `Graded ${grade}: ${reason.replace(/^[A-F]: /, '')}.`;
  const [, n, level, parts, better, allows] = m;
  return `Graded ${grade} because ${n} ${level.toLowerCase()} issue${n === '1' ? ' is' : 's are'} open${parts ? ` (${parts})` : ''}, and a ${better} allows ${allows}, whatever the health score.`;
}

// A check that gathered no evidence (inconclusive, or failed outright) is unassessed, not open.
const unassessed = (f: Finding): boolean => !f.passed && (!!f.inconclusive || !!f.notAssessed);
const isOpen = (f: Finding): boolean => !f.passed && !unassessed(f) && !f.waived;
const isWaived = (f: Finding): boolean => !f.passed && !unassessed(f) && !!f.waived;
const plural = (n: number, word: string, many = `${word}s`): string => `${n} ${n === 1 ? word : many}`;
const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const NUMBER_WORDS = ['No', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten'];
const countWord = (n: number): string => NUMBER_WORDS[n] ?? String(n);
const actions = (n: number): string => `${countWord(n)} action${n === 1 ? '' : 's'}`;
/** The verb agreeing with a count: verb(1, 'closes', 'close'). */
const verb = (n: number, one: string, many: string): string => (n === 1 ? one : many);

/** The findings schedule's order, which also numbers every reference: open by severity, waived, unassessed, passed. */
function scheduleOrder(findings: Finding[]): Finding[] {
  const bySev = (a: Finding, b: Finding): number => SEV_RANK[a.riskLevel] - SEV_RANK[b.riskLevel];
  return [
    ...findings.filter(isOpen).sort(bySev), ...findings.filter(isWaived).sort(bySev),
    ...findings.filter(unassessed), ...findings.filter((f) => f.passed),
  ];
}

/**
 * A CSS string literal for text that reaches a stylesheet (print page footers). Every character that
 * could end the string, the declaration or the style element is hex-escaped.
 */
function cssStr(text: string): string {
  return `"${text.replace(/[^\w .·:/()-]/gu, (ch) => `\\${ch.codePointAt(0)!.toString(16)} `)}"`;
}

/** An escaped title that may break after a slash, so long annotation lists wrap at the slash, not mid-word. */
function title(text: string): string {
  return esc(text).replace(/\//g, '/<wbr>');
}

/** Escaped text with `code` spans set apart. */
function prose(text: string): string {
  return esc(text).replace(/`([^`\s][^`]*)`/g, '<code>$1</code>');
}

/**
 * Tool-authored advice only: also turns "NAME (https://…)" into a link on NAME. Never used for finding
 * text, where a URL can be a lapsed or attacker-held domain the finding is warning about.
 */
function advice(text: string): string {
  return esc(text)
    .replace(/(\S+) \((https:\/\/[^\s)`]+)\)/g, '<a href="$2">$1</a>')
    .replace(/`([^`\s][^`]*)`/g, '<code>$1</code>');
}

export class ClientReportRenderer implements AuditRenderer {
  public readonly format = 'executive';
  public readonly fileExtension = '.html';
  public readonly filenamePrefix = 'SF_Audit_Executive';

  // Finding id to its schedule ref (F-001), and each chain's label (named C1…, potential P1…), for one render.
  private refs = new Map<string, string>();
  private labels: string[] = [];

  public constructor(private readonly opts: ClientReportOptions) {}

  public render(result: AuditResult): string {
    const b = this.opts.branding;
    const chains = result.attackChains ?? [];
    this.refs = new Map();
    scheduleOrder(result.findings).forEach((f, i) => { if (!this.refs.has(f.id)) this.refs.set(f.id, `F-${String(i + 1).padStart(3, '0')}`); });
    let nc = 0, np = 0;
    this.labels = chains.map((c) => (c.abuseCase ? `C${++nc}` : `P${++np}`));
    const plan = buildActionPlan(result.findings, chains);
    const roadmap = buildRoadmap(result.findings);
    const matrix = buildComplianceMatrix(result, this.opts.frameworks);

    const named = chains.map((c, i) => ({ c, i })).filter((x) => x.c.abuseCase);
    const potential = chains.map((c, i) => ({ c, i })).filter((x) => !x.c.abuseCase);
    const slides: Slide[] = [
      this.coverSlide(result, b),
      this.summarySlide(result, plan, chains),
      ...(plan.length ? [this.matrixSlide(plan)] : []),
      ...this.planSlides(plan, chains, result),
      ...this.threatSlides(result, chains),
      ...named.map(({ c, i }) => this.chainSlide(c, i, result.findings)),
      ...(potential.length ? [this.potentialSlide(potential)] : []),
      this.roadmapPage(roadmap),
      ...(matrix.length ? [this.matrixPage(matrix)] : []),
      ...(result.waivedFindings?.length ? [this.waiversPage(result.waivedFindings)] : []),
      this.findingsPage(result),
      this.signOffPage(result, b),
    ];
    const total = slides.length;
    const date = result.generatedAt.toISOString().slice(0, 10);
    const body = slides.map((s, i) => this.slide(s, i + 1, total, result, date)).join('\n');
    // Every printed page names its client, date and page, so a page pulled from the pack is still identified.
    const pages = slides.map((s, i) =>
      `@page s${i + 1}{@bottom-left{content:${cssStr(`${result.orgName} · ${result.orgId} · ${date}`)}}@bottom-right{content:${cssStr(`${s.kicker.toUpperCase()} · page `)} counter(page)}}`,
    ).join('\n');

    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${STRICT_CSP_META}<title>Security Assessment: ${esc(result.orgName)}</title>
<style>${deckFontFaceCss()}
${this.css(b)}
${pages}
</style></head><body><main class="deck">
${body}
</main></body></html>`;
  }

  private css(b: Branding): string {
    // A firm's own fonts and surfaces replace the deck's only when the firm changed them from the default.
    const display = b.fontDisplay && b.fontDisplay !== DEFAULT_BRANDING.fontDisplay ? `'${b.fontDisplay}',` : '';
    const text = b.fontBody && b.fontBody !== DEFAULT_BRANDING.fontBody ? `'${b.fontBody}',` : '';
    const own = (k: 'bg' | 'bgAlt' | 'border', concept: string): string => (b[k] && b[k] !== DEFAULT_BRANDING[k] ? b[k] : concept);
    return `:root{--ink:${b.ink};--accent:${b.primary};--muted:${b.muted};--paper:${own('bgAlt', '#ffffff')};--desk:${own('bg', '#eef0f1')};
--hair:${own('border', '#e3e6e9')};--crit:${CRIT};--amber:${AMBER};
--serif:${display}'Source Serif 4',Georgia,serif;--sans:${text}'Source Sans 3',system-ui,sans-serif;--ease:cubic-bezier(0.16,1,0.3,1)}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:var(--desk);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.5;font-variant-numeric:tabular-nums}
p{margin:0 0 10px}
strong{font-weight:650}
code{font-family:ui-monospace,Menlo,monospace;font-size:0.88em;background:color-mix(in srgb,var(--accent) 7%,var(--paper));padding:0 3px}
a{color:var(--accent);text-underline-offset:2px;transition:color 150ms var(--ease)}
a:hover{color:var(--crit)}
.muted{color:var(--muted)}
.deck{max-width:1280px;margin:0 auto;padding:36px 28px 56px;display:grid;grid-template-columns:minmax(0,1fr);gap:28px}
.slide{background:var(--paper);min-width:0;min-height:calc(min(1224px, 100vw - 56px) * 9 / 16);padding:52px 64px 26px;display:flex;flex-direction:column;box-shadow:0 1px 2px rgba(20,30,40,0.06),0 14px 34px -24px rgba(20,30,40,0.35)}
.slide.page{min-height:0}
.kicker{font-size:13px;font-weight:650;color:var(--accent);letter-spacing:0.01em}
h2.title{font-family:var(--serif);font-size:30px;font-weight:600;line-height:1.22;letter-spacing:-0.005em;margin:8px 0 0;max-width:34em}
.rule{width:72px;height:2px;background:var(--accent);margin:20px 0 24px}
.content{flex:1 0 auto;display:flex;flex-direction:column}
.content>*{flex:none}
.foot{display:flex;justify-content:space-between;gap:24px;margin-top:22px;padding-top:11px;border-top:1px solid var(--hair);font-size:11.5px;color:var(--muted);line-height:1.45}
.foot .src{max-width:110ch}
.foot .pg{white-space:nowrap}
h3{font-size:19px;font-weight:650;line-height:1.3;margin:0}
.lbl{font-size:12px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;color:var(--muted)}
.tag{display:inline-block;font-size:11px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;color:var(--c);border:1.25px solid var(--c);padding:0 6px;white-space:nowrap;line-height:1.6}
.tag.solid{background:var(--c);color:#fff}
.num{flex:none;width:26px;height:26px;border-radius:50%;display:inline-grid;place-items:center;font-size:13px;font-weight:700;border:1.5px solid var(--accent);color:var(--accent);background:var(--paper)}
.num.w1{background:var(--accent);color:#fff}
.num.w3{border-color:#9aa1a8;color:var(--muted)}
.cover{padding:64px 64px 30px}
.cover .content .kicker{color:var(--muted)}
.cover h1{font-family:var(--serif);font-size:50px;font-weight:600;line-height:1.08;letter-spacing:-0.015em;margin:16px 0 0;max-width:15em}
.cover .org{font-size:26px;font-weight:600;margin-top:14px}
.cover .sub{font-size:16px;color:var(--muted);margin-top:6px}
.cover .spacer{flex:1 1 auto;min-height:48px}
.cover .bottom{display:flex;align-items:flex-end;justify-content:space-between;gap:40px}
.grade{display:flex;align-items:center;gap:18px}
.grade .mark{flex:none;width:72px;height:72px;border-radius:12px;border:1px solid var(--hair);display:grid;place-items:center;font-family:var(--serif);font-size:42px;font-weight:600;color:var(--g)}
.grade .what{font-size:14px;color:var(--muted);max-width:52ch}
.grade .what strong{color:var(--ink)}
.prepared{font-size:13px;color:var(--muted);text-align:right}
.scr{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0}
.scr>div{padding:0 32px;border-left:1px solid var(--hair)}
.scr>div:first-child{padding-left:0;border-left:0}
.scr .head{font-size:19px;font-weight:650;line-height:1.3;margin:8px 0 12px}
.scr ul{margin:0;padding-left:18px;color:#3a434d;font-size:14.5px;line-height:1.55}
.scr li{margin-bottom:6px}
.scr .res .lbl{color:var(--accent)}
.waves{display:flex;flex-direction:column;gap:12px}
.wave{display:grid;grid-template-columns:28px minmax(0,1fr);gap:10px;font-size:14.5px;line-height:1.45}
.wave ol.w1{margin:4px 0 0;padding-left:18px}
.wave ol.w1 li{margin-bottom:3px}
.mx-wrap{flex:1 1 auto !important;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,1fr);gap:44px}
.plot{position:relative;min-height:360px}
.plot .area{position:absolute;left:34px;top:0;right:0;bottom:30px;display:grid;grid-template-columns:1fr 1fr;grid-template-rows:1fr 1fr;border-left:1.5px solid var(--ink);border-bottom:1.5px solid var(--ink)}
.plot .q{padding:10px 12px;font-size:12.5px;font-weight:700;color:var(--muted);background:#f6f7f8}
.plot .q.hot{background:color-mix(in srgb,var(--accent) 9%,var(--paper));color:var(--accent)}
.plot .q.r{text-align:right;border-left:1px dashed #c9ced3}
.plot .q.b{display:flex;align-items:flex-end;border-top:1px dashed #c9ced3}
.plot .q.r.b{justify-content:flex-end}
.plot .pt{position:absolute;transform:translate(-50%,50%)}
.plot .pt .num{width:30px;height:30px;box-shadow:0 0 0 3px var(--paper)}
.plot .yl{position:absolute;left:0;top:0;bottom:30px;width:24px;display:flex;align-items:center;justify-content:center}
.plot .yl span{transform:rotate(-90deg);white-space:nowrap;font-size:12.5px;font-weight:650;color:#3a434d}
.plot .xl{position:absolute;left:34px;right:0;bottom:0;height:24px;display:flex;justify-content:space-between;align-items:flex-end;font-size:12.5px;color:#3a434d}
.keylist{list-style:none;margin:0;padding:0}
.keylist li{display:grid;grid-template-columns:30px minmax(0,1fr) 92px;gap:10px;align-items:baseline;padding:5px 0;border-bottom:1px solid var(--hair);font-size:14px;line-height:1.35}
.keylist .e{font-size:12.5px;color:var(--muted);text-align:right}
.plan{width:100%;border-collapse:collapse;table-layout:fixed;font-size:14px}
.plan th{text-align:left;font-size:11.5px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;color:var(--muted);padding:0 10px 8px 0;border-bottom:1.5px solid var(--ink)}
.plan td{padding:9px 10px 9px 0;border-bottom:1px solid var(--hair);vertical-align:top;line-height:1.4}
.plan tr.wave-h td{border-bottom:0;padding:12px 0 2px;font-size:12.5px;font-weight:700;color:var(--accent)}
.plan tr.wave-h.w3 td{color:var(--muted)}
.plan tr.wave-h .why{font-weight:400;color:var(--muted)}
.plan .at{font-weight:600}
.plan .ad{display:block;font-size:12.5px;color:var(--muted);margin-top:2px}
.plan .ar{display:block;font-size:11.5px;color:#8a929b;margin-top:2px}
.plan .s{font-size:13px;color:#3a434d}
.balls{display:flex;gap:4px;padding-top:4px}
.balls i{width:11px;height:11px;border-radius:50%;border:1.5px solid #c9ced3}
.balls i.on{background:var(--accent);border-color:var(--accent)}
.jr{display:grid;grid-template-columns:240px repeat(15,minmax(0,1fr));align-content:start}
.jr .bar{display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:96px;padding:0 3px;font-size:12.5px;font-weight:700}
.jr .bar i{display:block;width:100%;max-width:42px;margin-top:3px;background:var(--accent)}
.jr .bar i.z{background:var(--hair)}
.jr .tl{min-height:52px;padding:7px 2px 6px;border-top:1.5px solid var(--ink);font-size:11px;line-height:1.2;text-align:center}
.jr .tl.z{color:#b3b9bf}
.jr .cn{display:flex;align-items:center;gap:8px;min-height:34px;padding:4px 10px 4px 0;border-top:1px solid #eef0f2;font-size:12.5px;line-height:1.25;min-width:0}
.jr .cn b{width:26px;flex:none}
.jr .cc{position:relative;min-height:34px;border-top:1px solid #eef0f2;display:grid;place-items:center}
.jr .cc .ln{position:absolute;top:calc(50% - 1px);height:0;border-top:2px solid var(--c)}
.jr .cc.pot .ln{border-top-style:dashed}
.jr .cc .dt{position:relative;width:13px;height:13px;border-radius:50%;background:var(--c)}
.tm{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:52px}
.hm{display:grid;grid-template-columns:200px repeat(5,minmax(0,1fr)) 52px;gap:4px;align-items:center}
.hm .h{font-size:11.5px;font-weight:700;color:var(--muted);text-align:center;padding-bottom:4px}
.hm .h.t{text-align:right}
.hm .n{font-size:14px;line-height:1.25}
.hm .n b{display:inline-block;width:20px}
.hm .c{height:46px;display:grid;place-items:center;font-size:14.5px;font-weight:700;background:#f6f7f8}
.hm .none{grid-column:span 5;height:46px;display:flex;align-items:center;padding:0 12px;font-size:13px;color:var(--muted);background:#f6f7f8}
.hm .tt{text-align:right;font-weight:700}
.lb{display:grid;grid-template-columns:190px minmax(0,1fr) 30px;gap:12px;align-items:center;min-height:38px;border-bottom:1px solid #eef0f2;font-size:14px}
.lb .segs{display:flex;gap:2px;height:12px}
.lb .segs i{display:block;height:12px}
.lb .st{font-size:12.5px;color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:12px;font-size:12px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{width:11px;height:11px;display:inline-block}
.sc{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:44px}
.steps{list-style:none;margin:0;padding:0}
.step{position:relative;display:grid;grid-template-columns:30px minmax(0,1fr);column-gap:14px;padding:0 0 13px;break-inside:avoid}
.step::before{content:"";position:absolute;left:14px;top:28px;bottom:0;border-left:1.5px solid #c9ced3}
.step:last-child::before{display:none}
.step .num{width:28px;height:28px;font-size:12px;border-color:#9aa1a8;color:#3a434d}
.step.cut .num{background:var(--crit);border-color:var(--crit);color:#fff}
.step .t{font-weight:600;line-height:1.35;padding-top:3px;font-size:14.5px}
.step .m{font-size:12px;color:var(--muted);margin-top:2px}
.cutmark{color:var(--crit);font-weight:700;white-space:nowrap;margin-left:6px}
.abuse{font-size:15px;margin-bottom:10px}
.narr{font-size:14px;color:#3a434d;line-height:1.6}
.breaks{border-left:3px solid var(--crit);background:color-mix(in srgb,var(--crit) 5%,var(--paper));padding:12px 16px;margin-top:14px;font-size:15px}
.breaks p,.full p{margin:0}
.breaks strong{color:var(--crit)}
.breaks.potential{border-left-color:var(--accent);background:color-mix(in srgb,var(--accent) 6%,var(--paper))}
.breaks.potential strong{color:var(--accent)}
.full{margin-top:10px;font-size:13px;color:var(--muted)}
.pot{width:100%;border-collapse:collapse;font-size:14px}
.pot td,.pot th{padding:10px 12px 10px 0;border-bottom:1px solid var(--hair);vertical-align:top;text-align:left}
.pot th{font-size:11.5px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;color:var(--muted);border-bottom:1.5px solid var(--ink)}
.sched{width:100%;border-collapse:collapse;font-size:13.5px;margin:0 0 30px;table-layout:fixed}
.sched caption{text-align:left;font-size:17px;font-weight:650;padding:0 0 8px;caption-side:top}
.sched caption .muted{font-size:13px;font-weight:400;margin-left:8px}
.sched th{text-align:left;font-size:11.5px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;color:var(--muted);border-bottom:1.5px solid var(--ink);padding:6px 10px 8px 0}
.sched td{border-bottom:1px solid var(--hair);padding:9px 10px 9px 0;vertical-align:top}
.c-ref{width:64px}.c-sv{width:104px}.c-fx{width:36%}.c-ctl{width:120px}.c-st{width:150px}.c-role{width:200px}.c-rev{width:56px}.c-date{width:120px}.c-by{width:220px}
.sched .ref{color:var(--accent);font-size:12.5px;white-space:nowrap}
.sched .sv{white-space:nowrap}
.mx .sv{text-align:right}
.sched .ft{font-weight:650;display:block;margin-bottom:2px}
.sched .fd{color:var(--muted);font-size:12.5px;display:block}
.sched .fx{font-size:12.5px}
.sched .fx .k{display:none}
.sched tbody tr{transition:background-color 150ms var(--ease)}
.sched tbody tr:hover{background:color-mix(in srgb,var(--accent) 4%,var(--paper))}
h3.cap{font-size:17px;margin:0 0 8px}
h3.cap .muted{font-size:13px;font-weight:400;margin-left:8px}
.passed{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:1fr 1fr;column-gap:24px;font-size:13px;border-top:1.5px solid var(--ink)}
.passed li{display:grid;grid-template-columns:60px minmax(0,1fr);gap:8px;padding:6px 0;border-bottom:1px solid var(--hair);break-inside:avoid;line-height:1.4}
.passed .ref{color:var(--accent);font-size:12px}
.phase{margin-bottom:26px}
.phase .ph{display:flex;align-items:baseline;gap:12px;padding-bottom:8px;border-bottom:1.5px solid var(--ink)}
.phase ul{list-style:none;margin:0;padding:0}
.phase li{display:grid;grid-template-columns:64px minmax(0,1fr) 96px;gap:12px;align-items:baseline;padding:8px 0;border-bottom:1px solid var(--hair);font-size:14px;line-height:1.4}
.phase .rref{color:var(--accent);font-size:12.5px}
.phase .rs{text-align:right}
.phase .empty{padding:10px 0;color:var(--muted);font-size:13.5px}
.aside{border-left:2px solid var(--accent);padding-left:14px;font-size:13.5px;color:var(--muted);margin:0 0 22px;max-width:110ch}
.approve td{height:46px}
.approve td.lbl{vertical-align:middle;color:var(--ink);text-transform:none;letter-spacing:0;font-weight:600;font-size:14px}
footer{margin-top:28px;color:var(--muted);font-size:13px;line-height:1.6;max-width:80ch}
footer .lbl{display:block;margin-bottom:6px;color:var(--ink)}
h3,.t,.ft,.at,.phase li>span:nth-child(2),.keylist li>span:nth-child(2){overflow-wrap:anywhere;min-width:0}
@media screen and (prefers-reduced-motion:no-preference){
.slide{animation:rise 520ms var(--ease) both}
.slide:nth-child(2){animation-delay:80ms}.slide:nth-child(n+3){animation-delay:140ms}
@supports (animation-timeline:view()){
.plot .pt{animation:pop linear both;animation-timeline:view();animation-range:entry 20% cover 35%}
.jr .bar i{transform-origin:bottom;animation:grow linear both;animation-timeline:view();animation-range:entry 10% cover 35%}
}}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
@keyframes pop{from{opacity:0;transform:translate(-50%,50%) scale(0.6)}to{opacity:1;transform:translate(-50%,50%) scale(1)}}
@keyframes grow{from{transform:scaleY(0)}to{transform:scaleY(1)}}
@media screen and (max-width:760px){
.deck{padding:14px 10px 28px;gap:16px}
.slide,.cover{min-height:0;padding:26px 20px 18px}
h2.title{font-size:22px}
.cover h1{font-size:32px}
.cover .bottom,.grade{flex-direction:column;align-items:flex-start}
.prepared{text-align:left}
.scr{grid-template-columns:minmax(0,1fr);gap:22px}
.scr>div{padding:0;border-left:0}
.mx-wrap,.tm,.sc{grid-template-columns:minmax(0,1fr);gap:24px}
.plot{min-height:300px}
.plan thead{display:none}
.plan,.plan tbody,.plan tr,.plan td{display:block;width:100%}
.plan tr{border-bottom:1px solid var(--hair);padding:8px 0}
.plan td{border:0;padding:2px 0}
.plan td[data-l]{display:flex;gap:8px;align-items:baseline}
.plan td[data-l]::before{content:attr(data-l);flex:none;width:58px;font-size:11px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;color:var(--muted)}
.content{min-width:0}
.jr{overflow-x:auto;grid-template-columns:150px repeat(15,48px)}
.hm{grid-template-columns:120px repeat(5,minmax(0,1fr)) 34px}
.lb{grid-template-columns:120px minmax(0,1fr) 24px}
.passed{grid-template-columns:minmax(0,1fr)}
.sched:not(.approve),.sched:not(.approve) tbody,.sched:not(.approve) tr,.sched:not(.approve) td{display:block;width:100%}
.sched:not(.approve) thead{display:none}
.sched caption{display:block}
.sched tr{border-bottom:1px solid var(--hair);padding:8px 0}
.sched td{border:0;padding:2px 0}
.sched td.ref,.sched td.sv{display:inline-block;width:auto;padding-right:6px}
.sched .fx .k{display:block;margin-top:6px}
.sched{table-layout:auto}
.foot{flex-direction:column;gap:6px}
}
@page{size:A4 landscape;margin:10mm 10mm 14mm;@bottom-left{font-family:'Source Sans 3',sans-serif;font-size:7.5pt;color:#5b646e}@bottom-right{font-family:'Source Sans 3',sans-serif;font-size:7.5pt;color:#5b646e}}
@media print{
body{background:#fff;font-size:12.5px}
.deck{max-width:none;padding:0;display:block}
.slide{box-shadow:none;break-before:page;min-height:182mm;padding:8mm 10mm 4mm}
/* A slide is one page: scale it to the sheet, keeping its frame (182mm / 0.8). */
.slide:not(.page){zoom:0.8;min-height:227mm;break-inside:avoid}
.slide.page{min-height:0}
.slide:first-child{break-before:auto}
.step,.plan tr,.sched tr,.keylist li,.phase li,.passed li,.breaks{break-inside:avoid}
h2.title,.rule{break-after:avoid}
}`;
  }

  private slide(s: Slide, n: number, total: number, r: AuditResult, date: string): string {
    const head = s.kind === 'cover' ? '' : `<div class="kicker">${esc(s.kicker)}</div><h2 class="title">${s.title}</h2><div class="rule"></div>`;
    return `<section class="slide${s.kind && s.kind !== 'slide' ? ` ${s.kind}` : ''}" style="page:s${n}" aria-label="${esc(s.kicker)}">
${head}<div class="content">${s.body}</div>
<div class="foot"><span class="src">${s.source ?? ''}</span><span class="pg">${esc(r.orgName)} · ${esc(date)} · ${n} / ${total}</span></div>
</section>`;
  }

  private tag(sev: RiskLevel, text: string): string {
    const solid = sev === 'CRITICAL' ? ' solid' : '';
    return `<span class="tag${solid}" style="--c:${SEV_COLOR[sev]}">${esc(text)}</span>`;
  }

  private gradeColor(g: string): string {
    return g === 'D' || g === 'F' ? 'var(--crit)' : g === 'C' ? 'var(--amber)' : 'var(--accent)';
  }

  private coverSlide(r: AuditResult, b: Branding): Slide {
    const prepared = `Prepared by ${esc(b.firmName)}${b.preparedFor ? ` for ${esc(b.preparedFor)}` : ''}`;
    return {
      kicker: 'Cover', title: '', kind: 'cover',
      body: `<div class="kicker">Salesforce security assessment</div>
<h1>Findings and action plan</h1>
<div class="org">${esc(r.orgName)}</div>
<div class="sub">${esc(r.orgType)} · ${esc(r.orgId)} · ${esc(r.generatedAt.toISOString().slice(0, 10))}</div>
<div class="spacer"></div>
<div class="bottom"><div class="grade"><div class="mark" style="--g:${this.gradeColor(r.grade)}">${esc(r.grade)}</div>
<div class="what">Grade <strong>${esc(r.grade)}</strong> · health score <strong>${r.healthScore}/100</strong><br>${esc(gradeInWords(r.grade, r.gradeReason))}</div></div>
<div class="prepared">${prepared}</div></div>`,
    };
  }

  private summarySlide(r: AuditResult, plan: PlannedAction[], chains: AttackChain[]): Slide {
    const open = r.findings.filter(isOpen);
    const count = (l: RiskLevel): number => open.filter((f) => f.riskLevel === l).length;
    const crit = count('CRITICAL'), high = count('HIGH');
    const passed = r.findings.filter((f) => f.passed).length;
    const named = chains.filter((c) => c.abuseCase);
    const critChains = chains.map((c, i) => ({ c, i })).filter((x) => x.c.severity === 'CRITICAL' && x.c.abuseCase);
    // Every critical chain, potential ones too: a path is only "closed" when an action breaks it.
    const allCrit = chains.map((c, i) => ({ c, i })).filter((x) => x.c.severity === 'CRITICAL');
    const wave1 = plan.filter((a) => a.wave === 1);
    const brokenByWave1 = new Set(wave1.flatMap((a) => a.breaks));
    const allCritBroken = allCrit.length > 0 && allCrit.every((x) => brokenByWave1.has(x.i));
    const rest = plan.length - wave1.length;
    const restText = rest ? `; ${rest} more action${verb(rest, ' completes', 's complete')} the plan` : '';
    const n1 = wave1.length;

    let headline: string;
    if (plan.length === 0) headline = 'No critical or high-severity issues are open; the remaining fixes are routine hardening';
    else if (allCritBroken) headline = `${actions(n1)} to start now ${verb(n1, 'closes', 'close')} every critical attack path${restText}`;
    else if (n1) headline = `${actions(n1)} to start now ${verb(n1, 'addresses', 'address')} the critical exposure${restText}`;
    else if (high) headline = `${actions(plan.length)} ${verb(plan.length, 'addresses', 'address')} every open high-severity issue; none is critical`;
    else headline = `${actions(plan.length)} ${verb(plan.length, 'addresses', 'address')} the remaining exposure; none is critical or high`;

    const c = r.coverage;
    const incon = r.findings.filter(unassessed).length;
    const waivedN = r.findings.filter(isWaived).length;
    const parts = [`${open.length} open`, `${passed} passed`, ...(incon ? [`${incon} inconclusive`] : []), ...(waivedN ? [`${waivedN} waived as accepted risk`] : [])];
    const situation = [
      c ? `${plural(c.checksRun, 'check')} ran (${c.checksAssessed} gathered evidence) and produced ${plural(r.findings.length, 'result')}: ${parts.join(', ')}` : `${plural(r.findings.length, 'result')}: ${parts.join(', ')}`,
      esc(gradeInWords(r.grade, r.gradeReason)),
    ];
    const compHead = crit ? `${plural(crit, 'critical finding')} and ${high} high are open`
      : high ? `${plural(high, 'high-severity finding')} ${high === 1 ? 'is' : 'are'} open` : `${plural(open.length, 'finding')} open, none critical or high`;
    const complication = [
      named.length ? `${plural(named.length, 'proven attack chain')} link findings into a path to data or control${critChains.length ? `, ${critChains.length} of them critical` : ''}${chains.length > named.length ? `; ${plural(chains.length - named.length, 'more path')} ${verb(chains.length - named.length, 'is', 'are')} possible but unproven` : ''}` : '',
      ...critChains.slice(0, 2).map((x) => `${esc(cap(x.c.abuseCase!.actor))} could ${esc(x.c.abuseCase!.goal)}`),
    ].filter(Boolean);
    const waves = ([1, 2, 3] as const).map((w) => ({ w, items: plan.filter((a) => a.wave === w) })).filter((x) => x.items.length);
    const resolution = waves.length
      ? `<div class="waves">${waves.map(({ w, items }) => {
        const named1 = w === 1 ? items.slice(0, 4) : items.slice(0, 1);
        const more = items.length - named1.length;
        const what = w === 1 && named1.length > 1
          ? `<ol class="w1">${named1.map((a) => `<li>${esc(a.title)}${a.breaks.length ? ` <span class="muted">(breaks ${a.breaks.map((i) => this.labels[i]).join(', ')})</span>` : ''}</li>`).join('')}</ol>${more ? `<span class="muted">and ${plural(more, 'more action')}</span>` : ''}`
          : `${esc(named1[0].title)}${more ? `, and ${plural(more, 'more action')}` : ''}`;
        return `<div class="wave"><span class="num w${w}">${w}</span><span><strong>${WAVE_LABEL[w]}:</strong> ${what}</span></div>`;
      }).join('')}</div>`
      : '<p>Keep the configuration where it is and re-run the audit after changes.</p>';
    const list = (xs: string[]): string => (xs.length ? `<ul>${xs.map((x) => `<li>${x}</li>`).join('')}</ul>` : '');
    return {
      kicker: 'Executive summary', title: esc(headline),
      body: `<div class="scr">
<div><div class="lbl">Situation</div><div class="head">The org scores ${r.healthScore}/100 on configuration health, graded ${esc(r.grade)}</div>${list(situation)}</div>
<div><div class="lbl">Complication</div><div class="head">${esc(compHead)}</div>${list(complication)}</div>
<div class="res"><div class="lbl">Resolution</div><div class="head">${waves.length ? `Act in ${countWord(waves.length).toLowerCase()} wave${waves.length === 1 ? '' : 's'}${n1 ? ', starting now' : ''}` : 'Hold the line'}</div>${resolution}</div>
</div>`,
      source: `${c ? `${esc(coverageSummary(c))}. ` : ''}Source: read-only configuration audit of ${esc(r.orgName)}. See Scope &amp; Liability on the last page.`,
    };
  }

  private matrixSlide(plan: PlannedAction[]): Slide {
    const shown = plan.slice(0, Math.max(1, Math.min(this.opts.topN, MATRIX_MAX)));
    const realMax = Math.max(...shown.map((a) => a.risk), 0);
    const maxRisk = realMax || 1;
    // Days of work counts as "do now": quick and moderate sit left of the midline, projects right.
    const X = { quick: 0.14, moderate: 0.37, project: 0.78 } as const;
    const placed: Array<{ x: number; y: number }> = [];
    const pts = shown.map((a, i) => {
      // Points sit on their effort column; only a collision nudges one sideways.
      const y = 0.08 + (a.risk / maxRisk) * 0.84;
      let x: number = X[a.effort];
      for (let k = 1; placed.some((p) => Math.abs(p.x - x) < 0.045 && Math.abs(p.y - y) < 0.07); k++) x = X[a.effort] + (k % 2 ? 1 : -1) * Math.ceil(k / 2) * 0.05;
      placed.push({ x, y });
      return `<div class="pt" style="left:calc(34px + (100% - 34px) * ${x.toFixed(3)});bottom:calc(30px + (100% - 30px) * ${y.toFixed(3)})"><span class="num w${a.wave}">${i + 1}</span></div>`;
    }).join('');
    const nums = (xs: number[]): string => (xs.length > 1 ? `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}` : String(xs[0]));
    const big = shown.map((a, i) => ({ a, n: i + 1 })).filter((x) => x.a.risk >= maxRisk / 2);
    const cheap = big.filter((x) => x.a.effort !== 'project').map((x) => x.n);
    const costly = big.filter((x) => x.a.effort === 'project').map((x) => x.n);
    const headline = realMax === 0 ? 'None of these actions removes critical or high-severity risk'
      : cheap.length && costly.length ? `Action${cheap.length === 1 ? '' : 's'} ${nums(cheap)} ${verb(cheap.length, 'is', 'are')} the cheapest large risk reduction${cheap.length === 1 ? '' : 's'}; ${nums(costly)} ${verb(costly.length, 'removes', 'remove')} as much but ${verb(costly.length, 'needs', 'need')} project funding`
        : cheap.length ? `Action${cheap.length === 1 ? '' : 's'} ${nums(cheap)} remove${cheap.length === 1 ? 's' : ''} the most risk for days of work or less`
          : `The largest risk reductions (${nums(costly)}) need project funding`;
    const key = shown.map((a, i) => `<li><span class="num w${a.wave}">${i + 1}</span><span>${esc(a.title)}</span><span class="e">${EFFORT_LABEL[a.effort]}</span></li>`).join('');
    return {
      kicker: 'Where to act', title: esc(headline),
      body: `<div class="mx-wrap"><div class="plot">
<div class="area"><div class="q hot">Do now</div><div class="q r">Plan and fund</div><div class="q b">Quick hygiene</div><div class="q r b">Schedule</div></div>
${pts}<div class="yl"><span>Risk removed →</span></div><div class="xl"><span>Under a day</span><span><strong>Effort →</strong></span><span>Weeks</span></div>
</div><ol class="keylist">${key}</ol></div>`,
      source: `Risk removed weighs the severity of each finding an action closes, and counts twice the severity of each attack chain it breaks. Effort is each check's remediation estimate.${plan.length > shown.length ? ` The top ${shown.length} of ${plan.length} actions are shown; all are in the action plan.` : ''}`,
    };
  }

  private planSlides(plan: PlannedAction[], chains: AttackChain[], r: AuditResult): Slide[] {
    if (plan.length === 0) return [];
    const maxRisk = Math.max(...plan.map((a) => a.risk), 1);
    const named = chains.filter((c) => c.abuseCase).length;
    const broken = new Set(plan.flatMap((a) => a.breaks)).size;
    const closed = new Set(plan.flatMap((a) => a.fixes)).size;
    const open = r.findings.filter(isOpen).length;
    const n = plan.length;
    const headline = `${actions(n)}${named ? ` ${verb(n, 'breaks', 'break')} ${broken} of ${plural(named, 'named attack chain')} and` : ''} ${verb(n, 'closes', 'close')} ${closed} of ${plural(open, 'open finding')}`;
    const label = (i: number): string => this.labels[i];
    const rows = plan.map((a, i) => {
      const refs = a.fixes.map((f) => this.refs.get(f.id)).filter(Boolean).join(' ');
      const breaks = a.breaks.length ? a.breaks.map(label).join(', ') : '—';
      const weakens = a.weakens.length ? `<span class="ad">weakens ${a.weakens.map(label).join(', ')}: part of its break point is waived or passed</span>` : '';
      const inChains = a.inChains.length ? `<span class="ad">part of ${a.inChains.map(label).join(', ')}</span>` : '';
      const balls = [1, 2, 3, 4].map((k) => `<i${k <= Math.ceil((a.risk / maxRisk) * 4) ? ' class="on"' : ''}></i>`).join('');
      return { wave: a.wave, html: `<tr><td><span class="num w${a.wave}">${i + 1}</span></td><td><span class="at">${title(a.title)}</span><span class="ad">${esc(a.detail ?? a.why)}</span><span class="ar">${esc(refs)}</span></td><td class="s" data-l="Breaks">${breaks}${weakens}${inChains}</td><td data-l="Risk"><span class="balls">${balls}</span></td><td class="s" data-l="Effort">${EFFORT_LABEL[a.effort]}</td><td class="s muted" data-l="Owner">[To agree]</td></tr>` };
    });
    const pages: Slide[] = [];
    for (let start = 0; start < rows.length; start += PLAN_ROWS_PER_SLIDE) {
      const chunk = rows.slice(start, start + PLAN_ROWS_PER_SLIDE);
      let last = 0;
      const body = chunk.map((row) => {
        const h = row.wave !== last ? `<tr class="wave-h w${row.wave}"><td></td><td colspan="5">${WAVE_LABEL[row.wave]} <span class="why">· ${WAVE_WHY[row.wave]}</span></td></tr>` : '';
        last = row.wave;
        return h + row.html;
      }).join('');
      const cont = start > 0;
      pages.push({
        kicker: cont ? 'Action plan (continued)' : 'Action plan',
        title: cont ? `Actions ${start + 1}–${Math.min(start + PLAN_ROWS_PER_SLIDE, rows.length)} of ${rows.length}` : esc(headline),
        body: `<table class="plan"><colgroup><col style="width:44px"><col><col style="width:150px"><col style="width:84px"><col style="width:104px"><col style="width:104px"></colgroup>
<thead><tr><th></th><th>Action</th><th>Breaks</th><th>Risk</th><th>Effort</th><th>Owner</th></tr></thead><tbody>${body}</tbody></table>`,
        source: 'Each named attack chain becomes the action that breaks it; every other open critical or high finding becomes an action per check. Risk marks: share of the largest action’s risk removed. References point to the findings appendix; medium and low fixes are in the roadmap.',
      });
    }
    return pages;
  }

  private threatSlides(r: AuditResult, chains: AttackChain[]): Slide[] {
    const out: Slide[] = [];
    const journey = buildAttackJourney(r.findings, chains);
    if (journey.tactics.some((t) => t.findings.length)) {
      const max = Math.max(...journey.tactics.map((t) => t.findings.length), 1);
      const top = journey.tactics.map((t, i) => ({ ...t, i })).filter((t) => t.findings.length)
        .sort((a, b) => b.findings.length - a.findings.length || a.i - b.i);
      const crit = chains.map((c, i) => ({ c, i })).filter((x) => x.c.severity === 'CRITICAL');
      const initial = ATTACK_TACTIC_ORDER.indexOf('initial-access');
      const fromOutside = crit.filter((x) => journey.chains[x.i][0] === initial).length;
      const cutoff = top[Math.min(1, top.length - 1)].findings.length;
      const lead = top.filter((t) => t.findings.length >= cutoff).slice(0, 3);
      const names = lead.map((t) => TACTIC_SHORT[t.tactic].toLowerCase().replace(' esc.', ' escalation'));
      const critClause = crit.length
        ? `; ${fromOutside === 0 ? 'none' : countWord(fromOutside).toLowerCase()} of the ${countWord(crit.length).toLowerCase()} critical chain${crit.length === 1 ? '' : 's'} ${fromOutside === 1 ? 'starts' : 'start'} with initial access`
        : '';
      const joined = names.length > 2 ? `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}` : names.join(' and ');
      const headline = `Findings cluster in ${joined}${critClause}`;
      const bars = journey.tactics.map((t) => `<div class="bar">${t.findings.length || ''}<i${t.findings.length ? '' : ' class="z"'} style="height:${t.findings.length ? Math.round((t.findings.length / max) * 64) : 2}px"></i></div>`).join('');
      const labels = journey.tactics.map((t) => `<div class="tl${t.findings.length ? '' : ' z'}">${esc(TACTIC_SHORT[t.tactic])}</div>`).join('');
      const rows = chains.map((c, ci) => {
        const hits = journey.chains[ci];
        const col = !c.abuseCase ? '#9aa1a8' : c.severity === 'CRITICAL' ? 'var(--crit)' : '#5b646e';
        const lo = hits[0] ?? -1, hi = hits[hits.length - 1] ?? -1;
        const cells = journey.tactics.map((_, ti) => {
          const span = hits.length > 1 && ti >= lo && ti <= hi;
          const line = span ? `<i class="ln" style="left:${ti > lo ? '0' : '50%'};right:${ti < hi ? '0' : '50%'}"></i>` : '';
          return `<div class="cc${c.abuseCase ? '' : ' pot'}" style="--c:${col}">${line}${hits.includes(ti) ? '<i class="dt"></i>' : ''}</div>`;
        }).join('');
        return `<div class="cn"><b style="color:${col}">${this.labels[ci]}</b><span>${esc(c.title)}${c.abuseCase ? '' : ' <em class="muted">(potential)</em>'}</span></div>${cells}`;
      }).join('');
      const none = chains.map((_, i) => (journey.chains[i].length ? '' : this.labels[i])).filter(Boolean);
      out.push({
        kicker: 'Threat model · MITRE ATT&CK', title: esc(headline),
        body: `<div class="jr"><div></div>${bars}<div></div>${labels}${rows}</div>`,
        source: `Bars: open findings whose granted access maps to a technique in each tactic (Enterprise ATT&amp;CK v20.0, verified techniques only). Rows: the tactics each attack chain reaches, in attack order.${none.length ? ` ${none.join(', ')} map${none.length === 1 ? 's' : ''} to no technique.` : ''}`,
      });
    }

    const view = buildThreatView(r.findings);
    const sevCount = (row: ThreatRow<string>): number[] => SEVERITIES.map((l) => row.findings.filter((f) => f.riskLevel === l).length);
    const shade = (n: number, crit: boolean): string => (!n ? '' : crit ? 'background:var(--crit);color:#fff'
      : `background:color-mix(in srgb,var(--accent) ${Math.round(16 + Math.min(n, 10) * 7)}%,var(--paper));${n >= 6 ? 'color:#fff' : ''}`);
    const stride = view.stride.map((row) => {
      const v = sevCount(row);
      const cells = row.findings.length
        ? v.map((n, i) => `<div class="c" style="${shade(n, i === 0)}">${n || ''}</div>`).join('')
        : `<div class="none">${esc(threatRowStatusText(row))}</div>`;
      return `<div class="n"><b>${esc(row.category)}</b>${esc(row.name)}</div>${cells}<div class="tt">${row.findings.length || ''}</div>`;
    }).join('');
    const critRows = view.stride.filter((row) => row.findings.some((f) => f.riskLevel === 'CRITICAL'));
    const busiest = [...view.stride].sort((a, b) => b.findings.length - a.findings.length)[0];
    // "All critical risk" holds only when every open critical finding sits in those categories.
    const unmappedCritical = r.findings.filter((f) => isOpen(f) && f.riskLevel === 'CRITICAL' && !f.threats?.stride?.length).length;
    let headline = critRows.length && critRows.length <= 2 && unmappedCritical === 0
      ? `All critical risk is ${critRows.map((x) => x.name.toLowerCase()).join(' or ')}`
      : busiest.findings.length ? `${busiest.name} carries the most open findings` : 'No open finding maps to a STRIDE category';
    const segColors = [CRIT, '#d98a7f', '#d9b071', '#cdd3d8'];
    let privacy = '';
    if (view.linddun) {
      const bars = view.linddun.map((row) => {
        const v = sevCount(row).slice(0, 4);
        const segs = row.findings.length
          ? `<span class="segs">${v.map((n, i) => (n ? `<i style="width:${n * 22}px;background:${segColors[i]}"></i>` : '')).join('')}</span>`
          : `<span class="st">${esc(threatRowStatusText(row))}</span>`;
        return `<div class="lb"><span>${esc(row.name)}</span>${segs}<b style="text-align:right">${row.findings.length || ''}</b></div>`;
      }).join('');
      const topPrivacy = [...view.linddun].sort((a, b) => b.findings.length - a.findings.length)[0];
      if (topPrivacy.findings.length) headline += `; on privacy, ${topPrivacy.name.toLowerCase()} leads`;
      privacy = `<div><h3 style="font-size:15px;margin-bottom:10px">Privacy threats (LINDDUN) · open findings</h3>${bars}
<div class="legend"><span><i style="background:${segColors[0]}"></i>Critical</span><span><i style="background:${segColors[1]}"></i>High</span><span><i style="background:${segColors[2]}"></i>Medium</span><span><i style="background:${segColors[3]}"></i>Low</span></div></div>`;
    }
    out.push({
      kicker: 'Threat model · STRIDE and LINDDUN', title: esc(headline),
      body: `<div class="tm"><div><h3 style="font-size:15px;margin-bottom:10px">Security threats (STRIDE) · open findings by severity <span class="muted" style="font-weight:400">(a finding counts in each category it touches)</span></h3>
<div class="hm"><div class="h"></div>${SEVERITIES.map((l) => `<div class="h">${cap(l.toLowerCase())}</div>`).join('')}<div class="h t">Total</div>${stride}</div></div>${privacy}</div>`,
      source: `Each check is mapped to the STRIDE categories it guards and, where personal data is involved, to LINDDUN.${[...view.stride, ...(view.linddun ?? [])].some((row) => !row.findings.length) ? ' A row without findings is not assurance: it says how many checks covered it.' : ''}`,
    });
    return out;
  }

  private stepMeta(s: AttackChainStep): string {
    const parts: string[] = [];
    const ref = this.refs.get(s.findingId);
    if (ref) parts.push(ref);
    if (s.severity) parts.push(cap(s.severity.toLowerCase()));
    for (const t of s.techniques ?? []) parts.push(techniqueLabel(t));
    return parts.map(esc).join(' · ');
  }

  private steps(c: AttackChain): string {
    return `<ol class="steps" aria-label="Steps, in attack order">${c.steps.map((s, i) => {
      const cut = s.breaksChain ? ' cut' : '';
      const mark = s.breaksChain ? '<span class="cutmark">✂ BREAK POINT</span>' : '';
      return `<li class="step${cut}"><span class="num">${i + 1}</span><div><div class="t">${title(s.title || s.findingId)}</div><div class="m">${this.stepMeta(s)}${mark}</div></div></li>`;
    }).join('')}</ol>`;
  }

  private chainSlide(c: AttackChain, i: number, findings: Finding[]): Slide {
    const openIds = new Set(findings.filter(isOpen).map((f) => f.id));
    const cutIds = [...new Set(c.steps.filter((s) => s.breaksChain).map((s) => s.findingId))];
    const fixable = cutIds.filter((id) => openIds.has(id)).length;
    const headline = cutIds.length === 0 ? esc(c.title)
      : fixable < cutIds.length ? `${esc(c.title)}: part of its break point is waived or passed, so it stays open`
        : `${esc(c.title)}: fixing ${plural(cutIds.length, 'finding')} breaks it`;
    return {
      kicker: `Attack scenario ${this.labels[i]} · ${cap(c.severity.toLowerCase())}`,
      title: headline,
      body: `<div class="sc"><div>${this.steps(c)}</div><div>
<p class="abuse"><strong>Abuse case:</strong> ${esc(c.abuseCase!.actor)} wants to ${esc(c.abuseCase!.goal)}.</p>
<div class="narr"><p>${esc(c.narrative)}</p></div>
<div class="breaks"><p><strong>Breaks the chain:</strong> ${esc(c.abuseCase!.breakPoint)}</p></div>
<div class="full"><p><strong>Full remediation:</strong> ${esc(c.remediation)}</p></div></div></div>`,
      source: `Steps run in attack order. Steps marked ✂ are the break point: fixing all of them stops the chain. References point to the findings appendix.`,
    };
  }

  private potentialSlide(list: Array<{ c: AttackChain; i: number }>): Slide {
    const rows = list.map(({ c, i }) => `<tr><td style="width:56px;color:var(--accent);font-weight:700">${this.labels[i]}</td><td><strong>${esc(c.title)}</strong><div style="font-size:13.5px;margin-top:4px;color:#3a434d">${esc(c.narrative)}</div><div class="muted" style="font-size:13px;margin-top:4px">${c.steps.map((s) => title(s.title || s.findingId)).join(' → ')}</div></td><td style="width:42%"><div class="breaks potential" style="margin-top:0"><p><strong>Recommended fixes:</strong> ${esc(c.remediation)}</p></div></td></tr>`).join('');
    return {
      kicker: 'Attack scenarios · potential',
      title: `${countWord(list.length)} further path${list.length === 1 ? ' is' : 's are'} possible but unproven`,
      body: `<table class="pot"><thead><tr><th></th><th>Path</th><th>What would close it</th></tr></thead><tbody>${rows}</tbody></table>`,
      source: 'Potential chains link findings whose access could combine; no single break point is proven for them, so their fixes are recommendations.',
    };
  }

  private roadmapPage(roadmap: Roadmap): Slide {
    const phase = (label: string, sub: string, arr: Finding[]): string => {
      const rows = arr.length
        ? `<ul>${arr.map((f) => `<li><span class="rref">${esc(this.refs.get(f.id) ?? '')}</span><span>${title(f.title)}</span><span class="rs">${this.tag(f.riskLevel, f.riskLevel)}</span></li>`).join('')}</ul>`
        : '<div class="empty">Nothing at this effort.</div>';
      return `<div class="phase"><div class="ph"><h3>${esc(label)}</h3><span class="muted">${arr.length} · ${esc(sub)}</span></div>${rows}</div>`;
    };
    return {
      kicker: 'Appendix · Remediation roadmap', kind: 'page',
      title: 'Every open fix above informational, grouped by the effort it takes',
      body: `${phase('Quick wins', 'a day or less each', roadmap.quick)}${phase('Moderate', 'days each', roadmap.moderate)}${phase('Projects', 'weeks each', roadmap.project)}`,
    };
  }

  private worst(findings: Finding[]): RiskLevel | undefined {
    return findings.slice().sort((a, b) => SEV_RANK[a.riskLevel] - SEV_RANK[b.riskLevel])[0]?.riskLevel;
  }

  private matrixPage(matrix: FrameworkMatrix[]): Slide {
    const blocks = matrix.map((fm) => {
      const rows = fm.rows.map((row) => {
        const w = this.worst(row.findings);
        const status = w
          ? this.tag(w, `${row.findings.length} finding${row.findings.length === 1 ? '' : 's'}`)
          : '<span class="muted">No findings detected</span>';
        return `<tr><td class="ref">${esc(row.control.id)}</td><td>${esc(row.control.title)}</td><td class="sv">${status}</td></tr>`;
      }).join('');
      return `<table class="sched mx"><colgroup><col class="c-ctl"><col><col class="c-st"></colgroup><caption>${esc(FRAMEWORK_LABEL[fm.framework])} <span class="muted">${esc(fm.version)}</span></caption>
<thead><tr><th>Control</th><th>Requirement area</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
    }).join('');
    return {
      kicker: 'Appendix · Compliance coverage', kind: 'page',
      title: 'Findings mapped to framework controls',
      body: blocks,
      source: '“No findings detected” is not an attestation of compliance. Status shows the findings mapped to a control, coloured by the most severe. See Scope &amp; Liability on the last page.',
    };
  }

  private waiversPage(waived: Finding[]): Slide {
    const rows = waived.map((f, i) => {
      // The approval (reason, approver, expiry) is on each item's note, or on the detail when the finding has no items.
      const scope = f.affectedItems?.length ? f.affectedItems.map((it) => (it.note ? `${it.label} ${it.note}` : it.label)).join('; ') : f.id;
      return `<tr><td class="ref">W-${String(i + 1).padStart(2, '0')}</td><td class="sv">${this.tag('INFO', 'WAIVED')}</td><td><span class="ft">${title(f.title)}</span><span class="fd">${esc(f.detail)}</span></td><td class="fx"><strong>Scope:</strong> ${esc(scope)}</td></tr>`;
    }).join('');
    return {
      kicker: 'Appendix · Accepted risks', kind: 'page',
      title: `${plural(waived.length, 'finding')} accepted under an approved waiver`,
      body: `<table class="sched"><colgroup><col class="c-ref"><col class="c-sv"><col><col class="c-fx"></colgroup><thead><tr><th>Ref</th><th>Status</th><th>Finding</th><th>Scope</th></tr></thead><tbody>${rows}</tbody></table>`,
      source: 'Waived findings are excluded from the score and the action plan, and still count toward the attack scenarios.',
    };
  }

  private coverageNote(r: AuditResult): string {
    const c = r.coverage;
    if (!c || c.notAssessed.length === 0) return '';
    return `<p class="aside">${prose(coverageSummary(c))}. The checks that gathered no evidence are listed as inconclusive below; their areas are unassessed, not clean. ${advice(coverageAdvice(c))}</p>`;
  }

  private findingsPage(r: AuditResult): Slide {
    const order = scheduleOrder(r.findings);
    const open = order.filter(isOpen);
    const waived = order.filter(isWaived);
    const incon = order.filter(unassessed);
    const passed = order.filter((f) => f.passed);
    const refOf = new Map(order.map((f, i) => [f, `F-${String(i + 1).padStart(3, '0')}`]));
    const ref = (f: Finding): string => refOf.get(f) ?? '';
    const row = (f: Finding, tag: string): string =>
      `<tr><td class="ref">${ref(f)}</td><td class="sv">${tag}</td><td><span class="ft">${title(f.title)}</span><span class="fd">${prose(f.detail)}</span></td><td class="fx"><span class="k lbl">Fix</span>${prose(f.remediation)}</td></tr>`;
    const cols = '<colgroup><col class="c-ref"><col class="c-sv"><col><col class="c-fx"></colgroup>';
    const table = (caption: string, note: string, head: string, rows: string): string => rows
      ? `<table class="sched">${cols}<caption>${caption} <span class="muted">${note}</span></caption><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>`
      : '';
    const passedList = passed.length
      ? `<h3 class="cap">Passed <span class="muted">${passed.length}</span></h3><ol class="passed">${passed.map((f) => `<li><span class="ref">${ref(f)}</span><span>${title(f.title)}</span></li>`).join('')}</ol>`
      : '';
    const body = order.length === 0 ? '<p class="muted">No check results in this run.</p>' : `${this.coverageNote(r)}
${table('Open findings', `${open.length}`, '<th>Ref</th><th>Severity</th><th>Finding</th><th>Remediation</th>', open.map((f) => row(f, this.tag(f.riskLevel, f.riskLevel))).join(''))}
${table('Waived', `${waived.length} · accepted risk, excluded from the score`, '<th>Ref</th><th>Severity</th><th>Finding</th><th>Remediation</th>',
    waived.map((f) => row(f, `${this.tag(f.riskLevel, f.riskLevel)} ${this.tag('INFO', 'WAIVED')}`)).join(''))}
${table('Inconclusive', `${incon.length} · no evidence gathered`, '<th>Ref</th><th>Status</th><th>Check</th><th>Next step</th>', incon.map((f) => row(f, this.tag('INFO', 'inconclusive'))).join(''))}
${passedList}`;
    return {
      kicker: 'Appendix · All findings', kind: 'page',
      title: 'Every check result, open findings first by severity',
      body,
    };
  }

  private signOffPage(r: AuditResult, b: Branding): Slide {
    return {
      kicker: 'Issue and approval', kind: 'page',
      title: 'Sign-off',
      body: `<table class="sched rev"><colgroup><col class="c-rev"><col class="c-date"><col><col class="c-by"></colgroup><thead><tr><th>Rev</th><th>Date</th><th>Description</th><th>By</th></tr></thead>
<tbody><tr><td class="ref">A</td><td>${esc(r.generatedAt.toISOString().slice(0, 10))}</td><td>Issued for review: grade ${esc(r.grade)}, health score ${r.healthScore}/100</td><td>${esc(b.firmName)}</td></tr></tbody></table>
<table class="sched approve"><colgroup><col class="c-role"><col><col><col class="c-date"></colgroup><thead><tr><th>Role</th><th>Name</th><th>Signature</th><th>Date</th></tr></thead>
<tbody>${['Prepared by', 'Reviewed by', 'Accepted by client'].map((role) => `<tr><td class="lbl">${role}</td><td></td><td></td><td></td></tr>`).join('')}</tbody></table>
${this.footer(b)}`,
    };
  }

  private footer(b: Branding): string {
    const site = b.website
      ? ` · <a href="https://${esc(b.website.replace(/^https?:\/\//, ''))}">${esc(b.website.replace(/^https?:\/\//, ''))}</a>`
      : '';
    return `<footer><span class="lbl">Scope &amp; Liability</span>
Read-only, point-in-time configuration review: not a penetration test, not a code audit. The grade is a prioritisation aid, not a certification. Validate findings before remediation. © ${new Date().getFullYear()} ${esc(b.firmName)} · ${esc(b.contact)}${site}<br>${toolCreditHtml('executive-report')}</footer>`;
  }
}
