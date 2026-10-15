#!/usr/bin/env node
// ist-link-check — the Intent → Spec → Test gate.
//
// Fails (exit 1) when:
//   1. a must-never (MN-xxx) has no rule (RULE-xxx) citing it
//   2. a rule has no test (visible or hidden) citing it
//   3. a must-never has no HIDDEN test covering it (directly, or via a rule it owns)
//   4. a rule cites an intent/must-never id that does not exist
//
// Conventions (all plain text, grep-able, no tooling needed to author):
//   intent/*.md   : "# INT-001 <title>"  and lines "- MN-001: <must never ...>"
//   spec/*.md     : "## RULE-001 <title>" then a line "cites: INT-001, MN-001"
//   tests/**      : any file mentioning RULE-xxx / MN-xxx (comments are fine)
//   tests/hidden/ : same, but CI-only. The agent never reads this folder.
//
// Usage: node scripts/ist-link-check.mjs [repoRoot] [--json] [--hidden-dir <path>]
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs'
import { join, relative } from 'node:path'

const args = process.argv.slice(2)
const json = args.includes('--json')
const hiddenFlag = args.indexOf('--hidden-dir')
const hiddenArg = hiddenFlag >= 0 ? args[hiddenFlag + 1] : undefined
const root = args.find((a, i) => !a.startsWith('--') && !(hiddenFlag >= 0 && i === hiddenFlag + 1)) ?? process.cwd()
// .ist/harness.json may point at an existing test layout (retrofit):
//   { "visibleDirs": ["src", "tests"], "hiddenDir": "tests/hidden" }
let cfg = {}
try { cfg = JSON.parse(readFileSync(join(root, '.ist', 'harness.json'), 'utf8')) } catch { /* none */ }
const hiddenDir = hiddenArg ?? (cfg.hiddenDir ? join(root, cfg.hiddenDir) : join(root, 'tests', 'hidden'))
const visibleDirs = (Array.isArray(cfg.visibleDirs) && cfg.visibleDirs.length ? cfg.visibleDirs : ['tests/visible']).map(d => join(root, d))

const ID = { int: /\bINT-\d{3,4}\b/g, mn: /\bMN-\d{3,4}\b/g, rule: /\bRULE-\d{3,4}\b/g }

function walk(dir, out = []) {
  if (!existsSync(dir)) return out
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue
    const p = join(dir, name)
    if (statSync(p).isDirectory()) { if (p !== hiddenDir) walk(p, out) }
    else out.push(p)
  }
  return out
}
const read = p => readFileSync(p, 'utf8')
const uniq = a => [...new Set(a)]

// ---- intents & must-nevers ----
const intents = new Map() // INT -> { file, mns: Set }
const mns = new Map()     // MN  -> { intent, file, text }
for (const f of walk(join(root, 'intent'))) {
  if (!f.endsWith('.md') || /README\.md$/i.test(f)) continue
  const text = read(f)
  let current = null
  for (const line of text.split('\n')) {
    const h = line.match(/^#\s+(INT-\d{3,4})\b/)
    if (h) { current = h[1]; intents.set(current, { file: f, mns: new Set() }); continue }
    const m = line.match(/^\s*-\s*(MN-\d{3,4})\s*:\s*(.+)$/)
    if (m) {
      mns.set(m[1], { intent: current, file: f, text: m[2].trim() })
      if (current) intents.get(current).mns.add(m[1])
    }
  }
}

// ---- rules ----
const rules = new Map() // RULE -> { file, cites: {int:[], mn:[]} }
for (const f of walk(join(root, 'spec'))) {
  if (!f.endsWith('.md') || /README\.md$/i.test(f)) continue
  const blocks = read(f).split(/^(?=##\s+RULE-\d{3,4}\b)/m)
  for (const b of blocks) {
    const h = b.match(/^##\s+(RULE-\d{3,4})\b/)
    if (!h) continue
    const citesLine = b.match(/^\s*cites\s*:\s*(.+)$/mi)?.[1] ?? ''
    rules.set(h[1], {
      file: f,
      cites: { int: uniq(citesLine.match(ID.int) ?? []), mn: uniq(citesLine.match(ID.mn) ?? []) },
    })
  }
}

// ---- tests ----
function cover(dirs) {
  const byRule = new Map(), byMn = new Map()
  for (const f of dirs.flatMap(d => walk(d))) {
    if (f.endsWith('.md')) continue
    const t = read(f)
    for (const r of uniq(t.match(ID.rule) ?? [])) byRule.set(r, [...(byRule.get(r) ?? []), f])
    for (const m of uniq(t.match(ID.mn) ?? [])) byMn.set(m, [...(byMn.get(m) ?? []), f])
  }
  return { byRule, byMn }
}
const visible = cover(visibleDirs)
const hidden = cover([hiddenDir])

// ---- gates ----
const errors = []
const rel = p => relative(root, p)

for (const [mn, info] of mns) {
  const owners = [...rules].filter(([, r]) => r.cites.mn.includes(mn)).map(([id]) => id)
  if (owners.length === 0) errors.push({ gate: 'must-never-without-rule', id: mn, where: rel(info.file), fix: `add a RULE in spec/ with "cites: ${info.intent ?? 'INT-xxx'}, ${mn}"` })
  const hiddenHit = hidden.byMn.has(mn) || owners.some(r => hidden.byRule.has(r))
  if (!hiddenHit) errors.push({ gate: 'must-never-without-hidden-test', id: mn, where: rel(info.file), fix: `add a test under ${rel(hiddenDir)}/ that mentions ${mn}${owners.length ? ` or ${owners.join('/')}` : ''}` })
}
for (const [rule, r] of rules) {
  if (!visible.byRule.has(rule) && !hidden.byRule.has(rule)) errors.push({ gate: 'rule-without-test', id: rule, where: rel(r.file), fix: `add a test mentioning ${rule} under ${visibleDirs.map(rel).join(' or ')} (or hidden)` })
  if (r.cites.int.length === 0 && r.cites.mn.length === 0) errors.push({ gate: 'rule-without-citation', id: rule, where: rel(r.file), fix: 'add a "cites: INT-xxx[, MN-xxx]" line under the heading' })
  for (const i of r.cites.int) if (!intents.has(i)) errors.push({ gate: 'dangling-citation', id: rule, where: rel(r.file), fix: `${i} is not defined in intent/` })
  for (const m of r.cites.mn) if (!mns.has(m)) errors.push({ gate: 'dangling-citation', id: rule, where: rel(r.file), fix: `${m} is not defined in intent/` })
}

const summary = {
  intents: intents.size, mustNevers: mns.size, rules: rules.size,
  visibleTestFiles: visibleDirs.flatMap(d => walk(d)).filter(f => !f.endsWith('.md')).length, hiddenTestFiles: walk(hiddenDir).filter(f => !f.endsWith('.md')).length,
  errors,
}

if (json) {
  console.log(JSON.stringify(summary, null, 2))
} else {
  console.log(`ist-link-check · ${summary.intents} intents · ${summary.mustNevers} must-nevers · ${summary.rules} rules · ${summary.visibleTestFiles} visible / ${summary.hiddenTestFiles} hidden test files`)
  for (const e of errors) console.log(`  ✗ ${e.gate.padEnd(30)} ${e.id.padEnd(9)} ${e.where}\n      → ${e.fix}`)
  console.log(errors.length ? `\n${errors.length} gate failure(s).` : '\nAll links hold.')
}
process.exit(errors.length ? 1 : 0)
