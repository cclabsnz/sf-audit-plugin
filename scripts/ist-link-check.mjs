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
// Usage: node scripts/ist-link-check.mjs [repoRoot] [--json] [--hidden-dir <path>] [--local] [--base <dir>]
//   --base: the runner's mode (INT-001 RULE-007). <dir> is the base branch checkout: visibleDirs and
//   hiddenDir come from its .ist/harness.json, any change to that file fails, and a must-never on base
//   that the PR no longer defines fails.
//   --local: coverage gaps (rule-without-test, must-never-without-hidden-test) are warnings, not
//   errors. For the local commit guard only: spec-first work creates them on purpose. CI never passes it.
import { readdirSync, readFileSync, lstatSync, existsSync, realpathSync, openSync, fstatSync, closeSync, readlinkSync, constants as fsConstants } from 'node:fs'
import { join, relative, isAbsolute, resolve, sep } from 'node:path'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'

const args = process.argv.slice(2)
const json = args.includes('--json')
// Flags that take a value; their value slot is never read as a flag or as the root.
const valueAt = new Set()
const flagValue = {}
for (const f of ['--hidden-dir', '--base']) {
  const i = args.indexOf(f)
  if (i < 0) continue
  const v = args[i + 1]
  if (v === undefined || v.startsWith('-')) {
    console.error(`ist-link-check: ${f} needs a path, got ${JSON.stringify(v)}`)
    process.exit(2)
  }
  flagValue[f] = v
  valueAt.add(i + 1)
}
const hiddenArg = flagValue['--hidden-dir']
// Only a flag in its own position counts: `--hidden-dir --local` must not switch local mode on.
const local = args.some((a, i) => a === '--local' && !valueAt.has(i))
// Absolute, so every join(root, …) below compares equal to an absolute hiddenDir.
const root = resolve(args.find((a, i) => !a.startsWith('--') && !valueAt.has(i)) ?? process.cwd())
const base = flagValue['--base'] ? resolve(flagValue['--base']) : undefined
// .ist/harness.json may point at an existing test layout (retrofit):
//   { "visibleDirs": ["src", "tests"], "hiddenDir": "tests/hidden" }
const harnessText = dir => (existsSync(join(dir, '.ist', 'harness.json')) ? readFileSync(join(dir, '.ist', 'harness.json'), 'utf8') : null)
const readCfg = dir => { try { return JSON.parse(harnessText(dir) ?? '{}') } catch { return {} } }
// With --base, the configuration that decides what counts is base's, never the PR's.
const cfg = readCfg(base ?? root)
const expand = p => (p.startsWith('~/') ? join(homedir(), p.slice(2)) : p)
const abs = p => (isAbsolute(expand(p)) ? resolve(expand(p)) : join(root, p))
const hiddenRaw = hiddenArg ?? cfg.hiddenDir ?? 'tests/hidden'
if (typeof hiddenRaw !== 'string' || hiddenRaw === '' || hiddenRaw.startsWith('-')) {
  console.error(`ist-link-check: invalid hidden-dir ${JSON.stringify(hiddenRaw)} (from ${hiddenArg !== undefined ? '--hidden-dir' : '.ist/harness.json'})`)
  process.exit(2)
}
const hiddenDir = abs(hiddenRaw)
// Visible dirs must stay inside the repo (lexically and after symlinks); others are refused, not walked.
const early = []
const rootReal = realpathSync(root)
const inside = p => p === rootReal || p.startsWith(rootReal + sep)
const visibleDirs = []
for (const d of Array.isArray(cfg.visibleDirs) && cfg.visibleDirs.length ? cfg.visibleDirs : ['tests/visible']) {
  const p = resolve(root, String(d))
  const real = existsSync(p) ? realpathSync(p) : resolve(rootReal, String(d))
  if (!inside(resolve(rootReal, String(d))) || !inside(real)) early.push({ gate: 'visible-dir-outside-root', id: String(d), where: '.ist/harness.json', fix: 'visibleDirs must name folders inside the repo' })
  else visibleDirs.push(p)
}

const ID = { int: /\bINT-\d{3,4}\b/g, mn: /\bMN-\d{3,4}\b/g, rule: /\bRULE-\d{3,4}\b/g }

// Symlinks are never followed (a link could pull in files from anywhere, or loop). Only the hidden dir
// itself, which the caller supplies, may be a link.
function walk(dir, out = [], allowLink = false) {
  if (!existsSync(dir)) return out
  if (!allowLink && lstatSync(dir).isSymbolicLink()) return out
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue
    const p = join(dir, name)
    const st = lstatSync(p)
    if (st.isSymbolicLink()) continue
    if (st.isDirectory()) { if (p !== hiddenDir) walk(p, out) }
    else out.push(p)
  }
  return out
}
const read = p => readFileSync(p, 'utf8')
const uniq = a => [...new Set(a)]

// ---- intents & must-nevers ----
function parseIntents(dir) {
  const intents = new Map() // INT -> { file, mns: Set }
  const mns = new Map()     // MN  -> { intent, file, text }
  for (const f of walk(join(dir, 'intent'))) {
    if (!f.endsWith('.md') || /README\.md$/i.test(f)) continue
    let current = null
    for (const line of read(f).split('\n')) {
      const h = line.match(/^#\s+(INT-\d{3,4})\b/)
      if (h) { current = h[1]; intents.set(current, { file: f, mns: new Set() }); continue }
      const m = line.match(/^\s*-\s*(MN-\d{3,4})\s*:\s*(.+)$/)
      if (m) {
        mns.set(m[1], { intent: current, file: f, text: m[2].trim() })
        if (current) intents.get(current).mns.add(m[1])
      }
    }
  }
  return { intents, mns }
}
const { intents, mns } = parseIntents(root)

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
function cover(dirs, allowLink = false) {
  const byRule = new Map(), byMn = new Map()
  for (const f of dirs.flatMap(d => walk(d, [], allowLink))) {
    if (f.endsWith('.md')) continue
    const t = read(f)
    for (const r of uniq(t.match(ID.rule) ?? [])) byRule.set(r, [...(byRule.get(r) ?? []), f])
    for (const m of uniq(t.match(ID.mn) ?? [])) byMn.set(m, [...(byMn.get(m) ?? []), f])
  }
  return { byRule, byMn }
}
const visible = cover(visibleDirs)
const hidden = cover([hiddenDir], true)

// ---- gates ----
let errors = [...early]
// Every entry under .ist/ — file (content hash and exec bit), dir, symlink (and its target) or
// other — so any add/remove/change/link shows (RULE-007). Entries are JSON-encoded, so no name
// can forge another entry. Each is opened once, without following links, and a file is hashed only
// through the handle that was checked; O_NONBLOCK so a FIFO cannot hang the open. Names are handled as raw bytes (listed as
// Buffers, recorded as latin1, which maps every byte to one char), so a name that is not UTF-8 is
// neither skipped nor merged with another. Any open error but "is a link", or "missing" for .ist/
// itself, stops the check: an entry that cannot be read must never compare equal.
const OPEN_FLAGS = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK
function istSnapshot(dir) {
  const out = []
  const visit = (d, rel, isRoot = false) => {
    let fd
    try {
      fd = openSync(d, OPEN_FLAGS)
    } catch (e) {
      if (e.code === 'ENOENT' && isRoot) return
      if (e.code === 'ELOOP' || e.code === 'EMLINK') return void out.push(['L', rel, readlinkSync(d, { encoding: 'buffer' }).toString('latin1')])
      console.error(`ist-link-check: cannot read ${JSON.stringify(rel)} (${e.code}); refusing to compare .ist/`)
      process.exit(2)
    }
    try {
      const st = fstatSync(fd)
      if (st.isFile()) return void out.push(['F', rel, st.mode & 0o111 ? 'x' : '-', createHash('sha256').update(readFileSync(fd)).digest('hex')])
      if (!st.isDirectory()) return void out.push(['X', rel])
    } finally {
      closeSync(fd)
    }
    out.push(['D', rel])
    // Node lists by path only; each child is then opened, without following links, on its own.
    const names = readdirSync(d, { encoding: 'buffer' }).sort(Buffer.compare)
    for (const name of names) visit(Buffer.concat([d, Buffer.from('/'), name]), `${rel}/${name.toString('latin1')}`)
  }
  visit(Buffer.from(join(dir, '.ist')), '.ist', true)
  return JSON.stringify(out)
}
if (base) {
  if (istSnapshot(base) !== istSnapshot(root)) errors.push({ gate: 'ist-config-changed', id: '.ist', where: '.ist/', fix: 'human review required: the PR changes what the gate counts' })
  for (const [mn, info] of parseIntents(base).mns) {
    if (!mns.has(mn)) errors.push({ gate: 'must-never-removed', id: mn, where: relative(base, info.file), fix: 'human review required: a must-never on the base branch is gone from the PR' })
  }
}
const rel = p => (p.startsWith(root) ? relative(root, p) : p)

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

const COVERAGE = new Set(['rule-without-test', 'must-never-without-hidden-test'])
const warnings = local ? errors.filter(e => COVERAGE.has(e.gate)) : []
if (local) errors = errors.filter(e => !COVERAGE.has(e.gate))

const summary = {
  intents: intents.size, mustNevers: mns.size, rules: rules.size,
  visibleTestFiles: visibleDirs.flatMap(d => walk(d)).filter(f => !f.endsWith('.md')).length, hiddenTestFiles: walk(hiddenDir, [], true).filter(f => !f.endsWith('.md')).length,
  errors, warnings,
}

if (json) {
  console.log(JSON.stringify(summary, null, 2))
} else {
  console.log(`ist-link-check · ${summary.intents} intents · ${summary.mustNevers} must-nevers · ${summary.rules} rules · ${summary.visibleTestFiles} visible / ${summary.hiddenTestFiles} hidden test files`)
  for (const e of errors) console.log(`  ✗ ${e.gate.padEnd(30)} ${e.id.padEnd(9)} ${e.where}\n      → ${e.fix}`)
  for (const e of warnings) console.log(`  ! ${e.gate.padEnd(30)} ${e.id.padEnd(9)} ${e.where}\n      → ${e.fix}`)
  console.log(errors.length ? `\n${errors.length} gate failure(s).` : warnings.length ? `\nNo blocking gaps; ${warnings.length} coverage warning(s) CI will fail on.` : '\nAll links hold.')
}
process.exit(errors.length ? 1 : 0)
