#!/usr/bin/env python3
# Generates src/compliance/nz/citations.generated.ts, the HISO 10029 and NZISM citations for every
# check, from three inputs:
#
#   data/compliance/check-nz-mapping.json  sf-audit's decisions: each check's SCF controls, and which
#                                          HSUP requirements and NZISM sections it cites, each tagged
#                                          "scf" (from SCF's published crosswalk) or "direct" (ours,
#                                          with a reason)
#   data/compliance/nz-sources.json        the requirement catalogues, from extract_nz_sources.py
#   the Secure Controls Framework 2026.3   downloaded at a pinned commit and checked by hash
#
#   pip install openpyxl
#   python3 scripts/compliance/derive_nz_citations.py [--scf path/to/scf.xlsx]
#
# The SCF is licensed CC BY-ND 4.0, so no extract of it is committed. Only the per-check citations
# this script derives are, with attribution. The script fails, and writes nothing, when an HSUP that
# SCF derives for a check is neither cited nor excluded with a reason, when a cited id does not
# exist in its source, or when the HSUP to HML pairing is not one to one.
import argparse
import difflib
import hashlib
import io
import json
import re
import sys
import urllib.request
from collections import defaultdict

import openpyxl

SCF_COMMIT = 'd08211314fc7ccfca8e6c84d2b27a2030339ef9c'
SCF_FILE = 'secure-controls-framework-scf-2026-3.xlsx'
SCF_URL = f'https://raw.githubusercontent.com/securecontrolsframework/securecontrolsframework/{SCF_COMMIT}/{SCF_FILE}'
SCF_SHA256 = '5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697'
SCF_SHEET = 'SCF 2026.3'
COL_HSUP = 'APAC New Zealand HISF Suppliers 2023'
COL_HML = 'APAC New Zealand HISF MLHSP 2023'
COL_NZISM = 'APAC New Zealand NZISM 3.9'
OUT = 'src/compliance/nz/citations.generated.ts'


def load_scf(path):
    data = open(path, 'rb').read() if path else urllib.request.urlopen(SCF_URL).read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SCF_SHA256:
        sys.exit(f'SCF file hash {digest} does not match the pinned {SCF_SHA256}')
    ws = openpyxl.load_workbook(io.BytesIO(data), read_only=True)[SCF_SHEET]
    rows = ws.iter_rows(values_only=True)
    hdr = [str(h).replace('\n', ' ') if h else '' for h in next(rows)]
    col = {k: hdr.index(k) for k in ('SCF #', 'SCF Control', COL_HSUP, COL_HML, COL_NZISM)}
    split = lambda v: [x.strip() for x in str(v).split('\n') if x.strip()] if v else []
    out = {}
    for r in rows:
        sid = r[col['SCF #']]
        if sid:
            out[sid] = {'name': r[col['SCF Control']], 'hsup': split(r[col[COL_HSUP]]),
                        'hml': [x for x in split(r[col[COL_HML]]) if x.startswith('HML')],
                        'nzism': split(r[col[COL_NZISM]])}
    return out


def lineage(sid):
    """An SCF id and its parents in SCF's own numbering: IAC-03.3 -> IAC-03.3, IAC-03."""
    out = [sid]
    while '.' in sid:
        sid = sid.rsplit('.', 1)[0]
        out.append(sid)
    return out


def section_key(s):
    return [int(p) for p in s.split('.')]


def pair_hsup_hml(src, scf):
    """Each HSUP's HML equivalent, by statement wording; SCF sharing a control is recorded as support."""
    norm = lambda s: re.sub(r'[^a-z ]', '', s.lower().replace('’', "'")).split()
    hml = src['hiso3']['requirements']
    by_hsup, by_hml = defaultdict(set), defaultdict(set)
    for sid, c in scf.items():
        for h in c['hsup']:
            by_hsup[h].add(sid)
        for h in c['hml']:
            by_hml[h].add(sid)
    pairs = {}
    for h, req in src['hiso4']['requirements'].items():
        score = lambda k: difflib.SequenceMatcher(None, norm(req['statement']), norm(hml[k]['statement'])).ratio()
        best = max(hml, key=score)
        pairs[h] = {'hml': best, 'similarity': round(score(best), 2), 'scfSupports': bool(by_hsup[h] & by_hml[best])}
    used = [p['hml'] for p in pairs.values()]
    weak = {h: p for h, p in pairs.items() if p['similarity'] < 0.6 and not p['scfSupports']}
    if len(set(used)) != len(used) or weak:
        sys.exit(f'HSUP to HML pairing is not one to one or has weak pairs: {weak}')
    return pairs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scf', help='a local copy of the pinned SCF workbook (otherwise downloaded)')
    args = ap.parse_args()

    src = json.load(open('data/compliance/nz-sources.json', encoding='utf-8'))
    mapping = json.load(open('data/compliance/check-nz-mapping.json', encoding='utf-8'))
    scf = load_scf(args.scf)
    hsup_reqs, nz = src['hiso4']['requirements'], src['nzism']
    pairs = pair_hsup_hml(src, scf)
    errors, dropped_nzism = [], set()

    def nzism_id(x):
        if x in nz['controls']:
            return x
        fixed = x.replace('C-', 'C.')  # SCF typos such as 11.8.11.C-02
        if fixed in nz['controls']:
            return fixed
        dropped_nzism.add(x)
        return None

    citations, sections_used = {}, defaultdict(set)
    for check, m in sorted(mapping.items()):
        for sid in m['scf']:
            if sid not in scf:
                errors.append(f'{check}: SCF {sid} does not exist in {SCF_SHEET}')
        parents = [p for s in m['scf'] for p in lineage(s) if p in scf]
        derived_hsup = sorted({h for p in parents for h in scf[p]['hsup']})
        cited = {c['id']: c for c in m['hsup']}
        excluded = {e['id'] for e in m.get('hsupExcluded', [])}
        for h in derived_hsup:
            if (h in cited) == (h in excluded):
                errors.append(f'{check}: SCF derives {h}; cite it or exclude it with a reason, not both or neither')
        for c in m['hsup']:
            if c['id'] not in hsup_reqs:
                errors.append(f"{check}: {c['id']} is not an HSUP requirement")
            if c['basis'] == 'scf' and c['id'] not in derived_hsup:
                errors.append(f"{check}: {c['id']} is tagged scf but SCF does not derive it")
            if c['basis'] == 'direct' and not c.get('reason'):
                errors.append(f"{check}: direct citation {c['id']} needs a reason")
        controls = sorted({x for p in parents for raw in scf[p]['nzism'] if (x := nzism_id(raw))}, key=lambda k: k)
        derived_sections = defaultdict(list)
        for x in controls:
            derived_sections['.'.join(x.split('.')[:2])].append(x)
        nz_excluded = {e['section'] for e in m.get('nzismExcluded', [])}
        nz_cites = []
        for sec in sorted(derived_sections, key=section_key):
            if sec not in nz_excluded:
                nz_cites.append({'section': sec, 'basis': 'scf', 'controls': derived_sections[sec]})
        for e in m.get('nzismExcluded', []):
            if e['section'] not in derived_sections:
                errors.append(f"{check}: excludes NZISM {e['section']}, which SCF does not derive")
        for d in m.get('nzismDirect', []):
            if d['section'] not in nz['sections']:
                errors.append(f"{check}: NZISM {d['section']} is not a v{nz['version']} section")
            elif d['section'] in derived_sections:
                errors.append(f"{check}: NZISM {d['section']} is already derived from SCF; do not add it as direct")
            else:
                nz_cites.append({'section': d['section'], 'basis': 'direct', 'reason': d['reason']})
        nz_cites.sort(key=lambda c: section_key(c['section']))
        for c in nz_cites:
            sections_used[c['section']].update(c.get('controls', []))
        hsup = sorted(m['hsup'], key=lambda c: int(c['id'][4:]))
        citations[check] = {
            'scf': m['scf'],
            'hsup': [{k: c[k] for k in ('id', 'basis', 'reason') if k in c} for c in hsup],
            'hml': [pairs[c['id']]['hml'] for c in hsup],
            'nzism': nz_cites,
            'scfDerivedHsup': derived_hsup,
        }
    if errors:
        sys.exit('\n'.join(errors))

    def reqs(part):
        return {k: {'area': v['area'], 'statement': v['statement']} for k, v in src[part]['requirements'].items()}

    levels = {sec: [{'id': x, 'level': nz['controls'][x]} for x in sorted(ids, key=lambda k: [int(p) if p.isdigit() else p for p in k.split('.')])]
              for sec, ids in sections_used.items()}
    body = {
        'SCF_SOURCE': {'name': 'Secure Controls Framework', 'version': '2026.3', 'url': 'https://securecontrolsframework.com', 'commit': SCF_COMMIT, 'sha256': SCF_SHA256,
                       'licence': 'CC BY-ND 4.0, SCF Council'},
        'HISO_SOURCES': {p: {k: src[p][k] for k in ('title', 'url', 'sha256', 'licence')} for p in ('hiso3', 'hiso4')},
        'NZISM_SOURCE': {'version': nz['version'], 'url': nz['url']},
        'HML_REQUIREMENTS': reqs('hiso3'),
        'HSUP_REQUIREMENTS': reqs('hiso4'),
        'HSUP_TO_HML': {h: p['hml'] for h, p in pairs.items()},
        'NZISM_SECTIONS': {sec: {'title': nz['sections'][sec], 'controls': levels[sec]}
                           for sec in sorted(sections_used, key=section_key)},
        'NZISM_DROPPED_SCF_IDS': sorted(dropped_nzism),
        'CHECK_NZ_CITATIONS': citations,
    }
    types = {
        'CHECK_NZ_CITATIONS': 'Record<string, CheckNzCitations>',
        'NZISM_SECTIONS': 'Record<string, { title: string; controls: { id: string; level: string }[] }>',
        'HML_REQUIREMENTS': 'Record<string, { area: string; statement: string }>',
        'HSUP_REQUIREMENTS': 'Record<string, { area: string; statement: string }>',
        'HSUP_TO_HML': 'Record<string, string>',
    }
    lines = ['// GENERATED by scripts/compliance/derive_nz_citations.py. Do not edit by hand: change',
             '// data/compliance/check-nz-mapping.json and run the script again.',
             "import type { CheckNzCitations } from './types.js';", '']
    for name, value in body.items():
        t = f': {types[name]}' if name in types else ''
        lines.append(f'export const {name}{t} = {json.dumps(value, indent=2, ensure_ascii=False)} as const;'
                     if not t else f'export const {name}{t} = {json.dumps(value, indent=2, ensure_ascii=False)};')
        lines.append('')
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    write_docs(body, mapping, src)
    print(f'{len(citations)} checks: {sum(1 for c in citations.values() if c["hsup"])} cite HSUP, '
          f'{sum(1 for c in citations.values() if c["nzism"])} cite NZISM; '
          f'{len(sections_used)} NZISM sections; dropped {len(dropped_nzism)} SCF NZISM ids not in the manual')


CROSSWALK_DOC = 'docs/compliance/nz-crosswalk.md'
WORKSHEET = 'docs/compliance/verification-worksheet.md'


def cell(s):
    return str(s).replace('|', '\\|').replace('\n', ' ')


def write_docs(body, mapping, src):
    """The reviewable per-check table, and the HISO / NZISM sections of the verification worksheet."""
    cites = body['CHECK_NZ_CITATIONS']
    out = ['# NZ crosswalk decisions', '',
           'GENERATED by `scripts/compliance/derive_nz_citations.py` from `data/compliance/check-nz-mapping.json`.',
           'Each check\'s SCF 2026.3 controls, the HISO 10029.4 (HSUP) requirements it cites with their HISO 10029.3',
           '(HML) pair, and the NZISM v3.9 sections it cites. `scf` = derived from the Secure Controls Framework',
           'crosswalk; `direct` = sf-audit\'s judgement, with the reason. SCF-derived requirements that were excluded',
           'are listed with the reason. The rules are in `spec/nz-compliance-crosswalk.md`.', '']
    for check, c in cites.items():
        m = mapping[check]
        out += [f'## `{check}`', '', f"SCF: {', '.join(c['scf']) or 'none'}. {cell(m['scfReason'])}", '']
        out += ['| Cites | HML pair | Basis | Reason |', '|---|---|---|---|']
        for h, hml in zip(c['hsup'], c['hml']):
            out.append(f"| {h['id']} {cell(body['HSUP_REQUIREMENTS'][h['id']]['area'])} | {hml} | {h['basis']} | {cell(h.get('reason', ''))} |")
        for n in c['nzism']:
            title = body['NZISM_SECTIONS'][n['section']]['title']
            detail = ', '.join(n.get('controls', [])) if n['basis'] == 'scf' else n.get('reason', '')
            out.append(f"| NZISM {n['section']} {cell(title)} | | {n['basis']} | {cell(detail)} |")
        if not c['hsup'] and not c['nzism']:
            out.append('| none | | | |')
        excl = [f"{e['id']} ({cell(e['reason'])})" for e in m.get('hsupExcluded', [])]
        excl += [f"NZISM {e['section']} ({cell(e['reason'])})" for e in m.get('nzismExcluded', [])]
        if excl:
            out += ['', 'Excluded from SCF: ' + '; '.join(excl)]
        if m.get('note'):
            out += ['', f"Note: {cell(m['note'])}"]
        out.append('')
    with open(CROSSWALK_DOC, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out))

    def table(rows):
        return ['| ✓ | id | title | sourceRef |', '|---|---|---|---|'] + rows

    hml_ids = sorted({x for c in cites.values() for x in c['hml']}, key=lambda k: int(k[3:]))
    hsup_ids = sorted({h['id'] for c in cites.values() for h in c['hsup']}, key=lambda k: int(k[4:]))
    secs = list(body['NZISM_SECTIONS'])
    nzv = f"NZISM v{body['NZISM_SOURCE']['version']}"
    blocks = {
        'HISO10029_3': (f'HISO 10029.3:2023 ({len(hml_ids)}/{len(hml_ids)} verified)',
                        [f"| [x] | HISO-{i} | {i} {cell(body['HML_REQUIREMENTS'][i]['area'])} | HISO 10029.3:2023, {i} |" for i in hml_ids]),
        'HISO10029_4': (f'HISO 10029.4:2025 ({len(hsup_ids)}/{len(hsup_ids)} verified)',
                        [f"| [x] | HISO-{i} | {i} {cell(body['HSUP_REQUIREMENTS'][i]['area'])} | HISO 10029.4:2025, {i} |" for i in hsup_ids]),
        'NZISM': (f'{nzv} ({len(secs)}/{len(secs)} verified)',
                  [f"| [x] | NZISM-{s} | {s} {cell(body['NZISM_SECTIONS'][s]['title'])} | {nzv}, {s} |" for s in secs]),
    }
    intro = ('Requirement ids and statements checked against the published PDFs by `test/unit/compliance/nzCrosswalk.test.ts`; '
             'which checks cite each one is in [nz-crosswalk.md](nz-crosswalk.md).')
    text = open(WORKSHEET, encoding='utf-8').read()
    start = re.search(r'^## HISO10029', text, re.M).start()
    end = re.search(r'^## HIPAA', text, re.M).start()
    new = []
    for fw, (heading, rows) in blocks.items():
        new += [f'## {fw} \u2014 {heading}', '', intro, ''] + table(rows) + ['']
    text = text[:start] + '\n'.join(new) + '\n' + text[end:]
    counts = [int(n) for n in re.findall(r'^## .*\((\d+)/\d+ verified\)', text, re.M)]
    total = sum(counts)
    text = re.sub(r'^Total controls: \d+ · Verified: \d+', f'Total controls: {total} · Verified: {total}', text, flags=re.M)
    with open(WORKSHEET, 'w', encoding='utf-8') as f:
        f.write(text)


if __name__ == '__main__':
    main()
