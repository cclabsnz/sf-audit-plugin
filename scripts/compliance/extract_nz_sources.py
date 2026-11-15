#!/usr/bin/env python3
# Extracts the NZ requirement catalogues the compliance crosswalk cites, from their official sources,
# into data/compliance/nz-sources.json. Run it again when Health NZ or the GCSB publish a new edition.
#
#   pip install pdfplumber
#   python3 scripts/compliance/extract_nz_sources.py <hiso-10029.3.pdf> <hiso-10029.4.pdf> <nzism.txt>
#
# The two PDFs are the published HISO parts (URLs and hashes are recorded in the output):
#   HISO 10029.3:2023 Guidance for Medium to Large Organisations (HML requirements)
#   HISO 10029.4:2025 Guidance for Suppliers (HSUP requirements)
# Both are licensed CC BY 4.0, so requirement statements are kept with attribution.
#
# nzism.txt is the rendered text of https://nzism.gcsb.govt.nz/ism-document. The site renders the
# manual with JavaScript, so save document.body.innerText from a browser rather than curl it. Only
# control numbers, compliance levels and section titles are kept, not control text.
import hashlib
import json
import re
import sys

import pdfplumber

HISO3_URL = ('https://static.info.content.health.nz/docs/HISO/'
             'HISO-10029-3-2023-Health-Information-Security-Framework-Guidance-for-Medium-to-Large-Organisations.pdf')
HISO4_URL = ('https://static.info.content.health.nz/docs/HISO/'
             'HISO-10029-4-Health-Information-Security-Framework-Guidance-for-Suppliers.pdf')
NZISM_URL = 'https://nzism.gcsb.govt.nz/ism-document'
FUNCTIONS = ('Plan', 'Identify', 'Protect', 'Detect', 'Respond', 'Recover')


def sha256(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def clean(s):
    return re.sub(r'\s+', ' ', s).strip()


def hiso_requirements(path, prefix, expected):
    """Reads the Functional Process | Control Area | Requirement | Guidance tables."""
    out = {}
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            for table in page.extract_tables():
                for row in table:
                    cells = [clean(c or '') for c in row]
                    for i, cell in enumerate(cells):
                        m = re.match(rf'^({prefix}\d{{2}}):\s*(.+)$', cell)
                        if not m or m.group(1) in out:
                            continue
                        function = next((c for c in cells[:i] if c in FUNCTIONS), '')
                        area = next((c for c in reversed(cells[:i]) if c and c not in FUNCTIONS), '')
                        out[m.group(1)] = {'function': function, 'area': area, 'statement': m.group(2)}
    missing = [f'{prefix}{n:02d}' for n in range(1, expected + 1) if f'{prefix}{n:02d}' not in out]
    if missing or any(not v['area'] or not v['function'] for v in out.values()):
        sys.exit(f'{path}: incomplete {prefix} extraction, missing {missing}')
    return dict(sorted(out.items()))


def nzism(path):
    lines = open(path, encoding='utf-8').read().split('\n')
    chapters, sections, controls = {}, {}, {}
    for i, raw in enumerate(lines):
        s = raw.strip()
        m = re.match(r'^(\d{1,2})\.(\d{1,2})\.\s+(\S.*)$', s)
        if m and not re.match(r'^\d', m.group(3)):
            sections.setdefault(f'{m.group(1)}.{m.group(2)}', m.group(3))
        m = re.match(r'^(\d{1,2})\.\s+([A-Z].*)$', s)
        if m and len(s) < 90:
            chapters.setdefault(m.group(1), m.group(2))
        m = re.match(r'^(\d{1,2}\.\d{1,2}\.\d{1,3}\.C\.\d{2})\.$', s)
        if m and i + 1 < len(lines):
            c = re.search(r'Compliance:\s*([A-Za-z ]+?)\s*\[CID:\d+\]', lines[i + 1])
            if c:
                controls.setdefault(m.group(1), c.group(1).strip())
    version = re.search(r'Version (\d+\.\d+)', '\n'.join(lines))
    if not version or len(controls) < 1000:
        sys.exit(f'{path}: does not look like the rendered NZISM ({len(controls)} controls)')
    key = lambda k: [int(p) if p.isdigit() else p for p in re.split(r'\.', k)]
    return {
        'version': version.group(1),
        'chapters': chapters,
        'sections': dict(sorted(sections.items(), key=lambda kv: key(kv[0]))),
        'controls': dict(sorted(controls.items(), key=lambda kv: key(kv[0]))),
    }


def main():
    if len(sys.argv) != 4:
        sys.exit('usage: extract_nz_sources.py <hiso-10029.3.pdf> <hiso-10029.4.pdf> <nzism.txt>')
    p3, p4, nz = sys.argv[1:]
    out = {
        'hiso3': {'title': 'HISO 10029.3:2023 Guidance for Medium to Large Organisations', 'url': HISO3_URL,
                  'sha256': sha256(p3), 'licence': 'CC BY 4.0, Health New Zealand | Te Whatu Ora',
                  'requirements': hiso_requirements(p3, 'HML', 75)},
        'hiso4': {'title': 'HISO 10029.4:2025 Guidance for Suppliers', 'url': HISO4_URL,
                  'sha256': sha256(p4), 'licence': 'CC BY 4.0, Health New Zealand | Te Whatu Ora',
                  'requirements': hiso_requirements(p4, 'HSUP', 68)},
        'nzism': {'url': NZISM_URL, **nzism(nz)},
    }
    with open('data/compliance/nz-sources.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write('\n')
    print(f"HML {len(out['hiso3']['requirements'])}, HSUP {len(out['hiso4']['requirements'])}, "
          f"NZISM v{out['nzism']['version']}: {len(out['nzism']['sections'])} sections, "
          f"{len(out['nzism']['controls'])} controls")


if __name__ == '__main__':
    main()
