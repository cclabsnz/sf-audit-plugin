# NZ compliance crosswalk

How each check gets its HISO 10029 and NZISM citations.

| Framework | Cited at | Source edition | Ids |
|---|---|---|---|
| HISO 10029.3, medium to large health organisations | requirement | HISO 10029.3:2023 | `HISO-HML39` |
| HISO 10029.4, suppliers | requirement | HISO 10029.4:2025 | `HISO-HSUP34` |
| NZISM | section, listing its controls | v3.9 | `NZISM-16.7` |
| NZ Privacy Act | principle, by domain (unchanged) | 2020 | `PRIVACY-IPP5` |

## Pipeline

1. `scripts/compliance/extract_nz_sources.py` reads the two HISO PDFs and the rendered NZISM into
   `data/compliance/nz-sources.json`: every HML and HSUP requirement (function, control area,
   statement; CC BY 4.0) and every NZISM v3.9 section and control number with its compliance level.
   It keeps no NZISM control text.
2. `data/compliance/check-nz-mapping.json` holds sf-audit's decisions per check: the SCF 2026.3
   controls a failing finding evidences, the HSUP requirements cited (`scf` or `direct`), the HSUP
   requirements SCF derives that are excluded (with a reason), and NZISM sections excluded or added
   directly (with a reason).
3. `scripts/compliance/derive_nz_citations.py` downloads SCF 2026.3 at a pinned commit, checks its
   SHA-256, derives each check's HSUP candidates and NZISM controls from SCF's columns (rolling a
   sub-control up to its SCF parent), pairs each HSUP with its HML equivalent, and writes
   `src/compliance/nz/citations.generated.ts`. No extract of SCF is committed (CC BY-ND 4.0).
4. The HISO and NZISM catalogues and `CHECK_CONTROL_MAP` read the generated file.

## RULE-120 Every cited id exists in its pinned source
cites: INT-015, MN-063
- When a check cites an HSUP, HML or NZISM control id
- then that id exists in `data/compliance/nz-sources.json`, and the HISO statement and NZISM section title rendered are the ones recorded there

## RULE-121 Every citation records its basis
cites: INT-015, MN-064
- When a check cites an HSUP requirement or an NZISM section
- then the citation is tagged `scf` only if SCF's crosswalk derives it for that check's SCF controls, and is otherwise tagged `direct` with a non-empty reason

## RULE-122 SCF's derivations are cited or excluded, never silently dropped
cites: INT-015, MN-065
- When SCF's crosswalk derives an HSUP requirement or NZISM section for a check
- then the mapping either cites it or lists it as excluded with a reason, and the derive script fails otherwise

## RULE-123 HML citations follow their HSUP pair
cites: INT-015, MN-063
- When a check cites an HSUP requirement
- then it also cites that requirement's HISO 10029.3 equivalent, where the pairing is one to one, matched on statement wording and supported by SCF where SCF maps both

## RULE-124 Either HISO part can be selected alone
cites: INT-015
- When `--frameworks` is `hiso`, or the `nz` pack is used
- then both HISO parts render; `hiso-provider` selects HISO 10029.3 only and `hiso-supplier` selects HISO 10029.4 only

## RULE-125 Every check has a crosswalk entry
cites: INT-015, MN-065
- When a check is in `CHECK_CONTROL_MAP`
- then it has an entry in `check-nz-mapping.json`, even if that entry cites nothing, so a new check cannot ship without a decision

## RULE-126 Citations stay "relevant to"
cites: INT-015, MN-066
- When a report renders a HISO or NZISM citation
- then it presents it as a requirement the finding bears on, never as compliance or non-compliance of the org as a whole
