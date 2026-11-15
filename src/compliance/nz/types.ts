// Where a NZ citation came from. "scf": derived from the Secure Controls Framework's published
// crosswalk. "direct": sf-audit's own judgement, which always carries a reason.
export type CitationBasis = 'scf' | 'direct';

export interface HsupCitation {
  id: string;            // e.g. 'HSUP34'
  basis: CitationBasis;
  reason?: string;       // required when basis is 'direct'
}

export interface NzismCitation {
  section: string;       // e.g. '16.7'
  basis: CitationBasis;
  controls?: string[];   // the v3.9 controls SCF maps, when basis is 'scf'
  reason?: string;       // required when basis is 'direct'
}

export interface CheckNzCitations {
  scf: string[];             // the SCF 2026.3 controls this check evidences
  hsup: HsupCitation[];      // HISO 10029.4:2025 supplier requirements
  hml: string[];             // HISO 10029.3:2023 equivalents of hsup, in the same order
  nzism: NzismCitation[];    // NZISM v3.9 sections
  scfDerivedHsup: string[];  // every HSUP SCF derives; each is cited or excluded in the mapping data
}
