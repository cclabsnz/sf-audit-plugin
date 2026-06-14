export type Framework =
  | 'OWASP' | 'SOC2' | 'ISO27001' | 'SBS'
  | 'HISO10029' | 'PRIVACY_ACT' | 'NZISM' | 'HIPAA' | 'GDPR';

export interface ControlDef {
  id: string;            // exact identifier, e.g. 'NZISM-16.1.35'
  framework: Framework;
  version: string;       // exact standard version mapped, e.g. 'ISO/IEC 27001:2022'
  title: string;
  requirement: string;   // faithful requirement text / close paraphrase
  sourceRef: string;     // citation, e.g. 'ISO/IEC 27001:2022, A.9.2'
  url?: string;
  verified: boolean;     // provenance gate — drafts are false until human-checked
}

export type FrameworkPack = 'universal' | 'nz' | 'all';
