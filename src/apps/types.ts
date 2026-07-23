export type Verb = 'read' | 'write' | 'delete';

export type AppCategory =
  | 'Salesforce-standard'
  | 'Org-custom'
  | 'Security-vendor'
  | 'Installed-package'
  | 'Third-party'
  | 'Unidentified';

export type ResolveConfidence = 'resolved' | 'inferred' | 'unidentified';

/** Observed usage for one connected app, derived from RestApi rows. */
export interface AppUsage {
  appId: string;
  objects: { object: string; verbs: Verb[] }[];
  requests: number;
  rowsProcessed: number;
  userIds: string[];
  soapOnly: boolean;
}

export interface ResolvedApp {
  appId: string;
  name: string;
  category: AppCategory;
  vendor?: string;
  purpose?: string;
  confidence: ResolveConfidence;
}

export interface GrantedAccess {
  appId: string;
  scope: string | null;
  objects: { object: string; verbs: Verb[] }[];
  runAsUsers: string[];
  multiUserInteractive: boolean;
}

export interface AppFinding {
  app: ResolvedApp;
  window: { since: number; attributionRatePct: number };
  used: AppUsage;
  granted: GrantedAccess;
  overGrant: {
    unusedObjects: string[];
    unusedVerbs: { object: string; verbs: Verb[] }[];
    scopeDowngrade: string | null;
    dormant: boolean;
  };
  recommendation: {
    permissionSet: {
      objectPermissions: { object: string; read: boolean; create: boolean; edit: boolean; delete: boolean }[];
    };
  };
  notes: string[];
}
