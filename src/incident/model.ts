/**
 * Types shared by `sf audit incident collect` and `report`. The bundle on disk is the contract
 * between the two commands: collect writes it, report only reads it.
 */

export const LOG_TYPES = [
  'AuraRequest', 'Sites', 'URI', 'ApexExecution', 'VisualforceRequest', 'ContentTransfer',
  'GraphQlQueryExecution', 'UniqueQuery', 'LightningError', 'ApexUnexpectedException',
] as const;
export type LogType = (typeof LOG_TYPES)[number];

/** Without these two, response sizes cannot be assessed, so a wave's result is `not-assessed`. */
export const REQUIRED_LOG_TYPES: readonly LogType[] = ['AuraRequest', 'Sites'];

export const DEFAULTS = {
  spikeRatio: 5,
  emptyBandBytes: 64,
  auditWindowDays: 4,
  /** jsforce autoFetchQuery stops here; a window returning this many rows may be truncated. */
  auditPageCap: 10000,
  outlierFloor: 100,
  outlierMultiple: 3,
} as const;

export function id15(id: string | undefined | null): string | undefined {
  const t = (id ?? '').trim();
  return t ? t.slice(0, 15) : undefined;
}

export interface AnomalyEvent {
  eventIdentifier: string;
  eventDate: string;
  score: number;
  userId15: string;
  username: string;
  sourceIp?: string;
  userAgent?: string;
  summary?: string;
  totalControllerEvents?: number;
  requestedEntities?: string;
  soqlCommands?: string;
}

export interface GuestUser {
  id15: string;
  username: string;
  name: string;
  profileName: string;
  permissionSetLabels: string[];
  siteNames: string[];
  /** false when the user came only from an anomaly event and is no longer an active guest. */
  active: boolean;
}

export interface Wave {
  id: string;            // 'W1', 'W2', … in start order
  guestId15: string;
  site: string;
  days: string[];        // YYYY-MM-DD, UTC, ascending
  eventIds: string[];
}

export type LogStatus = 'collected' | 'missing' | 'no-permission' | 'failed';

export interface LogCoverage {
  type: LogType;
  day: string;
  status: LogStatus;
  totalRows: number;
  guestRows: number;
  guestRowsByUser: Record<string, number>;
  malformed: number;
  file?: string;         // bundle-relative path
  detail?: string;
}

export interface AuditRow {
  createdDate: string;
  createdBy: string;
  section: string | null;
  action: string;
  display: string;
}

export interface AuditCoverage {
  from: string;
  to: string;
  truncatedWindows: Array<{ from: string; to: string }>;
  inaccessible: boolean;
}

export interface LoginRow {
  loginTime: string;
  userId15: string;
  sourceIp: string;
  status: string;
  loginUrl?: string;
  browser?: string;
}

export interface LoginDayCount { day: string; status: string; count: number }

export interface LinkedUser {
  id15: string;
  name: string;
  email: string;
  createdDate: string;
  createdById15: string;
  profileName: string;
  isActive: boolean;
}

export interface RunningUserLimits { queryAllFiles: boolean; viewAllData: boolean }

export interface BundleManifest {
  version: 1;
  complete: boolean;               // false until follow-up and the final seal succeed
  orgId: string;
  orgName: string;
  collectedAt: string;
  sinceDays: number;
  detectorAvailable: boolean;
  waves: Wave[];
  guests: GuestUser[];
  logs: LogCoverage[];
  audit: AuditCoverage;
  limits: RunningUserLimits;
  ipRangeFiles: string[];          // bundle-relative paths
  files: Record<string, string>;   // bundle-relative path -> sha256 hex
}

export interface FollowUp {
  logins: LoginRow[];
  users: LinkedUser[];
  /** True when a LoginHistory batch returned the queryAll cap, so some logins may be missing. */
  truncated?: boolean;
}

export type ActionClass = 'data-access' | 'auth' | 'plumbing' | 'unknown';
export type Classification = 'internal-testing' | 'automated-scan' | 'organic' | 'indeterminate';
export type WaveOutcome = 'access-gained' | 'content-returned' | 'no-evidence' | 'not-assessed';
