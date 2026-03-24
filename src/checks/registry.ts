import type { SecurityCheck } from './SecurityCheck.js';
import { HealthCheckCheck } from './impl/HealthCheckCheck.js';
import { UsersAndAdminsCheck } from './impl/UsersAndAdminsCheck.js';
import { PermissionsCheck } from './impl/PermissionsCheck.js';

// Order matters: a check's dependsOnCache must be satisfied by a preceding check's populatesCache.
// CheckEngine.validateCacheOrdering() enforces this at construction time.
export const CHECKS: SecurityCheck[] = [
  new HealthCheckCheck(),
  new UsersAndAdminsCheck(),
  new PermissionsCheck(),
];
