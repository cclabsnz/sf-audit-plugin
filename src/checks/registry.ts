import type { SecurityCheck } from './SecurityCheck.js';

// Sub-project 2 adds all check implementations to this array.
// Order matters: a check's dependsOnCache must be satisfied by a preceding check's populatesCache.
// CheckEngine.validateCacheOrdering() enforces this at construction time.
export const CHECKS: SecurityCheck[] = [];
