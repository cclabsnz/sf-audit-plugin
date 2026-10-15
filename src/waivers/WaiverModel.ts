import { z } from 'zod';

/** The longest a waiver may run from the day it is loaded. Longer acceptances must be re-approved. */
export const MAX_WAIVER_DAYS = 365;

// A calendar date or a full ISO 8601 timestamp. Date.parse alone accepts forms like "March 2030"
// whose meaning depends on the runtime, which is no basis for an expiry.
const ISO_DATE = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2}))?$/;

export const waiverEntrySchema = z
  .object({
    checkId: z.string().trim().min(1, 'checkId is required'),
    findingId: z.string().trim().min(1).optional(),
    entity: z.string().trim().min(1, 'entity is required'),
    reason: z.string().trim().min(5, 'reason must be at least 5 characters'),
    approvedBy: z.string().trim().min(3, 'approvedBy is required'),
    expiresAt: z
      .string()
      .regex(ISO_DATE, 'expiresAt must be an ISO 8601 date (2027-03-31) or timestamp')
      .refine((val) => !Number.isNaN(Date.parse(val)), { message: 'expiresAt is not a real date' }),
    acknowledgeCritical: z.boolean().optional(),
  })
  .strict();

export const waiversConfigSchema = z
  .object({
    $schema: z.string().optional(),
    _comment: z.string().optional(),
    waivers: z.array(waiverEntrySchema),
  })
  .strict();

export type WaiverEntry = z.infer<typeof waiverEntrySchema>;
export type WaiversConfig = z.infer<typeof waiversConfigSchema>;

export interface EvaluatedWaiver extends WaiverEntry {
  isExpired: boolean;
  daysRemaining: number;
}
