import { z } from 'zod';

export const QueryDefinitionSchema = z.object({
  api: z.enum(['soql', 'tooling', 'rest']),
  soql: z.string().optional(),
  path: z.string().optional(),
  description: z.string(),
  fallbackOnError: z.boolean().default(false),
  minApiVersion: z.string().optional(),
});

export type QueryDefinition = z.infer<typeof QueryDefinitionSchema>;

export const QueryFileSchema = z.record(z.string(), QueryDefinitionSchema);
export type QueryFile = z.infer<typeof QueryFileSchema>;
