/**
 * Run `fn` over `items` with at most `limit` promises in flight.
 *
 * Exists because some Salesforce reads cannot be batched at all — `Flow.Metadata` is
 * strictly one row per query — so bounded concurrency is the only way to make a bulk read
 * finish in reasonable time. Completion order is not preserved; sort results if output
 * determinism matters.
 */
export async function mapWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<void>,
): Promise<void> {
  if (limit < 1) throw new Error(`Concurrency limit must be >= 1, got ${limit}`);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i], i);
    }
  });
  await Promise.all(workers);
}
