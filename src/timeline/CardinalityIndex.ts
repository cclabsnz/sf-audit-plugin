import { joinKeysOf, type JoinKeys } from './JoinKeys.js';

/** The join-key types the index tracks. Mirrors the optional fields of {@link JoinKeys}. */
export type JoinKeyType = keyof JoinKeys;

export interface CardinalityIndex {
  /**
   * How many distinct actors share this key value in the window.
   *
   * Zero means the value was never seen, or was seen only on rows that carry no client address
   * — either way there is no evidence that it identifies anybody.
   */
  cardinality(type: JoinKeyType, value: string): number;
}

const KEY_TYPES: readonly JoinKeyType[] = ['requestId', 'clientIp', 'sessionKey', 'loginKey', 'userId'];

/**
 * Count distinct actors behind each join-key value across a window.
 *
 * This is the evidence for Invariant 2. Some keys identify a person and some identify a crowd,
 * and the difference is not knowable from the key's name: REQUEST_ID is reliably 1:1, while a
 * community guest USER_ID was measured at 1:1371 in a single hour. Expanding through the second
 * turns one actor's timeline into every anonymous visitor's, attributed to one actor.
 *
 * Actors are counted as distinct client IPs rather than rows on purpose. Rows measure how busy a
 * key was; IPs measure how many people stand behind it. A single actor making ten thousand
 * requests must stay expandable, and ten actors sharing one key must not.
 *
 * The index only measures. Refusing to expand, and recording why, belongs to the engine — a
 * timeline that was quietly bounded is as misleading as one that was over-attributed.
 */
export function buildCardinalityIndex(rows: ReadonlyArray<Record<string, unknown>>): CardinalityIndex {
  // type -> value -> set of distinct actor addresses
  const actors = new Map<JoinKeyType, Map<string, Set<string>>>();
  for (const type of KEY_TYPES) actors.set(type, new Map());

  for (const row of rows) {
    const keys = joinKeysOf(row);
    // Blank values already came back undefined, so nothing blank can accumulate a count.
    const actor = keys.clientIp;

    for (const type of KEY_TYPES) {
      const value = keys[type];
      if (value === undefined) continue;

      const byValue = actors.get(type)!;
      let seen = byValue.get(value);
      if (!seen) byValue.set(value, (seen = new Set()));

      // A row with no usable address still registers the key's existence but contributes no
      // actor — UniqueQuery carries no CLIENT_IP column at all, and counting it as an actor
      // would inflate every key it touches.
      if (actor !== undefined) seen.add(actor);
    }
  }

  return {
    cardinality(type, value) {
      return actors.get(type)?.get(value)?.size ?? 0;
    },
  };
}
