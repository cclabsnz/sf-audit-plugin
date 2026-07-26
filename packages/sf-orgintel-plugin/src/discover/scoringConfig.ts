/**
 * Anchor-object scoring configuration — the single source of truth for how the six
 * deterministic signals combine into a ranking. Weights sum to 1.0.
 *
 * Each signal is normalised to [0,1] across the analysed objects (see score.ts), then
 * multiplied by its weight and summed. The score is therefore relative to the org: the
 * busiest object trends toward 1.0, and the ranking is fully reproducible for a given org
 * state. Boolean signals (status-shaped, history) contribute 0 or their full weight.
 */
export interface DiscoverWeights {
  /** Record-triggered flows + Apex triggers + approval processes + workflow rules on the object. */
  automation: number;
  /** Presence of a status/stage/state/phase-shaped picklist — the mark of a lifecycle object. */
  statusShaped: number;
  /** Record volume and 90-day creation velocity (velocity weighted over raw total). */
  volumeVelocity: number;
  /** Relationship centrality — inbound lookup/master-detail in-degree from other objects. */
  centrality: number;
  /** Task/Event/EmailMessage attach rate over 90 days (approximate). */
  activity: number;
  /** Field history tracking already enabled (reused from the probe's catalog signal). */
  history: number;
}

export const DEFAULT_WEIGHTS: DiscoverWeights = {
  automation: 0.3,
  statusShaped: 0.15,
  volumeVelocity: 0.2,
  centrality: 0.15,
  activity: 0.1,
  history: 0.1,
};

/** Within volumeVelocity, how much weight the 90-day velocity gets vs the raw total. */
export const VELOCITY_SHARE = 0.7;

/** Picklist field-name pattern that marks a status/lifecycle field. */
export const STATUS_FIELD_PATTERN = /status|stage|state|phase/i;
