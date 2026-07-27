// Platform-behaviour layer: how Salesforce actually answers, kept in one place so a plugin
// cannot rediscover it by shipping the bug first.
export {
  isSalesforceId,
  describeSalesforceError,
  usableApexBody,
  qualifiedName,
} from './salesforceId.js';
export { mapWithConcurrency } from './concurrency.js';
export { FlowRepository } from './flowRepository.js';
export type {
  FlowDefinitionRecord,
  FlowTriggerRecord,
  FlowVersionRef,
  SelectedFlowVersions,
} from './flowRepository.js';
export { ApexRepository } from './apexRepository.js';
export type { ApexClassRecord, ApexTriggerRecord } from './apexRepository.js';
