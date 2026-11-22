// Explicit trusted synthetic wiring only; never re-export from the lifecycle/F command module.
export type {
  AggregateOnly, DeleteBroker, DeleteContext, FencedDrainContext, FilePrivacyGrant,
  HoldContext, HoldGrant, RetentionContext, RetentionPolicy,
} from './contract.js';
export { FilePrivacyError } from './contract.js';
export { makeFilePrivacyGrant, makeHoldGrant } from './grants.js';
export { changeFileHold, planRetention } from './retention.js';
export { drainFencedFileDecisions, reconcileFileDeletion } from './deletion.js';
export { createRestoredDeleteBroker, createSyntheticDeleteBroker, revokeDeleteBroker } from './broker.js';
