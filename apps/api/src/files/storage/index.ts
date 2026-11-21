/**
 * Internal private quarantine storage: B1 PUT/verification and B2 read-only probes.
 *
 * No NestJS provider, controller, HTTP route, database access, scanner or signed
 * URL. The B2 coordinator owns durable registration of attempts and probe claims.
 * Production mode is refused outright.
 *
 * A successful receipt is a *storage* fact (these bytes are in quarantine under this
 * key), not a file state, not permission, not `READY` and not a promise of safety.
 *
 * Deliberately not exported (MUST3): the config validator, the validated config type,
 * the response-cap plumbing and the internal error factory/brand. A caller only needs
 * the factory, the attempt helper, the frozen error vocabulary and the *caller-facing*
 * config type; everything else stays module-private so no credential-bearing or
 * validation-bypassing surface is reachable from outside.
 */
export {
  createPrivateQuarantineStorage,
} from './adapter.js';
export type {
  InspectRegisteredQuarantineInput, PrivateQuarantineStorage, PutQuarantinedInput, QuarantineReceipt,
  RegisteredQuarantineAttempt, RegisteredQuarantineObservation, RegisteredQuarantineStorage, VerifyQuarantinedInput,
} from './adapter.js';

export { prepareQuarantineAttempt } from './attempt.js';
export type { QuarantineAttempt, StorageTarget } from './attempt.js';

export {
  PRIVATE_STORAGE_ERROR_CODES, PRIVATE_STORAGE_FAILURE_REASONS, PrivateStorageError,
} from './errors.js';
export type { PrivateStorageErrorCode, PrivateStorageFailureReason } from './errors.js';

export type { PrivateQuarantineStorageConfig, StorageMode } from './config.js';
