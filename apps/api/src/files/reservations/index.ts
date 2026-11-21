/**
 * P03-04 slice A: the internal file-upload reservation surface.
 *
 * Everything here is a plain function over the caller's `PoolClient`: no NestJS
 * provider, no controller, no DI token, no authentication decorator, no HTTP
 * route, no object-storage SDK, no scanner and no signed URL. The caller opens the
 * transaction (`beginFileReservationTransaction` or the legal
 * `beginLegalTransaction`), supplies trusted inputs and commits, so the intent, its
 * audit row and its outbox row are one atomic unit.
 *
 * The only owner implemented in this slice is the F-owned `request_sessions`
 * anchor proven by a raw pre-submit token. The staff variant is refused with
 * `UNSUPPORTED_OWNER` before any database access: a staff id from a request body is
 * never a credential, and the staff command with real authorization is P03-05.
 *
 * Nothing in this module uploads, downloads, scans, deletes, streams or marks a
 * file READY. Slice B owns actual bytes and object keys; slice C owns scanner and
 * access; slice D owns delete/restore.
 */
import { LEGAL_BEGIN_SQL, assertCallerTransaction, beginLegalTransaction } from '../../settings/legal/legal-tx.js';
import type { FileReservationSqlClient } from './contract.js';
import { mapLegalPortError } from './errors.js';

export {
  FILE_INTENT_STATES, FILE_MIME_TYPES, FILE_RESERVATION_PURPOSE, FileReservationError,
} from './contract.js';
export type {
  CancelFileUploadIntentInput, FileIntentState, FileMimeType, FileOwnerSessionProof, FileReservationErrorCode,
  FileReservationPolicy, FileReservationPurpose, FileReservationSqlClient, FileUploadCancellation, FileUploadIntentView,
  FileUploadReservation, ReadFileUploadIntentInput, ReserveFileUploadInput,
} from './contract.js';

export { cancelFileUploadIntent, readFileUploadIntent, reserveFileUpload } from './intents.js';

export {
  cancelFileUploadIntentInput, fileReservationPolicy, fileSessionProof, isFileMimeType, mimeValue,
  readFileUploadIntentInput, reserveFileUploadInput, uuidValue,
} from './input.js';
export type {
  ParsedCancelFileUploadIntent, ParsedFilePolicy, ParsedFileSessionProof, ParsedReadFileUploadIntent,
  ParsedReserveFileUpload,
} from './input.js';

export {
  canonicalFileIntentPayload, canonicalFilePolicy, fileIntentBodySha256, filePolicySha256,
} from './hash.js';
export type { CanonicalFileIntentPayload, CanonicalFilePolicySnapshot } from './hash.js';

// The audit/outbox writer and its payload validator are deliberately *not* part of
// this public surface: the only producers are the ports above, which import
// `./audit.js` directly. Exporting the writer would let a caller persist an
// audit/outbox pair without a reservation, so the internal module stays internal.

export { mapFileReservationDbError, mapLegalPortError } from './errors.js';

/**
 * Explicit transaction start for callers of these ports: exactly the legal
 * `BEGIN ISOLATION LEVEL READ COMMITTED`. Reusing one helper keeps the two internal
 * surfaces on the same isolation contract; this module never opens a transaction by
 * itself.
 */
export const FILE_RESERVATION_BEGIN_SQL = LEGAL_BEGIN_SQL;

/**
 * Opens the caller's transaction with the required isolation. Identical to
 * `beginLegalTransaction`; exported here so a reservation caller does not need to
 * import the legal surface just for `BEGIN`.
 */
export async function beginFileReservationTransaction(client: FileReservationSqlClient): Promise<void> {
  await beginLegalTransaction(client);
}

/**
 * Proves the caller's transaction is an explicit multi-statement READ COMMITTED
 * transaction. A transaction that already pinned a stronger snapshot, or an
 * autocommit client, is refused with the typed `CONFLICT` — the guard never rolls
 * back, restarts or upgrades the caller's transaction.
 *
 * The legal guard's own refusal is translated here, so a caller that uses this
 * exported helper only ever sees `FileReservationError`, never a `LegalPortError`.
 */
export async function assertFileReservationTransaction(client: FileReservationSqlClient): Promise<void> {
  try {
    await assertCallerTransaction(client);
  } catch (error) {
    mapLegalPortError(error);
  }
}
