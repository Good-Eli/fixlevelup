/**
 * Safe audit + outbox for every successful reservation write, written in the
 * caller's transaction.
 *
 * The same transaction that inserts or cancels a reservation also inserts exactly
 * one `audit_logs` row and one `outbox_events` row sharing one event id. If either
 * insert fails the caller's transaction aborts and the reservation rolls back with
 * it: a successful reservation is never observable without its audit trail, and a
 * failed audit/outbox leaves no partial reservation.
 *
 * ## The payload is a fixed, complete and validated shape
 *
 * `FileIntentAuditDetails` is not a loose key/value bag: it has exactly nine
 * mandatory keys, and the writer validates every one of them at runtime, not only
 * at the type level. A caller that casts, a future caller that adds a field, or a
 * caller that smuggles a value through an `as never` cannot widen the persisted
 * payload:
 *
 * - `intentId`, `sessionId`, `policyVersionId`, `consentEvidenceId` are UUIDs;
 * - `declaredMime` is a member of the closed `FILE_MIME_TYPES` vocabulary;
 * - `purpose` is exactly `REQUEST_PROCESSING`;
 * - `state` is `RESERVED` or `CANCELLED` *and* must match the operation;
 * - `declaredBytes` is a positive JavaScript safe integer (`bigint` column);
 * - `rowVersion` is a positive PostgreSQL `integer` (max 2147483647);
 * - the object must be a plain record with exactly those own data keys: no extra
 *   key, no missing key, no symbol, no accessor, no custom prototype, no array.
 *
 * A session token, the session secret hash, the idempotency payload hash, a policy
 * source reference (free text), a legal text, a name or a URI therefore cannot be
 * placed in an event: there is no key for it, an unknown key is refused, and a
 * short arbitrary string under an allowed key is refused because the allowed keys
 * are identifiers, closed enums and bounded numbers — never free text.
 *
 * ## Public surface
 *
 * The writer and its validator are internal: the only producers are the ports in
 * `intents.ts`, which import this module directly. `index.ts` deliberately does not
 * re-export them, so a caller of the public reservation surface cannot write an
 * audit/outbox row that bypasses a port.
 */
import { randomUUID } from 'node:crypto';
import { FILE_RESERVATION_PURPOSE } from './contract.js';
import type { FileIntentState, FileReservationPurpose, FileReservationSqlClient } from './contract.js';
import { FileReservationError } from './contract.js';
import { guardFile } from './errors.js';
import { mimeValue, uuidValue } from './input.js';
import { MAX_PG_INTEGER } from './input.js';

/** The two and only two reservation operations that may write an audit/outbox pair. */
export type FileIntentAuditOperation = 'FILE_UPLOAD_INTENT_RESERVED' | 'FILE_UPLOAD_INTENT_CANCELLED';

/**
 * Exact reviewed audit payload: nine mandatory keys, no optional field, no free
 * text. The runtime validator below is authoritative; this interface only gives a
 * caller the exact shape to build and makes a new field an obvious review point.
 */
export interface FileIntentAuditDetails {
  readonly intentId: string;
  readonly sessionId: string;
  readonly policyVersionId: string;
  readonly declaredMime: string;
  readonly declaredBytes: number;
  readonly purpose: FileReservationPurpose;
  readonly consentEvidenceId: string;
  readonly state: FileIntentState;
  readonly rowVersion: number;
}

/** Closed key set: exactly these nine, in this reviewable order. */
const AUDIT_DETAIL_KEYS = [
  'intentId', 'sessionId', 'policyVersionId', 'declaredMime', 'declaredBytes', 'purpose', 'consentEvidenceId',
  'state', 'rowVersion',
] as const;

/** The operation and the state it records are one closed pair. */
const STATE_BY_OPERATION: Readonly<Record<FileIntentAuditOperation, FileIntentState>> = {
  FILE_UPLOAD_INTENT_RESERVED: 'RESERVED',
  FILE_UPLOAD_INTENT_CANCELLED: 'CANCELLED',
};

function invalid(): never {
  throw new FileReservationError('INVALID_INPUT');
}

/**
 * Narrows one plain audit record.
 *
 * Only an ordinary (or null-prototype) object is accepted: a class instance, an
 * array, a `Map`, a function or an object with a custom prototype is refused, so a
 * caller cannot smuggle behaviour through the prototype chain. Every own key —
 * including symbols — must be one of the nine allowed keys and must be a plain
 * *data* property: an accessor could execute caller code during validation or
 * return a different value on a second read. The key count plus the allowlist
 * check rejects unknown *and* missing keys; the descriptor walk rejects accessors.
 */
function auditRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    invalid();
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalid();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== AUDIT_DETAIL_KEYS.length) {
    invalid();
  }
  for (const key of keys) {
    if (typeof key === 'symbol' || !(AUDIT_DETAIL_KEYS as readonly string[]).includes(key)) {
      invalid();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      invalid();
    }
  }
  return value as Record<string, unknown>;
}

/** Closed operation vocabulary; validated at runtime, not only by the type. */
export function fileIntentAuditOperation(value: unknown): FileIntentAuditOperation {
  if (value !== 'FILE_UPLOAD_INTENT_RESERVED' && value !== 'FILE_UPLOAD_INTENT_CANCELLED') {
    invalid();
  }
  return value;
}

/**
 * The runtime gate of the audit payload. It accepts `unknown` on purpose: a caller
 * cast or an `any` cannot bypass it, and it returns a freshly built record (never
 * the caller's object), so nothing the caller still holds can mutate the persisted
 * payload afterwards.
 */
export function safeFileIntentAuditDetails(value: unknown): FileIntentAuditDetails {
  const record = auditRecord(value);

  const declaredBytes = record['declaredBytes'];
  if (typeof declaredBytes !== 'number' || !Number.isSafeInteger(declaredBytes) || declaredBytes < 1) {
    invalid();
  }
  const rowVersion = record['rowVersion'];
  if (typeof rowVersion !== 'number' || !Number.isSafeInteger(rowVersion) || rowVersion < 1
    || rowVersion > MAX_PG_INTEGER) {
    invalid();
  }
  if (record['purpose'] !== FILE_RESERVATION_PURPOSE) {
    invalid();
  }
  const state = record['state'];
  if (state !== 'RESERVED' && state !== 'CANCELLED') {
    invalid();
  }

  return {
    intentId: uuidValue(record['intentId']),
    sessionId: uuidValue(record['sessionId']),
    policyVersionId: uuidValue(record['policyVersionId']),
    declaredMime: mimeValue(record['declaredMime']),
    declaredBytes,
    purpose: FILE_RESERVATION_PURPOSE,
    consentEvidenceId: uuidValue(record['consentEvidenceId']),
    state,
    rowVersion,
  };
}

/**
 * Appends the audit and outbox rows for one reservation operation and returns the
 * shared event id. Both rows are written inside the caller's transaction; a
 * failure here aborts the whole transaction.
 *
 * Everything is validated *before* the first statement and before the event id is
 * generated: an invalid payload is refused with `INVALID_INPUT` and the client is
 * never queried.
 */
export async function writeFileIntentAudit(
  client: FileReservationSqlClient, operation: FileIntentAuditOperation, details: FileIntentAuditDetails,
): Promise<string> {
  const auditedOperation = fileIntentAuditOperation(operation);
  const payloadRecord = safeFileIntentAuditDetails(details);
  if (payloadRecord.state !== STATE_BY_OPERATION[auditedOperation]) {
    invalid();
  }
  const eventId = randomUUID();
  const payload = JSON.stringify(payloadRecord);
  await guardFile(async () => {
    await client.query(
      `INSERT INTO foundation.audit_logs (id,operation,correlation_id,details)
       VALUES ($1,$2,$3,$4::jsonb)`,
      [randomUUID(), auditedOperation, eventId, payload],
    );
    await client.query(
      `INSERT INTO foundation.outbox_events (id,event_id,event_type,payload)
       VALUES ($1,$2,$3,$4::jsonb)`,
      [randomUUID(), eventId, auditedOperation, payload],
    );
  });
  return eventId;
}
