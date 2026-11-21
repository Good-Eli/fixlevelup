/**
 * Safe audit + outbox for every legal write, written in the caller's transaction.
 *
 * The same transaction that inserts a document revision, an anchor or a consent
 * event also inserts exactly one `audit_logs` row and one `outbox_events` row
 * sharing one event id. If either insert fails, the caller's transaction aborts
 * and the domain write is rolled back with it: a successful legal write is never
 * observable without its audit trail.
 *
 * The payload is restricted by an allowlist of identifier/scalar keys. Legal text
 * (`title`, `body`, `legalBasis`), the raw session token and the secret hash can
 * never be placed in an event: the writer refuses unknown keys instead of
 * redacting them, so a future caller cannot accidentally widen the payload.
 * `reviewedBy` is an identifier, not a person's data: it names the staff member who
 * reviewed a published revision and is the audit "who" for that operation.
 */
import { randomUUID } from 'node:crypto';
import { LegalPortError } from './legal-contract.js';
import type { LegalSqlClient } from './legal-contract.js';
import { guard } from './legal-errors.js';

export type LegalAuditOperation =
  | 'LEGAL_DOCUMENT_CREATED'
  | 'LEGAL_DOCUMENT_VERSION_PUBLISHED'
  | 'REQUEST_SESSION_CREATED'
  | 'REQUEST_SESSION_REVOKED'
  | 'CONSENT_GIVEN'
  | 'CONSENT_REVOKED';

/** Identifier/scalar keys only. No free text, no body, no legal basis, no secret. */
const ALLOWED_DETAIL_KEYS = new Set([
  'documentId', 'purpose', 'kind', 'versionId', 'sequence', 'sessionId', 'evidenceId', 'action', 'source',
  'cityId', 'cityVersionId', 'supersedesId', 'reviewedBy',
]);

const MAX_DETAIL_TEXT = 128;

export type LegalAuditDetails = Readonly<Record<string, string | number | boolean | null>>;

function safeDetails(details: LegalAuditDetails): LegalAuditDetails {
  const safe: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(details)) {
    if (!ALLOWED_DETAIL_KEYS.has(key)) {
      throw new LegalPortError('INVALID_INPUT');
    }
    if (value === null) {
      safe[key] = null;
    } else if (typeof value === 'string') {
      if (value.length === 0 || value.length > MAX_DETAIL_TEXT) {
        throw new LegalPortError('INVALID_INPUT');
      }
      safe[key] = value;
    } else if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new LegalPortError('INVALID_INPUT');
      }
      safe[key] = value;
    } else if (typeof value === 'boolean') {
      safe[key] = value;
    } else {
      throw new LegalPortError('INVALID_INPUT');
    }
  }
  return safe;
}

/**
 * Appends the audit and outbox rows for one legal operation. Returns the shared
 * event id so the caller may include it in a receipt if it needs to correlate.
 */
export async function writeLegalAudit(
  client: LegalSqlClient, operation: LegalAuditOperation, details: LegalAuditDetails,
): Promise<string> {
  const eventId = randomUUID();
  const payload = JSON.stringify(safeDetails(details));
  await guard(async () => {
    await client.query(
      `INSERT INTO foundation.audit_logs (id,operation,correlation_id,details)
       VALUES ($1,$2,$3,$4::jsonb)`,
      [randomUUID(), operation, eventId, payload],
    );
    await client.query(
      `INSERT INTO foundation.outbox_events (id,event_id,event_type,payload)
       VALUES ($1,$2,$3,$4::jsonb)`,
      [randomUUID(), eventId, operation, payload],
    );
  });
  return eventId;
}
