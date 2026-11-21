/**
 * Safe audit + outbox writes for every configuration mutation.
 *
 * Each publish/archive writes both rows inside the caller's transaction, so a
 * failure to persist either one rolls the whole operation back: the caller never
 * sees a published revision without its audit trail, and an audit row never
 * describes a revision that was rolled back.
 *
 * The payload is deliberately restricted to identifiers, enum values, versions
 * and timestamps. No content body, reference label, operator address, contact,
 * legal text, policy text or secret is ever copied into `audit_logs.details` or
 * `outbox_events.payload`: those columns are read by operators and by the outbox
 * worker, neither of which needs the reviewed text to route an event.
 */
import { randomUUID } from 'node:crypto';
import { ConfigurationError } from './configuration-errors.js';
import type { ConfigurationClient } from './configuration-port.js';

/** Event/audit operation names. Lowercase dot vocabulary, at most 64 characters. */
export const CONFIGURATION_AUDIT_OPERATIONS = Object.freeze([
  'settings.publish',
  'reference.entry.create',
  'reference.version.publish',
  'reference.entry.archive',
  'content.block.create',
  'content.revision.publish',
  'content.block.archive',
] as const);
export type ConfigurationAuditOperation = typeof CONFIGURATION_AUDIT_OPERATIONS[number];

/** A value that may be copied into an audit/outbox payload. */
export type AuditScalar = string | number | null;

/**
 * Only identifier-shaped strings are accepted: a UUID, a stable code, an enum
 * value or an ISO instant. Anything with free text, whitespace or an oversized
 * value is refused, which is the structural guarantee that reviewed text cannot
 * reach an audit payload even by mistake.
 */
const SAFE_SCALAR = /^[A-Za-z0-9_.:+-]{1,64}$/;

function safeScalar(value: unknown, field: string): AuditScalar {
  if (value === null) {
    return null;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new ConfigurationError('INVALID_INPUT', `audit.${field}`);
    }
    return value;
  }
  if (typeof value === 'string' && SAFE_SCALAR.test(value)) {
    return value;
  }
  throw new ConfigurationError('INVALID_INPUT', `audit.${field}`);
}

/** Typed, allow-listed audit details: identifiers and versions only. */
export interface ConfigurationAuditDetails {
  readonly actorStaffId: string;
  readonly entity: 'SETTINGS' | 'REFERENCE_ENTRY' | 'REFERENCE_VERSION' | 'CONTENT_BLOCK' | 'CONTENT_REVISION';
  readonly entityId: string;
  readonly type?: string;
  readonly scope?: string;
  readonly cityId?: string | null;
  readonly version?: number;
  readonly entryId?: string;
  readonly blockId?: string;
  readonly revisionId?: string;
  readonly previousVersion?: number | null;
}

function payload(details: ConfigurationAuditDetails): string {
  const record: Record<string, AuditScalar> = {
    actorStaffId: safeScalar(details.actorStaffId, 'actorStaffId'),
    entity: safeScalar(details.entity, 'entity'),
    entityId: safeScalar(details.entityId, 'entityId'),
  };
  const optional: readonly (readonly [string, unknown])[] = [
    ['type', details.type], ['scope', details.scope], ['cityId', details.cityId],
    ['version', details.version], ['entryId', details.entryId], ['blockId', details.blockId],
    ['revisionId', details.revisionId], ['previousVersion', details.previousVersion],
  ];
  for (const [key, value] of optional) {
    if (value !== undefined) {
      record[key] = safeScalar(value, key);
    }
  }
  return JSON.stringify(record);
}

export interface ConfigurationAuditContext {
  readonly client: ConfigurationClient;
  readonly operation: ConfigurationAuditOperation;
  readonly details: ConfigurationAuditDetails;
}

/**
 * Writes one audit row and one outbox event with a shared correlation id.
 *
 * Both statements run on the caller's `PoolClient`; this helper never opens a
 * transaction, commits or rolls back. A driver failure propagates so the caller's
 * transaction aborts.
 */
export async function writeConfigurationAudit(context: ConfigurationAuditContext): Promise<string> {
  const { client, operation, details } = context;
  const correlationId = randomUUID();
  const body = payload(details);
  await client.query(
    `INSERT INTO foundation.audit_logs (id, operation, correlation_id, details) VALUES ($1,$2,$3,$4::jsonb)`,
    [randomUUID(), operation, correlationId, body],
  );
  await client.query(
    `INSERT INTO foundation.outbox_events (id, event_id, event_type, payload) VALUES ($1,$2,$3,$4::jsonb)`,
    [randomUUID(), correlationId, operation, JSON.stringify({ operation, ...JSON.parse(body) as Record<string, AuditScalar> })],
  );
  return correlationId;
}
