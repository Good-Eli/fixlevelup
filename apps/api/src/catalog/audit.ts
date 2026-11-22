import { randomUUID } from 'node:crypto';
import { DIRECTORY_KINDS, ITEM_KINDS } from './contracts.js';
import type { CatalogClient, CatalogReceipt, CatalogRevisionReceipt, DirectoryKind, ItemKind } from './contracts.js';
import { CatalogInternalError, isUuid, MAX_VERSION } from './validation.js';

type Operation =
  | `catalog.${'directory' | 'item' | 'mapping'}.${'create' | 'publish' | 'archive'}`
  | `catalog.price.${'publish' | 'close' | 'replace'}`;
type Kind = DirectoryKind | ItemKind | 'FAULT_SERVICE_MAPPING' | 'FIXED_PRICE';
const KINDS: readonly Kind[] = [...DIRECTORY_KINDS, ...ITEM_KINDS, 'FAULT_SERVICE_MAPPING', 'FIXED_PRICE'];

function evidenceId(value: string): string {
  if (!isUuid(value)) {
    throw new CatalogInternalError();
  }
  return value;
}

function evidenceVersion(value: number): number {
  if (!Number.isInteger(value) || value <= 0 || value > MAX_VERSION) {
    throw new CatalogInternalError();
  }
  return value;
}

export async function audit(
  client: CatalogClient, operation: Operation, actorStaffId: string, kind: Kind,
  receipt: CatalogReceipt | CatalogRevisionReceipt,
  target?: { cityId: string; itemId: string; priceVersionId?: string },
): Promise<void> {
  if (!KINDS.includes(kind)) {
    throw new CatalogInternalError();
  }
  const body = JSON.stringify({
    actorStaffId: evidenceId(actorStaffId),
    id: evidenceId(receipt.id),
    version: evidenceVersion(receipt.version),
    kind,
    ...('revisionId' in receipt ? {
      revisionId: evidenceId(receipt.revisionId),
      revisionVersion: evidenceVersion(receipt.revisionVersion),
    } : {}),
    ...(target ? {
      cityId: evidenceId(target.cityId), itemId: evidenceId(target.itemId),
      ...(target.priceVersionId !== undefined ? { priceVersionId: evidenceId(target.priceVersionId) } : {}),
    } : {}),
  });
  const correlationId = randomUUID();
  try {
    const auditRow = await client.query(`INSERT INTO foundation.audit_logs
      (id, operation, correlation_id, details) VALUES ($1, $2, $3, $4::jsonb)`,
    [randomUUID(), operation, correlationId, body]);
    if (auditRow.rowCount !== 1) {
      throw new CatalogInternalError();
    }
    const outboxRow = await client.query(`INSERT INTO foundation.outbox_events
      (id, event_id, event_type, payload) VALUES ($1, $2, $3, $4::jsonb)`,
    [randomUUID(), correlationId, operation, body]);
    if (outboxRow.rowCount !== 1) {
      throw new CatalogInternalError();
    }
  } catch {
    // Even a same-SQLSTATE audit/outbox fault is not a domain conflict.
    throw new CatalogInternalError();
  }
}
