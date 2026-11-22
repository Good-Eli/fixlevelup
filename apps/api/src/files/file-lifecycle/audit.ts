import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { refuseLifecycle } from './errors.js';

const EVENTS = {
  PROCESS_CLAIM: 'FILE_PROCESSING_CLAIMED', PROCESS_RELEASE: 'FILE_PROCESSING_RELEASED',
  SANITIZED_REGISTER: 'FILE_SANITIZED_REGISTERED', SANITIZED_DISPATCH: 'FILE_SANITIZED_DISPATCHED',
  SANITIZED_FAILED_NOBYTES: 'FILE_SANITIZED_FAILED_NOBYTES', SANITIZED_UNKNOWN: 'FILE_SANITIZED_UNKNOWN',
  PUBLISH: 'FILE_PUBLISHED', READ_CLAIM: 'FILE_READ_CLAIMED', READ_RELEASE: 'FILE_READ_RELEASED',
} as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function auditLifecycle(client: PoolClient, phase: keyof typeof EVENTS, intentId: string, operationId: string): Promise<void> {
  if (!Object.hasOwn(EVENTS, phase) || !UUID.test(intentId) || !UUID.test(operationId)) {
    refuseLifecycle('CONFLICT');
  }
  const payload = JSON.stringify({ intentId, operationId, phase });
  const eventId = randomUUID();
  const operation = EVENTS[phase];
  await client.query('INSERT INTO foundation.audit_logs (id,operation,correlation_id,details) VALUES ($1,$2,$3,$4::jsonb)',
    [randomUUID(), operation, eventId, payload]);
  await client.query('INSERT INTO foundation.outbox_events (id,event_id,event_type,payload) VALUES ($1,$2,$3,$4::jsonb)',
    [randomUUID(), eventId, operation, payload]);
}
